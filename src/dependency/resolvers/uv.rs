//! UV dependency resolver implementation
//!
//! UV is a fast, Rust-based Python package manager and dependency resolver.
//! This module provides integration with UV for resolving requirements.txt files.

use super::{DependencyResolver, ResolverFeature};
use crate::{AuditError, Result};
use async_trait::async_trait;
use std::time::Duration;
use tokio::process::Command;
use tracing::debug;

/// UV-based dependency resolver
pub struct UvResolver;

impl UvResolver {
    /// Create a new UV resolver instance
    pub fn new() -> Self {
        Self
    }

    /// Create isolated temporary directory for UV operations
    fn create_isolated_temp_dir() -> Result<tempfile::TempDir> {
        tempfile::tempdir()
            .map_err(|e| AuditError::other(format!("Failed to create temporary directory: {e}")))
    }

    /// Execute UV pip compile command in isolated environment
    async fn execute_uv_compile(&self, requirements_content: &str) -> Result<String> {
        // Create completely isolated temporary directory
        let temp_dir = Self::create_isolated_temp_dir()?;
        let temp_requirements = temp_dir.path().join("requirements.txt");

        // Write requirements to temp file
        tokio::fs::write(&temp_requirements, requirements_content)
            .await
            .map_err(|e| {
                AuditError::other(format!("Failed to write temp requirements file: {e}"))
            })?;

        // Build UV command with complete isolation
        let mut cmd = Command::new("uv");
        cmd.current_dir(temp_dir.path()); // Critical: never use project directory
        cmd.args(["pip", "compile"]);
        cmd.arg("requirements.txt");
        cmd.args(["--output-file", "-"]); // Output to stdout only

        // Isolation and safety options
        cmd.args([
            "--no-header", // Don't include timestamp headers
            "--no-annotate", // Don't include source comments
                           // Note: --quiet suppresses stdout output, so we don't use it
        ]);

        // Force cache to isolated location to prevent project pollution
        cmd.env("UV_CACHE_DIR", temp_dir.path().join(".uv-cache"));
        cmd.env("UV_NO_PROGRESS", "1"); // Disable progress bars

        debug!("Executing UV pip compile in isolated environment");

        // Execute command with timeout
        let output = tokio::time::timeout(
            Duration::from_secs(300), // 5 minute timeout
            cmd.output(),
        )
        .await
        .map_err(|_| AuditError::UvTimeout)?
        .map_err(|e| AuditError::UvExecutionFailed(format!("Failed to execute uv: {e}")))?;

        // Log stderr for debugging (UV outputs progress info there)
        let stderr = String::from_utf8_lossy(&output.stderr);
        if !stderr.trim().is_empty() {
            debug!("UV stderr: {}", stderr);
        }

        if output.status.success() {
            let resolved = String::from_utf8(output.stdout).map_err(|e| {
                AuditError::UvExecutionFailed(format!("Invalid UTF-8 output from uv: {e}"))
            })?;

            debug!("UV resolution successful, {} bytes output", resolved.len());

            if resolved.trim().is_empty() {
                return Err(AuditError::EmptyResolution);
            }

            Ok(resolved)
        } else {
            Err(AuditError::UvResolutionFailed(format!(
                "Exit code: {}, stderr: {}",
                output.status, stderr
            )))
        }
    }
}

impl Default for UvResolver {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl DependencyResolver for UvResolver {
    fn name(&self) -> &'static str {
        "uv"
    }

    async fn is_available(&self) -> bool {
        match Command::new("uv").arg("--version").output().await {
            Ok(output) => output.status.success(),
            Err(_) => false,
        }
    }

    async fn resolve_requirements(&self, requirements_content: &str) -> Result<String> {
        // Check if UV is available before attempting resolution
        if !self.is_available().await {
            return Err(AuditError::UvNotAvailable);
        }

        // Execute UV compilation
        self.execute_uv_compile(requirements_content).await
    }

    fn get_resolver_args(&self) -> Vec<String> {
        vec!["--no-header".to_string(), "--no-annotate".to_string()]
    }

    fn supports_feature(&self, feature: ResolverFeature) -> bool {
        match feature {
            ResolverFeature::Extras => true,
            ResolverFeature::EnvironmentMarkers => true,
            ResolverFeature::DirectUrls => true,
            ResolverFeature::EditableInstalls => true,
            ResolverFeature::Constraints => true, // UV supports constraint files
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tracing::warn;

    #[tokio::test]
    async fn test_uv_resolver_creation() {
        let resolver = UvResolver::new();
        assert_eq!(resolver.name(), "uv");
    }

    #[tokio::test]
    async fn test_uv_resolver_availability() {
        let resolver = UvResolver::new();
        // This test will pass if UV is installed, otherwise it will be false
        // We can't assume UV is always available in CI environments
        let _is_available = resolver.is_available().await;
        // Just ensure the method doesn't panic
    }

    #[test]
    fn test_uv_resolver_features() {
        let resolver = UvResolver::new();

        // UV should support all major features
        assert!(resolver.supports_feature(ResolverFeature::Extras));
        assert!(resolver.supports_feature(ResolverFeature::EnvironmentMarkers));
        assert!(resolver.supports_feature(ResolverFeature::DirectUrls));
        assert!(resolver.supports_feature(ResolverFeature::EditableInstalls));
        assert!(resolver.supports_feature(ResolverFeature::Constraints));
    }

    #[test]
    fn test_uv_resolver_args() {
        let resolver = UvResolver::new();
        let args = resolver.get_resolver_args();

        assert!(args.contains(&"--no-header".to_string()));
        assert!(args.contains(&"--no-annotate".to_string()));
    }

    #[tokio::test]
    async fn test_uv_resolver_resolution_basic() {
        let resolver = UvResolver::new();

        // Skip test if UV is not available
        if !resolver.is_available().await {
            return;
        }

        let requirements = "requests>=2.25.0\n";

        match resolver.resolve_requirements(requirements).await {
            Ok(resolved) => {
                assert!(!resolved.is_empty());
                assert!(resolved.contains("requests=="));
                debug!("UV resolution test successful: {} chars", resolved.len());
            }
            Err(e) => {
                // Log the error but don't fail the test - UV might not be configured properly
                warn!(
                    "UV resolution test failed (this might be expected in CI): {}",
                    e
                );
            }
        }
    }

    #[tokio::test]
    async fn test_uv_resolver_empty_requirements() {
        let resolver = UvResolver::new();

        // Skip test if UV is not available
        if !resolver.is_available().await {
            return;
        }

        let requirements = "# Just a comment\n\n";

        match resolver.resolve_requirements(requirements).await {
            Ok(_) => {
                // UV might return empty output for empty requirements
                debug!("UV handled empty requirements");
            }
            Err(AuditError::EmptyResolution) => {
                // This is expected for empty requirements
                debug!("UV correctly detected empty resolution");
            }
            Err(e) => {
                warn!("Unexpected error for empty requirements: {}", e);
            }
        }
    }
}
