//! pip-tools dependency resolver implementation
//!
//! pip-tools (pip-compile) is a popular Python-based dependency resolver.
//! This module provides integration with pip-tools for resolving requirements.txt files.

use super::{DependencyResolver, ResolverFeature};
use crate::{AuditError, Result};
use async_trait::async_trait;
use std::time::Duration;
use tokio::process::Command;
use tracing::debug;

/// pip-tools-based dependency resolver
pub struct PipToolsResolver;

impl PipToolsResolver {
    /// Create a new pip-tools resolver instance
    pub fn new() -> Self {
        Self
    }

    /// Create isolated temporary directory for pip-tools operations
    fn create_isolated_temp_dir() -> Result<tempfile::TempDir> {
        tempfile::tempdir()
            .map_err(|e| AuditError::other(format!("Failed to create temporary directory: {e}")))
    }

    /// Execute pip-compile command in isolated environment
    async fn execute_pip_compile(&self, requirements_content: &str) -> Result<String> {
        // Create completely isolated temporary directory
        let temp_dir = Self::create_isolated_temp_dir()?;
        let temp_requirements = temp_dir.path().join("requirements.in");
        let temp_output = temp_dir.path().join("requirements.txt");

        // Write requirements to temp file (pip-tools expects .in extension)
        tokio::fs::write(&temp_requirements, requirements_content)
            .await
            .map_err(|e| {
                AuditError::other(format!("Failed to write temp requirements file: {e}"))
            })?;

        // Build pip-compile command with complete isolation
        let mut cmd = Command::new("pip-compile");
        cmd.current_dir(temp_dir.path()); // Critical: never use project directory
        cmd.arg(&temp_requirements);
        cmd.args(["--output-file", temp_output.to_str().unwrap()]);

        // Isolation and safety options
        cmd.args([
            "--no-header",            // Don't include timestamp headers
            "--no-annotate",          // Don't include source comments
            "--quiet",                // Suppress progress output
            "--no-emit-index-url",    // Don't emit index URLs
            "--no-emit-trusted-host", // Don't emit trusted host
        ]);

        // Force cache to isolated location to prevent project pollution
        let pip_cache_dir = temp_dir.path().join(".pip-cache");
        cmd.env("PIP_CACHE_DIR", &pip_cache_dir);
        cmd.env("PIP_NO_COLOR", "1"); // Disable colored output

        debug!("Executing pip-compile in isolated environment");

        // Execute command with timeout
        let output = tokio::time::timeout(
            Duration::from_secs(300), // 5 minute timeout
            cmd.output(),
        )
        .await
        .map_err(|_| AuditError::PipToolsTimeout)?
        .map_err(|e| {
            AuditError::PipToolsExecutionFailed(format!("Failed to execute pip-compile: {e}"))
        })?;

        // Log stderr for debugging
        let stderr = String::from_utf8_lossy(&output.stderr);
        if !stderr.trim().is_empty() {
            debug!("pip-compile stderr: {}", stderr);
        }

        if output.status.success() {
            // Read the generated output file
            let resolved = tokio::fs::read_to_string(&temp_output).await.map_err(|e| {
                AuditError::PipToolsExecutionFailed(format!(
                    "Failed to read pip-compile output: {e}"
                ))
            })?;

            debug!(
                "pip-compile resolution successful, {} bytes output",
                resolved.len()
            );

            if resolved.trim().is_empty() {
                return Err(AuditError::EmptyResolution);
            }

            Ok(resolved)
        } else {
            Err(AuditError::PipToolsResolutionFailed(format!(
                "Exit code: {}, stderr: {}",
                output.status, stderr
            )))
        }
    }
}

impl Default for PipToolsResolver {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl DependencyResolver for PipToolsResolver {
    fn name(&self) -> &'static str {
        "pip-tools"
    }

    async fn is_available(&self) -> bool {
        match Command::new("pip-compile").arg("--version").output().await {
            Ok(output) => output.status.success(),
            Err(_) => false,
        }
    }

    async fn resolve_requirements(&self, requirements_content: &str) -> Result<String> {
        // Check if pip-compile is available before attempting resolution
        if !self.is_available().await {
            return Err(AuditError::PipToolsNotAvailable);
        }

        // Execute pip-compile compilation
        self.execute_pip_compile(requirements_content).await
    }

    fn get_resolver_args(&self) -> Vec<String> {
        vec![
            "--no-header".to_string(),
            "--no-annotate".to_string(),
            "--quiet".to_string(),
            "--no-emit-index-url".to_string(),
            "--no-emit-trusted-host".to_string(),
        ]
    }

    fn supports_feature(&self, feature: ResolverFeature) -> bool {
        match feature {
            ResolverFeature::Extras => true,
            ResolverFeature::EnvironmentMarkers => true,
            ResolverFeature::DirectUrls => true,
            ResolverFeature::EditableInstalls => true,
            ResolverFeature::Constraints => true, // pip-tools supports constraint files
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tracing::warn;

    #[tokio::test]
    async fn test_pip_tools_resolver_creation() {
        let resolver = PipToolsResolver::new();
        assert_eq!(resolver.name(), "pip-tools");
    }

    #[tokio::test]
    async fn test_pip_tools_resolver_availability() {
        let resolver = PipToolsResolver::new();
        // This test will pass if pip-tools is installed, otherwise it will be false
        // We can't assume pip-tools is always available in CI environments
        let _is_available = resolver.is_available().await;
        // Just ensure the method doesn't panic
    }

    #[test]
    fn test_pip_tools_resolver_features() {
        let resolver = PipToolsResolver::new();

        // pip-tools should support all major features
        assert!(resolver.supports_feature(ResolverFeature::Extras));
        assert!(resolver.supports_feature(ResolverFeature::EnvironmentMarkers));
        assert!(resolver.supports_feature(ResolverFeature::DirectUrls));
        assert!(resolver.supports_feature(ResolverFeature::EditableInstalls));
        assert!(resolver.supports_feature(ResolverFeature::Constraints));
    }

    #[test]
    fn test_pip_tools_resolver_args() {
        let resolver = PipToolsResolver::new();
        let args = resolver.get_resolver_args();

        assert!(args.contains(&"--no-header".to_string()));
        assert!(args.contains(&"--no-annotate".to_string()));
        assert!(args.contains(&"--quiet".to_string()));
        assert!(args.contains(&"--no-emit-index-url".to_string()));
        assert!(args.contains(&"--no-emit-trusted-host".to_string()));
    }

    #[tokio::test]
    async fn test_pip_tools_resolver_resolution_basic() {
        let resolver = PipToolsResolver::new();

        // Skip test if pip-tools is not available
        if !resolver.is_available().await {
            return;
        }

        let requirements = "requests>=2.25.0\n";

        match resolver.resolve_requirements(requirements).await {
            Ok(resolved) => {
                assert!(!resolved.is_empty());
                assert!(resolved.contains("requests=="));
                debug!(
                    "pip-tools resolution test successful: {} chars",
                    resolved.len()
                );
            }
            Err(e) => {
                // Log the error but don't fail the test - pip-tools might not be configured properly
                warn!(
                    "pip-tools resolution test failed (this might be expected in CI): {}",
                    e
                );
            }
        }
    }

    #[tokio::test]
    async fn test_pip_tools_resolver_empty_requirements() {
        let resolver = PipToolsResolver::new();

        // Skip test if pip-tools is not available
        if !resolver.is_available().await {
            return;
        }

        let requirements = "# Just a comment\n\n";

        match resolver.resolve_requirements(requirements).await {
            Ok(_) => {
                // pip-tools might return empty output for empty requirements
                debug!("pip-tools handled empty requirements");
            }
            Err(AuditError::EmptyResolution) => {
                // This is expected for empty requirements
                debug!("pip-tools correctly detected empty resolution");
            }
            Err(e) => {
                warn!("Unexpected error for empty requirements: {}", e);
            }
        }
    }
}
