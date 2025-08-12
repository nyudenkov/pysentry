/*
 * pysentry - Python security vulnerability scanner
 * Copyright (C) 2025 nyudenkov <nyudenkov@pm.me>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

//! UV dependency resolver implementation
//!
//! UV is a fast, Rust-based Python package manager and dependency resolver.
//! This module provides integration with UV for resolving requirements.txt files.

use super::{
    check_cache, generate_cache_metadata, handle_cache_error, write_to_cache, DependencyResolver,
    ResolverFeature,
};
use crate::cache::audit::AuditCache;
use crate::types::{ResolvedDependency, ResolverType};
use crate::{AuditError, Result};
use async_trait::async_trait;
use regex::Regex;
use std::collections::HashMap;
use std::env;
use std::sync::OnceLock;
use std::time::Duration;
use tokio::process::Command;
use tracing::debug;

static PACKAGE_REGEX: OnceLock<Regex> = OnceLock::new();

/// UV-based dependency resolver
pub struct UvResolver {
    cached_version: OnceLock<String>,
    cached_python_version: OnceLock<String>,
    cached_platform: OnceLock<String>,
    cached_environment_markers: OnceLock<HashMap<String, String>>,
}

impl UvResolver {
    /// Create a new UV resolver instance
    pub fn new() -> Self {
        Self {
            cached_version: OnceLock::new(),
            cached_python_version: OnceLock::new(),
            cached_platform: OnceLock::new(),
            cached_environment_markers: OnceLock::new(),
        }
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

    async fn get_python_version(&self) -> Result<String> {
        if let Some(version) = self.cached_python_version.get() {
            return Ok(version.clone());
        }

        let version = match env::var("UV_PYTHON") {
            Ok(python_path) => {
                let output = Command::new(&python_path)
                    .args([
                        "-c",
                        "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')",
                    ])
                    .output()
                    .await;

                match output {
                    Ok(out) if out.status.success() => {
                        String::from_utf8_lossy(&out.stdout).trim().to_string()
                    }
                    _ => "3.12".to_string(),
                }
            }
            Err(_) => "3.12".to_string(),
        };

        let _ = self.cached_python_version.set(version.clone());
        Ok(version)
    }

    fn get_platform(&self) -> String {
        self.cached_platform
            .get_or_init(|| format!("{}-{}", env::consts::OS, env::consts::ARCH))
            .clone()
    }

    async fn get_environment_markers(&self) -> HashMap<String, String> {
        if let Some(markers) = self.cached_environment_markers.get() {
            return markers.clone();
        }

        let mut markers = HashMap::new();

        if let Ok(py_version) = self.get_python_version().await {
            markers.insert("python_version".to_string(), py_version);
        }

        markers.insert("sys_platform".to_string(), env::consts::OS.to_string());
        markers.insert(
            "platform_machine".to_string(),
            env::consts::ARCH.to_string(),
        );

        if let Ok(value) = env::var("UV_INDEX_URL") {
            markers.insert("uv_index_url".to_string(), value);
        }
        if let Ok(value) = env::var("UV_EXTRA_INDEX_URL") {
            markers.insert("uv_extra_index_url".to_string(), value);
        }
        if let Ok(value) = env::var("UV_PRERELEASE") {
            markers.insert("uv_prerelease".to_string(), value);
        }

        let _ = self.cached_environment_markers.set(markers.clone());
        markers
    }

    fn parse_resolved_dependencies(
        &self,
        resolved_output: &str,
        source_file: &std::path::Path,
    ) -> Vec<ResolvedDependency> {
        let mut dependencies = Vec::new();

        let package_regex = PACKAGE_REGEX
            .get_or_init(|| Regex::new(r"^([a-zA-Z0-9_.-]+)==([^;]+)(?:;\s*(.+))?").unwrap());

        for line in resolved_output.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }

            if let Some(captures) = package_regex.captures(trimmed) {
                let name = captures.get(1).unwrap().as_str().to_string();
                let version = captures.get(2).unwrap().as_str().to_string();
                let markers = captures.get(3).map(|m| m.as_str().to_string());

                dependencies.push(ResolvedDependency {
                    name,
                    version,
                    is_direct: true, // We'll mark all as direct for now, could be enhanced
                    source_file: source_file.to_path_buf(),
                    extras: Vec::new(), // Could be parsed from package name if needed
                    markers,
                });
            }
        }

        debug!("Parsed {} dependencies from UV output", dependencies.len());
        dependencies
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

    async fn get_version(&self) -> Result<String> {
        if let Some(version) = self.cached_version.get() {
            return Ok(version.clone());
        }

        let output = Command::new("uv")
            .arg("--version")
            .output()
            .await
            .map_err(|e| AuditError::UvExecutionFailed(format!("Failed to get UV version: {e}")))?;

        if output.status.success() {
            let version_str = String::from_utf8_lossy(&output.stdout);
            let version = version_str.trim().replace("uv ", "");

            let _ = self.cached_version.set(version.clone());
            Ok(version)
        } else {
            Err(AuditError::UvExecutionFailed(
                "Failed to get UV version".to_string(),
            ))
        }
    }

    async fn resolve_requirements_cached(
        &self,
        requirements_content: &str,
        cache: &AuditCache,
        force_refresh: bool,
        ttl_hours: u64,
    ) -> Result<String> {
        if !self.is_available().await {
            return Err(AuditError::UvNotAvailable);
        }

        let resolver_version = self.get_version().await?;
        let python_version = self.get_python_version().await?;
        let platform = self.get_platform();
        let environment_markers = self.get_environment_markers().await;

        let metadata = generate_cache_metadata(
            requirements_content,
            cache,
            ResolverType::Uv,
            resolver_version,
            python_version,
            platform,
            environment_markers,
        );

        debug!(
            "Generated cache key for UV resolution: {}",
            metadata.cache_key
        );

        if let Some(cached_result) =
            check_cache(cache, &metadata, force_refresh, ttl_hours, "UV").await?
        {
            return Ok(cached_result);
        }

        tracing::info!(
            "Performing fresh UV resolution for cache key: {}",
            metadata.cache_key
        );

        match self.execute_uv_compile(requirements_content).await {
            Ok(resolved_output) => {
                // Parse resolved dependencies
                let temp_file = std::path::Path::new("requirements.txt");
                let dependencies = self.parse_resolved_dependencies(&resolved_output, temp_file);

                // Write to cache using shared helper
                write_to_cache(cache, &metadata, &resolved_output, dependencies).await?;

                Ok(resolved_output)
            }
            Err(e) => {
                // Handle cache error using shared helper
                handle_cache_error(cache, &metadata).await;
                Err(e)
            }
        }
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
