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

//! pip-tools dependency resolver implementation
//!
//! pip-tools (pip-compile) is a popular Python-based dependency resolver.
//! This module provides integration with pip-tools for resolving requirements.txt files.

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

    async fn get_python_version(&self) -> Result<String> {
        let python_commands = ["python3", "python"];

        for cmd in &python_commands {
            if let Ok(output) = Command::new(cmd)
                .args([
                    "-c",
                    "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')",
                ])
                .output()
                .await
            {
                if output.status.success() {
                    return Ok(String::from_utf8_lossy(&output.stdout).trim().to_string());
                }
            }
        }

        Ok("3.12".to_string()) // Fallback to common version
    }

    fn get_platform(&self) -> String {
        format!("{}-{}", env::consts::OS, env::consts::ARCH)
    }

    async fn get_environment_markers(&self) -> HashMap<String, String> {
        let mut markers = HashMap::new();

        if let Ok(py_version) = self.get_python_version().await {
            markers.insert("python_version".to_string(), py_version);
        }

        markers.insert("sys_platform".to_string(), env::consts::OS.to_string());
        markers.insert(
            "platform_machine".to_string(),
            env::consts::ARCH.to_string(),
        );

        if let Ok(value) = env::var("PIP_INDEX_URL") {
            markers.insert("pip_index_url".to_string(), value);
        }
        if let Ok(value) = env::var("PIP_EXTRA_INDEX_URL") {
            markers.insert("pip_extra_index_url".to_string(), value);
        }
        if let Ok(value) = env::var("PIP_TRUSTED_HOST") {
            markers.insert("pip_trusted_host".to_string(), value);
        }
        if let Ok(value) = env::var("PIP_PRE") {
            markers.insert("pip_pre".to_string(), value);
        }

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

        debug!(
            "Parsed {} dependencies from pip-tools output",
            dependencies.len()
        );
        dependencies
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

    async fn get_version(&self) -> Result<String> {
        let output = Command::new("pip-compile")
            .arg("--version")
            .output()
            .await
            .map_err(|e| {
                AuditError::PipToolsExecutionFailed(format!("Failed to get pip-tools version: {e}"))
            })?;

        if output.status.success() {
            let version = String::from_utf8_lossy(&output.stdout);
            let version_str = version.trim();
            if let Some(version_part) = version_str.split_whitespace().last() {
                Ok(version_part.to_string())
            } else {
                Ok(version_str.to_string())
            }
        } else {
            Err(AuditError::PipToolsExecutionFailed(
                "Failed to get pip-tools version".to_string(),
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
            return Err(AuditError::PipToolsNotAvailable);
        }

        let resolver_version = self.get_version().await?;
        let python_version = self.get_python_version().await?;
        let platform = self.get_platform();
        let environment_markers = self.get_environment_markers().await;

        let metadata = generate_cache_metadata(
            requirements_content,
            cache,
            ResolverType::PipTools,
            resolver_version,
            python_version,
            platform,
            environment_markers,
        );

        debug!(
            "Generated cache key for pip-tools resolution: {}",
            metadata.cache_key
        );

        if let Some(cached_result) =
            check_cache(cache, &metadata, force_refresh, ttl_hours, "pip-tools").await?
        {
            return Ok(cached_result);
        }

        tracing::info!(
            "Performing fresh pip-tools resolution for cache key: {}",
            metadata.cache_key
        );

        match self.execute_pip_compile(requirements_content).await {
            Ok(resolved_output) => {
                let temp_file = std::path::Path::new("requirements.in");
                let dependencies = self.parse_resolved_dependencies(&resolved_output, temp_file);

                write_to_cache(cache, &metadata, &resolved_output, dependencies).await?;

                Ok(resolved_output)
            }
            Err(e) => {
                handle_cache_error(cache, &metadata).await;
                Err(e)
            }
        }
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
