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

//! External dependency resolvers
//!
//! This module provides a pluggable architecture for dependency resolution
//! using external tools like uv and pip-tools.

use crate::cache::audit::AuditCache;
use crate::types::{ResolutionCacheEntry, ResolvedDependency, ResolverType};
use crate::{AuditError, Result};
use async_trait::async_trait;
use std::collections::HashMap;
use tracing::info;

pub mod pip_tools;
pub mod uv;

pub struct CacheMetadata {
    pub cache_key: String,
    pub resolver_type: ResolverType,
    pub resolver_version: String,
    pub python_version: String,
    pub platform: String,
    pub environment_markers: HashMap<String, String>,
}

pub fn generate_cache_metadata(
    requirements_content: &str,
    cache: &AuditCache,
    resolver_type: ResolverType,
    resolver_version: String,
    python_version: String,
    platform: String,
    environment_markers: HashMap<String, String>,
) -> CacheMetadata {
    let cache_key = cache.generate_resolution_cache_key(
        requirements_content,
        &resolver_type,
        &resolver_version,
        &python_version,
        &platform,
        &environment_markers,
    );

    CacheMetadata {
        cache_key,
        resolver_type,
        resolver_version,
        python_version,
        platform,
        environment_markers,
    }
}

pub async fn check_cache(
    cache: &AuditCache,
    metadata: &CacheMetadata,
    force_refresh: bool,
    ttl_hours: u64,
    resolver_name: &str,
) -> Result<Option<String>> {
    if !force_refresh {
        if let Ok(false) = cache.should_refresh_resolution(&metadata.cache_key, ttl_hours) {
            if let Ok(Some(cache_entry)) = cache.read_resolution_cache(&metadata.cache_key).await {
                info!(
                    "Using cached {} resolution for key: {}",
                    resolver_name, metadata.cache_key
                );

                return Ok(Some(cache_entry.output));
            }
        }
    }
    Ok(None)
}

pub async fn write_to_cache(
    cache: &AuditCache,
    metadata: &CacheMetadata,
    resolved_output: &str,
    dependencies: Vec<ResolvedDependency>,
) -> Result<()> {
    let cache_entry = ResolutionCacheEntry {
        output: resolved_output.to_string(),
        resolver_type: metadata.resolver_type,
        resolver_version: metadata.resolver_version.clone(),
        python_version: metadata.python_version.clone(),
        dependencies,
    };

    if let Err(e) = cache
        .write_resolution_cache(&metadata.cache_key, &cache_entry)
        .await
    {
        tracing::warn!("Failed to write resolution cache: {}", e);
    }
    Ok(())
}

pub async fn handle_cache_error(cache: &AuditCache, metadata: &CacheMetadata) {
    if let Err(cache_err) = cache
        .clear_resolution_cache_entry(&metadata.cache_key)
        .await
    {
        tracing::warn!(
            "Failed to clear resolution cache entry after error: {}",
            cache_err
        );
    }
}

/// Trait for external dependency resolvers
#[async_trait]
pub trait DependencyResolver: Send + Sync {
    /// Returns the name of this resolver (e.g., "uv", "pip-tools")
    fn name(&self) -> &'static str;

    /// Check if this resolver is available on the system
    async fn is_available(&self) -> bool;

    /// Resolve requirements content into a pinned dependencies string
    ///
    /// Takes raw requirements.txt content and returns resolved dependencies
    /// in the format "package==version" (one per line)
    async fn resolve_requirements(&self, requirements_content: &str) -> Result<String>;

    async fn get_version(&self) -> Result<String>;

    async fn resolve_requirements_cached(
        &self,
        requirements_content: &str,
        cache: &AuditCache,
        force_refresh: bool,
        ttl_hours: u64,
    ) -> Result<String>;

    /// Get resolver-specific command line arguments if needed
    fn get_resolver_args(&self) -> Vec<String> {
        Vec::new()
    }

    /// Check if resolver supports a specific feature
    fn supports_feature(&self, _feature: ResolverFeature) -> bool {
        true // Default: support all features
    }
}

/// Features that resolvers may or may not support
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResolverFeature {
    /// Support for extras like package[extra]
    Extras,
    /// Support for environment markers like package; python_version >= "3.8"
    EnvironmentMarkers,
    /// Support for direct URL dependencies
    DirectUrls,
    /// Support for editable installs (-e)
    EditableInstalls,
    /// Support for constraint files
    Constraints,
}

/// Registry for managing dependency resolvers
pub struct ResolverRegistry;

impl ResolverRegistry {
    /// Create a resolver instance for the given type
    pub fn create_resolver(resolver_type: ResolverType) -> Box<dyn DependencyResolver> {
        match resolver_type {
            ResolverType::Uv => Box::new(uv::UvResolver::new()),
            ResolverType::PipTools => Box::new(pip_tools::PipToolsResolver::new()),
        }
    }

    /// Auto-detect the best available resolver
    pub async fn detect_best_resolver() -> Result<ResolverType> {
        // Try resolvers in order of preference
        let candidates = vec![
            ResolverType::Uv,       // Fastest, most reliable
            ResolverType::PipTools, // Widely used
        ];

        for resolver_type in candidates {
            let resolver = Self::create_resolver(resolver_type);
            if resolver.is_available().await {
                return Ok(resolver_type);
            }
        }

        Err(AuditError::other(
            "No supported dependency resolver found. Please install uv or pip-tools.",
        ))
    }

    /// Get all available resolvers on the system
    pub async fn get_available_resolvers() -> Vec<ResolverType> {
        let mut available = Vec::new();
        let candidates = vec![ResolverType::Uv, ResolverType::PipTools];

        for resolver_type in candidates {
            let resolver = Self::create_resolver(resolver_type);
            if resolver.is_available().await {
                available.push(resolver_type);
            }
        }

        available
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_resolver_type_display() {
        assert_eq!(ResolverType::Uv.to_string(), "uv");
        assert_eq!(ResolverType::PipTools.to_string(), "pip-tools");
    }

    #[test]
    fn test_resolver_type_from_str() {
        assert_eq!(ResolverType::from("uv"), ResolverType::Uv);
        assert_eq!(ResolverType::from("pip-tools"), ResolverType::PipTools);
        assert_eq!(ResolverType::from("piptools"), ResolverType::PipTools);
        assert_eq!(ResolverType::from("unknown"), ResolverType::Uv); // Fallback
    }

    #[tokio::test]
    async fn test_resolver_registry() {
        // Test that we can create resolvers
        let uv_resolver = ResolverRegistry::create_resolver(ResolverType::Uv);
        assert_eq!(uv_resolver.name(), "uv");

        let pip_tools_resolver = ResolverRegistry::create_resolver(ResolverType::PipTools);
        assert_eq!(pip_tools_resolver.name(), "pip-tools");
    }
}
