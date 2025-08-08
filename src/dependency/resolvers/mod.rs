//! External dependency resolvers
//!
//! This module provides a pluggable architecture for dependency resolution
//! using external tools like uv and pip-tools.

use crate::{AuditError, Result};
use async_trait::async_trait;
use std::fmt::Display;

pub mod pip_tools;
pub mod uv;

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

/// Available resolver types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResolverType {
    /// UV resolver (Rust-based, fastest)
    Uv,
    /// pip-tools resolver (Python-based, widely used)
    PipTools,
}

impl Display for ResolverType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ResolverType::Uv => write!(f, "uv"),
            ResolverType::PipTools => write!(f, "pip-tools"),
        }
    }
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

impl From<&str> for ResolverType {
    fn from(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "uv" => ResolverType::Uv,
            "pip-tools" | "pip_tools" | "piptools" => ResolverType::PipTools,
            _ => ResolverType::Uv, // Default fallback
        }
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
