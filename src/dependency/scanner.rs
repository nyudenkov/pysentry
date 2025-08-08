pub use crate::parsers::DependencyStats;
use crate::parsers::{ParsedDependency, ParserRegistry};
use crate::Result;
use std::path::Path;
use tracing::{debug, info};

/// Main dependency scanner that orchestrates parsing using the parser registry
pub struct DependencyScanner {
    parser_registry: ParserRegistry,
    include_dev: bool,
    include_optional: bool,
    direct_only: bool,
}

impl DependencyScanner {
    /// Create a new dependency scanner with specified options
    pub fn new(
        include_dev: bool,
        include_optional: bool,
        direct_only: bool,
        resolver: Option<crate::dependency::resolvers::ResolverType>,
    ) -> Self {
        Self {
            parser_registry: ParserRegistry::new(resolver),
            include_dev,
            include_optional,
            direct_only,
        }
    }

    /// Scan dependencies from a project directory using the best available parser
    pub async fn scan_project(&self, project_dir: &Path) -> Result<Vec<ScannedDependency>> {
        debug!("Scanning dependencies in: {}", project_dir.display());

        // Use parser registry to automatically select and parse with the best parser
        let (parsed_dependencies, parser_name) = self
            .parser_registry
            .parse_project(
                project_dir,
                self.include_dev,
                self.include_optional,
                self.direct_only,
            )
            .await?;

        info!("Used parser: {} for project scanning", parser_name);
        debug!("Parsed {} dependencies", parsed_dependencies.len());

        // Convert ParsedDependency to ScannedDependency (keeping backward compatibility)
        let scanned_dependencies: Vec<ScannedDependency> = parsed_dependencies
            .into_iter()
            .map(|dep| ScannedDependency {
                name: dep.name,
                version: dep.version,
                is_direct: dep.is_direct,
                source: dep.source.into(),
                path: dep.path,
            })
            .collect();

        debug!(
            "Successfully scanned {} dependencies",
            scanned_dependencies.len()
        );
        Ok(scanned_dependencies)
    }

    /// Get dependency statistics
    pub fn get_stats(&self, dependencies: &[ScannedDependency]) -> DependencyStats {
        // Convert ScannedDependency back to ParsedDependency for stats calculation
        let parsed_deps: Vec<ParsedDependency> = dependencies
            .iter()
            .map(|dep| ParsedDependency {
                name: dep.name.clone(),
                version: dep.version.clone(),
                is_direct: dep.is_direct,
                source: dep.source.clone().into(),
                path: dep.path.clone(),
                dependency_type: crate::parsers::DependencyType::Main, // Default assumption for backward compatibility
            })
            .collect();

        DependencyStats::from_dependencies(&parsed_deps)
    }

    /// Validate dependencies and return warnings
    pub fn validate_dependencies(&self, dependencies: &[ScannedDependency]) -> Vec<String> {
        // For now, provide basic validation
        let mut warnings = Vec::new();

        if dependencies.is_empty() {
            warnings.push(
                "No dependencies found. This might indicate an issue with dependency resolution."
                    .to_string(),
            );
            return warnings;
        }

        // Check for placeholder versions
        let placeholder_count = dependencies
            .iter()
            .filter(|dep| dep.version == crate::types::Version::new([0, 0, 0]))
            .count();

        if placeholder_count > 0 {
            warnings.push(format!(
                "{placeholder_count} dependencies have placeholder versions. Consider using a lock file for accurate version information."
            ));
        }

        // Check for very large dependency trees
        if dependencies.len() > 1000 {
            warnings.push(format!(
                "Found {} dependencies. This is a very large dependency tree that may take longer to audit.",
                dependencies.len()
            ));
        }

        warnings
    }
}

/// Backward compatibility: ScannedDependency structure
/// This maintains compatibility with the existing codebase while we transition
#[derive(Debug, Clone)]
pub struct ScannedDependency {
    /// Package name
    pub name: crate::types::PackageName,
    /// Installed version
    pub version: crate::types::Version,
    /// Whether this is a direct dependency (listed in pyproject.toml)
    pub is_direct: bool,
    /// Source of the dependency (PyPI, git, path, etc.)
    pub source: DependencySource,
    /// Optional path for path dependencies
    pub path: Option<std::path::PathBuf>,
}

/// Backward compatibility: DependencySource enum
#[derive(Debug, Clone)]
pub enum DependencySource {
    /// PyPI registry
    Registry,
    /// Git repository
    Git { url: String, rev: Option<String> },
    /// Local path
    Path,
    /// Direct URL
    Url(String),
}

// Conversion implementations for backward compatibility
impl From<crate::parsers::DependencySource> for DependencySource {
    fn from(source: crate::parsers::DependencySource) -> Self {
        match source {
            crate::parsers::DependencySource::Registry => DependencySource::Registry,
            crate::parsers::DependencySource::Git { url, rev } => {
                DependencySource::Git { url, rev }
            }
            crate::parsers::DependencySource::Path => DependencySource::Path,
            crate::parsers::DependencySource::Url(url) => DependencySource::Url(url),
        }
    }
}

impl From<DependencySource> for crate::parsers::DependencySource {
    fn from(source: DependencySource) -> Self {
        match source {
            DependencySource::Registry => crate::parsers::DependencySource::Registry,
            DependencySource::Git { url, rev } => {
                crate::parsers::DependencySource::Git { url, rev }
            }
            DependencySource::Path => crate::parsers::DependencySource::Path,
            DependencySource::Url(url) => crate::parsers::DependencySource::Url(url),
        }
    }
}

impl Default for DependencyScanner {
    fn default() -> Self {
        Self::new(false, false, false, None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    #[test]
    fn test_dependency_scanner_creation() {
        let scanner = DependencyScanner::new(true, true, false, None);
        assert!(scanner.include_dev);
        assert!(scanner.include_optional);
        assert!(!scanner.direct_only);
    }

    #[test]
    fn test_dependency_source_conversion() {
        let parser_source = crate::parsers::DependencySource::Registry;
        let scanner_source: DependencySource = parser_source.into();

        match scanner_source {
            DependencySource::Registry => (),
            _ => panic!("Conversion failed"),
        }
    }

    #[test]
    fn test_dependency_stats_calculation() {
        let dependencies = vec![
            ScannedDependency {
                name: crate::types::PackageName::from_str("package1").unwrap(),
                version: crate::types::Version::from_str("1.0.0").unwrap(),
                is_direct: true,
                source: DependencySource::Registry,
                path: None,
            },
            ScannedDependency {
                name: crate::types::PackageName::from_str("package2").unwrap(),
                version: crate::types::Version::from_str("2.0.0").unwrap(),
                is_direct: false,
                source: DependencySource::Registry,
                path: None,
            },
        ];

        let scanner = DependencyScanner::default();
        let stats = scanner.get_stats(&dependencies);

        assert_eq!(stats.total_packages, 2);
        assert_eq!(stats.direct_packages, 1);
        assert_eq!(stats.transitive_packages, 1);
    }

    #[test]
    fn test_validation_empty_dependencies() {
        let scanner = DependencyScanner::default();
        let warnings = scanner.validate_dependencies(&[]);
        assert!(!warnings.is_empty());
        assert!(warnings[0].contains("No dependencies found"));
    }

    #[test]
    fn test_validation_placeholder_versions() {
        let dependencies = vec![ScannedDependency {
            name: crate::types::PackageName::from_str("package1").unwrap(),
            version: crate::types::Version::new([0, 0, 0]),
            is_direct: true,
            source: DependencySource::Registry,
            path: None,
        }];

        let scanner = DependencyScanner::default();
        let warnings = scanner.validate_dependencies(&dependencies);
        assert!(warnings.iter().any(|w| w.contains("placeholder versions")));
    }
}
