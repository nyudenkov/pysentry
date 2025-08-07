use super::{DependencySource, DependencyType, ParsedDependency, ProjectParser};
use crate::{
    types::{PackageName, Version},
    AuditError, Result,
};
use async_trait::async_trait;
use serde::Deserialize;
use std::collections::HashMap;
use std::path::Path;
use std::str::FromStr;
use tracing::{debug, warn};

/// PyProject.toml structure for parsing dependencies
#[derive(Debug, Deserialize)]
struct PyProject {
    project: Option<Project>,
    #[serde(rename = "dependency-groups")]
    dependency_groups: Option<HashMap<String, Vec<String>>>,
}

#[derive(Debug, Deserialize)]
struct Project {
    #[allow(dead_code)] // Used for deserialization
    name: Option<String>,
    dependencies: Option<Vec<String>>,
    #[serde(rename = "optional-dependencies")]
    optional_dependencies: Option<HashMap<String, Vec<String>>>,
}

/// PyProject.toml parser (for projects without lock files)
pub struct PyProjectParser;

impl Default for PyProjectParser {
    fn default() -> Self {
        Self::new()
    }
}

impl PyProjectParser {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl ProjectParser for PyProjectParser {
    fn name(&self) -> &'static str {
        "pyproject.toml"
    }

    fn can_parse(&self, project_path: &Path) -> bool {
        project_path.join("pyproject.toml").exists() && !project_path.join("uv.lock").exists()
    }

    fn priority(&self) -> u8 {
        2 // Lower priority than lock files - only used when lock file is not available
    }

    async fn parse_dependencies(
        &self,
        project_path: &Path,
        include_dev: bool,
        include_optional: bool,
        _direct_only: bool, // PyProject parser only finds direct dependencies
    ) -> Result<Vec<ParsedDependency>> {
        let pyproject_path = project_path.join("pyproject.toml");
        debug!("Reading pyproject.toml: {}", pyproject_path.display());

        let content = tokio::fs::read_to_string(&pyproject_path)
            .await
            .map_err(|e| AuditError::DependencyRead(Box::new(e)))?;

        let pyproject: PyProject =
            toml::from_str(&content).map_err(|e| AuditError::DependencyRead(Box::new(e)))?;

        let mut dependencies = Vec::new();
        let mut warned_about_placeholder = false;

        // Get direct dependencies with types and version specs
        let direct_deps_with_info =
            self.get_direct_dependencies_with_info(&pyproject, include_dev, include_optional)?;

        for (package_name, dep_type, version_spec) in direct_deps_with_info {
            // Check if this dependency type should be included
            if !self.should_include_dependency_type(dep_type, include_dev, include_optional) {
                continue;
            }

            // For pyproject.toml scanning, we can only get direct dependencies
            // and we don't know the exact installed versions without a lock file
            if !warned_about_placeholder {
                warn!(
                    "Scanning from pyproject.toml only shows direct dependencies with version constraints. \
                    Run 'uv lock' to generate a complete dependency tree with exact versions."
                );
                warned_about_placeholder = true;
            }

            // Try to extract a reasonable version from the version specification
            let version = Self::extract_version_from_spec(&version_spec)
                .unwrap_or_else(|| Version::new([0, 0, 0]));

            // Determine source type from package name/spec
            let source = Self::determine_source_from_spec(&package_name, &version_spec);
            let path = Self::extract_path_from_spec(&version_spec);

            dependencies.push(ParsedDependency {
                name: package_name,
                version,
                is_direct: true,
                source,
                path,
                dependency_type: dep_type,
            });
        }

        debug!(
            "Found {} direct dependencies in pyproject.toml",
            dependencies.len()
        );

        Ok(dependencies)
    }

    fn validate_dependencies(&self, dependencies: &[ParsedDependency]) -> Vec<String> {
        let mut warnings = Vec::new();

        if dependencies.is_empty() {
            warnings.push("No dependencies found in pyproject.toml.".to_string());
            return warnings;
        }

        // Check for placeholder versions
        let placeholder_count = dependencies
            .iter()
            .filter(|dep| dep.version == Version::new([0, 0, 0]))
            .count();

        if placeholder_count > 0 {
            warnings.push(format!(
                "{placeholder_count} dependencies have placeholder versions. Run 'uv lock' for accurate version information."
            ));
        }

        // Warn about missing transitive dependencies
        warnings.push(
            "Only direct dependencies are available from pyproject.toml. \
            Run 'uv lock' to include transitive dependencies in the audit."
                .to_string(),
        );

        warnings
    }
}

impl PyProjectParser {
    /// Get direct dependencies with their types and version specs from pyproject.toml
    fn get_direct_dependencies_with_info(
        &self,
        pyproject: &PyProject,
        include_dev: bool,
        include_optional: bool,
    ) -> Result<Vec<(PackageName, DependencyType, String)>> {
        // Use a map to track dependencies with proper priority
        let mut deps_map: HashMap<PackageName, (DependencyType, String)> = HashMap::new();

        // Add main dependencies
        if let Some(project_table) = &pyproject.project {
            if let Some(dependencies) = &project_table.dependencies {
                for dep_str in dependencies {
                    if let Ok(package_name) = self.extract_package_name_from_dep_string(dep_str) {
                        deps_map.insert(package_name, (DependencyType::Main, dep_str.clone()));
                    }
                }
            }

            // Add optional dependencies if requested
            if include_optional {
                if let Some(optional_deps) = &project_table.optional_dependencies {
                    for deps in optional_deps.values() {
                        for dep_str in deps {
                            if let Ok(package_name) =
                                self.extract_package_name_from_dep_string(dep_str)
                            {
                                // Only insert if not already present as Main
                                deps_map
                                    .entry(package_name)
                                    .or_insert((DependencyType::Optional, dep_str.clone()));
                            }
                        }
                    }
                }
            }
        }

        // Add development dependencies if requested
        if include_dev {
            if let Some(dep_groups) = &pyproject.dependency_groups {
                // Include all dependency groups for graph analysis
                for (group_name, deps) in dep_groups {
                    debug!("Processing dependency group: {}", group_name);
                    for dep_str in deps {
                        if let Ok(package_name) = self.extract_package_name_from_dep_string(dep_str)
                        {
                            // Dev dependencies override everything else
                            deps_map.insert(package_name, (DependencyType::Dev, dep_str.clone()));
                        }
                    }
                }
            }
        }

        // Convert map to vector
        let direct_deps: Vec<(PackageName, DependencyType, String)> = deps_map
            .into_iter()
            .map(|(name, (dep_type, spec))| (name, dep_type, spec))
            .collect();

        debug!(
            "Found {} direct dependencies with info: {} main, {} dev, {} optional",
            direct_deps.len(),
            direct_deps
                .iter()
                .filter(|(_, t, _)| *t == DependencyType::Main)
                .count(),
            direct_deps
                .iter()
                .filter(|(_, t, _)| *t == DependencyType::Dev)
                .count(),
            direct_deps
                .iter()
                .filter(|(_, t, _)| *t == DependencyType::Optional)
                .count(),
        );

        Ok(direct_deps)
    }

    /// Extract package name from a dependency string like "package>=1.0" or "package[extra]>=1.0"
    fn extract_package_name_from_dep_string(&self, dep_str: &str) -> Result<PackageName> {
        // Simple extraction - find the package name before any version specifiers, extras, or URL specs
        let dep_str = dep_str.trim();

        // Handle the common cases:
        // - "package>=1.0"
        // - "package[extra]>=1.0"
        // - "package @ git+https://..."
        // - "package"

        let name_part = if let Some(pos) = dep_str.find(&['>', '<', '=', '!', '~', '[', '@'][..]) {
            &dep_str[..pos]
        } else {
            dep_str
        };

        let package_name = name_part.trim();

        PackageName::from_str(package_name).map_err(|_| {
            AuditError::InvalidDependency(format!("Invalid package name: {package_name}"))
        })
    }

    /// Check if a dependency type should be included based on configuration
    fn should_include_dependency_type(
        &self,
        dep_type: DependencyType,
        include_dev: bool,
        include_optional: bool,
    ) -> bool {
        match dep_type {
            DependencyType::Main => true,
            DependencyType::Dev => include_dev,
            DependencyType::Optional => include_optional,
        }
    }

    /// Extract version from dependency specification string
    fn extract_version_from_spec(version_spec: &str) -> Option<Version> {
        // Try to extract version from specs like "package>=1.0.0", "package==2.1.0", etc.

        // Look for exact version specification (==)
        if let Some(pos) = version_spec.find("==") {
            let version_part = &version_spec[pos + 2..];
            // Extract version until space, comma, or end
            let version_str = version_part
                .split_whitespace()
                .next()
                .unwrap_or(version_part)
                .split(',')
                .next()
                .unwrap_or(version_part)
                .trim();

            if let Ok(version) = Version::from_str(version_str) {
                return Some(version);
            }
        }

        // Look for minimum version specification (>=)
        if let Some(pos) = version_spec.find(">=") {
            let version_part = &version_spec[pos + 2..];
            let version_str = version_part
                .split_whitespace()
                .next()
                .unwrap_or(version_part)
                .split(',')
                .next()
                .unwrap_or(version_part)
                .trim();

            if let Ok(version) = Version::from_str(version_str) {
                return Some(version);
            }
        }

        None
    }

    /// Determine source type from dependency specification
    fn determine_source_from_spec(
        _package_name: &PackageName,
        version_spec: &str,
    ) -> DependencySource {
        // Check if it's a URL-based dependency
        if version_spec.contains("git+") || version_spec.contains(".git") {
            // Extract URL for Git dependencies
            let url = if let Some(pos) = version_spec.find("git+") {
                version_spec[pos..]
                    .split_whitespace()
                    .next()
                    .unwrap_or("")
                    .to_string()
            } else if let Some(pos) = version_spec.find('@') {
                version_spec[pos + 1..]
                    .split_whitespace()
                    .next()
                    .unwrap_or("")
                    .to_string()
            } else {
                "unknown".to_string()
            };

            return DependencySource::Git { url, rev: None };
        }

        if version_spec.contains("file://")
            || version_spec.contains("./")
            || version_spec.contains("../")
        {
            return DependencySource::Path;
        }

        if version_spec.contains("http://") || version_spec.contains("https://") {
            let url = version_spec
                .split_whitespace()
                .find(|s| s.starts_with("http"))
                .unwrap_or("unknown")
                .to_string();
            return DependencySource::Url(url);
        }

        // Default to registry
        DependencySource::Registry
    }

    /// Extract path from dependency specification
    fn extract_path_from_spec(version_spec: &str) -> Option<std::path::PathBuf> {
        if version_spec.contains("file://") {
            if let Some(pos) = version_spec.find("file://") {
                let path_part = &version_spec[pos + 7..];
                let path_str = path_part.split_whitespace().next().unwrap_or(path_part);
                return Some(std::path::PathBuf::from(path_str));
            }
        }

        if version_spec.contains("./") || version_spec.contains("../") {
            // Find relative path
            for part in version_spec.split_whitespace() {
                if part.starts_with("./") || part.starts_with("../") {
                    return Some(std::path::PathBuf::from(part));
                }
            }
        }

        None
    }
}
