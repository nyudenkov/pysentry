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

use super::{DependencySource, DependencyType, ParsedDependency, ProjectParser, SkippedPackage};
use crate::{
    dependency::resolvers::{DependencyResolver, ResolverRegistry},
    types::{PackageName, ResolverType, Version},
    AuditError, Result,
};
use async_trait::async_trait;
use serde::Deserialize;
use std::collections::{HashMap, HashSet};
use std::path::Path;
use std::str::FromStr;
use tracing::{debug, info, warn};

#[derive(Debug, Deserialize, Clone)]
#[serde(untagged)]
enum DependencyGroupEntry {
    /// A regular dependency specification string (PEP 508)
    Dependency(String),
    /// An include-group reference
    IncludeGroup {
        #[serde(rename = "include-group")]
        include_group: String,
    },
}

/// PyProject.toml structure for parsing dependencies
#[derive(Debug, Deserialize)]
struct PyProject {
    project: Option<Project>,
    #[serde(rename = "dependency-groups")]
    dependency_groups: Option<HashMap<String, Vec<DependencyGroupEntry>>>,
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
pub struct PyProjectParser {
    resolver: Option<Box<dyn DependencyResolver>>,
}

impl Default for PyProjectParser {
    fn default() -> Self {
        Self::new(None)
    }
}

impl PyProjectParser {
    pub fn new(resolver: Option<ResolverType>) -> Self {
        Self {
            resolver: resolver.map(ResolverRegistry::create_resolver),
        }
    }

    fn has_resolver(&self) -> bool {
        self.resolver.is_some()
    }

    async fn is_resolver_available(&self) -> bool {
        match &self.resolver {
            Some(resolver) => resolver.is_available().await,
            None => false,
        }
    }

    async fn parse_with_resolver(
        &self,
        direct_deps_with_info: &[(PackageName, DependencyType, String)],
        include_dev: bool,
        include_optional: bool,
        direct_only: bool,
    ) -> Result<Vec<ParsedDependency>> {
        let resolver = self
            .resolver
            .as_ref()
            .ok_or_else(|| AuditError::other("Resolver not available"))?;

        if !resolver.is_available().await {
            return Err(AuditError::other(format!(
                "{} resolver not available",
                resolver.name()
            )));
        }

        let requirements_content = self.convert_to_requirements_format(
            direct_deps_with_info,
            include_dev,
            include_optional,
        )?;

        debug!("Generated requirements content:\n{}", requirements_content);

        let resolved_content = resolver.resolve_requirements(&requirements_content).await?;

        debug!("Resolver output:\n{}", resolved_content);

        // Parse resolved content
        self.parse_resolved_content(&resolved_content, direct_deps_with_info, direct_only)
            .await
    }

    async fn parse_without_resolver(
        &self,
        direct_deps_with_info: Vec<(PackageName, DependencyType, String)>,
        include_dev: bool,
        include_optional: bool,
        direct_only: bool,
    ) -> Result<Vec<ParsedDependency>> {
        let mut dependencies = Vec::new();
        let mut warned_about_placeholder = false;

        // Check if we have unspecified versions or need transitive dependencies
        let has_unspecified_versions = direct_deps_with_info
            .iter()
            .any(|(_, _, spec)| Self::extract_version_from_spec(spec).is_none());
        let needs_transitive = !direct_only;

        for (package_name, dep_type, version_spec) in direct_deps_with_info {
            // Check if this dependency type should be included
            if !self.should_include_dependency_type(dep_type, include_dev, include_optional) {
                continue;
            }

            // Warn about resolver benefits when we could benefit from one
            if !warned_about_placeholder
                && (has_unspecified_versions || needs_transitive || !self.has_resolver())
            {
                let reason = if has_unspecified_versions && needs_transitive {
                    "exact versions and transitive dependencies"
                } else if has_unspecified_versions {
                    "exact versions"
                } else if needs_transitive {
                    "transitive dependencies"
                } else {
                    "exact versions and transitive dependencies"
                };

                warn!(
                    "Scanning from pyproject.toml only shows direct dependencies with version constraints. \
                    Consider using a resolver (uv/pip-tools) for {}.",
                    reason
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

    /// Convert pyproject.toml dependencies to requirements.txt format
    fn convert_to_requirements_format(
        &self,
        direct_deps_with_info: &[(PackageName, DependencyType, String)],
        include_dev: bool,
        include_optional: bool,
    ) -> Result<String> {
        let mut requirements = Vec::new();

        for (package_name, dep_type, version_spec) in direct_deps_with_info {
            if !self.should_include_dependency_type(*dep_type, include_dev, include_optional) {
                continue;
            }

            let requirement_line =
                self.convert_dependency_spec_to_requirement(package_name, version_spec)?;
            requirements.push(requirement_line);
        }

        Ok(requirements.join("\n"))
    }

    /// Convert a single dependency specification to requirements.txt format
    fn convert_dependency_spec_to_requirement(
        &self,
        package_name: &PackageName,
        version_spec: &str,
    ) -> Result<String> {
        // For most cases, we can just return the original spec as it's already close to requirements.txt format
        // However, we need to handle special cases:

        // If the spec is just the package name (no version), return as-is
        if version_spec
            .trim()
            .eq_ignore_ascii_case(package_name.as_str())
        {
            return Ok(package_name.to_string());
        }

        // If the spec contains the package name followed by version constraints, return as-is
        // Use case-insensitive comparison to handle normalized vs original package names
        if version_spec
            .to_ascii_lowercase()
            .starts_with(&package_name.as_str().to_ascii_lowercase())
        {
            return Ok(version_spec.to_string());
        }

        // Otherwise, assume the version_spec is just the version part and prepend package name
        Ok(format!("{package_name}{version_spec}"))
    }

    /// Parse resolved content from resolver output
    async fn parse_resolved_content(
        &self,
        resolved_content: &str,
        direct_deps_with_info: &[(PackageName, DependencyType, String)],
        direct_only: bool,
    ) -> Result<Vec<ParsedDependency>> {
        let mut dependencies = Vec::new();

        // Extract direct dependencies for marking
        let direct_deps: HashSet<PackageName> = direct_deps_with_info
            .iter()
            .map(|(name, _, _)| name.clone())
            .collect();

        // Parse resolved content (pinned requirements format)
        for (line_num, line) in resolved_content.lines().enumerate() {
            let line = line.trim();

            // Skip comments and empty lines
            if line.is_empty() || line.starts_with('#') {
                continue;
            }

            // Parse pinned dependency: "package==version"
            if let Some((name_part, version_part)) = line.split_once("==") {
                let name = name_part.trim();

                // Extract version (handle extras and environment markers)
                let version = version_part
                    .split_whitespace()
                    .next()
                    .unwrap_or("")
                    .split(';') // Remove environment markers
                    .next()
                    .unwrap_or("")
                    .trim();

                match Version::from_str(version) {
                    Ok(parsed_version) => {
                        let package_name = PackageName::new(name);
                        let is_direct = direct_deps.contains(&package_name);

                        // Skip transitive dependencies if direct_only is requested
                        if direct_only && !is_direct {
                            continue;
                        }

                        // Determine dependency type based on original specifications
                        let dependency_type = self.get_dependency_type_from_original(
                            &package_name,
                            direct_deps_with_info,
                        );

                        dependencies.push(ParsedDependency {
                            name: package_name,
                            version: parsed_version,
                            is_direct,
                            source: DependencySource::Registry, // Resolver typically works with PyPI
                            path: None,
                            dependency_type,
                        });
                    }
                    Err(e) => {
                        warn!(
                            "Failed to parse version '{}' for package '{}' on line {}: {}",
                            version,
                            name,
                            line_num + 1,
                            e
                        );
                    }
                }
            } else if !line.starts_with('#') && !line.trim().is_empty() {
                debug!("Skipping unrecognized line format: {}", line);
            }
        }

        if dependencies.is_empty() {
            return Err(AuditError::other("No dependencies resolved"));
        }

        Ok(dependencies)
    }

    /// Get dependency type from original specifications
    fn get_dependency_type_from_original(
        &self,
        package_name: &PackageName,
        direct_deps_with_info: &[(PackageName, DependencyType, String)],
    ) -> DependencyType {
        // Find the dependency type from original specifications
        direct_deps_with_info
            .iter()
            .find(|(name, _, _)| name == package_name)
            .map(|(_, dep_type, _)| *dep_type)
            .unwrap_or(DependencyType::Main) // Default to Main for transitive dependencies
    }
}

#[async_trait]
impl ProjectParser for PyProjectParser {
    fn name(&self) -> &'static str {
        "pyproject.toml"
    }

    fn can_parse(&self, project_path: &Path) -> bool {
        project_path.join("pyproject.toml").exists()
    }

    fn priority(&self) -> u8 {
        2 // Lower priority than lock files - only used when lock file is not available
    }

    async fn parse_dependencies(
        &self,
        project_path: &Path,
        include_dev: bool,
        include_optional: bool,
        direct_only: bool,
    ) -> Result<(Vec<ParsedDependency>, Vec<SkippedPackage>)> {
        let pyproject_path = project_path.join("pyproject.toml");
        debug!("Reading pyproject.toml: {}", pyproject_path.display());

        let content = tokio::fs::read_to_string(&pyproject_path)
            .await
            .map_err(|e| AuditError::DependencyRead(Box::new(e)))?;

        let pyproject: PyProject =
            toml::from_str(&content).map_err(|e| AuditError::DependencyRead(Box::new(e)))?;

        // Get direct dependencies with types and version specs
        let direct_deps_with_info =
            self.get_direct_dependencies_with_info(&pyproject, include_dev, include_optional)?;

        // Check if we have unspecified versions and should use resolver
        let has_unspecified_versions = direct_deps_with_info
            .iter()
            .any(|(_, _, spec)| Self::extract_version_from_spec(spec).is_none());

        let should_use_resolver = self.has_resolver()
            && self.is_resolver_available().await
            && (has_unspecified_versions || !direct_only);

        if should_use_resolver {
            debug!(
                "Using resolver for pyproject.toml dependencies{}",
                if has_unspecified_versions {
                    " due to unspecified versions"
                } else {
                    " for transitive dependency resolution"
                }
            );
            match self
                .parse_with_resolver(
                    &direct_deps_with_info,
                    include_dev,
                    include_optional,
                    direct_only,
                )
                .await
            {
                Ok(dependencies) => {
                    info!(
                        "Successfully resolved {} dependencies using {} resolver",
                        dependencies.len(),
                        self.resolver.as_ref().unwrap().name()
                    );
                    return Ok((dependencies, Vec::new()));
                }
                Err(e) => {
                    warn!(
                        "Resolver failed ({}), falling back to basic parsing: {}",
                        self.resolver.as_ref().map_or("unknown", |r| r.name()),
                        e
                    );
                }
            }
        } else if (has_unspecified_versions || !direct_only) && self.has_resolver() {
            warn!(
                "Resolver {} is configured but not available, falling back to basic parsing",
                self.resolver.as_ref().map_or("unknown", |r| r.name())
            );
        }

        // Fallback to current behavior
        let dependencies = self
            .parse_without_resolver(
                direct_deps_with_info,
                include_dev,
                include_optional,
                direct_only,
            )
            .await?;

        Ok((dependencies, Vec::new()))
    }

    fn validate_dependencies(&self, dependencies: &[ParsedDependency]) -> Vec<String> {
        let mut warnings = Vec::new();

        if dependencies.is_empty() {
            warnings.push("No dependencies found in pyproject.toml.".to_string());
            return warnings;
        }

        // Check if resolver was used
        let has_resolver = self.has_resolver();
        let has_transitive_deps = dependencies.iter().any(|dep| !dep.is_direct);

        // Check for placeholder versions (only relevant if resolver wasn't used)
        let placeholder_count = dependencies
            .iter()
            .filter(|dep| dep.version == Version::new([0, 0, 0]))
            .count();

        if placeholder_count > 0 && !has_resolver {
            warnings.push(format!(
                "{placeholder_count} dependencies have placeholder versions. \
                Install uv or pip-tools for exact version resolution."
            ));
        }

        // Warn about missing transitive dependencies if resolver wasn't used
        if !has_transitive_deps && !has_resolver {
            warnings.push(
                "Only direct dependencies are available from pyproject.toml. \
                Install uv or pip-tools to include transitive dependencies in the audit."
                    .to_string(),
            );
        } else if has_transitive_deps && has_resolver {
            // Success case - provide informational message
            let direct_count = dependencies.iter().filter(|dep| dep.is_direct).count();
            let transitive_count = dependencies.len() - direct_count;
            info!(
                "Successfully resolved {direct_count} direct and {transitive_count} transitive dependencies from pyproject.toml"
            );
        }

        // Check for large dependency trees (when using resolver)
        if has_transitive_deps && dependencies.len() > 100 {
            let dep_len = dependencies.len();
            warnings.push(format!(
                "Found {dep_len} dependencies from pyproject.toml resolution. This is a large dependency tree."
            ));
        }

        warnings
    }
}

impl PyProjectParser {
    /// Resolve dependency group entries recursively, handling include-group references
    #[allow(clippy::only_used_in_recursion)]
    fn resolve_dependency_group_entries(
        &self,
        entries: &[DependencyGroupEntry],
        dep_groups: &HashMap<String, Vec<DependencyGroupEntry>>,
        _visited: &mut HashSet<String>,
        current_path: &mut Vec<String>,
    ) -> Result<Vec<String>> {
        let mut resolved_deps = Vec::new();

        for entry in entries {
            match entry {
                DependencyGroupEntry::Dependency(dep_str) => {
                    resolved_deps.push(dep_str.clone());
                }
                DependencyGroupEntry::IncludeGroup { include_group } => {
                    if current_path.contains(include_group) {
                        return Err(AuditError::InvalidDependency(format!(
                            "Circular dependency detected in include-group: {} -> {}",
                            current_path.join(" -> "),
                            include_group
                        )));
                    }

                    if let Some(included_entries) = dep_groups.get(include_group) {
                        current_path.push(include_group.clone());

                        let included_deps = self.resolve_dependency_group_entries(
                            included_entries,
                            dep_groups,
                            _visited,
                            current_path,
                        )?;

                        resolved_deps.extend(included_deps);

                        current_path.pop();
                    } else {
                        warn!("Referenced dependency group '{}' not found", include_group);
                    }
                }
            }
        }

        Ok(resolved_deps)
    }

    /// Get direct dependencies with their types and version specs from pyproject.toml
    fn get_direct_dependencies_with_info(
        &self,
        pyproject: &PyProject,
        include_dev: bool,
        include_optional: bool,
    ) -> Result<Vec<(PackageName, DependencyType, String)>> {
        // Use a map to track dependencies with proper priority
        // Key is the full dependency string to handle extras properly (e.g., psycopg[binary] vs psycopg[c])
        let mut deps_map: HashMap<String, (PackageName, DependencyType, String)> = HashMap::new();

        // Add main dependencies
        if let Some(project_table) = &pyproject.project {
            if let Some(dependencies) = &project_table.dependencies {
                for dep_str in dependencies {
                    if let Ok(package_name) = self.extract_package_name_from_dep_string(dep_str) {
                        // Use the full dep_str as key to distinguish between different extras
                        deps_map.insert(
                            dep_str.clone(),
                            (package_name, DependencyType::Main, dep_str.clone()),
                        );
                    }
                }
            }

            // Add optional dependencies if requested
            if include_optional {
                if let Some(optional_deps) = &project_table.optional_dependencies {
                    for (group_name, deps) in optional_deps {
                        debug!(
                            "Processing optional dependency group '{}' as Optional",
                            group_name
                        );

                        for dep_str in deps {
                            if let Ok(package_name) =
                                self.extract_package_name_from_dep_string(dep_str)
                            {
                                // Insert with full dep_str as key - this allows different extras of same package
                                // Only insert if not already present (main dependencies take priority)
                                // All non-main dependencies are now classified as Optional
                                deps_map.entry(dep_str.clone()).or_insert((
                                    package_name,
                                    DependencyType::Optional,
                                    dep_str.clone(),
                                ));
                            }
                        }
                    }
                }
            }
        }

        // Add development dependencies if requested (PEP 735 dependency-groups)
        if include_dev {
            if let Some(dep_groups) = &pyproject.dependency_groups {
                // Resolve all dependency groups with include-group support
                for (group_name, entries) in dep_groups {
                    debug!("Processing dependency group '{}' as Optional", group_name);

                    let mut visited = HashSet::new();
                    let mut current_path = Vec::new();

                    match self.resolve_dependency_group_entries(
                        entries,
                        dep_groups,
                        &mut visited,
                        &mut current_path,
                    ) {
                        Ok(resolved_deps) => {
                            for dep_str in resolved_deps {
                                if let Ok(package_name) =
                                    self.extract_package_name_from_dep_string(&dep_str)
                                {
                                    // All dependency groups are classified as Optional
                                    deps_map.insert(
                                        dep_str.clone(),
                                        (package_name, DependencyType::Optional, dep_str.clone()),
                                    );
                                }
                            }
                        }
                        Err(e) => {
                            warn!("Failed to resolve dependency group '{}': {}", group_name, e);
                        }
                    }
                }
            }
        }

        // Convert map to vector
        let direct_deps: Vec<(PackageName, DependencyType, String)> = deps_map
            .into_iter()
            .map(|(_key, (name, dep_type, spec))| (name, dep_type, spec))
            .collect();

        debug!(
            "Found {} direct dependencies with info: {} main, {} optional",
            direct_deps.len(),
            direct_deps
                .iter()
                .filter(|(_, t, _)| *t == DependencyType::Main)
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
        _include_dev: bool,
        include_optional: bool,
    ) -> bool {
        match dep_type {
            DependencyType::Main => true,
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::Version;

    #[test]
    fn test_extract_version_from_spec() {
        // Test exact version
        let version = PyProjectParser::extract_version_from_spec("package==1.2.3");
        assert_eq!(version, Some(Version::from_str("1.2.3").unwrap()));

        // Test minimum version
        let version = PyProjectParser::extract_version_from_spec("package>=2.0.0");
        assert_eq!(version, Some(Version::from_str("2.0.0").unwrap()));

        // Test no version
        let version = PyProjectParser::extract_version_from_spec("package");
        assert_eq!(version, None);
    }

    #[test]
    fn test_convert_dependency_spec_to_requirement() {
        let parser = PyProjectParser::new(None);
        let package_name = PackageName::new("requests");

        // Test with version constraint
        let result = parser
            .convert_dependency_spec_to_requirement(&package_name, "requests>=2.25.0")
            .unwrap();
        assert_eq!(result, "requests>=2.25.0");

        // Test with just package name
        let result = parser
            .convert_dependency_spec_to_requirement(&package_name, "requests")
            .unwrap();
        assert_eq!(result, "requests");

        // Test with version spec only
        let result = parser
            .convert_dependency_spec_to_requirement(&package_name, ">=2.0.0")
            .unwrap();
        assert_eq!(result, "requests>=2.0.0");
    }

    #[test]
    fn test_convert_to_requirements_format() {
        let parser = PyProjectParser::new(None);
        let deps_with_info = vec![
            (
                PackageName::new("requests"),
                DependencyType::Main,
                "requests>=2.25.0".to_string(),
            ),
            (
                PackageName::new("click"),
                DependencyType::Main,
                "click>=8.0".to_string(),
            ),
            (
                PackageName::new("pytest"),
                DependencyType::Optional,
                "pytest".to_string(),
            ),
        ];

        // Test including only main dependencies
        let result = parser
            .convert_to_requirements_format(&deps_with_info, false, false)
            .unwrap();
        let lines: Vec<&str> = result.lines().collect();
        assert_eq!(lines.len(), 2);
        assert!(lines.contains(&"requests>=2.25.0"));
        assert!(lines.contains(&"click>=8.0"));

        // Test including optional dependencies
        let result = parser
            .convert_to_requirements_format(&deps_with_info, false, true)
            .unwrap();
        let lines: Vec<&str> = result.lines().collect();
        assert_eq!(lines.len(), 3);
        assert!(lines.contains(&"requests>=2.25.0"));
        assert!(lines.contains(&"click>=8.0"));
        assert!(lines.contains(&"pytest"));
    }

    #[test]
    fn test_has_resolver() {
        let parser_without_resolver = PyProjectParser::new(None);
        assert!(!parser_without_resolver.has_resolver());

        // Testing with resolver would require mocking the resolver trait
    }

    #[tokio::test]
    async fn test_parse_resolved_content() {
        let parser = PyProjectParser::new(None);
        let resolved_content = r#"
click==8.1.3
requests==2.28.1
certifi==2022.9.24
charset-normalizer==2.1.1
idna==3.4
urllib3==1.26.12
"#;
        let direct_deps_with_info = vec![
            (
                PackageName::new("requests"),
                DependencyType::Main,
                "requests>=2.25.0".to_string(),
            ),
            (
                PackageName::new("click"),
                DependencyType::Main,
                "click>=8.0".to_string(),
            ),
        ];

        let result = parser
            .parse_resolved_content(resolved_content, &direct_deps_with_info, false)
            .await
            .unwrap();

        assert_eq!(result.len(), 6); // 2 direct + 4 transitive

        // Check direct dependencies
        let click_dep = result
            .iter()
            .find(|dep| dep.name.as_str() == "click")
            .unwrap();
        assert!(click_dep.is_direct);
        assert_eq!(click_dep.version, Version::from_str("8.1.3").unwrap());
        assert_eq!(click_dep.dependency_type, DependencyType::Main);

        let requests_dep = result
            .iter()
            .find(|dep| dep.name.as_str() == "requests")
            .unwrap();
        assert!(requests_dep.is_direct);
        assert_eq!(requests_dep.version, Version::from_str("2.28.1").unwrap());
        assert_eq!(requests_dep.dependency_type, DependencyType::Main);

        // Check transitive dependencies
        let certifi_dep = result
            .iter()
            .find(|dep| dep.name.as_str() == "certifi")
            .unwrap();
        assert!(!certifi_dep.is_direct);
        assert_eq!(certifi_dep.version, Version::from_str("2022.9.24").unwrap());
        assert_eq!(certifi_dep.dependency_type, DependencyType::Main);
    }

    #[tokio::test]
    async fn test_parse_resolved_content_direct_only() {
        let parser = PyProjectParser::new(None);
        let resolved_content = r#"
click==8.1.3
requests==2.28.1
certifi==2022.9.24
charset-normalizer==2.1.1
"#;
        let direct_deps_with_info = vec![
            (
                PackageName::new("requests"),
                DependencyType::Main,
                "requests>=2.25.0".to_string(),
            ),
            (
                PackageName::new("click"),
                DependencyType::Main,
                "click>=8.0".to_string(),
            ),
        ];

        let result = parser
            .parse_resolved_content(resolved_content, &direct_deps_with_info, true)
            .await
            .unwrap();

        // Should only include direct dependencies
        assert_eq!(result.len(), 2);
        assert!(result.iter().all(|dep| dep.is_direct));

        let package_names: HashSet<String> =
            result.iter().map(|dep| dep.name.to_string()).collect();
        assert!(package_names.contains("click"));
        assert!(package_names.contains("requests"));
        assert!(!package_names.contains("certifi"));
        assert!(!package_names.contains("charset-normalizer"));
    }

    #[test]
    fn test_get_dependency_type_from_original() {
        let parser = PyProjectParser::new(None);
        let direct_deps_with_info = vec![
            (
                PackageName::new("requests"),
                DependencyType::Main,
                "requests>=2.25.0".to_string(),
            ),
            (
                PackageName::new("pytest"),
                DependencyType::Optional,
                "pytest".to_string(),
            ),
        ];

        // Test finding existing dependency
        let dep_type = parser.get_dependency_type_from_original(
            &PackageName::new("requests"),
            &direct_deps_with_info,
        );
        assert_eq!(dep_type, DependencyType::Main);

        let dep_type = parser
            .get_dependency_type_from_original(&PackageName::new("pytest"), &direct_deps_with_info);
        assert_eq!(dep_type, DependencyType::Optional);

        // Test default for non-existing dependency (transitive)
        let dep_type = parser.get_dependency_type_from_original(
            &PackageName::new("certifi"),
            &direct_deps_with_info,
        );
        assert_eq!(dep_type, DependencyType::Main);
    }

    #[test]
    fn test_dependency_group_entry_deserialization() {
        use serde_json;

        let json = r#""pytest>=6.0""#;
        let entry: DependencyGroupEntry = serde_json::from_str(json).unwrap();
        match entry {
            DependencyGroupEntry::Dependency(dep) => assert_eq!(dep, "pytest>=6.0"),
            _ => panic!("Expected Dependency variant"),
        }

        let json = r#"{"include-group": "test"}"#;
        let entry: DependencyGroupEntry = serde_json::from_str(json).unwrap();
        match entry {
            DependencyGroupEntry::IncludeGroup { include_group } => {
                assert_eq!(include_group, "test")
            }
            _ => panic!("Expected IncludeGroup variant"),
        }
    }

    #[test]
    fn test_resolve_dependency_group_entries_simple() {
        let parser = PyProjectParser::new(None);
        let mut dep_groups = HashMap::new();

        dep_groups.insert(
            "test".to_string(),
            vec![
                DependencyGroupEntry::Dependency("pytest".to_string()),
                DependencyGroupEntry::Dependency("coverage".to_string()),
            ],
        );

        let mut visited = HashSet::new();
        let mut current_path = Vec::new();

        let result = parser
            .resolve_dependency_group_entries(
                &dep_groups["test"],
                &dep_groups,
                &mut visited,
                &mut current_path,
            )
            .unwrap();

        assert_eq!(result.len(), 2);
        assert!(result.contains(&"pytest".to_string()));
        assert!(result.contains(&"coverage".to_string()));
    }

    #[test]
    fn test_resolve_dependency_group_entries_with_includes() {
        let parser = PyProjectParser::new(None);
        let mut dep_groups = HashMap::new();

        dep_groups.insert(
            "test".to_string(),
            vec![
                DependencyGroupEntry::Dependency("pytest".to_string()),
                DependencyGroupEntry::Dependency("coverage".to_string()),
            ],
        );

        dep_groups.insert(
            "typing".to_string(),
            vec![
                DependencyGroupEntry::Dependency("mypy".to_string()),
                DependencyGroupEntry::Dependency("types-requests".to_string()),
            ],
        );

        dep_groups.insert(
            "typing-test".to_string(),
            vec![
                DependencyGroupEntry::IncludeGroup {
                    include_group: "typing".to_string(),
                },
                DependencyGroupEntry::IncludeGroup {
                    include_group: "test".to_string(),
                },
                DependencyGroupEntry::Dependency("additional-dep".to_string()),
            ],
        );

        let mut visited = HashSet::new();
        let mut current_path = Vec::new();

        let result = parser
            .resolve_dependency_group_entries(
                &dep_groups["typing-test"],
                &dep_groups,
                &mut visited,
                &mut current_path,
            )
            .unwrap();

        assert_eq!(result.len(), 5);
        assert!(result.contains(&"mypy".to_string()));
        assert!(result.contains(&"types-requests".to_string()));
        assert!(result.contains(&"pytest".to_string()));
        assert!(result.contains(&"coverage".to_string()));
        assert!(result.contains(&"additional-dep".to_string()));
    }

    #[test]
    fn test_resolve_dependency_group_entries_nested_includes() {
        let parser = PyProjectParser::new(None);
        let mut dep_groups = HashMap::new();

        dep_groups.insert(
            "base".to_string(),
            vec![DependencyGroupEntry::Dependency("requests".to_string())],
        );

        dep_groups.insert(
            "middleware".to_string(),
            vec![
                DependencyGroupEntry::IncludeGroup {
                    include_group: "base".to_string(),
                },
                DependencyGroupEntry::Dependency("flask".to_string()),
            ],
        );

        dep_groups.insert(
            "full".to_string(),
            vec![
                DependencyGroupEntry::IncludeGroup {
                    include_group: "middleware".to_string(),
                },
                DependencyGroupEntry::Dependency("pytest".to_string()),
            ],
        );

        let mut visited = HashSet::new();
        let mut current_path = Vec::new();

        let result = parser
            .resolve_dependency_group_entries(
                &dep_groups["full"],
                &dep_groups,
                &mut visited,
                &mut current_path,
            )
            .unwrap();

        assert_eq!(result.len(), 3);
        assert!(result.contains(&"requests".to_string()));
        assert!(result.contains(&"flask".to_string()));
        assert!(result.contains(&"pytest".to_string()));
    }

    #[test]
    fn test_resolve_dependency_group_entries_cycle_detection() {
        let parser = PyProjectParser::new(None);
        let mut dep_groups = HashMap::new();

        dep_groups.insert(
            "a".to_string(),
            vec![
                DependencyGroupEntry::IncludeGroup {
                    include_group: "b".to_string(),
                },
                DependencyGroupEntry::Dependency("dep-a".to_string()),
            ],
        );

        dep_groups.insert(
            "b".to_string(),
            vec![
                DependencyGroupEntry::IncludeGroup {
                    include_group: "c".to_string(),
                },
                DependencyGroupEntry::Dependency("dep-b".to_string()),
            ],
        );

        dep_groups.insert(
            "c".to_string(),
            vec![
                DependencyGroupEntry::IncludeGroup {
                    include_group: "a".to_string(),
                },
                DependencyGroupEntry::Dependency("dep-c".to_string()),
            ],
        );

        let mut visited = HashSet::new();
        let mut current_path = Vec::new();

        let result = parser.resolve_dependency_group_entries(
            &dep_groups["a"],
            &dep_groups,
            &mut visited,
            &mut current_path,
        );

        assert!(result.is_err());
        let error_msg = format!("{}", result.unwrap_err());
        assert!(error_msg.contains("Circular dependency detected"));
    }

    #[test]
    fn test_resolve_dependency_group_entries_missing_group() {
        let parser = PyProjectParser::new(None);
        let mut dep_groups = HashMap::new();

        dep_groups.insert(
            "test".to_string(),
            vec![
                DependencyGroupEntry::IncludeGroup {
                    include_group: "missing".to_string(),
                },
                DependencyGroupEntry::Dependency("pytest".to_string()),
            ],
        );

        let mut visited = HashSet::new();
        let mut current_path = Vec::new();

        let result = parser
            .resolve_dependency_group_entries(
                &dep_groups["test"],
                &dep_groups,
                &mut visited,
                &mut current_path,
            )
            .unwrap();

        assert_eq!(result.len(), 1);
        assert!(result.contains(&"pytest".to_string()));
    }

    #[test]
    fn test_pyproject_toml_with_include_groups() {
        let toml_content = r#"
[dependency-groups]
test = ["pytest", "coverage"]
typing = ["mypy", "types-requests"]
typing-test = [
    {include-group = "typing"},
    {include-group = "test"},
    "additional-dep"
]
"#;

        let pyproject: PyProject = toml::from_str(toml_content).unwrap();
        let dep_groups = pyproject.dependency_groups.unwrap();

        assert_eq!(dep_groups.len(), 3);

        let test_group = &dep_groups["test"];
        assert_eq!(test_group.len(), 2);
        match &test_group[0] {
            DependencyGroupEntry::Dependency(dep) => assert_eq!(dep, "pytest"),
            _ => panic!("Expected Dependency variant"),
        }

        let typing_test_group = &dep_groups["typing-test"];
        assert_eq!(typing_test_group.len(), 3);
        match &typing_test_group[0] {
            DependencyGroupEntry::IncludeGroup { include_group } => {
                assert_eq!(include_group, "typing")
            }
            _ => panic!("Expected IncludeGroup variant"),
        }
        match &typing_test_group[1] {
            DependencyGroupEntry::IncludeGroup { include_group } => {
                assert_eq!(include_group, "test")
            }
            _ => panic!("Expected IncludeGroup variant"),
        }
        match &typing_test_group[2] {
            DependencyGroupEntry::Dependency(dep) => assert_eq!(dep, "additional-dep"),
            _ => panic!("Expected Dependency variant"),
        }
    }
}
