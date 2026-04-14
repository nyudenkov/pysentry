// SPDX-License-Identifier: MIT

use super::{
    manifest_reader, DependencySource, DependencyType, ParsedDependency, ProjectParser, SkipReason,
    SkippedPackage,
};
use crate::{
    types::{PackageName, Version},
    AuditError, Result,
};
use async_trait::async_trait;
use serde::Deserialize;
use std::collections::{HashMap, HashSet};
use std::path::Path;
use std::str::FromStr;
use tracing::{debug, warn};

/// lock file structure matching real uv.lock format
#[derive(Debug, Deserialize)]
struct Lock {
    #[serde(rename = "package")]
    packages: Vec<Package>,
    #[serde(default)]
    #[allow(dead_code)] // Used for deserialization
    requires_python: Option<String>,
    #[serde(default)]
    #[allow(dead_code)] // Used for deserialization
    version: Option<u32>,
    #[serde(default)]
    #[allow(dead_code)] // Used for deserialization
    revision: Option<u32>,
    #[serde(default)]
    #[allow(dead_code)] // Used for deserialization
    resolution_markers: Option<Vec<String>>,
}

/// Package information from lock file (matching real uv.lock format)
#[derive(Debug, Clone, Deserialize)]
struct Package {
    name: String,
    #[serde(default)]
    version: Option<String>,
    #[serde(default)]
    source: Option<serde_json::Value>, // Used for source detection
    #[serde(skip)]
    #[allow(dead_code)]
    sdist: Option<serde_json::Value>,
    #[serde(skip)]
    #[allow(dead_code)]
    wheels: Option<Vec<serde_json::Value>>,
    #[serde(default)]
    #[allow(dead_code)] // Used for deserialization
    resolution_markers: Option<Vec<String>>,
    #[serde(default)]
    dependencies: Vec<Dependency>, // Used for dependency graph analysis
    #[serde(default, rename = "optional-dependencies")]
    #[allow(dead_code)] // Used for deserialization
    optional_dependencies: HashMap<String, Vec<Dependency>>,
    #[serde(default)]
    #[allow(dead_code)] // Used for deserialization
    dev_dependencies: Vec<Dependency>,
}

/// Dependency specification
#[derive(Debug, Clone, Deserialize)]
struct Dependency {
    name: String, // Used for dependency graph analysis
    #[serde(default)]
    #[allow(dead_code)] // Used for deserialization
    version: Option<String>,
    #[serde(default)]
    #[allow(dead_code)] // Used for deserialization
    extras: Vec<String>,
    #[serde(default)]
    #[allow(dead_code)] // Used for deserialization
    marker: Option<String>,
}

// PyProject.toml support removed - lock parser now only works with lock file structure

/// UV lock file parser
pub struct UvLockParser;

impl Default for UvLockParser {
    fn default() -> Self {
        Self::new()
    }
}

impl UvLockParser {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl ProjectParser for UvLockParser {
    fn name(&self) -> &'static str {
        "uv.lock"
    }

    fn can_parse(&self, project_path: &Path) -> bool {
        project_path.join("uv.lock").exists()
    }

    fn priority(&self) -> u8 {
        1 // Highest priority - lock files have exact versions
    }

    async fn parse_dependencies(
        &self,
        project_path: &Path,
        _include_dev: bool,
        include_optional: bool,
        direct_only: bool,
    ) -> Result<(Vec<ParsedDependency>, Vec<SkippedPackage>)> {
        #[cfg(feature = "hotpath")]
        let _hp_wall = hotpath::MeasurementGuardSync::new("lock::parse_dependencies", false, false);
        let lock_path = project_path.join("uv.lock");
        debug!("Reading lock file: {}", lock_path.display());

        let content = tokio::fs::read_to_string(&lock_path)
            .await
            .map_err(|e| AuditError::DependencyRead(Box::new(e)))?;

        let lock: Lock = Self::deserialize_lock(&content)?;

        if lock.packages.is_empty() {
            warn!("Lock file contains no packages: {}", lock_path.display());
            return Ok((Vec::new(), Vec::new()));
        }

        debug!("Found {} packages in lock file", lock.packages.len());

        // Identify packages that come from optional dependency groups.
        // Skipped when include_optional=true — the result is only used to filter packages
        // out, so an empty set produces identical behaviour when nothing is being filtered.
        let optional_packages = if include_optional {
            HashSet::new()
        } else {
            let set = self.identify_optional_packages(&lock);
            debug!(
                "Identified {} optional packages (direct and transitive)",
                set.len()
            );
            set
        };

        let direct_set: HashSet<PackageName> =
            match manifest_reader::read_direct_deps_from_pyproject(
                &project_path.join("pyproject.toml"),
            )
            .await?
            {
                Some(names) if !names.is_empty() => names,
                _ => {
                    warn!(
                    "No pyproject.toml found alongside uv.lock — using graph inference for is_direct (diamond dependencies may be misclassified)"
                );
                    Self::infer_direct_deps(&lock.packages)
                }
            };

        let mut dependencies = Vec::new();
        let mut seen_packages = HashSet::new();
        let mut skipped_packages = Vec::new();

        // Process all packages and extract both main and optional dependencies
        for package in &lock.packages {
            let package_name = PackageName::new(&package.name);

            let version = match &package.version {
                Some(version_str) => Version::from_str(version_str)?,
                None => {
                    if self.is_virtual_package(package) {
                        debug!(
                            "Skipping virtual package '{}' - not installed, dependencies handled separately",
                            package_name
                        );
                        skipped_packages.push(SkippedPackage {
                            name: package_name.clone(),
                            reason: SkipReason::Virtual,
                        });
                    } else {
                        debug!(
                            "Skipping editable package '{}' - no version field in lock file",
                            package_name
                        );
                        skipped_packages.push(SkippedPackage {
                            name: package_name.clone(),
                            reason: SkipReason::Editable,
                        });
                    }
                    continue;
                }
            };

            // Skip if we've already processed this package (deduplication)
            if seen_packages.contains(&package_name) {
                continue;
            }
            seen_packages.insert(package_name.clone());

            let is_direct = direct_set.contains(&package_name);

            if direct_only && !is_direct {
                continue;
            }

            // Skip optional packages when include_optional is false
            if optional_packages.contains(&package_name) && !include_optional {
                debug!(
                    "Skipping {} - optional dependency with include_optional=false",
                    package_name
                );
                continue;
            }

            let source = self.determine_source_from_lock_package(package);
            let dependency = ParsedDependency {
                name: package_name,
                version,
                is_direct,
                source,
                path: None, // TODO: Extract path for local dependencies
                source_file: Some("uv.lock".to_string()),
            };

            dependencies.push(dependency);
        }

        // Process dependencies referenced by main dependencies
        let all_dep_refs = self.collect_all_dependency_references(&lock);

        for (dep_name, _dep_type, is_from_optional_group) in all_dep_refs {
            // Skip if we've already processed this as a package
            if seen_packages.contains(&dep_name) {
                continue;
            }

            // Skip optional dependencies if not requested
            if is_from_optional_group && !include_optional {
                debug!(
                    "Skipping optional dependency {} - include_optional=false",
                    dep_name
                );
                continue;
            }

            let is_direct = direct_set.contains(&dep_name);

            if direct_only && !is_direct {
                continue;
            }

            let dependency = ParsedDependency {
                name: dep_name,
                version: Version::new([0, 0, 0]),
                is_direct,
                source: DependencySource::Registry,
                path: None,
                source_file: Some("uv.lock".to_string()),
            };

            dependencies.push(dependency);
        }

        debug!("Scanned {} dependencies from lock file", dependencies.len());
        if !skipped_packages.is_empty() {
            debug!(
                "Skipped scanning {} packages due to missing version information: {}",
                skipped_packages.len(),
                skipped_packages
                    .iter()
                    .map(|pkg| format!("• {} ({})", pkg.name, pkg.reason))
                    .collect::<Vec<_>>()
                    .join(", ")
            );
        }
        Ok((dependencies, skipped_packages))
    }

    fn validate_dependencies(&self, dependencies: &[ParsedDependency]) -> Vec<String> {
        let mut warnings = Vec::new();

        if dependencies.is_empty() {
            warnings.push("No dependencies found in lock file. This might indicate an issue with dependency resolution.".to_string());
            return warnings;
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

impl UvLockParser {
    #[cfg_attr(feature = "hotpath", hotpath::measure)]
    fn deserialize_lock(content: &str) -> Result<Lock> {
        toml::from_str(content).map_err(AuditError::LockFileParse)
    }

    /// Identify packages that come from optional dependency groups (and their transitive deps)
    #[cfg_attr(feature = "hotpath", hotpath::measure)]
    fn identify_optional_packages(&self, lock: &Lock) -> HashSet<PackageName> {
        let mut optional_packages = HashSet::new();
        let mut to_process = Vec::new();

        // First, collect all direct optional dependencies
        for package in &lock.packages {
            for optional_deps in package.optional_dependencies.values() {
                for dep in optional_deps {
                    let dep_name = PackageName::new(&dep.name);
                    optional_packages.insert(dep_name.clone());
                    to_process.push(dep_name);
                }
            }
        }

        // Build a dependency graph for traversal
        let dep_graph = self.build_dependency_graph(lock);

        // Now find all transitive dependencies of optional packages
        let mut visited = HashSet::new();
        while let Some(pkg) = to_process.pop() {
            if visited.contains(&pkg) {
                continue;
            }
            visited.insert(pkg.clone());

            // Add all dependencies of this optional package
            if let Some(deps) = dep_graph.get(&pkg) {
                for dep in deps {
                    if !optional_packages.contains(dep) {
                        optional_packages.insert(dep.clone());
                        to_process.push(dep.clone());
                    }
                }
            }
        }

        debug!(
            "Identified {} optional packages (including transitive)",
            optional_packages.len()
        );
        optional_packages
    }

    /// Collect all dependency references from both main and optional dependencies
    #[cfg_attr(feature = "hotpath", hotpath::measure)]
    fn collect_all_dependency_references(
        &self,
        lock: &Lock,
    ) -> Vec<(PackageName, DependencyType, bool)> {
        let mut dep_refs = Vec::new();

        for package in &lock.packages {
            // Process main dependencies
            for dep in &package.dependencies {
                let dep_name = PackageName::new(&dep.name);
                dep_refs.push((dep_name, DependencyType::Main, false));
            }

            // Process optional dependencies from all groups
            for optional_deps in package.optional_dependencies.values() {
                for dep in optional_deps {
                    let dep_name = PackageName::new(&dep.name);
                    dep_refs.push((dep_name, DependencyType::Optional, true));
                }
            }
        }

        debug!(
            "Collected {} dependency references from lock file",
            dep_refs.len()
        );
        dep_refs
    }

    /// Build dependency graph from uv.lock file including both main and optional dependencies
    #[cfg_attr(feature = "hotpath", hotpath::measure)]
    fn build_dependency_graph(&self, lock: &Lock) -> HashMap<PackageName, Vec<PackageName>> {
        let mut graph = HashMap::new();

        for package in &lock.packages {
            let package_name = PackageName::new(&package.name);
            let mut deps = Vec::new();

            // Parse main dependencies from the package
            for dep in &package.dependencies {
                let dep_name = PackageName::new(&dep.name);
                deps.push(dep_name);
            }

            // Parse optional dependencies from all groups
            for optional_deps in package.optional_dependencies.values() {
                for dep in optional_deps {
                    let dep_name = PackageName::new(&dep.name);
                    deps.push(dep_name);
                }
            }

            // Insert all package entries, including same name with different versions/markers
            // Use entry().or_insert() to avoid overwriting, but this means we keep first occurrence
            // TODO: Consider if we need to merge dependencies from multiple versions of same package
            if let std::collections::hash_map::Entry::Vacant(e) = graph.entry(package_name.clone())
            {
                e.insert(deps);
            } else {
                // Package already exists, merge dependencies
                if let Some(existing_deps) = graph.get_mut(&package_name) {
                    for dep in deps {
                        if !existing_deps.contains(&dep) {
                            existing_deps.push(dep);
                        }
                    }
                }
            }
        }

        debug!("Built dependency graph with {} packages", graph.len());
        graph
    }

    /// Determine source type from lock file package data
    fn determine_source_from_lock_package(&self, package: &Package) -> DependencySource {
        // Try to parse the source field from the lock file package
        if let Some(source_value) = &package.source {
            if let Some(source_obj) = source_value.as_object() {
                // Check for registry source
                if source_obj.contains_key("registry") {
                    return DependencySource::Registry;
                }

                // Check for git source
                if let Some(git_url) = source_obj.get("git").and_then(|v| v.as_str()) {
                    let rev = source_obj
                        .get("rev")
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string());
                    return DependencySource::Git {
                        url: git_url.to_string(),
                        rev,
                    };
                }

                // Check for path source
                if source_obj.contains_key("path") {
                    return DependencySource::Path;
                }

                // Check for direct URL source
                if let Some(url) = source_obj.get("url").and_then(|v| v.as_str()) {
                    return DependencySource::Url(url.to_string());
                }
            }
        }

        // Default to registry if we can't determine the source
        DependencySource::Registry
    }

    #[cfg_attr(feature = "hotpath", hotpath::measure)]
    fn infer_direct_deps(packages: &[Package]) -> HashSet<PackageName> {
        let mut transitive_deps = HashSet::new();
        for package in packages {
            for dep in &package.dependencies {
                transitive_deps.insert(PackageName::new(&dep.name));
            }
            for optional_deps in package.optional_dependencies.values() {
                for dep in optional_deps {
                    transitive_deps.insert(PackageName::new(&dep.name));
                }
            }
        }
        packages
            .iter()
            .filter_map(|pkg| {
                let name = PackageName::new(&pkg.name);
                if transitive_deps.contains(&name) {
                    None
                } else {
                    Some(name)
                }
            })
            .collect()
    }

    fn is_virtual_package(&self, package: &Package) -> bool {
        if let Some(source_value) = &package.source {
            if let Some(source_obj) = source_value.as_object() {
                if source_obj.contains_key("virtual") {
                    return true;
                }
            }
        }
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use tempfile::TempDir;
    use tokio;

    async fn create_test_lock_file(content: &str) -> (TempDir, PathBuf) {
        let temp_dir = TempDir::new().unwrap();
        let lock_path = temp_dir.path().join("uv.lock");
        let project_path = temp_dir.path().to_path_buf();
        tokio::fs::write(&lock_path, content).await.unwrap();
        (temp_dir, project_path)
    }

    #[tokio::test]
    async fn test_parse_virtual_package_without_version() {
        let lock_content = r#"
version = 1
revision = 2
requires-python = ">=3.13"

[[package]]
name = "mypackage"
source = { virtual = "." }
"#;

        let (_temp_dir, project_path) = create_test_lock_file(lock_content).await;
        let parser = UvLockParser::new();

        let result = parser
            .parse_dependencies(&project_path, false, false, false)
            .await;
        assert!(result.is_ok());

        let (dependencies, skipped_packages) = result.unwrap();
        assert_eq!(dependencies.len(), 0);
        assert_eq!(skipped_packages.len(), 1);
    }

    #[tokio::test]
    async fn test_parse_editable_package_without_version() {
        let lock_content = r#"
version = 1
revision = 2
requires-python = ">=3.13"

[[package]]
name = "mypackage"
source = { editable = "." }
"#;

        let (_temp_dir, project_path) = create_test_lock_file(lock_content).await;
        let parser = UvLockParser::new();

        let result = parser
            .parse_dependencies(&project_path, false, false, false)
            .await;
        assert!(result.is_ok());

        let (dependencies, skipped_packages) = result.unwrap();
        assert_eq!(dependencies.len(), 0);
        assert_eq!(skipped_packages.len(), 1);
    }

    #[tokio::test]
    async fn test_parse_mixed_packages_with_and_without_versions() {
        let lock_content = r#"
version = 1
revision = 2
requires-python = ">=3.13"

[[package]]
name = "normal-package"
version = "1.2.3"
source = { registry = "https://pypi.org/simple" }

[[package]]
name = "virtual-package"
source = { virtual = "." }

[[package]]
name = "editable-package"
source = { editable = "." }
"#;

        let (_temp_dir, project_path) = create_test_lock_file(lock_content).await;
        let parser = UvLockParser::new();

        let result = parser
            .parse_dependencies(&project_path, false, false, false)
            .await;
        assert!(result.is_ok());

        let (dependencies, skipped_packages) = result.unwrap();
        assert_eq!(dependencies.len(), 1);
        assert_eq!(skipped_packages.len(), 2);

        let normal_pkg = dependencies
            .iter()
            .find(|d| d.name.to_string() == "normal-package")
            .unwrap();
        assert_eq!(normal_pkg.version, Version::from_str("1.2.3").unwrap());
    }

    #[tokio::test]
    async fn test_skipped_packages_are_not_processed() {
        let lock_content = r#"
version = 1
revision = 2
requires-python = ">=3.13"

[[package]]
name = "editable-package-1"
source = { editable = "." }

[[package]]
name = "editable-package-2"
source = { editable = "../other" }
"#;

        let (_temp_dir, project_path) = create_test_lock_file(lock_content).await;
        let parser = UvLockParser::new();

        let (dependencies, skipped_packages) = parser
            .parse_dependencies(&project_path, false, false, false)
            .await
            .unwrap();
        let _warnings = parser.validate_dependencies(&dependencies);

        assert_eq!(dependencies.len(), 0);
        assert_eq!(skipped_packages.len(), 2);

        let warnings = parser.validate_dependencies(&dependencies);
        assert!(warnings.len() <= 1);
        if !warnings.is_empty() {
            assert!(warnings[0].contains("No dependencies found"));
        }
    }

    #[tokio::test]
    async fn test_uv_lock_is_direct_with_companion() {
        let lock_content = r#"
version = 1
revision = 2
requires-python = ">=3.11"

[[package]]
name = "django"
version = "4.2.0"
source = { registry = "https://pypi.org/simple" }
dependencies = [
  { name = "certifi" },
]

[[package]]
name = "certifi"
version = "2024.1.1"
source = { registry = "https://pypi.org/simple" }
"#;
        let pyproject_content = r#"
[project]
name = "myapp"
dependencies = ["django>=4.2"]
"#;

        let (temp_dir, project_path) = create_test_lock_file(lock_content).await;
        tokio::fs::write(temp_dir.path().join("pyproject.toml"), pyproject_content)
            .await
            .unwrap();

        let parser = UvLockParser::new();
        let (deps, _) = parser
            .parse_dependencies(&project_path, false, false, false)
            .await
            .unwrap();

        let django = deps
            .iter()
            .find(|d| d.name == PackageName::new("django"))
            .unwrap();
        let certifi = deps
            .iter()
            .find(|d| d.name == PackageName::new("certifi"))
            .unwrap();
        assert!(django.is_direct, "django should be direct");
        assert!(!certifi.is_direct, "certifi should be transitive");
    }

    #[tokio::test]
    async fn test_uv_lock_direct_only_filters_transitive() {
        let lock_content = r#"
version = 1
revision = 2
requires-python = ">=3.11"

[[package]]
name = "django"
version = "4.2.0"
source = { registry = "https://pypi.org/simple" }
dependencies = [
  { name = "certifi" },
]

[[package]]
name = "certifi"
version = "2024.1.1"
source = { registry = "https://pypi.org/simple" }
"#;
        let pyproject_content = r#"
[project]
name = "myapp"
dependencies = ["django>=4.2"]
"#;

        let (temp_dir, project_path) = create_test_lock_file(lock_content).await;
        tokio::fs::write(temp_dir.path().join("pyproject.toml"), pyproject_content)
            .await
            .unwrap();

        let parser = UvLockParser::new();
        let (deps, _) = parser
            .parse_dependencies(&project_path, false, false, true)
            .await
            .unwrap();

        assert_eq!(deps.len(), 1);
        assert_eq!(deps[0].name, PackageName::new("django"));
    }

    #[tokio::test]
    async fn test_uv_lock_inference_fallback_no_companion() {
        let lock_content = r#"
version = 1
revision = 2
requires-python = ">=3.11"

[[package]]
name = "requests"
version = "2.31.0"
source = { registry = "https://pypi.org/simple" }
dependencies = [
  { name = "certifi" },
]

[[package]]
name = "certifi"
version = "2024.1.1"
source = { registry = "https://pypi.org/simple" }
"#;

        let (_temp_dir, project_path) = create_test_lock_file(lock_content).await;
        let parser = UvLockParser::new();
        let (deps, _) = parser
            .parse_dependencies(&project_path, false, false, false)
            .await
            .unwrap();

        assert_eq!(deps.len(), 2, "all packages should be classified");
        let requests = deps
            .iter()
            .find(|d| d.name == PackageName::new("requests"))
            .unwrap();
        let certifi = deps
            .iter()
            .find(|d| d.name == PackageName::new("certifi"))
            .unwrap();
        assert!(requests.is_direct, "requests should be inferred as direct");
        assert!(
            !certifi.is_direct,
            "certifi should be inferred as transitive"
        );
    }

    #[test]
    fn test_is_virtual_package() {
        let parser = UvLockParser::new();

        let virtual_package = Package {
            name: "test".to_string(),
            version: None,
            source: Some(serde_json::json!({"virtual": "."})),
            sdist: None,
            wheels: None,
            resolution_markers: None,
            dependencies: vec![],
            optional_dependencies: HashMap::new(),
            dev_dependencies: vec![],
        };

        assert!(parser.is_virtual_package(&virtual_package));

        let editable_package = Package {
            name: "test".to_string(),
            version: None,
            source: Some(serde_json::json!({"editable": "."})),
            sdist: None,
            wheels: None,
            resolution_markers: None,
            dependencies: vec![],
            optional_dependencies: HashMap::new(),
            dev_dependencies: vec![],
        };

        assert!(!parser.is_virtual_package(&editable_package));

        let registry_package = Package {
            name: "test".to_string(),
            version: Some("1.0.0".to_string()),
            source: Some(serde_json::json!({"registry": "https://pypi.org/simple"})),
            sdist: None,
            wheels: None,
            resolution_markers: None,
            dependencies: vec![],
            optional_dependencies: HashMap::new(),
            dev_dependencies: vec![],
        };

        assert!(!parser.is_virtual_package(&registry_package));
    }
}
