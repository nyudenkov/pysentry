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
    optional_dependencies: HashMap<String, Vec<Dependency>>,
    // Real uv.lock encodes PEP 735 [dependency-groups] as a table keyed by group name under
    // [package.dev-dependencies] on the root virtual package. This field mirrors that shape so
    // `identify_optional_packages` can treat declared groups as optional under --exclude-extra.
    // The explicit rename is required because TOML uses kebab-case and serde does not convert
    // automatically — match the `optional-dependencies` pattern above.
    #[serde(default, rename = "dev-dependencies")]
    dev_dependencies: HashMap<String, Vec<Dependency>>,
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
pub struct UvLockParser {
    groups: Option<HashSet<String>>,
}

impl Default for UvLockParser {
    fn default() -> Self {
        Self::new()
    }
}

impl UvLockParser {
    pub fn new() -> Self {
        Self { groups: None }
    }

    pub(crate) fn with_groups(mut self, groups: Option<HashSet<String>>) -> Self {
        self.groups = groups;
        self
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
        //
        // `main_roots_seed` is the set of packages declared in [project].dependencies /
        // [tool.poetry.dependencies] — the project's production deps, with NO groups
        // included. It's fed into identify_optional_packages so shared transitives between
        // main and optional groups are not mis-classified as optional. Passing an empty
        // groups filter works because manifest_reader always includes main deps regardless
        // of the filter — see read_direct_deps_from_pyproject's doc comment.
        let main_roots_seed: Option<HashSet<PackageName>> =
            manifest_reader::read_direct_deps_from_pyproject(
                &project_path.join("pyproject.toml"),
                Some(&HashSet::new()),
            )
            .await?;
        let optional_packages = if include_optional {
            HashSet::new()
        } else {
            let set = self.identify_optional_packages(&lock, main_roots_seed.as_ref());
            debug!(
                "Identified {} optional packages (direct and transitive)",
                set.len()
            );
            set
        };

        // When `groups` is set, an empty result from the manifest reader is meaningful:
        // it means the selected group legitimately resolved to nothing (empty group,
        // include-group pointing at a missing group, etc.). Trust it and keep direct_set
        // empty — the reachability closure below will then correctly narrow to nothing.
        // Only fall through to graph inference when pyproject.toml is actually absent.
        //
        // We use the with-extras variant so `httpx[http2]`-style entries preserve their
        // `[http2]` activation — needed to fold pkg.optional_dependencies[extra] into
        // the reachability edge map below (otherwise extras-only transitives like `h2`
        // are silently dropped).
        let (direct_set, requested_extras): (
            HashSet<PackageName>,
            HashMap<PackageName, HashSet<String>>,
        ) = match manifest_reader::read_direct_deps_with_extras_from_pyproject(
            &project_path.join("pyproject.toml"),
            self.groups.as_ref(),
        )
        .await?
        {
            Some((names, extras)) => (names, extras),
            None => {
                warn!(
                    "No pyproject.toml found alongside uv.lock — using graph inference for is_direct (diamond dependencies may be misclassified)"
                );
                (Self::infer_direct_deps(&lock.packages), HashMap::new())
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

        if self.groups.is_some() {
            let seeds = direct_set.clone();
            // For each package, the edge set contains its main dependencies PLUS the
            // `optional-dependencies[<extra>]` entries for any extra the project
            // explicitly requested on that package (e.g. `httpx[http2]` in a group
            // declaration activates `httpx`'s `http2` extra, pulling `h2` into reach).
            let edges: HashMap<PackageName, HashSet<PackageName>> = lock
                .packages
                .iter()
                .map(|pkg| {
                    let key = PackageName::new(&pkg.name);
                    let mut vals: HashSet<PackageName> = pkg
                        .dependencies
                        .iter()
                        .map(|d| PackageName::new(&d.name))
                        .collect();
                    if let Some(extras) = requested_extras.get(&key) {
                        for extra in extras {
                            // `extra` is normalized (PEP 685); match the lock's
                            // optional-dependencies keys by normalized form too, so an extra
                            // requested as `my_extra` still resolves a `my-extra` lock key.
                            let opt_deps = pkg
                                .optional_dependencies
                                .iter()
                                .find(|(name, _)| {
                                    manifest_reader::normalize_group_name(name.as_str()) == *extra
                                })
                                .map(|(_, deps)| deps);
                            if let Some(opt_deps) = opt_deps {
                                for d in opt_deps {
                                    vals.insert(PackageName::new(&d.name));
                                }
                            }
                        }
                    }
                    (key, vals)
                })
                .collect();
            let reachable = crate::parsers::reachability::reachable_closure(&seeds, &edges);
            dependencies.retain(|d| reachable.contains(&d.name));
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

    /// Identify packages that come from optional dependency groups (and their transitive deps).
    ///
    /// `main_roots_seed` is the set of packages declared in pyproject's main dependency
    /// sections ([project].dependencies / [tool.poetry.dependencies]). When present, it
    /// is used to compute the "main-reachable" closure that shared transitives are
    /// subtracted from. The virtual-root heuristic is only used when pyproject.toml is
    /// absent (seed is None) — that heuristic fails for library projects whose root is
    /// source = { editable = "." } or a registry package.
    #[cfg_attr(feature = "hotpath", hotpath::measure)]
    fn identify_optional_packages(
        &self,
        lock: &Lock,
        main_roots_seed: Option<&HashSet<PackageName>>,
    ) -> HashSet<PackageName> {
        let mut optional_packages = HashSet::new();
        let mut to_process = Vec::new();

        // First, collect all direct optional dependencies. PEP 621 [project.optional-dependencies]
        // show up here as `optional_dependencies`; PEP 735 [dependency-groups] show up as
        // `dev_dependencies` (uv's lock-file encoding keys the table by group name). Both are
        // "extras" from --exclude-extra's perspective and should be filtered identically.
        for package in &lock.packages {
            for optional_deps in package.optional_dependencies.values() {
                for dep in optional_deps {
                    let dep_name = PackageName::new(&dep.name);
                    optional_packages.insert(dep_name.clone());
                    to_process.push(dep_name);
                }
            }
            for group_deps in package.dev_dependencies.values() {
                for dep in group_deps {
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

        // A package reachable from a main dep is a legitimate main dep and must NOT be
        // filtered out by --exclude-extra, even if it is ALSO reachable from an optional
        // group. Shared transitives belong to the more-permissive classification.
        //
        // Prefer the caller-supplied seed (derived from pyproject's [project].dependencies
        // / [tool.poetry.dependencies]) because it works for any workspace shape. Fall
        // back to the virtual-root heuristic only when pyproject.toml is absent — that
        // heuristic misses library projects whose root is editable or a registry entry.
        let main_roots: HashSet<PackageName> = match main_roots_seed {
            Some(seed) => seed.clone(),
            None => lock
                .packages
                .iter()
                .filter(|p| self.is_virtual_package(p))
                .flat_map(|p| p.dependencies.iter().map(|d| PackageName::new(&d.name)))
                .collect(),
        };
        if !main_roots.is_empty() {
            let main_reachable =
                crate::parsers::reachability::reachable_closure(&main_roots, &dep_graph);
            optional_packages.retain(|p| !main_reachable.contains(p));
        }

        debug!(
            "Identified {} optional packages (including transitive, excluding main-reachable)",
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
    fn build_dependency_graph(&self, lock: &Lock) -> HashMap<PackageName, HashSet<PackageName>> {
        let mut graph: HashMap<PackageName, HashSet<PackageName>> = HashMap::new();

        for package in &lock.packages {
            let package_name = PackageName::new(&package.name);
            // Merge dependencies across same-name packages with different versions/markers;
            // the HashSet dedupes overlapping edges automatically.
            let deps = graph.entry(package_name).or_default();

            // Parse main dependencies from the package
            for dep in &package.dependencies {
                deps.insert(PackageName::new(&dep.name));
            }

            // Parse optional dependencies from all groups
            for optional_deps in package.optional_dependencies.values() {
                for dep in optional_deps {
                    deps.insert(PackageName::new(&dep.name));
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
            dev_dependencies: HashMap::new(),
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
            dev_dependencies: HashMap::new(),
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
            dev_dependencies: HashMap::new(),
        };

        assert!(!parser.is_virtual_package(&registry_package));
    }

    // Lock: root (virtual) -> a -> b; c -> d; e (standalone).
    // With group filter active and a as the only direct dep,
    // reachability keeps {a, b} and drops {c, d, e}.
    #[tokio::test]
    async fn test_uv_lock_reachability_closure_drops_unreachable() {
        let lock_content = r#"
version = 1
requires-python = ">=3.11"

[[package]]
name = "root"
source = { virtual = "." }
dependencies = [{ name = "a" }]

[[package]]
name = "a"
version = "1.0.0"
source = { registry = "https://pypi.org/simple" }
dependencies = [{ name = "b" }]

[[package]]
name = "b"
version = "1.0.0"
source = { registry = "https://pypi.org/simple" }

[[package]]
name = "c"
version = "1.0.0"
source = { registry = "https://pypi.org/simple" }
dependencies = [{ name = "d" }]

[[package]]
name = "d"
version = "1.0.0"
source = { registry = "https://pypi.org/simple" }

[[package]]
name = "e"
version = "1.0.0"
source = { registry = "https://pypi.org/simple" }
"#;
        let pyproject_content = r#"
[project]
name = "myapp"
dependencies = ["a>=1.0"]
"#;

        let (temp_dir, project_path) = create_test_lock_file(lock_content).await;
        tokio::fs::write(temp_dir.path().join("pyproject.toml"), pyproject_content)
            .await
            .unwrap();

        let parser = UvLockParser::new().with_groups(Some(HashSet::from(["dev".to_string()])));
        let (deps, _) = parser
            .parse_dependencies(&project_path, false, false, false)
            .await
            .unwrap();

        let names: HashSet<String> = deps.iter().map(|d| d.name.to_string()).collect();
        assert!(names.contains("a"), "a must be included (direct seed)");
        assert!(names.contains("b"), "b must be included (reachable from a)");
        assert!(!names.contains("c"), "c must be dropped (unreachable)");
        assert!(!names.contains("d"), "d must be dropped (unreachable)");
        assert!(!names.contains("e"), "e must be dropped (unreachable)");
    }

    // Lock: a -> b -> c (linear chain). All three are reachable from seed {a}.
    #[tokio::test]
    async fn test_uv_lock_reachability_includes_transitive() {
        let lock_content = r#"
version = 1
requires-python = ">=3.11"

[[package]]
name = "a"
version = "1.0.0"
source = { registry = "https://pypi.org/simple" }
dependencies = [{ name = "b" }]

[[package]]
name = "b"
version = "1.0.0"
source = { registry = "https://pypi.org/simple" }
dependencies = [{ name = "c" }]

[[package]]
name = "c"
version = "1.0.0"
source = { registry = "https://pypi.org/simple" }
"#;
        let pyproject_content = r#"
[project]
name = "myapp"
dependencies = ["a>=1.0"]
"#;

        let (temp_dir, project_path) = create_test_lock_file(lock_content).await;
        tokio::fs::write(temp_dir.path().join("pyproject.toml"), pyproject_content)
            .await
            .unwrap();

        let parser = UvLockParser::new().with_groups(Some(HashSet::from(["dev".to_string()])));
        let (deps, _) = parser
            .parse_dependencies(&project_path, false, false, false)
            .await
            .unwrap();

        let names: HashSet<String> = deps.iter().map(|d| d.name.to_string()).collect();
        assert!(names.contains("a"));
        assert!(names.contains("b"));
        assert!(names.contains("c"));
    }

    // groups=None: reachability block is skipped entirely; all packages returned.
    #[tokio::test]
    async fn test_uv_lock_groups_none_unchanged_behavior() {
        let lock_content = r#"
version = 1
requires-python = ">=3.11"

[[package]]
name = "a"
version = "1.0.0"
source = { registry = "https://pypi.org/simple" }
dependencies = [{ name = "b" }]

[[package]]
name = "b"
version = "1.0.0"
source = { registry = "https://pypi.org/simple" }

[[package]]
name = "c"
version = "1.0.0"
source = { registry = "https://pypi.org/simple" }
"#;
        let pyproject_content = r#"
[project]
name = "myapp"
dependencies = ["a>=1.0"]
"#;

        let (temp_dir, project_path) = create_test_lock_file(lock_content).await;
        tokio::fs::write(temp_dir.path().join("pyproject.toml"), pyproject_content)
            .await
            .unwrap();

        // groups=None: no reachability filtering applied
        let parser = UvLockParser::new();
        let (deps, _) = parser
            .parse_dependencies(&project_path, false, false, false)
            .await
            .unwrap();

        let names: HashSet<String> = deps.iter().map(|d| d.name.to_string()).collect();
        assert!(names.contains("a"));
        assert!(names.contains("b"));
        assert!(
            names.contains("c"),
            "c must not be dropped when groups=None"
        );
    }

    // Regression for bug_007: an empty group resolution must NOT fall through to
    // infer_direct_deps (which would seed from graph roots and close over the whole
    // main tree). With pyproject present and BOTH main deps and the requested group
    // legitimately empty, the direct_set stays empty and reachability yields nothing.
    // Note: `[project].dependencies` is always included regardless of group filter, so
    // an empty-group scenario that produces an empty result requires main deps to be
    // empty too (otherwise main deps are correctly included — that's the semantic).
    #[tokio::test]
    async fn test_uv_lock_empty_group_stays_empty() {
        let lock_content = r#"
version = 1
requires-python = ">=3.11"

[[package]]
name = "root"
source = { virtual = "." }
dependencies = [{ name = "django" }]

[[package]]
name = "django"
version = "4.2.0"
source = { registry = "https://pypi.org/simple" }
dependencies = [{ name = "certifi" }]

[[package]]
name = "certifi"
version = "2024.1.1"
source = { registry = "https://pypi.org/simple" }
"#;
        // pyproject declares group `ci = []` legitimately empty and NO main deps.
        // Without the bug_007 fix, `Some(empty)` falls through to infer_direct_deps,
        // seeds from graph roots (including the virtual project root), and the
        // reachability closure covers the entire main tree. With the fix, the empty
        // set is trusted and reachability yields nothing.
        let pyproject_content = r#"
[project]
name = "myapp"

[dependency-groups]
ci = []
dev = ["pytest"]
"#;

        let (temp_dir, project_path) = create_test_lock_file(lock_content).await;
        tokio::fs::write(temp_dir.path().join("pyproject.toml"), pyproject_content)
            .await
            .unwrap();

        // include_optional=true mirrors the real --group path (which conflicts with
        // --exclude-extra). We want to verify the reachability closure alone produces
        // an empty result — not accidentally get a pass because of optional-filtering.
        let parser = UvLockParser::new().with_groups(Some(HashSet::from(["ci".to_string()])));
        let (deps, _) = parser
            .parse_dependencies(&project_path, false, true, false)
            .await
            .unwrap();

        assert!(
            deps.is_empty(),
            "empty group ci with no main deps must produce empty scan, got: {:?}",
            deps.iter().map(|d| d.name.to_string()).collect::<Vec<_>>()
        );
    }

    // Regression for bug_005: an extras-activated transitive (e.g. httpx[http2] -> h2)
    // must be reachable from the seed under --group. Without the fix, only httpx's
    // main dependencies are walked and h2 is silently dropped.
    #[tokio::test]
    async fn test_uv_lock_extras_activate_optional_deps() {
        let lock_content = r#"
version = 1
requires-python = ">=3.11"

[[package]]
name = "root"
source = { virtual = "." }
dependencies = [{ name = "httpx" }]

[[package]]
name = "httpx"
version = "0.27.0"
source = { registry = "https://pypi.org/simple" }
dependencies = [{ name = "anyio" }]

[package.optional-dependencies]
http2 = [{ name = "h2" }]

[[package]]
name = "anyio"
version = "4.0.0"
source = { registry = "https://pypi.org/simple" }

[[package]]
name = "h2"
version = "4.1.0"
source = { registry = "https://pypi.org/simple" }
"#;
        let pyproject_content = r#"
[project]
name = "myapp"
dependencies = []

[dependency-groups]
prod = ["httpx[http2]>=0.27"]
"#;

        let (temp_dir, project_path) = create_test_lock_file(lock_content).await;
        tokio::fs::write(temp_dir.path().join("pyproject.toml"), pyproject_content)
            .await
            .unwrap();

        // --group conflicts with --exclude-extra, so include_optional=true in the
        // real call path. Mirror that here so the optional-package pre-filter (which
        // triggers only when include_optional=false) does not mask the reachability
        // step we are actually testing.
        let parser = UvLockParser::new().with_groups(Some(HashSet::from(["prod".to_string()])));
        let (deps, _) = parser
            .parse_dependencies(&project_path, false, true, false)
            .await
            .unwrap();

        let names: HashSet<String> = deps.iter().map(|d| d.name.to_string()).collect();
        assert!(
            names.contains("httpx"),
            "httpx must be present (direct seed)"
        );
        assert!(
            names.contains("anyio"),
            "anyio must be present (main transitive of httpx)"
        );
        assert!(
            names.contains("h2"),
            "h2 must be present — activated via httpx[http2] extras, got: {names:?}"
        );
    }

    // P2 regression: an extra requested with a non-normalized separator (`my_extra`) must
    // still resolve a lock optional-dependencies key written in normalized form (`my-extra`).
    // Before PEP 685 normalization of extras, the raw HashMap lookup missed and the
    // extras-only transitive (h2) was silently dropped from the reachable closure.
    #[tokio::test]
    async fn test_uv_lock_extras_normalized_separator_mismatch() {
        let lock_content = r#"
version = 1
requires-python = ">=3.11"

[[package]]
name = "root"
source = { virtual = "." }
dependencies = [{ name = "httpx" }]

[[package]]
name = "httpx"
version = "0.27.0"
source = { registry = "https://pypi.org/simple" }
dependencies = [{ name = "anyio" }]

[package.optional-dependencies]
my-extra = [{ name = "h2" }]

[[package]]
name = "anyio"
version = "4.0.0"
source = { registry = "https://pypi.org/simple" }

[[package]]
name = "h2"
version = "4.1.0"
source = { registry = "https://pypi.org/simple" }
"#;
        let pyproject_content = r#"
[project]
name = "myapp"
dependencies = []

[dependency-groups]
prod = ["httpx[my_extra]>=0.27"]
"#;

        let (temp_dir, project_path) = create_test_lock_file(lock_content).await;
        tokio::fs::write(temp_dir.path().join("pyproject.toml"), pyproject_content)
            .await
            .unwrap();

        let parser = UvLockParser::new().with_groups(Some(HashSet::from(["prod".to_string()])));
        let (deps, _) = parser
            .parse_dependencies(&project_path, false, true, false)
            .await
            .unwrap();

        let names: HashSet<String> = deps.iter().map(|d| d.name.to_string()).collect();
        assert!(
            names.contains("h2"),
            "h2 must resolve via httpx[my_extra] matching the normalized my-extra lock key, got: {names:?}"
        );
    }

    // Regression for bug_006: shared transitives between [project].dependencies and a
    // PEP 735 dev group must NOT be filtered out under --exclude-extra when the root
    // is encoded as `editable` (library project), not `virtual`.
    #[tokio::test]
    async fn test_uv_lock_library_root_shared_transitive_kept() {
        let lock_content = r#"
version = 1
requires-python = ">=3.11"

[[package]]
name = "mylib"
version = "0.1.0"
source = { editable = "." }
dependencies = [{ name = "requests" }]

[package.dev-dependencies]
dev = [
    { name = "pytest" },
    { name = "requests" },
]

[[package]]
name = "requests"
version = "2.31.0"
source = { registry = "https://pypi.org/simple" }
dependencies = [{ name = "certifi" }]

[[package]]
name = "certifi"
version = "2024.1.1"
source = { registry = "https://pypi.org/simple" }

[[package]]
name = "pytest"
version = "8.0.0"
source = { registry = "https://pypi.org/simple" }
"#;
        let pyproject_content = r#"
[project]
name = "mylib"
dependencies = ["requests>=2.31"]

[dependency-groups]
dev = ["pytest>=8", "requests>=2.31"]
"#;

        let (temp_dir, project_path) = create_test_lock_file(lock_content).await;
        tokio::fs::write(temp_dir.path().join("pyproject.toml"), pyproject_content)
            .await
            .unwrap();

        // include_optional = false reproduces --exclude-extra behavior.
        let parser = UvLockParser::new();
        let (deps, _) = parser
            .parse_dependencies(&project_path, false, false, false)
            .await
            .unwrap();

        let names: HashSet<String> = deps.iter().map(|d| d.name.to_string()).collect();
        assert!(
            names.contains("requests"),
            "requests is in [project].dependencies; must be kept even with an editable root and shared dev membership"
        );
        assert!(
            names.contains("certifi"),
            "certifi is reachable from requests (main transitive); must be kept, got: {names:?}"
        );
        assert!(
            !names.contains("pytest"),
            "pytest is dev-only; must be filtered under --exclude-extra"
        );
    }

    // Lock: a -> b -> a (cycle). Reachability terminates without looping.
    #[tokio::test]
    async fn test_uv_lock_reachability_handles_cycle() {
        let lock_content = r#"
version = 1
requires-python = ">=3.11"

[[package]]
name = "a"
version = "1.0.0"
source = { registry = "https://pypi.org/simple" }
dependencies = [{ name = "b" }]

[[package]]
name = "b"
version = "1.0.0"
source = { registry = "https://pypi.org/simple" }
dependencies = [{ name = "a" }]
"#;
        let pyproject_content = r#"
[project]
name = "myapp"
dependencies = ["a>=1.0"]
"#;

        let (temp_dir, project_path) = create_test_lock_file(lock_content).await;
        tokio::fs::write(temp_dir.path().join("pyproject.toml"), pyproject_content)
            .await
            .unwrap();

        let parser = UvLockParser::new().with_groups(Some(HashSet::from(["dev".to_string()])));
        let (deps, _) = parser
            .parse_dependencies(&project_path, false, false, false)
            .await
            .unwrap();

        let names: HashSet<String> = deps.iter().map(|d| d.name.to_string()).collect();
        assert!(names.contains("a"));
        assert!(names.contains("b"));
        assert_eq!(
            names.len(),
            2,
            "cycle must not cause duplicates or extra entries"
        );
    }
}
