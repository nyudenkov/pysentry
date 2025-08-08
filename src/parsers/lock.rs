use super::{DependencySource, DependencyType, ParsedDependency, ProjectParser};
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
    version: String,
    #[serde(default)]
    source: Option<serde_json::Value>, // Used for source detection
    #[serde(default)]
    #[allow(dead_code)] // Used for deserialization
    sdist: Option<serde_json::Value>,
    #[serde(default)]
    #[allow(dead_code)] // Used for deserialization
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
    ) -> Result<Vec<ParsedDependency>> {
        let lock_path = project_path.join("uv.lock");
        debug!("Reading lock file: {}", lock_path.display());

        let content = tokio::fs::read_to_string(&lock_path)
            .await
            .map_err(|e| AuditError::DependencyRead(Box::new(e)))?;

        let lock: Lock = toml::from_str(&content).map_err(AuditError::LockFileParse)?;

        if lock.packages.is_empty() {
            warn!("Lock file contains no packages: {}", lock_path.display());
            return Ok(Vec::new());
        }

        debug!("Found {} packages in lock file", lock.packages.len());

        // Identify packages that come from optional dependency groups
        let optional_packages = self.identify_optional_packages(&lock);
        debug!(
            "Identified {} optional packages (direct and transitive)",
            optional_packages.len()
        );

        // Infer direct dependencies from lock file structure only
        let direct_deps = self
            .infer_direct_dependencies_from_lock(project_path)
            .await?;

        // Build dependency graph from uv.lock
        let dependency_graph = self.build_dependency_graph(&lock);

        // Determine which packages are reachable from which direct dependencies
        let _reachability = self.analyze_reachability(&direct_deps, &dependency_graph);

        let mut dependencies = Vec::new();
        let mut seen_packages = HashSet::new();

        // Warn about --direct-only being ignored for uv.lock files
        if direct_only {
            warn!(
                "--direct-only flag is ignored for uv.lock files (scanning all main dependencies)"
            );
        }

        // Process all packages and extract both main and optional dependencies
        for package in &lock.packages {
            let package_name = PackageName::new(&package.name);
            let version = Version::from_str(&package.version)?;

            // Skip if we've already processed this package (deduplication)
            if seen_packages.contains(&package_name) {
                continue;
            }
            seen_packages.insert(package_name.clone());

            // Check if this package should be included based on direct/transitive filtering
            let dep_info = direct_deps.get(&package_name);
            // For uv.lock files, we ignore direct_only filtering, so always treat as direct
            // This ensures the vulnerability matcher doesn't filter them out
            let is_direct = true;

            // Skip direct_only filtering for uv.lock files since inference is unreliable
            // uv.lock contains all resolved dependencies, so this filter doesn't make sense

            // Skip optional packages when include_optional is false
            if optional_packages.contains(&package_name) && !include_optional {
                debug!(
                    "Skipping {} - optional dependency with include_optional=false",
                    package_name
                );
                continue;
            }

            let source = self.determine_source_from_lock_package(package);
            let dependency_type = dep_info.copied().unwrap_or(DependencyType::Main);

            let dependency = ParsedDependency {
                name: package_name,
                version,
                is_direct,
                source,
                path: None, // TODO: Extract path for local dependencies
                dependency_type,
            };

            dependencies.push(dependency);
        }

        // Process dependencies referenced by main dependencies
        let all_dep_refs = self.collect_all_dependency_references(&lock);

        for (dep_name, dep_type, is_from_optional_group) in all_dep_refs {
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

            // Skip direct-only filtering for dependency references (consistent with warning)
            // Since we ignore the --direct-only flag for uv.lock files, don't filter here either

            // Create a placeholder dependency for dependencies that are referenced but not in packages
            // This happens when lock file has dependency references but the actual package isn't included
            // Use version 0.0.0 as placeholder - this will trigger warnings in validation
            let dependency = ParsedDependency {
                name: dep_name,
                version: Version::new([0, 0, 0]), // Placeholder version
                is_direct: true, // Always treat as direct since we're ignoring direct_only filtering
                source: DependencySource::Registry, // Default assumption
                path: None,
                dependency_type: dep_type,
            };

            dependencies.push(dependency);
        }

        debug!("Scanned {} dependencies from lock file", dependencies.len());
        Ok(dependencies)
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
    /// Identify packages that come from optional dependency groups (and their transitive deps)
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

    /// Analyze which packages are reachable from which direct dependencies
    fn analyze_reachability(
        &self,
        direct_deps: &HashMap<PackageName, DependencyType>,
        graph: &HashMap<PackageName, Vec<PackageName>>,
    ) -> HashMap<PackageName, HashSet<DependencyType>> {
        let mut reachability = HashMap::new();

        // For each direct dependency, do a DFS to find all reachable packages
        for (direct_dep, dep_type) in direct_deps {
            debug!(
                "Starting DFS from direct dependency '{}' of type {:?}",
                direct_dep, dep_type
            );
            let mut visited = HashSet::new();
            let mut stack = vec![direct_dep.clone()];

            while let Some(current) = stack.pop() {
                if visited.contains(&current) {
                    continue;
                }
                visited.insert(current.clone());

                // Mark this package as reachable from this dependency type
                reachability
                    .entry(current.clone())
                    .or_insert_with(HashSet::new)
                    .insert(*dep_type);

                // Add dependencies to the stack for further exploration
                if let Some(deps) = graph.get(&current) {
                    for dep in deps {
                        if !visited.contains(dep) {
                            stack.push(dep.clone());
                        }
                    }
                }
            }
        }

        debug!("Analyzed reachability for {} packages", reachability.len());
        reachability
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

    /// Infer direct dependencies from lock file structure when pyproject.toml is missing
    /// by finding packages that are not dependencies of any other package (root nodes)
    async fn infer_direct_dependencies_from_lock(
        &self,
        project_dir: &Path,
    ) -> Result<HashMap<PackageName, DependencyType>> {
        let lock_path = project_dir.join("uv.lock");
        let content = tokio::fs::read_to_string(&lock_path)
            .await
            .map_err(|e| AuditError::DependencyRead(Box::new(e)))?;

        let lock: Lock = toml::from_str(&content).map_err(AuditError::LockFileParse)?;

        // Build a set of all packages that are dependencies of other packages (both main and optional)
        let mut transitive_deps = HashSet::new();
        for package in &lock.packages {
            // Add main dependencies
            for dep in &package.dependencies {
                transitive_deps.insert(PackageName::new(&dep.name));
            }

            // Add optional dependencies from all groups
            for optional_deps in package.optional_dependencies.values() {
                for dep in optional_deps {
                    transitive_deps.insert(PackageName::new(&dep.name));
                }
            }
        }

        // Find root packages (packages that are not dependencies of others)
        let mut direct_deps = HashMap::new();
        for package in &lock.packages {
            let package_name = PackageName::new(&package.name);
            if !transitive_deps.contains(&package_name) {
                // This package is not a dependency of any other package - it's likely a direct dependency
                // For now, assume all root packages are Main type since we can't distinguish from lock file alone
                // TODO: Consider if we can infer optional vs main based on dependency group context
                direct_deps.insert(package_name, DependencyType::Main);
            }
        }

        debug!(
            "Inferred {} direct dependencies from lock file structure: {}",
            direct_deps.len(),
            direct_deps
                .keys()
                .map(|k| k.to_string())
                .collect::<Vec<_>>()
                .join(", ")
        );

        Ok(direct_deps)
    }
}
