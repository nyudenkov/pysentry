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
    #[serde(default)]
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

/// PyProject.toml structure for parsing direct dependencies
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
        include_dev: bool,
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

        // Get direct dependencies from pyproject.toml
        let direct_deps = self
            .get_direct_dependencies(project_path, include_dev, include_optional)
            .await?;

        // Build dependency graph from uv.lock
        let dependency_graph = self.build_dependency_graph(&lock);

        // Determine which packages are reachable from which direct dependencies
        let reachability = self.analyze_reachability(&direct_deps, &dependency_graph);

        let mut dependencies = Vec::new();
        let mut seen_packages = HashSet::new();

        for package in &lock.packages {
            let name = PackageName::new(&package.name);
            let version = Version::from_str(&package.version)?;

            // Skip if we've already processed this package (deduplication)
            if seen_packages.contains(&name) {
                continue;
            }
            seen_packages.insert(name.clone());

            // Determine if this is a direct dependency and what type
            let dep_info = direct_deps.get(&name);
            let is_direct = if direct_deps.is_empty() {
                // No pyproject.toml found - treat all packages as direct
                true
            } else {
                dep_info.is_some()
            };

            // Check if package should be included based on reachability
            let should_include = if direct_deps.is_empty() {
                // No pyproject.toml found - include all packages as main dependencies
                true
            } else if let Some(info) = dep_info {
                // It's a direct dependency - check if we should include this type
                self.should_include_dependency_type(info, include_dev, include_optional)
            } else if direct_only {
                // Skip all transitive dependencies if direct_only is enabled
                false
            } else {
                // It's a transitive dependency - check if it's reachable from allowed direct deps
                self.should_include_transitive(
                    &name,
                    &reachability,
                    &direct_deps,
                    include_dev,
                    include_optional,
                )
            };

            if !should_include {
                debug!("Skipping {} due to filtering rules", name);
                continue;
            }

            let source = self.determine_source_from_lock_package(package);
            let dependency_type = dep_info.copied().unwrap_or(DependencyType::Main);

            let dependency = ParsedDependency {
                name,
                version,
                is_direct,
                source,
                path: None, // TODO: Extract path for local dependencies
                dependency_type,
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
    /// Parse pyproject.toml to get direct dependencies with their types
    async fn get_direct_dependencies(
        &self,
        project_dir: &Path,
        include_dev: bool,
        include_optional: bool,
    ) -> Result<HashMap<PackageName, DependencyType>> {
        let pyproject_path = project_dir.join("pyproject.toml");

        if !pyproject_path.exists() {
            debug!(
                "No pyproject.toml found, inferring direct dependencies from lock file structure"
            );
            // When pyproject.toml is missing, infer direct dependencies from the lock file
            // by finding packages that are not dependencies of any other package (roots)
            return self.infer_direct_dependencies_from_lock(project_dir).await;
        }

        let content = tokio::fs::read_to_string(&pyproject_path)
            .await
            .map_err(|e| AuditError::DependencyRead(Box::new(e)))?;

        let pyproject: PyProject =
            toml::from_str(&content).map_err(|e| AuditError::DependencyRead(Box::new(e)))?;

        let mut direct_deps = HashMap::new();

        // Add main dependencies
        if let Some(project) = &pyproject.project {
            if let Some(dependencies) = &project.dependencies {
                for dep_str in dependencies {
                    if let Ok(name) = self.extract_package_name(dep_str) {
                        direct_deps.insert(name, DependencyType::Main);
                    }
                }
            }

            // Add optional dependencies if requested
            if include_optional {
                if let Some(optional_deps) = &project.optional_dependencies {
                    for deps in optional_deps.values() {
                        for dep_str in deps {
                            if let Ok(name) = self.extract_package_name(dep_str) {
                                // Don't override main dependencies, but always analyze for graph
                                direct_deps.entry(name).or_insert(DependencyType::Optional);
                            }
                        }
                    }
                }
            }
        }

        // Add dependency-groups for graph analysis if dev dependencies are requested
        if include_dev {
            if let Some(dep_groups) = &pyproject.dependency_groups {
                // Include all dependency groups for graph analysis
                for (group_name, deps) in dep_groups {
                    debug!("Processing dependency group: {}", group_name);
                    for dep_str in deps {
                        if let Ok(name) = self.extract_package_name(dep_str) {
                            // Always add dev dependencies to the graph analysis
                            direct_deps.insert(name, DependencyType::Dev);
                        }
                    }
                }
            }
        }

        debug!("Found {} direct dependencies", direct_deps.len());
        let main_count = direct_deps
            .values()
            .filter(|&t| *t == DependencyType::Main)
            .count();
        let dev_count = direct_deps
            .values()
            .filter(|&t| *t == DependencyType::Dev)
            .count();
        let optional_count = direct_deps
            .values()
            .filter(|&t| *t == DependencyType::Optional)
            .count();
        debug!(
            "Direct deps breakdown: {} main, {} dev, {} optional",
            main_count, dev_count, optional_count
        );

        Ok(direct_deps)
    }

    /// Extract package name from dependency specification
    fn extract_package_name(&self, dep_spec: &str) -> Result<PackageName> {
        // Handle specs like "package>=1.0", "package[extra]>=1.0", etc.
        let name_part = dep_spec
            .split(&['>', '<', '=', '!', '~', '[', '@'][..])
            .next()
            .unwrap_or(dep_spec)
            .trim();

        PackageName::from_str(name_part).map_err(|_| {
            AuditError::InvalidDependency(format!("Invalid package name: {name_part}"))
        })
    }

    /// Check if a dependency type should be included
    fn should_include_dependency_type(
        &self,
        dep_type: &DependencyType,
        include_dev: bool,
        include_optional: bool,
    ) -> bool {
        match dep_type {
            DependencyType::Main => true,
            DependencyType::Dev => include_dev,
            DependencyType::Optional => include_optional,
        }
    }

    /// Build dependency graph from uv.lock file
    fn build_dependency_graph(&self, lock: &Lock) -> HashMap<PackageName, Vec<PackageName>> {
        let mut graph = HashMap::new();

        for package in &lock.packages {
            let package_name = PackageName::new(&package.name);
            let mut deps = Vec::new();

            // Parse dependencies from the package
            for dep in &package.dependencies {
                let dep_name = PackageName::new(&dep.name);
                deps.push(dep_name);
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

    /// Determine if a transitive dependency should be included based on reachability
    fn should_include_transitive(
        &self,
        package: &PackageName,
        reachability: &HashMap<PackageName, HashSet<DependencyType>>,
        _direct_deps: &HashMap<PackageName, DependencyType>,
        include_dev: bool,
        include_optional: bool,
    ) -> bool {
        if let Some(reachable_from) = reachability.get(package) {
            // Check if this package is reachable from any allowed dependency types
            for dep_type in reachable_from {
                if self.should_include_dependency_type(dep_type, include_dev, include_optional) {
                    return true;
                }
            }
        }

        // Not reachable from any allowed dependency types
        false
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

        // Build a set of all packages that are dependencies of other packages
        let mut transitive_deps = HashSet::new();
        for package in &lock.packages {
            for dep in &package.dependencies {
                transitive_deps.insert(PackageName::new(&dep.name));
            }
        }

        // Find root packages (packages that are not dependencies of others)
        let mut direct_deps = HashMap::new();
        for package in &lock.packages {
            let package_name = PackageName::new(&package.name);
            if !transitive_deps.contains(&package_name) {
                // This package is not a dependency of any other package - it's likely a direct dependency
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
