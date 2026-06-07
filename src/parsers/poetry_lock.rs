// SPDX-License-Identifier: MIT

use super::{
    manifest_reader, DependencySource, DependencyType, ParsedDependency, ProjectParser,
    SkippedPackage,
};
use crate::{
    types::{PackageName, Version},
    AuditError, Result,
};
use async_trait::async_trait;
use serde::{Deserialize, Deserializer};
use std::collections::{HashMap, HashSet};
use std::path::Path;
use std::str::FromStr;
use tracing::{debug, warn};

/// Custom deserializer for markers field that can handle both Poetry 1.x (string) and Poetry 2.x (map) formats
fn deserialize_markers<'de, D>(deserializer: D) -> std::result::Result<Option<String>, D::Error>
where
    D: Deserializer<'de>,
{
    use serde::de::{MapAccess, Visitor};

    struct MarkersVisitor;

    impl<'de> Visitor<'de> for MarkersVisitor {
        type Value = Option<String>;

        fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
            formatter.write_str("a string or map of markers")
        }

        fn visit_str<E>(self, value: &str) -> std::result::Result<Self::Value, E>
        where
            E: serde::de::Error,
        {
            Ok(Some(value.to_string()))
        }

        fn visit_map<M>(self, mut map: M) -> std::result::Result<Self::Value, M::Error>
        where
            M: MapAccess<'de>,
        {
            // For Poetry 2.x grouped markers, extract the main group marker if it exists
            // Otherwise, concatenate all group markers with " or " (conservative approach)
            let mut markers = Vec::new();

            while let Some((key, value)) = map.next_entry::<String, String>()? {
                // Prefer the "main" group marker if available
                if key == "main" {
                    return Ok(Some(value));
                }
                markers.push(value);
            }

            // If no main group found, combine all markers
            if !markers.is_empty() {
                Ok(Some(markers.join(" or ")))
            } else {
                Ok(None)
            }
        }

        fn visit_none<E>(self) -> std::result::Result<Self::Value, E>
        where
            E: serde::de::Error,
        {
            Ok(None)
        }

        fn visit_unit<E>(self) -> std::result::Result<Self::Value, E>
        where
            E: serde::de::Error,
        {
            Ok(None)
        }
    }

    deserializer.deserialize_any(MarkersVisitor)
}

/// Poetry lock file structure
#[derive(Debug, Deserialize)]
struct PoetryLock {
    #[serde(rename = "package")]
    packages: Vec<Package>,
    #[serde(skip)]
    #[allow(dead_code)]
    metadata: Option<serde_json::Value>,
}

/// Package information from poetry.lock file
#[derive(Debug, Clone, Deserialize)]
struct Package {
    name: String,
    version: String,
    #[serde(default)]
    #[allow(dead_code)]
    description: Option<String>,
    #[serde(default)]
    optional: bool,
    #[serde(default, rename = "python-versions")]
    #[allow(dead_code)]
    python_versions: Option<String>,
    #[serde(default)]
    groups: Vec<String>,
    #[serde(skip)]
    #[allow(dead_code)]
    files: Vec<serde_json::Value>,
    #[serde(default)]
    dependencies: HashMap<String, serde::de::IgnoredAny>,
    // Maps an extra name (e.g. "http2") to the PEP 508 strings it activates
    // (e.g. ["h2 (>=3,<5)"]). Used to fold extras-activated transitives into the
    // reachability closure under `--group`.
    #[serde(default)]
    extras: HashMap<String, Vec<String>>,
    #[serde(default, deserialize_with = "deserialize_markers")]
    #[allow(dead_code)]
    markers: Option<String>,
    #[serde(default)]
    source: Option<PoetrySource>,
}

/// Source information for poetry packages
#[derive(Debug, Clone, Deserialize)]
struct PoetrySource {
    #[serde(default)]
    r#type: Option<String>,
    #[serde(default)]
    url: Option<String>,
    #[serde(default)]
    reference: Option<String>,
    #[serde(default)]
    resolved_reference: Option<String>,
}

/// Poetry lock file parser
pub struct PoetryLockParser {
    groups: Option<HashSet<String>>,
}

impl Default for PoetryLockParser {
    fn default() -> Self {
        Self::new()
    }
}

impl PoetryLockParser {
    pub fn new() -> Self {
        Self { groups: None }
    }

    pub(crate) fn with_groups(mut self, groups: Option<HashSet<String>>) -> Self {
        self.groups = groups;
        self
    }
}

#[async_trait]
impl ProjectParser for PoetryLockParser {
    fn name(&self) -> &'static str {
        "poetry.lock"
    }

    fn can_parse(&self, project_path: &Path) -> bool {
        project_path.join("poetry.lock").exists()
    }

    fn priority(&self) -> u8 {
        1 // Same priority as lock files with exact versions, but will be after uv.lock in registry order
    }

    async fn parse_dependencies(
        &self,
        project_path: &Path,
        _include_dev: bool,
        include_optional: bool,
        direct_only: bool,
    ) -> Result<(Vec<ParsedDependency>, Vec<SkippedPackage>)> {
        #[cfg(feature = "hotpath")]
        let _hp_wall =
            hotpath::MeasurementGuardSync::new("poetry_lock::parse_dependencies", false, false);
        let lock_path = project_path.join("poetry.lock");
        debug!("Reading poetry lock file: {}", lock_path.display());

        let content = tokio::fs::read_to_string(&lock_path)
            .await
            .map_err(|e| AuditError::DependencyRead(Box::new(e)))?;

        let lock: PoetryLock = Self::deserialize_poetry_lock(&content)?;

        if lock.packages.is_empty() {
            warn!(
                "Poetry lock file contains no packages: {}",
                lock_path.display()
            );
            return Ok((Vec::new(), Vec::new()));
        }

        debug!("Found {} packages in poetry lock file", lock.packages.len());

        // See lock.rs for the rationale: with `--group`, Some(empty) is a legitimate
        // narrow-to-nothing signal, not a "missing pyproject" fallback. We use the
        // with-extras variant so `mypkg[extra]` entries (PEP 508 syntax or Poetry's
        // `extras = [...]` table form) preserve their activation for the reachability
        // closure below.
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
                    "No pyproject.toml found alongside poetry.lock — using graph inference for is_direct (diamond dependencies may be misclassified)"
                );
                (Self::infer_direct_deps(&lock.packages), HashMap::new())
            }
        };

        let mut dependencies = Vec::new();
        let mut seen_packages = HashSet::new();

        // Process all packages
        for package in &lock.packages {
            let package_name = PackageName::new(&package.name);
            let version = Version::from_str(&package.version)?;

            // Skip if we've already processed this package (deduplication)
            if seen_packages.contains(&package_name) {
                continue;
            }
            seen_packages.insert(package_name.clone());

            let is_direct = direct_set.contains(&package_name);

            if direct_only && !is_direct {
                continue;
            }

            // Determine dependency type from groups
            let dependency_type = if package.optional || self.is_dev_dependency(&package.groups) {
                DependencyType::Optional
            } else {
                DependencyType::Main
            };

            // Skip optional packages when include_optional is false
            if dependency_type == DependencyType::Optional && !include_optional {
                debug!(
                    "Skipping {} - optional dependency with include_optional=false",
                    package_name
                );
                continue;
            }

            let source = self.determine_source_from_package(package);

            let dependency = ParsedDependency {
                name: package_name,
                version,
                is_direct,
                source,
                path: None, // TODO: Extract path for path dependencies
                source_file: Some("poetry.lock".to_string()),
            };

            dependencies.push(dependency);
        }

        if self.groups.is_some() {
            let seeds = direct_set.clone();
            // For each package, start with its main dependency names, then fold in any
            // extras the project requested on that package. Poetry's lock encodes
            // [package.extras] as a table of PEP 508 strings (e.g. "h2 (>=3,<5)"), so
            // we use manifest_reader::extract_package_name to recover the bare name.
            let edges: HashMap<PackageName, HashSet<PackageName>> = lock
                .packages
                .iter()
                .map(|pkg| {
                    let key = PackageName::new(&pkg.name);
                    let mut vals: HashSet<PackageName> = pkg
                        .dependencies
                        .keys()
                        .map(|n| PackageName::new(n))
                        .collect();
                    if let Some(extras) = requested_extras.get(&key) {
                        for extra in extras {
                            // `extra` is normalized (PEP 685); match the lock's [package.extras]
                            // keys by normalized form so a non-normalized lock key still resolves.
                            let pep508_entries = pkg
                                .extras
                                .iter()
                                .find(|(name, _)| {
                                    manifest_reader::normalize_group_name(name.as_str()) == *extra
                                })
                                .map(|(_, entries)| entries);
                            if let Some(pep508_entries) = pep508_entries {
                                for entry in pep508_entries {
                                    if let Some(name) = manifest_reader::extract_package_name(entry)
                                    {
                                        vals.insert(name);
                                    }
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

        debug!(
            "Scanned {} dependencies from poetry lock file",
            dependencies.len()
        );
        Ok((dependencies, Vec::new()))
    }

    fn validate_dependencies(&self, dependencies: &[ParsedDependency]) -> Vec<String> {
        let mut warnings = Vec::new();

        if dependencies.is_empty() {
            warnings.push("No dependencies found in poetry lock file. This might indicate an issue with dependency resolution.".to_string());
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

impl PoetryLockParser {
    /// Determine if dependency belongs to development groups
    fn is_dev_dependency(&self, groups: &[String]) -> bool {
        groups.iter().any(|group| {
            matches!(
                group.as_str(),
                "dev" | "test" | "docs" | "lint" | "typing" | "dev-dependencies"
            )
        })
    }

    /// Determine source type from poetry package data
    fn determine_source_from_package(&self, package: &Package) -> DependencySource {
        if let Some(source) = &package.source {
            match source.r#type.as_deref() {
                Some("git") => {
                    let url = source.url.clone().unwrap_or_default();
                    let rev = source
                        .resolved_reference
                        .clone()
                        .or_else(|| source.reference.clone());
                    return DependencySource::Git { url, rev };
                }
                Some("directory") | Some("file") => {
                    return DependencySource::Path;
                }
                Some("url") => {
                    if let Some(url) = &source.url {
                        return DependencySource::Url(url.clone());
                    }
                }
                _ => {
                    // For other types or unknown, assume registry
                }
            }
        }

        // Default to registry (PyPI)
        DependencySource::Registry
    }

    #[cfg_attr(feature = "hotpath", hotpath::measure)]
    fn deserialize_poetry_lock(content: &str) -> Result<PoetryLock> {
        toml::from_str(content).map_err(AuditError::LockFileParse)
    }

    /// Infer direct dependencies from poetry.lock file structure when pyproject.toml is not used
    /// by finding packages that are not dependencies of any other package (root nodes)
    #[cfg_attr(feature = "hotpath", hotpath::measure)]
    fn infer_direct_deps(packages: &[Package]) -> HashSet<PackageName> {
        let mut transitive_deps = HashSet::new();
        for package in packages {
            for dep_name in package.dependencies.keys() {
                transitive_deps.insert(PackageName::new(dep_name));
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use tempfile::TempDir;

    async fn create_test_poetry_lock(content: &str) -> (TempDir, PathBuf) {
        let temp_dir = TempDir::new().unwrap();
        let lock_path = temp_dir.path().join("poetry.lock");
        let project_path = temp_dir.path().to_path_buf();
        tokio::fs::write(&lock_path, content).await.unwrap();
        (temp_dir, project_path)
    }

    #[tokio::test]
    async fn test_poetry_lock_is_direct_with_companion() {
        let lock_content = r#"
[[package]]
name = "django"
version = "4.2.0"
optional = false
groups = ["main"]
files = []

[package.dependencies]
certifi = ">=14.5.14"

[[package]]
name = "certifi"
version = "2024.1.1"
optional = false
groups = ["main"]
files = []
"#;
        let pyproject_content = r#"
[project]
name = "myapp"
dependencies = ["django>=4.2"]
"#;

        let (temp_dir, project_path) = create_test_poetry_lock(lock_content).await;
        tokio::fs::write(temp_dir.path().join("pyproject.toml"), pyproject_content)
            .await
            .unwrap();

        let parser = PoetryLockParser::new();
        let (deps, _) = parser
            .parse_dependencies(&project_path, false, true, false)
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
    async fn test_poetry_lock_direct_only_filters_transitive() {
        let lock_content = r#"
[[package]]
name = "django"
version = "4.2.0"
optional = false
groups = ["main"]
files = []

[package.dependencies]
certifi = ">=14.5.14"

[[package]]
name = "certifi"
version = "2024.1.1"
optional = false
groups = ["main"]
files = []
"#;
        let pyproject_content = r#"
[project]
name = "myapp"
dependencies = ["django>=4.2"]
"#;

        let (temp_dir, project_path) = create_test_poetry_lock(lock_content).await;
        tokio::fs::write(temp_dir.path().join("pyproject.toml"), pyproject_content)
            .await
            .unwrap();

        let parser = PoetryLockParser::new();
        let (deps, _) = parser
            .parse_dependencies(&project_path, false, true, true)
            .await
            .unwrap();

        assert_eq!(deps.len(), 1);
        assert_eq!(deps[0].name, PackageName::new("django"));
    }

    #[tokio::test]
    async fn test_poetry_lock_inference_fallback_no_companion() {
        let lock_content = r#"
[[package]]
name = "requests"
version = "2.31.0"
optional = false
groups = ["main"]
files = []

[package.dependencies]
certifi = ">=14.5.14"

[[package]]
name = "certifi"
version = "2024.1.1"
optional = false
groups = ["main"]
files = []
"#;

        let (_temp_dir, project_path) = create_test_poetry_lock(lock_content).await;
        let parser = PoetryLockParser::new();
        let (deps, _) = parser
            .parse_dependencies(&project_path, false, true, false)
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

    // a -> b; c -> d. Seed = {a}. Reachable = {a, b}. Unreachable = {c, d}.
    #[tokio::test]
    async fn test_poetry_lock_reachability_closure_drops_unreachable() {
        let lock_content = r#"
[[package]]
name = "a"
version = "1.0.0"
optional = false
groups = ["main"]
files = []

[package.dependencies]
b = ">=1.0"

[[package]]
name = "b"
version = "1.0.0"
optional = false
groups = ["main"]
files = []

[[package]]
name = "c"
version = "1.0.0"
optional = false
groups = ["main"]
files = []

[package.dependencies]
d = ">=1.0"

[[package]]
name = "d"
version = "1.0.0"
optional = false
groups = ["main"]
files = []
"#;
        let pyproject_content = r#"
[project]
name = "myapp"
dependencies = ["a>=1.0"]
"#;

        let (temp_dir, project_path) = create_test_poetry_lock(lock_content).await;
        tokio::fs::write(temp_dir.path().join("pyproject.toml"), pyproject_content)
            .await
            .unwrap();

        let parser = PoetryLockParser::new().with_groups(Some(HashSet::from(["dev".to_string()])));
        let (deps, _) = parser
            .parse_dependencies(&project_path, false, true, false)
            .await
            .unwrap();

        let names: HashSet<String> = deps.iter().map(|d| d.name.to_string()).collect();
        assert!(names.contains("a"), "a must be included (direct seed)");
        assert!(names.contains("b"), "b must be included (reachable from a)");
        assert!(!names.contains("c"), "c must be dropped (unreachable)");
        assert!(!names.contains("d"), "d must be dropped (unreachable)");
    }

    // a -> b -> c (linear chain). All reachable from seed {a}.
    #[tokio::test]
    async fn test_poetry_lock_reachability_includes_transitive() {
        let lock_content = r#"
[[package]]
name = "a"
version = "1.0.0"
optional = false
groups = ["main"]
files = []

[package.dependencies]
b = ">=1.0"

[[package]]
name = "b"
version = "1.0.0"
optional = false
groups = ["main"]
files = []

[package.dependencies]
c = ">=1.0"

[[package]]
name = "c"
version = "1.0.0"
optional = false
groups = ["main"]
files = []
"#;
        let pyproject_content = r#"
[project]
name = "myapp"
dependencies = ["a>=1.0"]
"#;

        let (temp_dir, project_path) = create_test_poetry_lock(lock_content).await;
        tokio::fs::write(temp_dir.path().join("pyproject.toml"), pyproject_content)
            .await
            .unwrap();

        let parser = PoetryLockParser::new().with_groups(Some(HashSet::from(["dev".to_string()])));
        let (deps, _) = parser
            .parse_dependencies(&project_path, false, true, false)
            .await
            .unwrap();

        let names: HashSet<String> = deps.iter().map(|d| d.name.to_string()).collect();
        assert!(names.contains("a"));
        assert!(names.contains("b"));
        assert!(names.contains("c"));
    }

    // Regression for bug_005 in poetry.lock: an extras-activated transitive declared
    // under [package.extras] (e.g. httpx[http2] -> h2) must be reachable from the seed
    // under --group. Without the fix, only httpx's [package.dependencies] are walked
    // and h2 is silently dropped.
    #[tokio::test]
    async fn test_poetry_lock_extras_activate_optional_deps() {
        let lock_content = r#"
[[package]]
name = "httpx"
version = "0.27.0"
optional = false
groups = ["main"]
files = []

[package.dependencies]
anyio = ">=3.0"

[package.extras]
http2 = ["h2 (>=3,<5)"]

[[package]]
name = "anyio"
version = "4.0.0"
optional = false
groups = ["main"]
files = []

[[package]]
name = "h2"
version = "4.1.0"
optional = false
groups = ["main"]
files = []
"#;
        let pyproject_content = r#"
[project]
name = "myapp"
dependencies = []

[dependency-groups]
prod = ["httpx[http2]>=0.27"]
"#;

        let (temp_dir, project_path) = create_test_poetry_lock(lock_content).await;
        tokio::fs::write(temp_dir.path().join("pyproject.toml"), pyproject_content)
            .await
            .unwrap();

        let parser = PoetryLockParser::new().with_groups(Some(HashSet::from(["prod".to_string()])));
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

    // groups=None: reachability block skipped; all packages returned.
    #[tokio::test]
    async fn test_poetry_lock_groups_none_unchanged_behavior() {
        let lock_content = r#"
[[package]]
name = "a"
version = "1.0.0"
optional = false
groups = ["main"]
files = []

[package.dependencies]
b = ">=1.0"

[[package]]
name = "b"
version = "1.0.0"
optional = false
groups = ["main"]
files = []

[[package]]
name = "c"
version = "1.0.0"
optional = false
groups = ["main"]
files = []
"#;
        let pyproject_content = r#"
[project]
name = "myapp"
dependencies = ["a>=1.0"]
"#;

        let (temp_dir, project_path) = create_test_poetry_lock(lock_content).await;
        tokio::fs::write(temp_dir.path().join("pyproject.toml"), pyproject_content)
            .await
            .unwrap();

        // groups=None: no reachability filtering applied
        let parser = PoetryLockParser::new();
        let (deps, _) = parser
            .parse_dependencies(&project_path, false, true, false)
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
}
