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
    #[serde(default)]
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
    #[serde(default)]
    #[allow(dead_code)]
    files: Vec<serde_json::Value>,
    #[serde(default)]
    dependencies: HashMap<String, serde_json::Value>,
    #[serde(default)]
    #[allow(dead_code)]
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
pub struct PoetryLockParser;

impl Default for PoetryLockParser {
    fn default() -> Self {
        Self::new()
    }
}

impl PoetryLockParser {
    pub fn new() -> Self {
        Self
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
        let lock_path = project_path.join("poetry.lock");
        debug!("Reading poetry lock file: {}", lock_path.display());

        let content = tokio::fs::read_to_string(&lock_path)
            .await
            .map_err(|e| AuditError::DependencyRead(Box::new(e)))?;

        let lock: PoetryLock = toml::from_str(&content).map_err(AuditError::LockFileParse)?;

        if lock.packages.is_empty() {
            warn!(
                "Poetry lock file contains no packages: {}",
                lock_path.display()
            );
            return Ok((Vec::new(), Vec::new()));
        }

        debug!("Found {} packages in poetry lock file", lock.packages.len());

        // Infer direct dependencies from lock file structure only
        let _direct_deps = self
            .infer_direct_dependencies_from_lock(project_path)
            .await?;

        // Warn about --direct-only being ignored for poetry.lock files similar to uv.lock
        if direct_only {
            warn!(
                "--direct-only flag is ignored for poetry.lock files (scanning all main dependencies)"
            );
        }

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

            // For poetry.lock files, we ignore direct_only filtering, so always treat as direct
            // This ensures the vulnerability matcher doesn't filter them out
            let is_direct = true;

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
                dependency_type,
            };

            dependencies.push(dependency);
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

    /// Infer direct dependencies from poetry.lock file structure when pyproject.toml is not used
    /// by finding packages that are not dependencies of any other package (root nodes)
    async fn infer_direct_dependencies_from_lock(
        &self,
        project_dir: &Path,
    ) -> Result<HashMap<PackageName, DependencyType>> {
        let lock_path = project_dir.join("poetry.lock");
        let content = tokio::fs::read_to_string(&lock_path)
            .await
            .map_err(|e| AuditError::DependencyRead(Box::new(e)))?;

        let lock: PoetryLock = toml::from_str(&content).map_err(AuditError::LockFileParse)?;

        // Build a set of all packages that are dependencies of other packages
        let mut transitive_deps = HashSet::new();
        for package in &lock.packages {
            // Add dependencies from the dependencies field
            for dep_name in package.dependencies.keys() {
                transitive_deps.insert(PackageName::new(dep_name));
            }
        }

        // Find root packages (packages that are not dependencies of others)
        let mut direct_deps = HashMap::new();
        for package in &lock.packages {
            let package_name = PackageName::new(&package.name);
            if !transitive_deps.contains(&package_name) {
                // This package is not a dependency of any other package - it's likely a direct dependency
                // Determine type based on groups
                let dependency_type = if package.optional || self.is_dev_dependency(&package.groups)
                {
                    DependencyType::Optional
                } else {
                    DependencyType::Main
                };
                direct_deps.insert(package_name, dependency_type);
            }
        }

        debug!(
            "Inferred {} direct dependencies from poetry lock file structure: {}",
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
