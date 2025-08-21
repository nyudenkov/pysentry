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

fn deserialize_dependency_spec<'de, D>(
    deserializer: D,
) -> std::result::Result<Option<String>, D::Error>
where
    D: Deserializer<'de>,
{
    use serde::de::{MapAccess, Visitor};

    struct DependencySpecVisitor;

    impl<'de> Visitor<'de> for DependencySpecVisitor {
        type Value = Option<String>;

        fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
            formatter.write_str("a string or object representing dependency specification")
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
            let mut version = None;

            while let Some((key, value)) = map.next_entry::<String, serde_json::Value>()? {
                if key == "version" {
                    if let Some(v) = value.as_str() {
                        version = Some(v.to_string());
                    }
                }
            }

            Ok(version)
        }

        fn visit_none<E>(self) -> std::result::Result<Self::Value, E>
        where
            E: serde::de::Error,
        {
            Ok(None)
        }
    }

    deserializer.deserialize_any(DependencySpecVisitor)
}

#[derive(Debug, Deserialize)]
struct PipfileLock {
    #[serde(rename = "_meta")]
    #[allow(dead_code)]
    meta: Option<PipfileMeta>,
    #[serde(rename = "default")]
    #[serde(default)]
    default_packages: HashMap<String, PipfileLockPackage>,
    #[serde(rename = "develop")]
    #[serde(default)]
    develop_packages: HashMap<String, PipfileLockPackage>,
}

#[derive(Debug, Deserialize)]
struct PipfileMeta {
    #[allow(dead_code)]
    hash: Option<serde_json::Value>,
    #[allow(dead_code)]
    #[serde(rename = "pipfile-spec")]
    pipfile_spec: Option<u32>,
    #[allow(dead_code)]
    requires: Option<serde_json::Value>,
    #[allow(dead_code)]
    sources: Option<Vec<serde_json::Value>>,
}

#[derive(Debug, Clone, Deserialize)]
struct PipfileLockPackage {
    #[serde(deserialize_with = "deserialize_dependency_spec")]
    #[serde(default)]
    version: Option<String>,
    #[serde(default)]
    #[allow(dead_code)]
    hashes: Vec<String>,
    #[serde(default)]
    #[allow(dead_code)]
    index: Option<String>,
    #[serde(default)]
    #[allow(dead_code)]
    markers: Option<String>,
    #[serde(default)]
    #[allow(dead_code)]
    extras: Vec<String>,
    #[serde(default)]
    git: Option<String>,
    #[serde(default)]
    #[serde(rename = "ref")]
    git_ref: Option<String>,
    #[serde(default)]
    path: Option<String>,
    #[serde(default)]
    file: Option<String>,
    #[serde(default)]
    #[allow(dead_code)]
    editable: bool,
}

pub struct PipfileLockParser;

impl Default for PipfileLockParser {
    fn default() -> Self {
        Self::new()
    }
}

impl PipfileLockParser {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl ProjectParser for PipfileLockParser {
    fn name(&self) -> &'static str {
        "Pipfile.lock"
    }

    fn can_parse(&self, project_path: &Path) -> bool {
        project_path.join("Pipfile.lock").exists()
    }

    fn priority(&self) -> u8 {
        1 // Same priority as other lock files with exact versions
    }

    async fn parse_dependencies(
        &self,
        project_path: &Path,
        _include_dev: bool,
        include_optional: bool,
        direct_only: bool,
    ) -> Result<(Vec<ParsedDependency>, Vec<SkippedPackage>)> {
        let lock_path = project_path.join("Pipfile.lock");
        debug!("Reading Pipfile lock file: {}", lock_path.display());

        let content = tokio::fs::read_to_string(&lock_path)
            .await
            .map_err(|e| AuditError::DependencyRead(Box::new(e)))?;

        let lock: PipfileLock = serde_json::from_str(&content)
            .map_err(|e| AuditError::other(format!("Failed to parse Pipfile.lock: {e}")))?;

        let total_packages = lock.default_packages.len() + lock.develop_packages.len();
        if total_packages == 0 {
            warn!("Pipfile.lock contains no packages: {}", lock_path.display());
            return Ok((Vec::new(), Vec::new()));
        }

        debug!("Found {} packages in Pipfile.lock", total_packages);

        if direct_only {
            warn!(
                "--direct-only flag is ignored for Pipfile.lock files (scanning all dependencies)"
            );
        }

        let mut dependencies = Vec::new();
        let mut seen_packages = HashSet::new();

        for (package_name, package_info) in &lock.default_packages {
            if let Some(dependency) = self.process_package(
                package_name,
                package_info,
                DependencyType::Main,
                &mut seen_packages,
            )? {
                dependencies.push(dependency);
            }
        }

        if include_optional {
            for (package_name, package_info) in &lock.develop_packages {
                if let Some(dependency) = self.process_package(
                    package_name,
                    package_info,
                    DependencyType::Optional,
                    &mut seen_packages,
                )? {
                    dependencies.push(dependency);
                }
            }
        }

        debug!(
            "Scanned {} dependencies from Pipfile.lock",
            dependencies.len()
        );
        Ok((dependencies, Vec::new()))
    }

    fn validate_dependencies(&self, dependencies: &[ParsedDependency]) -> Vec<String> {
        let mut warnings = Vec::new();

        if dependencies.is_empty() {
            warnings.push("No dependencies found in Pipfile.lock. This might indicate an issue with dependency resolution or an empty lock file.".to_string());
            return warnings;
        }

        if dependencies.len() > 1000 {
            warnings.push(format!(
                "Found {} dependencies. This is a very large dependency tree that may take longer to audit.",
                dependencies.len()
            ));
        }

        let missing_version_count = dependencies
            .iter()
            .filter(|dep| dep.version == Version::new([0, 0, 0]))
            .count();

        if missing_version_count > 0 {
            warnings.push(format!(
                "{missing_version_count} dependencies are missing version information."
            ));
        }

        warnings
    }
}

impl PipfileLockParser {
    fn process_package(
        &self,
        package_name: &str,
        package_info: &PipfileLockPackage,
        dependency_type: DependencyType,
        seen_packages: &mut HashSet<PackageName>,
    ) -> Result<Option<ParsedDependency>> {
        let package_name_obj = PackageName::new(package_name);

        if seen_packages.contains(&package_name_obj) {
            return Ok(None);
        }
        seen_packages.insert(package_name_obj.clone());

        let version = if let Some(version_str) = &package_info.version {
            let clean_version = version_str
                .trim_start_matches("==")
                .trim_start_matches(">=")
                .trim_start_matches("<=")
                .trim_start_matches(">")
                .trim_start_matches("<")
                .trim_start_matches("~=")
                .trim_start_matches("!=")
                .trim();

            Version::from_str(clean_version).unwrap_or_else(|_| {
                warn!(
                    "Failed to parse version '{}' for package '{}'",
                    version_str, package_name
                );
                Version::new([0, 0, 0])
            })
        } else {
            warn!("Package '{}' has no version information", package_name);
            Version::new([0, 0, 0])
        };

        let source = self.determine_source_from_package(package_info);

        let path = if matches!(source, DependencySource::Path) {
            package_info.path.as_ref().map(std::path::PathBuf::from)
        } else {
            None
        };

        let is_direct = true;

        let dependency = ParsedDependency {
            name: package_name_obj,
            version,
            is_direct,
            source,
            path,
            dependency_type,
        };

        Ok(Some(dependency))
    }

    fn determine_source_from_package(&self, package: &PipfileLockPackage) -> DependencySource {
        if let Some(git_url) = &package.git {
            let rev = package.git_ref.clone();
            return DependencySource::Git {
                url: git_url.clone(),
                rev,
            };
        }

        if package.path.is_some() {
            return DependencySource::Path;
        }

        if let Some(file_url) = &package.file {
            return DependencySource::Url(file_url.clone());
        }

        DependencySource::Registry
    }
}
