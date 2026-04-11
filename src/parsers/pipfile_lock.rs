// SPDX-License-Identifier: MIT

use super::{manifest_reader, DependencySource, ParsedDependency, ProjectParser, SkippedPackage};
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
        #[cfg(feature = "hotpath")]
        let _hp_wall = hotpath::MeasurementGuardSync::new("pipfile_lock::parse_dependencies", false, false);
        let lock_path = project_path.join("Pipfile.lock");
        debug!("Reading Pipfile lock file: {}", lock_path.display());

        let content = tokio::fs::read_to_string(&lock_path)
            .await
            .map_err(|e| AuditError::DependencyRead(Box::new(e)))?;

        let lock: PipfileLock = Self::deserialize_pipfile_lock(&content)?;

        let total_packages = lock.default_packages.len() + lock.develop_packages.len();
        if total_packages == 0 {
            warn!("Pipfile.lock contains no packages: {}", lock_path.display());
            return Ok((Vec::new(), Vec::new()));
        }

        debug!("Found {} packages in Pipfile.lock", total_packages);

        let companion_set =
            manifest_reader::read_direct_deps_from_pipfile(&project_path.join("Pipfile")).await?;
        if companion_set.is_none() {
            warn!(
                "No Pipfile found alongside Pipfile.lock — cannot determine direct dependencies, treating all as direct"
            );
        }

        let mut dependencies = Vec::new();
        let mut seen_packages = HashSet::new();

        for (package_name, package_info) in &lock.default_packages {
            let is_direct = companion_set
                .as_ref()
                .map_or(true, |set| set.is_empty() || set.contains(&PackageName::new(package_name)));
            if direct_only && !is_direct {
                continue;
            }
            if let Some(dependency) =
                self.process_package(package_name, package_info, is_direct, &mut seen_packages)?
            {
                dependencies.push(dependency);
            }
        }

        if include_optional {
            for (package_name, package_info) in &lock.develop_packages {
                let is_direct = companion_set
                    .as_ref()
                    .map_or(true, |set| set.is_empty() || set.contains(&PackageName::new(package_name)));
                if direct_only && !is_direct {
                    continue;
                }
                if let Some(dependency) =
                    self.process_package(package_name, package_info, is_direct, &mut seen_packages)?
                {
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
    #[cfg_attr(feature = "hotpath", hotpath::measure)]
    fn deserialize_pipfile_lock(content: &str) -> Result<PipfileLock> {
        serde_json::from_str(content)
            .map_err(|e| AuditError::other(format!("Failed to parse Pipfile.lock: {e}")))
    }

    #[cfg_attr(feature = "hotpath", hotpath::measure)]
    fn process_package(
        &self,
        package_name: &str,
        package_info: &PipfileLockPackage,
        is_direct: bool,
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

        let dependency = ParsedDependency {
            name: package_name_obj,
            version,
            is_direct,
            source,
            path,
            source_file: Some("Pipfile.lock".to_string()),
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use tempfile::TempDir;

    async fn create_test_pipfile_lock(content: &str) -> (TempDir, PathBuf) {
        let temp_dir = TempDir::new().unwrap();
        let lock_path = temp_dir.path().join("Pipfile.lock");
        let project_path = temp_dir.path().to_path_buf();
        tokio::fs::write(&lock_path, content).await.unwrap();
        (temp_dir, project_path)
    }

    const LOCK_CONTENT: &str = r#"
{
    "default": {
        "django": {"version": "==4.2.0"},
        "certifi": {"version": "==2024.1.1"}
    },
    "develop": {}
}
"#;

    const PIPFILE_CONTENT: &str = r#"
[packages]
django = ">=4.2"
"#;

    #[tokio::test]
    async fn test_pipfile_lock_is_direct_with_companion() {
        let (temp_dir, project_path) = create_test_pipfile_lock(LOCK_CONTENT).await;
        tokio::fs::write(temp_dir.path().join("Pipfile"), PIPFILE_CONTENT)
            .await
            .unwrap();

        let parser = PipfileLockParser::new();
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
    async fn test_pipfile_lock_direct_only_filters_transitive() {
        let (temp_dir, project_path) = create_test_pipfile_lock(LOCK_CONTENT).await;
        tokio::fs::write(temp_dir.path().join("Pipfile"), PIPFILE_CONTENT)
            .await
            .unwrap();

        let parser = PipfileLockParser::new();
        let (deps, _) = parser
            .parse_dependencies(&project_path, false, false, true)
            .await
            .unwrap();

        assert_eq!(deps.len(), 1);
        assert_eq!(deps[0].name, PackageName::new("django"));
    }

    #[tokio::test]
    async fn test_pipfile_lock_no_companion_all_marked_direct() {
        let (_temp_dir, project_path) = create_test_pipfile_lock(LOCK_CONTENT).await;

        let parser = PipfileLockParser::new();
        let (deps, _) = parser
            .parse_dependencies(&project_path, false, false, false)
            .await
            .unwrap();

        assert_eq!(deps.len(), 2, "all packages should be returned");
        assert!(
            deps.iter().all(|d| d.is_direct),
            "all packages should be marked direct when no Pipfile companion"
        );
    }
}
