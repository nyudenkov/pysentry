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

use super::{
    DependencySource, DependencyType, ParsedDependency, ProjectParser, SkipReason, SkippedPackage,
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

#[derive(Debug, Deserialize)]
struct PyLock {
    #[serde(rename = "lock-version")]
    lock_version: String,
    #[serde(rename = "created-by")]
    #[allow(dead_code)]
    created_by: String,
    #[serde(default)]
    #[allow(dead_code)]
    environments: Option<Vec<String>>,
    #[serde(rename = "requires-python")]
    #[serde(default)]
    #[allow(dead_code)]
    requires_python: Option<String>,
    #[serde(default)]
    #[allow(dead_code)]
    extras: Vec<String>,
    #[serde(rename = "dependency-groups")]
    #[serde(default)]
    #[allow(dead_code)]
    dependency_groups: Vec<String>,
    #[serde(rename = "default-groups")]
    #[serde(default)]
    #[allow(dead_code)]
    default_groups: Vec<String>,
    #[serde(rename = "package")]
    #[serde(default)]
    packages: Vec<PyLockPackage>,
}

#[derive(Debug, Clone, Deserialize)]
struct PyLockPackage {
    name: String,
    #[serde(default)]
    version: Option<String>,
    #[serde(default)]
    #[allow(dead_code)]
    marker: Option<String>,
    #[serde(rename = "requires-python")]
    #[serde(default)]
    #[allow(dead_code)]
    requires_python: Option<String>,
    #[serde(default)]
    #[allow(dead_code)]
    dependencies: Vec<PyLockDependency>,
    #[serde(default)]
    vcs: Option<PyLockVcsSource>,
    #[serde(default)]
    directory: Option<PyLockDirectorySource>,
    #[serde(default)]
    archive: Option<PyLockArchiveSource>,
    #[serde(default)]
    sdist: Option<PyLockSdistSource>,
    #[serde(default)]
    wheels: Vec<PyLockWheelSource>,
    #[serde(default)]
    #[allow(dead_code)]
    index: Option<String>,
    #[serde(default)]
    #[allow(dead_code)]
    attestation_identities: Vec<serde_json::Value>,
}

#[derive(Debug, Clone, Deserialize)]
struct PyLockDependency {
    #[allow(dead_code)]
    name: String,
    #[serde(default)]
    #[allow(dead_code)]
    version: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
struct PyLockVcsSource {
    #[serde(rename = "type")]
    #[allow(dead_code)]
    vcs_type: String,
    #[serde(default)]
    url: Option<String>,
    #[serde(default)]
    path: Option<String>,
    #[serde(rename = "requested-revision")]
    #[serde(default)]
    #[allow(dead_code)]
    requested_revision: Option<String>,
    #[serde(rename = "commit-id")]
    commit_id: String,
    #[serde(default)]
    #[allow(dead_code)]
    subdirectory: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
struct PyLockDirectorySource {
    #[allow(dead_code)]
    path: String,
    #[serde(default)]
    #[allow(dead_code)]
    editable: bool,
    #[serde(default)]
    #[allow(dead_code)]
    subdirectory: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
struct PyLockArchiveSource {
    #[serde(default)]
    url: Option<String>,
    #[serde(default)]
    path: Option<String>,
    #[serde(default)]
    #[allow(dead_code)]
    size: Option<u64>,
    #[serde(default)]
    #[allow(dead_code)]
    upload_time: Option<String>,
    #[allow(dead_code)]
    hashes: HashMap<String, String>,
    #[serde(default)]
    #[allow(dead_code)]
    subdirectory: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
struct PyLockSdistSource {
    #[serde(default)]
    #[allow(dead_code)]
    name: Option<String>,
    #[serde(default)]
    url: Option<String>,
    #[serde(default)]
    path: Option<String>,
    #[serde(default)]
    #[allow(dead_code)]
    size: Option<u64>,
    #[serde(default)]
    #[allow(dead_code)]
    upload_time: Option<String>,
    #[serde(default)]
    #[allow(dead_code)]
    hashes: HashMap<String, String>,
}

#[derive(Debug, Clone, Deserialize)]
struct PyLockWheelSource {
    #[serde(default)]
    #[allow(dead_code)]
    name: Option<String>,
    #[serde(default)]
    url: Option<String>,
    #[serde(default)]
    path: Option<String>,
    #[serde(default)]
    #[allow(dead_code)]
    size: Option<u64>,
    #[serde(default)]
    #[allow(dead_code)]
    upload_time: Option<String>,
    #[serde(default)]
    #[allow(dead_code)]
    hashes: HashMap<String, String>,
}

pub struct PyLockParser;

impl Default for PyLockParser {
    fn default() -> Self {
        Self::new()
    }
}

impl PyLockParser {
    pub fn new() -> Self {
        Self
    }

    fn is_pylock_file(filename: &str) -> bool {
        filename == "pylock.toml"
            || (filename.starts_with("pylock.")
                && filename.ends_with(".toml")
                && filename.len() > 11)
    }

    fn find_pylock_files(&self, project_path: &Path) -> Vec<std::path::PathBuf> {
        let mut pylock_files = Vec::new();

        if let Ok(entries) = std::fs::read_dir(project_path) {
            for entry in entries.flatten() {
                if let Some(filename) = entry.file_name().to_str() {
                    if Self::is_pylock_file(filename) {
                        pylock_files.push(entry.path());
                    }
                }
            }
        }

        pylock_files.sort_by(|a, b| {
            let a_name = a.file_name().and_then(|n| n.to_str()).unwrap_or("");
            let b_name = b.file_name().and_then(|n| n.to_str()).unwrap_or("");

            // pylock.toml comes first
            if a_name == "pylock.toml" && b_name != "pylock.toml" {
                std::cmp::Ordering::Less
            } else if a_name != "pylock.toml" && b_name == "pylock.toml" {
                std::cmp::Ordering::Greater
            } else {
                a_name.cmp(b_name)
            }
        });

        pylock_files
    }

    fn determine_source_from_package(&self, package: &PyLockPackage) -> DependencySource {
        if let Some(vcs) = &package.vcs {
            let url = vcs
                .url
                .clone()
                .or_else(|| vcs.path.clone())
                .unwrap_or_default();
            return DependencySource::Git {
                url,
                rev: Some(vcs.commit_id.clone()),
            };
        }

        if let Some(_directory) = &package.directory {
            return DependencySource::Path;
        }

        if let Some(archive) = &package.archive {
            if let Some(url) = &archive.url {
                return DependencySource::Url(url.clone());
            } else if archive.path.is_some() {
                return DependencySource::Path;
            }
        }

        if let Some(sdist) = &package.sdist {
            if let Some(url) = &sdist.url {
                return DependencySource::Url(url.clone());
            } else if sdist.path.is_some() {
                return DependencySource::Path;
            }
        }

        if let Some(wheel) = package.wheels.first() {
            if let Some(url) = &wheel.url {
                return DependencySource::Url(url.clone());
            } else if wheel.path.is_some() {
                return DependencySource::Path;
            }
        }

        DependencySource::Registry
    }
}

#[async_trait]
impl ProjectParser for PyLockParser {
    fn name(&self) -> &'static str {
        "pylock.toml"
    }

    fn can_parse(&self, project_path: &Path) -> bool {
        !self.find_pylock_files(project_path).is_empty()
    }

    fn priority(&self) -> u8 {
        1
    }

    async fn parse_dependencies(
        &self,
        project_path: &Path,
        _include_dev: bool,
        include_optional: bool,
        direct_only: bool,
    ) -> Result<(Vec<ParsedDependency>, Vec<SkippedPackage>)> {
        let pylock_files = self.find_pylock_files(project_path);

        if pylock_files.is_empty() {
            return Err(AuditError::NoDependencyInfo);
        }

        let pylock_path = &pylock_files[0];
        debug!("Reading pylock file: {}", pylock_path.display());

        let content = tokio::fs::read_to_string(pylock_path)
            .await
            .map_err(|e| AuditError::DependencyRead(Box::new(e)))?;

        let lock: PyLock = toml::from_str(&content).map_err(AuditError::LockFileParse)?;

        self.validate_lock_version(&lock.lock_version)?;

        if lock.packages.is_empty() {
            warn!(
                "PyLock file contains no packages: {}",
                pylock_path.display()
            );
            return Ok((Vec::new(), Vec::new()));
        }

        debug!("Found {} packages in pylock file", lock.packages.len());

        if direct_only {
            warn!(
                "--direct-only flag is ignored for pylock.toml files (scanning all dependencies)"
            );
        }

        let mut dependencies = Vec::new();
        let mut seen_packages = HashSet::new();
        let mut skipped_packages = Vec::new();

        for package in &lock.packages {
            let package_name = PackageName::new(&package.name);

            if seen_packages.contains(&package_name) {
                continue;
            }
            seen_packages.insert(package_name.clone());

            let version = match &package.version {
                Some(version_str) => match Version::from_str(version_str) {
                    Ok(v) => v,
                    Err(e) => {
                        debug!(
                            "Skipping package '{}' - invalid version '{}': {}",
                            package_name, version_str, e
                        );
                        skipped_packages.push(SkippedPackage {
                            name: package_name,
                            reason: SkipReason::Other(format!("invalid version: {version_str}")),
                        });
                        continue;
                    }
                },
                None => {
                    debug!(
                        "Skipping package '{}' - no version information",
                        package_name
                    );
                    skipped_packages.push(SkippedPackage {
                        name: package_name,
                        reason: SkipReason::MissingVersion,
                    });
                    continue;
                }
            };

            let is_direct = true;

            // Determine dependency type - for now, treat all as main unless we can infer otherwise
            // TODO: Could enhance this by analyzing dependency groups or markers
            let dependency_type = DependencyType::Main;

            if !include_optional && dependency_type == DependencyType::Optional {
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
            "Scanned {} dependencies from pylock file",
            dependencies.len()
        );

        if !skipped_packages.is_empty() {
            debug!(
                "Skipped {} packages: {}",
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
            warnings.push("No dependencies found in pylock file. This might indicate an issue with dependency resolution.".to_string());
            return warnings;
        }

        if dependencies.len() > 1000 {
            warnings.push(format!(
                "Found {} dependencies. This is a very large dependency tree that may take longer to audit.",
                dependencies.len()
            ));
        }

        warnings
    }
}

impl PyLockParser {
    fn validate_lock_version(&self, version: &str) -> Result<()> {
        // Currently, only "1.0" is defined by PEP 751
        match version {
            "1.0" => Ok(()),
            v if v.starts_with("1.") => {
                // Same major version but different minor - warn but continue
                warn!(
                    "Unknown pylock format minor version '{}', but major version is supported. Proceeding with parsing.",
                    v
                );
                Ok(())
            }
            _ => {
                // Different major version - this is an error
                let error_msg = format!(
                    "Unsupported pylock format version '{version}'. Only version 1.x is supported."
                );
                Err(AuditError::other(error_msg))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use tempfile::TempDir;

    async fn create_test_pylock_file(content: &str, filename: &str) -> (TempDir, PathBuf) {
        let temp_dir = TempDir::new().unwrap();
        let lock_path = temp_dir.path().join(filename);
        let project_path = temp_dir.path().to_path_buf();
        tokio::fs::write(&lock_path, content).await.unwrap();
        (temp_dir, project_path)
    }

    #[tokio::test]
    async fn test_parse_basic_pylock() {
        let lock_content = r#"
lock-version = "1.0"
created-by = "test-tool"

[[package]]
name = "requests"
version = "2.28.1"
"#;

        let (_temp_dir, project_path) = create_test_pylock_file(lock_content, "pylock.toml").await;
        let parser = PyLockParser::new();

        assert!(parser.can_parse(&project_path));

        let result = parser
            .parse_dependencies(&project_path, false, false, false)
            .await;
        assert!(result.is_ok());

        let (dependencies, skipped) = result.unwrap();
        assert_eq!(dependencies.len(), 1);
        assert_eq!(skipped.len(), 0);
        assert_eq!(dependencies[0].name.to_string(), "requests");
        assert_eq!(
            dependencies[0].version,
            Version::from_str("2.28.1").unwrap()
        );
    }

    #[tokio::test]
    async fn test_parse_named_pylock_file() {
        let lock_content = r#"
lock-version = "1.0"
created-by = "test-tool"

[[package]]
name = "numpy"
version = "1.24.0"
"#;

        let (_temp_dir, project_path) =
            create_test_pylock_file(lock_content, "pylock.production.toml").await;
        let parser = PyLockParser::new();

        assert!(parser.can_parse(&project_path));

        let result = parser
            .parse_dependencies(&project_path, false, false, false)
            .await;
        assert!(result.is_ok());

        let (dependencies, _) = result.unwrap();
        assert_eq!(dependencies.len(), 1);
        assert_eq!(dependencies[0].name.to_string(), "numpy");
    }

    #[test]
    fn test_is_pylock_file() {
        assert!(PyLockParser::is_pylock_file("pylock.toml"));
        assert!(PyLockParser::is_pylock_file("pylock.dev.toml"));
        assert!(PyLockParser::is_pylock_file("pylock.production.toml"));
        assert!(!PyLockParser::is_pylock_file("pyproject.toml"));
        assert!(!PyLockParser::is_pylock_file("poetry.lock"));
        assert!(!PyLockParser::is_pylock_file("pylock")); // No .toml extension
        assert!(!PyLockParser::is_pylock_file("pylock.toml.bak")); // Doesn't end with .toml
    }

    #[tokio::test]
    async fn test_version_validation() {
        let parser = PyLockParser::new();

        // Valid version
        assert!(parser.validate_lock_version("1.0").is_ok());

        // Same major, different minor (should warn but succeed)
        assert!(parser.validate_lock_version("1.1").is_ok());

        // Different major version (should fail)
        assert!(parser.validate_lock_version("2.0").is_err());
    }

    #[tokio::test]
    async fn test_package_without_version() {
        let lock_content = r#"
lock-version = "1.0"
created-by = "test-tool"

[[package]]
name = "requests"

[[package]]
name = "numpy"
version = "1.24.0"
"#;

        let (_temp_dir, project_path) = create_test_pylock_file(lock_content, "pylock.toml").await;
        let parser = PyLockParser::new();

        let result = parser
            .parse_dependencies(&project_path, false, false, false)
            .await;
        assert!(result.is_ok());

        let (dependencies, skipped) = result.unwrap();
        assert_eq!(dependencies.len(), 1); // Only numpy should be included
        assert_eq!(skipped.len(), 1); // requests should be skipped
        assert_eq!(dependencies[0].name.to_string(), "numpy");
        assert_eq!(skipped[0].name.to_string(), "requests");
    }

    #[tokio::test]
    async fn test_vcs_source_detection() {
        let lock_content = r#"
lock-version = "1.0"
created-by = "test-tool"

[[package]]
name = "requests"
version = "2.28.1"

[package.vcs]
type = "git"
url = "https://github.com/psf/requests.git"
commit-id = "abc123"
"#;

        let (_temp_dir, project_path) = create_test_pylock_file(lock_content, "pylock.toml").await;
        let parser = PyLockParser::new();

        let (dependencies, _) = parser
            .parse_dependencies(&project_path, false, false, false)
            .await
            .unwrap();

        assert_eq!(dependencies.len(), 1);
        let dep = &dependencies[0];
        assert_eq!(dep.name.to_string(), "requests");
        match &dep.source {
            DependencySource::Git { url, rev } => {
                assert_eq!(url, "https://github.com/psf/requests.git");
                assert_eq!(rev.as_ref().unwrap(), "abc123");
            }
            _ => panic!("Expected Git source"),
        }
    }

    #[tokio::test]
    async fn test_wheel_source_detection() {
        let lock_content = r#"
lock-version = "1.0"
created-by = "test-tool"

[[package]]
name = "requests"
version = "2.28.1"

[[package.wheels]]
name = "requests-2.28.1-py3-none-any.whl"
url = "https://files.pythonhosted.org/packages/.../requests-2.28.1-py3-none-any.whl"
size = 62826
[package.wheels.hashes]
sha256 = "7c5599b102feddaa661c826c56ab4fee28bfd17f5abca1ebbe3e7f19d7c97deff"
"#;

        let (_temp_dir, project_path) = create_test_pylock_file(lock_content, "pylock.toml").await;
        let parser = PyLockParser::new();

        let (dependencies, _) = parser
            .parse_dependencies(&project_path, false, false, false)
            .await
            .unwrap();

        assert_eq!(dependencies.len(), 1);
        let dep = &dependencies[0];
        assert_eq!(dep.name.to_string(), "requests");
        match &dep.source {
            DependencySource::Url(url) => {
                assert!(url.contains("requests-2.28.1-py3-none-any.whl"));
            }
            _ => panic!("Expected URL source for wheel"),
        }
    }

    #[tokio::test]
    async fn test_directory_source_detection() {
        let lock_content = r#"
lock-version = "1.0"
created-by = "test-tool"

[[package]]
name = "local-package"
version = "0.1.0"

[package.directory]
path = "./local-package"
editable = true
"#;

        let (_temp_dir, project_path) = create_test_pylock_file(lock_content, "pylock.toml").await;
        let parser = PyLockParser::new();

        let (dependencies, _) = parser
            .parse_dependencies(&project_path, false, false, false)
            .await
            .unwrap();

        assert_eq!(dependencies.len(), 1);
        let dep = &dependencies[0];
        assert_eq!(dep.name.to_string(), "local-package");
        match &dep.source {
            DependencySource::Path => {
                // Expected path source
            }
            _ => panic!("Expected Path source for directory"),
        }
    }

    #[tokio::test]
    async fn test_multiple_pylock_files_preference() {
        // Create multiple pylock files
        let temp_dir = TempDir::new().unwrap();
        let project_path = temp_dir.path().to_path_buf();

        // Create pylock.toml (preferred)
        let preferred_content = r#"
lock-version = "1.0"
created-by = "preferred-tool"

[[package]]
name = "preferred-package"
version = "1.0.0"
"#;
        tokio::fs::write(project_path.join("pylock.toml"), preferred_content)
            .await
            .unwrap();

        // Create pylock.dev.toml (should not be used)
        let dev_content = r#"
lock-version = "1.0"
created-by = "dev-tool"

[[package]]
name = "dev-package"
version = "1.0.0"
"#;
        tokio::fs::write(project_path.join("pylock.dev.toml"), dev_content)
            .await
            .unwrap();

        let parser = PyLockParser::new();
        let (dependencies, _) = parser
            .parse_dependencies(&project_path, false, false, false)
            .await
            .unwrap();

        // Should use pylock.toml, not pylock.dev.toml
        assert_eq!(dependencies.len(), 1);
        assert_eq!(dependencies[0].name.to_string(), "preferred-package");
    }

    #[tokio::test]
    async fn test_empty_packages_list() {
        let lock_content = r#"
lock-version = "1.0"
created-by = "test-tool"
"#;

        let (_temp_dir, project_path) = create_test_pylock_file(lock_content, "pylock.toml").await;
        let parser = PyLockParser::new();

        let result = parser
            .parse_dependencies(&project_path, false, false, false)
            .await;
        assert!(result.is_ok());

        let (dependencies, skipped) = result.unwrap();
        assert_eq!(dependencies.len(), 0);
        assert_eq!(skipped.len(), 0);
    }
}
