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
use serde::{Deserialize, Deserializer};
use std::collections::{HashMap, HashSet};
use std::path::Path;
use std::str::FromStr;
use tracing::{debug, info, warn};

fn deserialize_dependency<'de, D>(
    deserializer: D,
) -> std::result::Result<PipfileDependency, D::Error>
where
    D: Deserializer<'de>,
{
    use serde::de::{MapAccess, Visitor};

    struct DependencyVisitor;

    impl<'de> Visitor<'de> for DependencyVisitor {
        type Value = PipfileDependency;

        fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
            formatter.write_str("a string or object representing dependency specification")
        }

        fn visit_str<E>(self, value: &str) -> std::result::Result<Self::Value, E>
        where
            E: serde::de::Error,
        {
            Ok(PipfileDependency {
                version: Some(value.to_string()),
                git: None,
                git_ref: None,
                path: None,
                file: None,
                editable: false,
                extras: Vec::new(),
                markers: None,
                index: None,
            })
        }

        fn visit_map<M>(self, mut map: M) -> std::result::Result<Self::Value, M::Error>
        where
            M: MapAccess<'de>,
        {
            let mut dependency = PipfileDependency::default();

            while let Some((key, value)) = map.next_entry::<String, serde_json::Value>()? {
                match key.as_str() {
                    "version" => {
                        if let Some(v) = value.as_str() {
                            dependency.version = Some(v.to_string());
                        }
                    }
                    "git" => {
                        if let Some(v) = value.as_str() {
                            dependency.git = Some(v.to_string());
                        }
                    }
                    "ref" => {
                        if let Some(v) = value.as_str() {
                            dependency.git_ref = Some(v.to_string());
                        }
                    }
                    "path" => {
                        if let Some(v) = value.as_str() {
                            dependency.path = Some(v.to_string());
                        }
                    }
                    "file" => {
                        if let Some(v) = value.as_str() {
                            dependency.file = Some(v.to_string());
                        }
                    }
                    "editable" => {
                        dependency.editable = value.as_bool().unwrap_or(false);
                    }
                    "extras" => {
                        if let Some(extras_array) = value.as_array() {
                            dependency.extras = extras_array
                                .iter()
                                .filter_map(|v| v.as_str().map(|s| s.to_string()))
                                .collect();
                        }
                    }
                    "markers" => {
                        if let Some(v) = value.as_str() {
                            dependency.markers = Some(v.to_string());
                        }
                    }
                    "index" => {
                        if let Some(v) = value.as_str() {
                            dependency.index = Some(v.to_string());
                        }
                    }
                    _ => {
                        // Ignore unknown fields
                    }
                }
            }

            Ok(dependency)
        }
    }

    deserializer.deserialize_any(DependencyVisitor)
}

#[derive(Debug, Deserialize)]
struct Pipfile {
    #[serde(default)]
    #[allow(dead_code)]
    source: Vec<PipfileSource>,
    #[serde(default)]
    packages: HashMap<String, PipfileDependency>,
    #[serde(rename = "dev-packages")]
    #[serde(default)]
    dev_packages: HashMap<String, PipfileDependency>,
    #[serde(default)]
    #[allow(dead_code)]
    requires: Option<PipfileRequires>,
    #[serde(default)]
    #[allow(dead_code)]
    scripts: HashMap<String, String>,
    #[serde(default)]
    #[allow(dead_code)]
    pipenv: HashMap<String, serde_json::Value>,
}

#[derive(Debug, Deserialize, Clone)]
struct PipfileSource {
    #[allow(dead_code)]
    name: String,
    #[allow(dead_code)]
    url: String,
    #[serde(default = "default_verify_ssl")]
    #[allow(dead_code)]
    verify_ssl: bool,
}

fn default_verify_ssl() -> bool {
    true
}

#[derive(Debug, Deserialize)]
struct PipfileRequires {
    #[allow(dead_code)]
    python_version: Option<String>,
    #[allow(dead_code)]
    python_full_version: Option<String>,
}

#[derive(Debug, Clone, Default)]
struct PipfileDependency {
    version: Option<String>,
    git: Option<String>,
    git_ref: Option<String>,
    path: Option<String>,
    file: Option<String>,
    editable: bool,
    extras: Vec<String>,
    markers: Option<String>,
    index: Option<String>,
}

impl<'de> Deserialize<'de> for PipfileDependency {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserialize_dependency(deserializer)
    }
}

pub struct PipfileParser {
    resolver: Option<Box<dyn DependencyResolver>>,
}

impl Default for PipfileParser {
    fn default() -> Self {
        Self::new(None)
    }
}

impl PipfileParser {
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
}

#[async_trait]
impl ProjectParser for PipfileParser {
    fn name(&self) -> &'static str {
        "Pipfile"
    }

    fn can_parse(&self, project_path: &Path) -> bool {
        project_path.join("Pipfile").exists() && !project_path.join("Pipfile.lock").exists()
    }

    fn priority(&self) -> u8 {
        4 // Between pyproject.toml (2) and requirements.txt (5)
    }

    async fn parse_dependencies(
        &self,
        project_path: &Path,
        include_dev: bool,
        include_optional: bool,
        direct_only: bool,
    ) -> Result<(Vec<ParsedDependency>, Vec<SkippedPackage>)> {
        let pipfile_path = project_path.join("Pipfile");
        debug!("Reading Pipfile: {}", pipfile_path.display());

        let content = tokio::fs::read_to_string(&pipfile_path)
            .await
            .map_err(|e| AuditError::DependencyRead(Box::new(e)))?;

        let pipfile: Pipfile = toml::from_str(&content).map_err(AuditError::LockFileParse)?;

        let mut direct_deps_with_info = Vec::new();

        for (package_name, dep_spec) in &pipfile.packages {
            let spec_string = self.convert_dependency_to_spec(dep_spec)?;
            direct_deps_with_info.push((
                PackageName::new(package_name),
                DependencyType::Main,
                spec_string,
            ));
        }

        if include_dev || include_optional {
            for (package_name, dep_spec) in &pipfile.dev_packages {
                let spec_string = self.convert_dependency_to_spec(dep_spec)?;
                direct_deps_with_info.push((
                    PackageName::new(package_name),
                    DependencyType::Optional,
                    spec_string,
                ));
            }
        }

        if direct_deps_with_info.is_empty() {
            warn!(
                "No dependencies found in Pipfile: {}",
                pipfile_path.display()
            );
            return Ok((Vec::new(), Vec::new()));
        }

        debug!(
            "Found {} direct dependencies in Pipfile",
            direct_deps_with_info.len()
        );

        let dependencies = if self.has_resolver() && self.is_resolver_available().await {
            info!("Using external resolver for Pipfile dependency resolution");
            self.parse_with_resolver(
                &direct_deps_with_info,
                include_dev,
                include_optional,
                direct_only,
            )
            .await?
        } else {
            warn!("No resolver available for Pipfile - using basic parsing (may miss transitive dependencies)");
            self.parse_without_resolver(
                direct_deps_with_info,
                include_dev,
                include_optional,
                direct_only,
            )
            .await?
        };

        Ok((dependencies, Vec::new()))
    }

    fn validate_dependencies(&self, dependencies: &[ParsedDependency]) -> Vec<String> {
        let mut warnings = Vec::new();

        if dependencies.is_empty() {
            warnings.push("No dependencies found in Pipfile. Consider checking your Pipfile format or adding dependencies.".to_string());
            return warnings;
        }

        let placeholder_count = dependencies
            .iter()
            .filter(|dep| dep.version == Version::new([0, 0, 0]))
            .count();

        if placeholder_count > 0 {
            warnings.push(format!(
                "{placeholder_count} dependencies have placeholder versions. Consider using 'pipenv lock' to generate Pipfile.lock for accurate version information."
            ));
        }

        let direct_only_count = dependencies.iter().filter(|dep| dep.is_direct).count();
        if direct_only_count == dependencies.len() && dependencies.len() > 3 {
            warnings.push(
                "Only direct dependencies found. Consider using 'pipenv lock' to capture transitive dependencies for more comprehensive security scanning.".to_string(),
            );
        }

        warnings
    }
}

impl PipfileParser {
    fn convert_dependency_to_spec(&self, dep: &PipfileDependency) -> Result<String> {
        // Handle git dependencies
        if let Some(git_url) = &dep.git {
            let mut git_spec = format!("git+{git_url}");
            if let Some(git_ref) = &dep.git_ref {
                git_spec.push('@');
                git_spec.push_str(git_ref);
            }
            if dep.editable {
                return Ok(format!("-e {git_spec}"));
            } else {
                return Ok(git_spec);
            }
        }

        if let Some(path) = &dep.path {
            if dep.editable {
                return Ok(format!("-e {path}"));
            } else {
                return Ok(path.clone());
            }
        }

        if let Some(file_url) = &dep.file {
            return Ok(file_url.clone());
        }

        let version_spec = if let Some(version) = &dep.version {
            if version == "*" {
                String::new()
            } else {
                version.clone()
            }
        } else {
            String::new()
        };

        if !dep.extras.is_empty() {
            return Ok(format!("[{}]{}", dep.extras.join(","), version_spec));
        }

        Ok(version_spec)
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
        let mut warned_about_resolver = false;

        for (package_name, dep_type, version_spec) in direct_deps_with_info {
            if !self.should_include_dependency_type(dep_type, include_dev, include_optional) {
                continue;
            }

            if !warned_about_resolver && !direct_only {
                warn!(
                    "Using Pipfile without resolver - transitive dependencies will be missing. Consider using 'pipenv lock' or installing uv/pip-tools for complete dependency resolution."
                );
                warned_about_resolver = true;
            }

            let version = self
                .extract_version_from_spec(&version_spec)
                .unwrap_or_else(|| Version::new([0, 0, 0]));

            let source = self.determine_source_from_spec(&version_spec);

            let dependency = ParsedDependency {
                name: package_name,
                version,
                is_direct: true,
                source,
                path: None,
                dependency_type: dep_type,
            };

            dependencies.push(dependency);
        }

        Ok(dependencies)
    }

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

            let requirement_line = format!("{package_name}{version_spec}");
            requirements.push(requirement_line);
        }

        Ok(requirements.join("\n"))
    }

    async fn parse_resolved_content(
        &self,
        resolved_content: &str,
        direct_deps_with_info: &[(PackageName, DependencyType, String)],
        direct_only: bool,
    ) -> Result<Vec<ParsedDependency>> {
        let mut dependencies = Vec::new();
        let direct_packages: HashSet<PackageName> = direct_deps_with_info
            .iter()
            .map(|(name, _, _)| name.clone())
            .collect();

        for line in resolved_content.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }

            if line.starts_with("-e ") {
                continue;
            }

            if let Some((package_name_str, version_str)) = self.parse_resolved_line(line) {
                let package_name = PackageName::new(&package_name_str);
                let is_direct = direct_packages.contains(&package_name);

                if direct_only && !is_direct {
                    continue;
                }

                let version =
                    Version::from_str(&version_str).unwrap_or_else(|_| Version::new([0, 0, 0]));

                let dependency_type = if is_direct {
                    direct_deps_with_info
                        .iter()
                        .find(|(name, _, _)| name == &package_name)
                        .map(|(_, dep_type, _)| *dep_type)
                        .unwrap_or(DependencyType::Main)
                } else {
                    DependencyType::Main
                };

                let dependency = ParsedDependency {
                    name: package_name,
                    version,
                    is_direct,
                    source: DependencySource::Registry,
                    path: None,
                    dependency_type,
                };

                dependencies.push(dependency);
            }
        }

        Ok(dependencies)
    }

    fn parse_resolved_line(&self, line: &str) -> Option<(String, String)> {
        if let Some(eq_pos) = line.find("==") {
            let package_name = line[..eq_pos].trim().to_string();
            let version = line[eq_pos + 2..].split_whitespace().next()?.to_string();
            Some((package_name, version))
        } else {
            None
        }
    }

    fn should_include_dependency_type(
        &self,
        dep_type: DependencyType,
        include_dev: bool,
        include_optional: bool,
    ) -> bool {
        match dep_type {
            DependencyType::Main => true,
            DependencyType::Optional => include_dev || include_optional,
        }
    }

    fn extract_version_from_spec(&self, spec: &str) -> Option<Version> {
        if let Some(version_str) = spec.strip_prefix("==") {
            Version::from_str(version_str.trim()).ok()
        } else if spec == "*"
            || spec.starts_with(">=")
            || spec.starts_with("<=")
            || spec.starts_with("~=")
        {
            None
        } else {
            Version::from_str(spec.trim()).ok()
        }
    }

    fn determine_source_from_spec(&self, spec: &str) -> DependencySource {
        if spec.starts_with("git+") || spec.contains("github.com") || spec.contains("gitlab.com") {
            DependencySource::Git {
                url: spec.to_string(),
                rev: None,
            }
        } else if spec.starts_with("http://") || spec.starts_with("https://") {
            DependencySource::Url(spec.to_string())
        } else if spec.starts_with("./") || spec.starts_with("../") || spec.starts_with("/") {
            DependencySource::Path
        } else {
            DependencySource::Registry
        }
    }
}
