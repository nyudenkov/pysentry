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

use crate::types::{PackageName, Version};
use crate::{AuditError, Result};
use async_trait::async_trait;
use std::path::Path;

pub mod lock;
pub mod pipfile;
pub mod pipfile_lock;
pub mod poetry_lock;
pub mod pylock;
pub mod pyproject;
pub mod requirements;

#[derive(Debug, Clone)]
pub struct SkippedPackage {
    pub name: PackageName,
    pub reason: SkipReason,
}

#[derive(Debug, Clone)]
pub enum SkipReason {
    Virtual,
    Editable,
    MissingVersion,
    Other(String),
}

impl std::fmt::Display for SkipReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SkipReason::Virtual => write!(f, "virtual package - dependencies handled separately"),
            SkipReason::Editable => write!(f, "editable install - no version available"),
            SkipReason::MissingVersion => write!(f, "missing version information"),
            SkipReason::Other(desc) => write!(f, "{desc}"),
        }
    }
}

/// A dependency parsed from a project file
#[derive(Debug, Clone)]
pub struct ParsedDependency {
    /// Package name
    pub name: PackageName,
    /// Installed or specified version
    pub version: Version,
    /// Whether this is a direct dependency (listed in main dependencies)
    pub is_direct: bool,
    /// Source of the dependency (PyPI, git, path, etc.)
    pub source: DependencySource,
    /// Optional path for path dependencies
    pub path: Option<std::path::PathBuf>,
    /// Type of dependency (main, dev, optional)
    pub dependency_type: DependencyType,
}

/// Source type for dependencies
#[derive(Debug, Clone)]
pub enum DependencySource {
    /// PyPI registry
    Registry,
    /// Git repository
    Git { url: String, rev: Option<String> },
    /// Local path
    Path,
    /// Direct URL
    Url(String),
}

/// Type of dependency
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DependencyType {
    /// Main production dependency
    Main,
    /// Optional dependency (includes dev dependencies, optional groups, etc.)
    Optional,
}

/// Trait for parsing different project file formats
#[async_trait]
pub trait ProjectParser: Send + Sync {
    /// Returns the name of this parser (e.g., "uv.lock", "pyproject.toml")
    fn name(&self) -> &'static str;

    /// Check if this parser can handle the given project directory
    fn can_parse(&self, project_path: &Path) -> bool;

    /// Priority for parser selection (lower number = higher priority)
    /// 1 = highest priority (lock files with exact versions)
    /// 5 = lowest priority (basic requirement files)
    fn priority(&self) -> u8;

    /// Parse dependencies from the project directory
    async fn parse_dependencies(
        &self,
        project_path: &Path,
        include_dev: bool,
        include_optional: bool,
        direct_only: bool,
    ) -> Result<(Vec<ParsedDependency>, Vec<SkippedPackage>)>;

    /// Validate the parsed dependencies and return warnings
    fn validate_dependencies(&self, dependencies: &[ParsedDependency]) -> Vec<String> {
        let mut warnings = Vec::new();

        if dependencies.is_empty() {
            warnings.push(
                "No dependencies found. This might indicate an issue with dependency resolution."
                    .to_string(),
            );
            return warnings;
        }

        // Check for placeholder versions
        let placeholder_count = dependencies
            .iter()
            .filter(|dep| dep.version == Version::new([0, 0, 0]))
            .count();

        if placeholder_count > 0 {
            warnings.push(format!(
                "{placeholder_count} dependencies have placeholder versions. Consider using a lock file for accurate version information."
            ));
        }

        warnings
    }
}

/// Registry for managing multiple project parsers
pub struct ParserRegistry {
    parsers: Vec<Box<dyn ProjectParser>>,
}

impl ParserRegistry {
    /// Create a new parser registry
    pub fn new(resolver: Option<crate::types::ResolverType>) -> Self {
        match resolver {
            Some(resolver_type) => {
                let parsers: Vec<Box<dyn ProjectParser>> = vec![
                    Box::new(lock::UvLockParser::new()),
                    Box::new(poetry_lock::PoetryLockParser::new()),
                    Box::new(pipfile_lock::PipfileLockParser::new()),
                    Box::new(pylock::PyLockParser::new()),
                    Box::new(pyproject::PyProjectParser::new(Some(resolver_type))),
                    Box::new(pipfile::PipfileParser::new(Some(resolver_type))),
                    Box::new(requirements::RequirementsParser::new(Some(resolver_type))),
                ];
                Self { parsers }
            }
            None => {
                let parsers: Vec<Box<dyn ProjectParser>> = vec![
                    Box::new(lock::UvLockParser::new()),
                    Box::new(poetry_lock::PoetryLockParser::new()),
                    Box::new(pipfile_lock::PipfileLockParser::new()),
                    Box::new(pylock::PyLockParser::new()),
                    Box::new(pyproject::PyProjectParser::new(None)),
                    Box::new(pipfile::PipfileParser::new(None)),
                    Box::new(requirements::RequirementsParser::new(None)),
                ];
                Self { parsers }
            }
        }
    }

    /// Parse dependencies from a project directory using the best available parser
    /// Returns dependencies, skipped packages, and parser name
    pub async fn parse_project(
        &self,
        project_path: &Path,
        include_dev: bool,
        include_optional: bool,
        direct_only: bool,
    ) -> Result<(Vec<ParsedDependency>, Vec<SkippedPackage>, &'static str)> {
        // Find all compatible parsers
        let mut compatible_parsers: Vec<&Box<dyn ProjectParser>> = self
            .parsers
            .iter()
            .filter(|parser| parser.can_parse(project_path))
            .collect();

        if compatible_parsers.is_empty() {
            return Err(AuditError::NoDependencyInfo);
        }

        // Sort by priority (lower number = higher priority)
        compatible_parsers.sort_by_key(|parser| parser.priority());

        // Use the highest priority parser
        let parser = compatible_parsers[0];
        let parser_name = parser.name();

        tracing::debug!(
            "Using parser: {} for project: {}",
            parser_name,
            project_path.display()
        );

        let (dependencies, skipped_packages) = parser
            .parse_dependencies(project_path, include_dev, include_optional, direct_only)
            .await?;

        Ok((dependencies, skipped_packages, parser_name))
    }

    /// Get validation warnings for parsed dependencies including skipped packages
    pub fn validate_dependencies(
        &self,
        dependencies: &[ParsedDependency],
        skipped_packages: &[SkippedPackage],
        parser_name: &str,
    ) -> Vec<String> {
        let mut warnings = Vec::new();

        if !skipped_packages.is_empty() {
            warnings.push(format!(
                "Skipped {} packages during vulnerability scan:",
                skipped_packages.len()
            ));

            for skipped in skipped_packages {
                warnings.push(format!("  • {} ({})", skipped.name, skipped.reason));
            }
        }

        if let Some(parser) = self.parsers.iter().find(|p| p.name() == parser_name) {
            warnings.extend(parser.validate_dependencies(dependencies));
        } else if dependencies.is_empty() {
            warnings.push("No dependencies found.".to_string());
        } else {
            let placeholder_count = dependencies
                .iter()
                .filter(|dep| dep.version == Version::new([0, 0, 0]))
                .count();

            if placeholder_count > 0 {
                warnings.push(format!(
                    "{placeholder_count} dependencies have placeholder versions. Consider using a lock file for accurate version information."
                ));
            }
        }

        warnings
    }
}

impl Default for ParserRegistry {
    fn default() -> Self {
        Self::new(None)
    }
}

/// Statistics about parsed dependencies
#[derive(Debug, Clone)]
pub struct DependencyStats {
    pub total_packages: usize,
    pub direct_packages: usize,
    pub transitive_packages: usize,
    pub by_type: std::collections::HashMap<DependencyType, usize>,
    pub by_source: std::collections::HashMap<String, usize>,
}

impl DependencyStats {
    /// Calculate statistics from parsed dependencies
    pub fn from_dependencies(dependencies: &[ParsedDependency]) -> Self {
        let total_packages = dependencies.len();
        let direct_packages = dependencies.iter().filter(|d| d.is_direct).count();
        let transitive_packages = total_packages - direct_packages;

        let mut by_type = std::collections::HashMap::new();
        let mut by_source = std::collections::HashMap::new();

        for dep in dependencies {
            *by_type.entry(dep.dependency_type).or_insert(0) += 1;

            let source_name = match &dep.source {
                DependencySource::Registry => "Registry",
                DependencySource::Git { .. } => "Git",
                DependencySource::Path => "Path",
                DependencySource::Url(_) => "URL",
            };
            *by_source.entry(source_name.to_string()).or_insert(0) += 1;
        }

        Self {
            total_packages,
            direct_packages,
            transitive_packages,
            by_type,
            by_source,
        }
    }
}

impl std::fmt::Display for DependencyStats {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Found {} packages ({} direct, {} transitive)",
            self.total_packages, self.direct_packages, self.transitive_packages
        )?;

        if !self.by_source.is_empty() {
            write!(f, " - Sources: ")?;
            let mut first = true;
            for (source, count) in &self.by_source {
                if !first {
                    write!(f, ", ")?;
                }
                write!(f, "{source}: {count}")?;
                first = false;
            }
        }

        Ok(())
    }
}
