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

//! Generic requirements.txt parser with pluggable resolvers
//!
//! This parser can work with any dependency resolver (UV, pip-tools)
//! through the DependencyResolver trait, providing better separation of concerns.

use super::{DependencySource, DependencyType, ParsedDependency, ProjectParser, SkippedPackage};
use crate::{
    dependency::resolvers::{DependencyResolver, ResolverRegistry},
    types::{PackageName, ResolverType, Version},
    AuditError, Result,
};
use async_trait::async_trait;
use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use tracing::{debug, info, warn};

/// Generic requirements.txt parser that works with any resolver
pub struct RequirementsParser {
    resolver: Box<dyn DependencyResolver>,
}

impl RequirementsParser {
    /// Create a new requirements parser
    pub fn new(resolver: Option<ResolverType>) -> Self {
        let resolver_type = resolver.unwrap_or(ResolverType::Uv);
        let resolver = ResolverRegistry::create_resolver(resolver_type);

        Self { resolver }
    }

    /// Find requirements files in the project directory
    fn find_requirements_files(&self, project_path: &Path, include_dev: bool) -> Vec<PathBuf> {
        let mut files = Vec::new();

        // Main requirements.txt
        let main_requirements = project_path.join("requirements.txt");
        if main_requirements.exists() {
            files.push(main_requirements);
        }

        // Development requirements files if requested
        if include_dev {
            let dev_patterns = [
                "requirements-dev.txt",
                "requirements-development.txt",
                "requirements/dev.txt",
                "requirements/development.txt",
                "dev-requirements.txt",
                "requirements-test.txt",
                "requirements/test.txt",
                "test-requirements.txt",
            ];

            for pattern in &dev_patterns {
                let dev_file = project_path.join(pattern);
                if dev_file.exists() {
                    debug!("Found dev requirements file: {}", dev_file.display());
                    files.push(dev_file);
                }
            }
        }

        files
    }

    /// Extract package name from requirement specification
    fn extract_package_name(&self, requirement_line: &str) -> Result<Option<PackageName>> {
        let line = requirement_line.trim();

        // Skip empty lines and comments
        if line.is_empty() || line.starts_with('#') {
            return Ok(None);
        }

        // Handle -e editable installs
        let line = if line.starts_with("-e ") {
            line.strip_prefix("-e ").unwrap_or(line)
        } else {
            line
        };

        // Skip other pip flags
        if line.starts_with('-') {
            return Ok(None);
        }

        // Handle URL requirements with #egg=
        if line.contains("://") {
            if let Some(egg_part) = line.split("#egg=").nth(1) {
                let egg_name = egg_part.split('&').next().unwrap_or("").trim();
                if !egg_name.is_empty() {
                    return Ok(Some(PackageName::new(egg_name)));
                }
            }
            return Ok(None); // Skip complex URL parsing for now
        }

        // Extract name from version specifier (e.g., "flask>=2.0,<3.0")
        let name_part = line
            .split(&['>', '<', '=', '!', '~', ';', ' '][..])
            .next()
            .unwrap_or("")
            .trim();

        // Remove extras (e.g., "requests[security]" -> "requests")
        let package_name = if let Some(bracket_pos) = name_part.find('[') {
            &name_part[..bracket_pos]
        } else {
            name_part
        };

        if package_name.is_empty() {
            return Ok(None);
        }

        Ok(Some(PackageName::new(package_name)))
    }

    /// Combine multiple requirements files into single content
    async fn combine_requirements_files(&self, files: &[PathBuf]) -> Result<String> {
        let mut combined = String::new();

        for file in files {
            debug!("Reading requirements file: {}", file.display());

            let content = tokio::fs::read_to_string(file).await.map_err(|e| {
                AuditError::other(format!(
                    "Failed to read requirements file {}: {}",
                    file.display(),
                    e
                ))
            })?;

            combined.push_str(&format!("# From: {}\n", file.display()));
            combined.push_str(&content);
            combined.push('\n');
        }

        Ok(combined)
    }

    /// Parse resolved content into ParsedDependency structs
    async fn parse_resolved_content(
        &self,
        resolved_content: &str,
        original_requirements: &str,
    ) -> Result<Vec<ParsedDependency>> {
        let mut dependencies = Vec::new();

        // Extract direct dependencies from original requirements
        let direct_deps = self.extract_direct_dependencies(original_requirements)?;

        // Parse resolved content (pinned requirements format)
        for (line_num, line) in resolved_content.lines().enumerate() {
            let line = line.trim();

            // Skip comments and empty lines
            if line.is_empty() || line.starts_with('#') {
                continue;
            }

            // Parse pinned dependency: "package==version"
            if let Some((name_part, version_part)) = line.split_once("==") {
                let name = name_part.trim();

                // Extract version (handle extras and environment markers)
                let version = version_part
                    .split_whitespace()
                    .next()
                    .unwrap_or("")
                    .split(';') // Remove environment markers
                    .next()
                    .unwrap_or("")
                    .trim();

                match Version::from_str(version) {
                    Ok(parsed_version) => {
                        let package_name = PackageName::new(name);
                        let is_direct = direct_deps.contains(&package_name);

                        dependencies.push(ParsedDependency {
                            name: package_name,
                            version: parsed_version,
                            is_direct,
                            source: DependencySource::Registry, // Most resolvers work with PyPI
                            path: None,
                            dependency_type: DependencyType::Main, // We'll refine this based on file patterns later
                        });
                    }
                    Err(e) => {
                        warn!(
                            "Failed to parse version '{}' for package '{}' on line {}: {}",
                            version,
                            name,
                            line_num + 1,
                            e
                        );
                    }
                }
            } else if !line.starts_with('#') && !line.trim().is_empty() {
                debug!("Skipping unrecognized line format: {}", line);
            }
        }

        if dependencies.is_empty() {
            return Err(AuditError::EmptyResolution);
        }

        Ok(dependencies)
    }

    /// Extract direct dependency names from original requirements content
    fn extract_direct_dependencies(
        &self,
        requirements_content: &str,
    ) -> Result<HashSet<PackageName>> {
        let mut direct_deps = HashSet::new();

        for line in requirements_content.lines() {
            if let Some(package_name) = self.extract_package_name(line)? {
                direct_deps.insert(package_name);
            }
        }

        debug!(
            "Extracted {} direct dependencies from requirements",
            direct_deps.len()
        );
        Ok(direct_deps)
    }

    /// Parse explicit requirements files (bypasses auto-discovery)
    pub async fn parse_explicit_files(
        &self,
        requirements_files: &[PathBuf],
        direct_only: bool,
    ) -> Result<Vec<ParsedDependency>> {
        info!(
            "Parsing explicit requirements files with {} resolver",
            self.resolver.name()
        );

        // Check if resolver is available
        if !self.resolver.is_available().await {
            return Err(AuditError::other(format!(
                "{} resolver not available. Please install {}",
                self.resolver.name(),
                self.resolver.name()
            )));
        }

        // Validate that all files exist
        for file in requirements_files {
            if !file.exists() {
                return Err(AuditError::other(format!(
                    "Requirements file does not exist: {}",
                    file.display()
                )));
            }
        }

        debug!(
            "Using {} explicit requirements files",
            requirements_files.len()
        );

        // Combine all requirements files into one
        let combined_requirements = self.combine_explicit_files(requirements_files).await?;

        // Resolve dependencies using the configured resolver
        let resolved_content = self
            .resolver
            .resolve_requirements(&combined_requirements)
            .await?;

        // Parse the resolved dependencies
        let dependencies = self
            .parse_resolved_content(&resolved_content, &combined_requirements)
            .await?;

        // Filter dependencies based on options
        let filtered_dependencies = if direct_only {
            dependencies
                .into_iter()
                .filter(|dep| dep.is_direct)
                .collect()
        } else {
            dependencies
        };

        info!(
            "Successfully parsed {} dependencies from explicit requirements files",
            filtered_dependencies.len()
        );
        Ok(filtered_dependencies)
    }

    /// Parse include directive (-r or -c) from a requirements line
    fn parse_include_directive(line: &str) -> Option<(&str, &str)> {
        let trimmed = line.trim();

        // Handle -r and --requirement (for requirements includes)
        if let Some(path) = trimmed.strip_prefix("-r ") {
            return Some(("r", path.trim()));
        }
        if let Some(path) = trimmed.strip_prefix("--requirement ") {
            return Some(("r", path.trim()));
        }
        if let Some(path) = trimmed.strip_prefix("--requirement=") {
            return Some(("r", path.trim()));
        }

        // Handle -c and --constraint (for constraint files - same issue)
        if let Some(path) = trimmed.strip_prefix("-c ") {
            return Some(("c", path.trim()));
        }
        if let Some(path) = trimmed.strip_prefix("--constraint ") {
            return Some(("c", path.trim()));
        }
        if let Some(path) = trimmed.strip_prefix("--constraint=") {
            return Some(("c", path.trim()));
        }

        None
    }

    /// Resolve relative -r/-c directive paths to absolute paths
    fn resolve_requirements_includes(content: &str, source_file: &Path) -> Result<String> {
        let parent_dir = source_file.parent().ok_or_else(|| {
            AuditError::other(format!(
                "Cannot get parent directory for: {}",
                source_file.display()
            ))
        })?;

        let mut resolved = String::new();

        for line in content.lines() {
            if let Some((directive_type, rel_path)) = Self::parse_include_directive(line) {
                // Resolve relative path to absolute path
                let include_path = parent_dir.join(rel_path);

                match include_path.canonicalize() {
                    Ok(abs_path) => {
                        let flag = if directive_type == "r" { "-r" } else { "-c" };
                        debug!("Resolved {} {} -> {}", flag, rel_path, abs_path.display());
                        resolved.push_str(&format!("{} {}\n", flag, abs_path.display()));
                    }
                    Err(e) => {
                        // If file doesn't exist, keep original path and let UV handle the error
                        // This preserves existing error messages from UV
                        warn!(
                            "Could not resolve include path '{}' from {}: {}. Using original path.",
                            rel_path,
                            source_file.display(),
                            e
                        );
                        resolved.push_str(line);
                        resolved.push('\n');
                    }
                }
            } else {
                // Not an include directive, keep line as-is
                resolved.push_str(line);
                resolved.push('\n');
            }
        }

        Ok(resolved)
    }

    /// Combine multiple explicit requirements files into single content
    async fn combine_explicit_files(&self, files: &[PathBuf]) -> Result<String> {
        let mut combined = String::new();

        for file in files {
            debug!("Reading explicit requirements file: {}", file.display());

            let content = tokio::fs::read_to_string(file).await.map_err(|e| {
                AuditError::other(format!(
                    "Failed to read requirements file {}: {}",
                    file.display(),
                    e
                ))
            })?;

            // Resolve relative -r/-c directives to absolute paths
            let resolved_content = Self::resolve_requirements_includes(&content, file)?;

            combined.push_str(&format!("# From: {}\n", file.display()));
            combined.push_str(&resolved_content);
            combined.push('\n');
        }

        Ok(combined)
    }
}

#[async_trait]
impl ProjectParser for RequirementsParser {
    fn name(&self) -> &'static str {
        // We need to return a static str, but we want to show the resolver name
        // For now, we'll use a generic name and the resolver info will be logged
        "requirements.txt (configurable resolver)"
    }

    fn can_parse(&self, project_path: &Path) -> bool {
        project_path.join("requirements.txt").exists()
    }

    fn priority(&self) -> u8 {
        7 // Medium priority - after lock files and pyproject.toml, before simple parsers
    }

    async fn parse_dependencies(
        &self,
        project_path: &Path,
        include_dev: bool,
        _include_optional: bool,
        direct_only: bool,
    ) -> Result<(Vec<ParsedDependency>, Vec<SkippedPackage>)> {
        info!(
            "Parsing requirements.txt files with {} resolver",
            self.resolver.name()
        );

        // Check if resolver is available
        if !self.resolver.is_available().await {
            return Err(AuditError::other(format!(
                "{} resolver not available. Please install {}",
                self.resolver.name(),
                self.resolver.name()
            )));
        }

        // Find all requirements files
        let requirements_files = self.find_requirements_files(project_path, include_dev);
        if requirements_files.is_empty() {
            return Err(AuditError::NoRequirementsFound);
        }

        debug!("Found {} requirements files", requirements_files.len());

        // Combine all requirements files into one
        let combined_requirements = self.combine_requirements_files(&requirements_files).await?;

        // Resolve dependencies using the configured resolver
        let resolved_content = self
            .resolver
            .resolve_requirements(&combined_requirements)
            .await?;

        // Parse the resolved dependencies
        let dependencies = self
            .parse_resolved_content(&resolved_content, &combined_requirements)
            .await?;

        // Filter dependencies based on options
        let filtered_dependencies = if direct_only {
            dependencies
                .into_iter()
                .filter(|dep| dep.is_direct)
                .collect()
        } else {
            dependencies
        };

        info!(
            "Successfully parsed {} dependencies from requirements.txt",
            filtered_dependencies.len()
        );
        Ok((filtered_dependencies, Vec::new()))
    }

    fn validate_dependencies(&self, dependencies: &[ParsedDependency]) -> Vec<String> {
        let mut warnings = Vec::new();

        if dependencies.is_empty() {
            warnings.push("No dependencies found in requirements.txt files. Check if the files contain valid package specifications.".to_string());
            return warnings;
        }

        // Check for large dependency trees
        if dependencies.len() > 200 {
            let dep_len = dependencies.len();
            warnings.push(format!(
                "Found {dep_len} dependencies. This is a large dependency tree from requirements.txt resolution."
            ));
        }

        // Check for potential issues with transitive dependencies
        let direct_count = dependencies.iter().filter(|dep| dep.is_direct).count();
        let transitive_count = dependencies.len() - direct_count;

        if transitive_count > direct_count * 5 {
            warnings.push(format!(
                "High transitive dependency ratio: {direct_count} direct, {transitive_count} transitive. Consider using a lock file for better control."
            ));
        }

        warnings
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::ResolverType;

    #[test]
    fn test_requirements_parser_creation() {
        let parser = RequirementsParser::new(Some(ResolverType::Uv));
        assert_eq!(parser.resolver.name(), "uv");
    }

    #[tokio::test]
    async fn test_extract_package_name() {
        let parser = RequirementsParser::new(Some(ResolverType::Uv));

        // Test basic package name
        let result = parser.extract_package_name("requests>=2.25.0").unwrap();
        assert_eq!(result, Some(PackageName::new("requests")));

        // Test with extras
        let result = parser
            .extract_package_name("requests[security]>=2.25.0")
            .unwrap();
        assert_eq!(result, Some(PackageName::new("requests")));

        // Test comment (should be None)
        let result = parser.extract_package_name("# This is a comment").unwrap();
        assert_eq!(result, None);

        // Test empty line (should be None)
        let result = parser.extract_package_name("   ").unwrap();
        assert_eq!(result, None);
    }

    #[test]
    fn test_find_requirements_files() {
        // This test would need a mock filesystem or actual test files
        // For now, we'll just test the method exists and doesn't panic
        let parser = RequirementsParser::new(Some(ResolverType::Uv));
        let files = parser.find_requirements_files(Path::new("."), false);
        // The result depends on the current directory, so we just ensure it doesn't crash
        let _count = files.len();
    }

    #[tokio::test]
    async fn test_extract_direct_dependencies() {
        let parser = RequirementsParser::new(Some(ResolverType::Uv));
        let requirements = r#"
# Main dependencies
requests>=2.25.0
flask>=2.0,<3.0

# Comment
click>=8.0.0
"#;

        let result = parser.extract_direct_dependencies(requirements).unwrap();
        assert_eq!(result.len(), 3);
        assert!(result.contains(&PackageName::new("requests")));
        assert!(result.contains(&PackageName::new("flask")));
        assert!(result.contains(&PackageName::new("click")));
    }

    #[test]
    fn test_parse_include_directive() {
        // Test -r directive
        assert_eq!(
            RequirementsParser::parse_include_directive("-r ../requirements.txt"),
            Some(("r", "../requirements.txt"))
        );

        // Test --requirement directive
        assert_eq!(
            RequirementsParser::parse_include_directive("--requirement base.txt"),
            Some(("r", "base.txt"))
        );

        // Test --requirement= directive
        assert_eq!(
            RequirementsParser::parse_include_directive("--requirement=../requirements.txt"),
            Some(("r", "../requirements.txt"))
        );

        // Test -c constraint directive
        assert_eq!(
            RequirementsParser::parse_include_directive("-c constraints.txt"),
            Some(("c", "constraints.txt"))
        );

        // Test --constraint directive
        assert_eq!(
            RequirementsParser::parse_include_directive("--constraint ../constraints.txt"),
            Some(("c", "../constraints.txt"))
        );

        // Test --constraint= directive
        assert_eq!(
            RequirementsParser::parse_include_directive("--constraint=constraints.txt"),
            Some(("c", "constraints.txt"))
        );

        // Test with extra whitespace
        assert_eq!(
            RequirementsParser::parse_include_directive("  -r   ../requirements.txt  "),
            Some(("r", "../requirements.txt"))
        );

        // Test non-directive lines
        assert_eq!(
            RequirementsParser::parse_include_directive("requests>=2.25.0"),
            None
        );
        assert_eq!(
            RequirementsParser::parse_include_directive("# Comment"),
            None
        );
        assert_eq!(RequirementsParser::parse_include_directive(""), None);
    }

    #[test]
    fn test_resolve_requirements_includes() {
        use std::fs;
        use tempfile::TempDir;

        // Create temporary directory structure
        let temp_dir = TempDir::new().unwrap();
        let project_path = temp_dir.path();

        // Create requirements files
        let base_req = project_path.join("requirements.txt");
        fs::write(&base_req, "flask==2.0.0\n").unwrap();

        // Create dev subdirectory
        let dev_dir = project_path.join("dev");
        fs::create_dir(&dev_dir).unwrap();
        let dev_req = dev_dir.join("requirements.txt");

        // Test content with relative path
        let content_with_include = "-r ../requirements.txt\npytest==8.4.2\n";

        let resolved =
            RequirementsParser::resolve_requirements_includes(content_with_include, &dev_req)
                .unwrap();

        // Should contain absolute path to requirements.txt
        assert!(resolved.contains("-r"));
        assert!(resolved.contains("requirements.txt"));
        assert!(resolved.contains("pytest==8.4.2"));

        // Verify the path was made absolute
        let expected_abs_path = base_req.canonicalize().unwrap();
        assert!(resolved.contains(&expected_abs_path.display().to_string()));
    }

    #[test]
    fn test_resolve_requirements_includes_constraint_files() {
        use std::fs;
        use tempfile::TempDir;

        let temp_dir = TempDir::new().unwrap();
        let project_path = temp_dir.path();

        // Create constraint file
        let constraints = project_path.join("constraints.txt");
        fs::write(&constraints, "flask<3.0\n").unwrap();

        // Create dev subdirectory
        let dev_dir = project_path.join("dev");
        fs::create_dir(&dev_dir).unwrap();
        let dev_req = dev_dir.join("requirements.txt");

        let content = "-c ../constraints.txt\nflask>=2.0\n";

        let resolved =
            RequirementsParser::resolve_requirements_includes(content, &dev_req).unwrap();

        // Should contain absolute path to constraints.txt
        assert!(resolved.contains("-c"));
        assert!(resolved.contains("constraints.txt"));
        assert!(resolved.contains("flask>=2.0"));

        let expected_abs_path = constraints.canonicalize().unwrap();
        assert!(resolved.contains(&expected_abs_path.display().to_string()));
    }

    #[test]
    fn test_resolve_requirements_includes_preserves_regular_lines() {
        use std::fs;
        use tempfile::TempDir;

        let temp_dir = TempDir::new().unwrap();
        let test_file = temp_dir.path().join("requirements.txt");
        fs::write(&test_file, "").unwrap();

        let content = r#"
# This is a comment
requests>=2.25.0
flask[async]>=2.0,<3.0

click==8.0.0
"#;

        let resolved =
            RequirementsParser::resolve_requirements_includes(content, &test_file).unwrap();

        // All lines should be preserved
        assert!(resolved.contains("# This is a comment"));
        assert!(resolved.contains("requests>=2.25.0"));
        assert!(resolved.contains("flask[async]>=2.0,<3.0"));
        assert!(resolved.contains("click==8.0.0"));
    }

    #[test]
    fn test_resolve_requirements_includes_multiple_directives() {
        use std::fs;
        use tempfile::TempDir;

        let temp_dir = TempDir::new().unwrap();
        let project_path = temp_dir.path();

        // Create referenced files
        let base_req = project_path.join("base.txt");
        fs::write(&base_req, "flask==2.0.0\n").unwrap();

        let security_req = project_path.join("security.txt");
        fs::write(&security_req, "cryptography>=3.0\n").unwrap();

        let dev_req = project_path.join("dev.txt");

        let content = "-r base.txt\n-r security.txt\npytest==8.4.2\n";

        let resolved =
            RequirementsParser::resolve_requirements_includes(content, &dev_req).unwrap();

        // Both includes should be resolved to absolute paths
        let base_abs = base_req.canonicalize().unwrap();
        let security_abs = security_req.canonicalize().unwrap();

        assert!(resolved.contains(&format!("-r {}", base_abs.display())));
        assert!(resolved.contains(&format!("-r {}", security_abs.display())));
        assert!(resolved.contains("pytest==8.4.2"));
    }
}
