// SPDX-License-Identifier: MIT

//! SARIF (Static Analysis Results Interchange Format) report generation for pysentry
//!
//! This module implements comprehensive SARIF 2.1.0 compliant output for security
//! vulnerability reports, optimized for GitHub Security and GitLab Security integration.

use crate::maintenance::{MaintenanceIssue, MaintenanceIssueType};
use crate::parsers::DependencyStats;
use crate::types::PackageName;
use crate::vulnerability::database::{Severity, VulnerabilityMatch};
use crate::vulnerability::matcher::{DatabaseStats, FixSuggestion};
use crate::{AuditError, Result};
use chrono::Utc;
use serde_json::{json, Value};
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use tracing::{debug, info};

/// Generator for SARIF 2.1.0 compliant security reports
pub struct SarifGenerator {
    /// Project root directory for relative path resolution
    project_root: PathBuf,
    /// Cache for parsed file locations
    location_cache: HashMap<String, Vec<LocationInfo>>,
    /// Rules (vulnerability definitions) generated for this report
    rules: Vec<Value>,
}

/// Information about a location in a source file
#[derive(Debug, Clone)]
struct LocationInfo {
    /// File path relative to project root
    file_path: String,
    /// Line number (1-based)
    line: Option<u32>,
    /// Column number (1-based)
    column: Option<u32>,
    /// Context information (e.g., dependency declaration)
    context: Option<String>,
}

impl SarifGenerator {
    /// Create a new SARIF generator
    pub fn new(project_root: impl AsRef<Path>) -> Self {
        Self {
            project_root: project_root.as_ref().to_path_buf(),
            location_cache: HashMap::new(),
            rules: Vec::new(),
        }
    }

    /// Generate a complete SARIF report
    pub fn generate_report(
        &mut self,
        matches: &[VulnerabilityMatch],
        dependency_stats: &DependencyStats,
        database_stats: &DatabaseStats,
        fix_suggestions: &[FixSuggestion],
        warnings: &[String],
        maintenance_issues: &[MaintenanceIssue],
    ) -> Result<String> {
        info!(
            "Generating SARIF 2.1.0 report with {} vulnerabilities and {} maintenance issues",
            matches.len(),
            maintenance_issues.len()
        );

        // Pre-process locations for better mapping
        self.preprocess_locations(matches);

        // Generate rules for each unique vulnerability
        self.generate_rules(matches);

        // Generate rules for maintenance issues (PEP 792)
        self.generate_maintenance_rules(maintenance_issues);

        // Create SARIF results
        let mut results = self.create_sarif_results(matches, fix_suggestions);

        // Add maintenance issue results
        results.extend(self.create_maintenance_results(maintenance_issues));

        // Build the complete SARIF document
        let sarif = self.build_sarif_document(&results, dependency_stats, database_stats, warnings);

        // Serialize to JSON
        let json = serde_json::to_string_pretty(&sarif).map_err(AuditError::Json)?;

        info!("SARIF report generated successfully");
        Ok(json)
    }

    /// Pre-process file locations for better mapping
    fn preprocess_locations(&mut self, matches: &[VulnerabilityMatch]) {
        let mut packages_to_locate: HashSet<PackageName> = HashSet::new();

        for m in matches {
            packages_to_locate.insert(m.package_name.clone());
        }

        debug!(
            "Pre-processing locations for {} packages",
            packages_to_locate.len()
        );

        // Parse pyproject.toml for direct dependencies
        if let Ok(locations) = self.parse_pyproject_locations(&packages_to_locate) {
            for (package, locs) in locations {
                self.location_cache
                    .insert(format!("pyproject.toml:{package}"), locs);
            }
        }

        // Parse uv.lock for all dependencies
        if let Ok(locations) = self.parse_lock_locations(&packages_to_locate) {
            for (package, locs) in locations {
                self.location_cache
                    .insert(format!("uv.lock:{package}"), locs);
            }
        }
    }

    /// Parse pyproject.toml to find dependency locations
    fn parse_pyproject_locations(
        &self,
        packages: &HashSet<PackageName>,
    ) -> Result<HashMap<PackageName, Vec<LocationInfo>>> {
        let pyproject_path = self.project_root.join("pyproject.toml");
        if !pyproject_path.exists() {
            return Ok(HashMap::new());
        }

        let content = fs_err::read_to_string(&pyproject_path)
            .map_err(|e| AuditError::Cache(anyhow::Error::from(e)))?;

        let mut locations = HashMap::new();
        let lines: Vec<&str> = content.lines().collect();

        // Simple parser to find dependency declarations
        let mut in_dependencies = false;
        let mut in_dev_dependencies = false;
        let mut current_section = None;

        for (line_idx, line) in lines.iter().enumerate() {
            let line_num = u32::try_from(line_idx + 1).unwrap_or(0);
            let trimmed = line.trim();

            // Track TOML sections
            if trimmed.starts_with('[') && trimmed.ends_with(']') {
                // Reset flags
                in_dependencies = false;
                in_dev_dependencies = false;

                // Check for dependencies sections
                if trimmed == "[project]" {
                    // We're in project section, but not yet in dependencies
                    current_section = Some(trimmed.to_string());
                    continue;
                }

                current_section = Some(trimmed.to_string());
                continue;
            }

            // Check for array-style dependencies in project section
            if current_section.as_deref() == Some("[project]") && trimmed == "dependencies = [" {
                in_dependencies = true;
                continue;
            }

            // Check for end of array
            if in_dependencies && trimmed == "]" {
                in_dependencies = false;
                continue;
            }

            // Look for package declarations
            if (in_dependencies || in_dev_dependencies)
                && !trimmed.is_empty()
                && !trimmed.starts_with('#')
            {
                for package in packages {
                    let package_str = package.to_string();

                    // Match various dependency declaration formats
                    if trimmed.contains(&package_str) {
                        // Try to find the exact column position
                        if let Some(col) = line.find(&package_str) {
                            let location = LocationInfo {
                                file_path: "pyproject.toml".to_string(),
                                line: Some(line_num),
                                column: Some(u32::try_from(col + 1).unwrap_or(0)),
                                context: Some(format!(
                                    "Dependency declaration in {}",
                                    current_section.as_deref().unwrap_or("unknown section")
                                )),
                            };

                            locations
                                .entry(package.clone())
                                .or_insert_with(Vec::new)
                                .push(location);
                        }
                    }
                }
            }
        }

        debug!(
            "Found {} package locations in pyproject.toml",
            locations.len()
        );
        Ok(locations)
    }

    /// Parse uv.lock to find dependency locations
    fn parse_lock_locations(
        &self,
        packages: &HashSet<PackageName>,
    ) -> Result<HashMap<PackageName, Vec<LocationInfo>>> {
        let lock_path = self.project_root.join("uv.lock");
        if !lock_path.exists() {
            return Ok(HashMap::new());
        }

        let content = fs_err::read_to_string(&lock_path)
            .map_err(|e| AuditError::Cache(anyhow::Error::from(e)))?;

        let mut locations = HashMap::new();
        let lines: Vec<&str> = content.lines().collect();

        // Parse the lock file format to find package declarations

        for (line_idx, line) in lines.iter().enumerate() {
            let line_num = u32::try_from(line_idx + 1).unwrap_or(0);
            let trimmed = line.trim();

            // Look for package declarations in lock file
            if let Some(name_start) = trimmed.find("name = \"") {
                if let Some(name_end) = trimmed[name_start + 8..].find('"') {
                    let package_name_str = &trimmed[name_start + 8..name_start + 8 + name_end];

                    // Check if this is one of our target packages
                    for package in packages {
                        if package.to_string() == package_name_str {
                            let location = LocationInfo {
                                file_path: "uv.lock".to_string(),
                                line: Some(line_num),
                                column: Some(u32::try_from(name_start + 8 + 1).unwrap_or(0)),
                                context: Some("Package declaration in lock file".to_string()),
                            };

                            locations
                                .entry(package.clone())
                                .or_insert_with(Vec::new)
                                .push(location);
                        }
                    }
                }
            }
        }

        debug!("Found {} package locations in uv.lock", locations.len());
        Ok(locations)
    }

    /// Generate rule definitions for vulnerabilities
    fn generate_rules(&mut self, matches: &[VulnerabilityMatch]) {
        let mut seen_rules = HashSet::new();

        for m in matches {
            let rule_id = &m.vulnerability.id;

            if seen_rules.contains(rule_id) {
                continue;
            }
            seen_rules.insert(rule_id.clone());

            // Create rule with comprehensive metadata
            let mut rule = json!({
                "id": rule_id,
                "name": format!("Security vulnerability {rule_id}"),
                "shortDescription": {
                    "text": m.vulnerability.summary
                },
                "defaultConfiguration": {
                    "level": Self::severity_to_sarif_level(m.vulnerability.severity)
                },
                "properties": {
                    "security-severity": Self::get_security_severity_score(m.vulnerability.severity),
                    "vulnerability_id": m.vulnerability.id,
                    "severity": format!("{:?}", m.vulnerability.severity),
                    "tags": ["security", "vulnerability", format!("{:?}", m.vulnerability.severity).to_lowercase()]
                }
            });

            // Add full description if available
            if let Some(description) = &m.vulnerability.description {
                rule["fullDescription"] = json!({
                    "text": description
                });
            }

            // Add help message
            rule["help"] = json!({
                "text": Self::create_help_text(&m.vulnerability),
                "markdown": Self::create_help_text(&m.vulnerability)
            });

            // Add help URI if available
            if let Some(primary_ref) = Self::extract_primary_reference(&m.vulnerability.references)
            {
                rule["helpUri"] = json!(primary_ref);
            }

            // Add CVSS score if available
            if let Some(cvss) = m.vulnerability.cvss_score {
                rule["properties"]["cvss_score"] = json!(cvss);
            }

            // Add withdrawal information if available
            if let Some(withdrawn_date) = &m.vulnerability.withdrawn {
                rule["properties"]["withdrawn"] = json!(withdrawn_date.to_rfc3339());
                rule["properties"]["tags"] = json!([
                    "security",
                    "vulnerability",
                    format!("{:?}", m.vulnerability.severity).to_lowercase(),
                    "withdrawn"
                ]);
            }

            // Add timestamps if available
            if let Some(published) = &m.vulnerability.published {
                rule["properties"]["published_date"] = json!(published.to_string());
            }
            if let Some(modified) = &m.vulnerability.modified {
                rule["properties"]["modified_date"] = json!(modified.to_string());
            }

            self.rules.push(rule);
        }

        debug!("Generated {} SARIF rules", self.rules.len());
    }

    /// Generate rule definitions for maintenance issues (PEP 792)
    fn generate_maintenance_rules(&mut self, issues: &[MaintenanceIssue]) {
        let mut seen_types = HashSet::new();

        for issue in issues {
            let rule_id = Self::maintenance_rule_id(&issue.issue_type);

            if seen_types.contains(&issue.issue_type) {
                continue;
            }
            seen_types.insert(issue.issue_type);

            let (level, severity_score, description) = match issue.issue_type {
                MaintenanceIssueType::Quarantined => (
                    "error",
                    "9.0",
                    "Package has been quarantined due to malware, security compromise, or other critical issues. Immediate removal is recommended.",
                ),
                MaintenanceIssueType::Deprecated => (
                    "warning",
                    "4.0",
                    "Package has been deprecated and is no longer recommended for use. Consider migrating to an alternative.",
                ),
                MaintenanceIssueType::Archived => (
                    "note",
                    "2.0",
                    "Package has been archived and will not receive further updates, including security fixes.",
                ),
            };

            let rule = json!({
                "id": rule_id,
                "name": format!("PEP 792 {} Package", issue.issue_type),
                "shortDescription": {
                    "text": format!("Package is {}", issue.issue_type.to_string().to_lowercase())
                },
                "fullDescription": {
                    "text": description
                },
                "defaultConfiguration": {
                    "level": level
                },
                "help": {
                    "text": format!("This package has been marked as {} per PEP 792 Project Status Markers. {}",
                        issue.issue_type.to_string().to_lowercase(), description),
                    "markdown": format!("## PEP 792: {} Package\n\n{}\n\nSee [PEP 792](https://peps.python.org/pep-0792/) for more information.",
                        issue.issue_type, description)
                },
                "helpUri": "https://peps.python.org/pep-0792/",
                "properties": {
                    "security-severity": severity_score,
                    "maintenance_status": issue.issue_type.to_string().to_lowercase(),
                    "tags": ["maintenance", "pep792", issue.issue_type.to_string().to_lowercase()]
                }
            });

            self.rules.push(rule);
        }

        debug!("Generated {} maintenance rules (PEP 792)", seen_types.len());
    }

    /// Get the SARIF rule ID for a maintenance issue type
    fn maintenance_rule_id(issue_type: &MaintenanceIssueType) -> String {
        format!("PEP792-{}", issue_type.to_string().to_uppercase())
    }

    /// Create SARIF results for maintenance issues
    fn create_maintenance_results(&self, issues: &[MaintenanceIssue]) -> Vec<Value> {
        let mut results = Vec::new();

        for issue in issues {
            let rule_id = Self::maintenance_rule_id(&issue.issue_type);

            let level = match issue.issue_type {
                MaintenanceIssueType::Quarantined => "error",
                MaintenanceIssueType::Deprecated => "warning",
                MaintenanceIssueType::Archived => "note",
            };

            let message = if let Some(reason) = &issue.reason {
                format!(
                    "Package '{}' v{} is {}: {}",
                    issue.package_name, issue.installed_version, issue.issue_type, reason
                )
            } else {
                format!(
                    "Package '{}' v{} is {}",
                    issue.package_name, issue.installed_version, issue.issue_type
                )
            };

            let dep_type = if issue.is_direct {
                "direct"
            } else {
                "transitive"
            };

            // Use source file if available, otherwise fall back to defaults
            let file_path = issue.source_file.as_deref().unwrap_or(if issue.is_direct {
                "pyproject.toml"
            } else {
                "uv.lock"
            });

            let result = json!({
                "ruleId": rule_id,
                "ruleIndex": self.find_rule_index(&rule_id),
                "message": {
                    "text": message
                },
                "level": level,
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": file_path
                        }
                    },
                    "logicalLocations": [{
                        "name": issue.package_name.to_string(),
                        "kind": "package"
                    }]
                }],
                "properties": {
                    "package_name": issue.package_name.to_string(),
                    "installed_version": issue.installed_version.to_string(),
                    "is_direct_dependency": issue.is_direct,
                    "dependency_type": dep_type,
                    "maintenance_status": issue.issue_type.to_string().to_lowercase(),
                    "reason": issue.reason
                }
            });

            results.push(result);
        }

        debug!("Created {} maintenance SARIF results", results.len());
        results
    }

    /// Create help text for a vulnerability
    fn create_help_text(vulnerability: &crate::vulnerability::database::Vulnerability) -> String {
        use std::fmt::Write;
        let mut help_text = format!("## {}\n\n", vulnerability.summary);

        if let Some(description) = &vulnerability.description {
            write!(help_text, "**Description:** {description}\n\n").unwrap();
        }

        if let Some(cvss) = vulnerability.cvss_score {
            write!(help_text, "**CVSS Score:** {cvss:.1}\n\n").unwrap();
        }

        if !vulnerability.fixed_versions.is_empty() {
            help_text.push_str("**Fixed Versions:**\n");
            for version in &vulnerability.fixed_versions {
                writeln!(help_text, "- {version}").unwrap();
            }
            help_text.push('\n');
        }

        if !vulnerability.references.is_empty() {
            help_text.push_str("**References:**\n");
            for reference in &vulnerability.references {
                writeln!(help_text, "- {reference}").unwrap();
            }
        }

        help_text
    }

    /// Extract primary reference URL
    fn extract_primary_reference(references: &[String]) -> Option<String> {
        // Prefer GHSA or CVE URLs, then any HTTPS URL
        references
            .iter()
            .find(|r| r.contains("github.com/advisories/") || r.contains("cve.mitre.org"))
            .or_else(|| references.iter().find(|r| r.starts_with("https://")))
            .cloned()
    }

    /// Convert severity to SARIF level
    fn severity_to_sarif_level(severity: Severity) -> &'static str {
        match severity {
            Severity::Critical => "error",
            Severity::High => "error",
            Severity::Medium => "warning",
            Severity::Low => "note",
        }
    }

    /// Get security severity score for GitHub integration
    fn get_security_severity_score(severity: Severity) -> &'static str {
        match severity {
            Severity::Critical => "10.0",
            Severity::High => "8.0",
            Severity::Medium => "5.0",
            Severity::Low => "2.0",
        }
    }

    /// Create SARIF results from vulnerability matches
    fn create_sarif_results(
        &self,
        matches: &[VulnerabilityMatch],
        fix_suggestions: &[FixSuggestion],
    ) -> Vec<Value> {
        let mut results = Vec::new();

        // Create a map of package names to fix suggestions for quick lookup
        let fix_map: HashMap<&PackageName, &FixSuggestion> = fix_suggestions
            .iter()
            .map(|fs| (&fs.package_name, fs))
            .collect();

        for m in matches {
            let mut result = json!({
                "ruleId": m.vulnerability.id,
                "ruleIndex": self.find_rule_index(&m.vulnerability.id),
                "message": {
                    "text": format!(
                        "Package '{}' version {} has vulnerability {}: {}",
                        m.package_name,
                        m.installed_version,
                        m.vulnerability.id,
                        m.vulnerability.summary
                    )
                },
                "level": Self::severity_to_sarif_level(m.vulnerability.severity),
                "locations": self.create_locations_for_match(m),
                "properties": {
                    "package_name": m.package_name.to_string(),
                    "installed_version": m.installed_version.to_string(),
                    "is_direct_dependency": m.is_direct,
                    "vulnerability_severity": format!("{:?}", m.vulnerability.severity)
                }
            });

            // Add CVSS score if available
            if let Some(cvss) = m.vulnerability.cvss_score {
                result["properties"]["cvss_score"] = json!(cvss);
            }

            // Add fixed versions if available
            if !m.vulnerability.fixed_versions.is_empty() {
                let fixed_versions: Vec<String> = m
                    .vulnerability
                    .fixed_versions
                    .iter()
                    .map(ToString::to_string)
                    .collect();
                result["properties"]["fixed_versions"] = json!(fixed_versions);
            }

            // Add fix information if available
            if let Some(fix_suggestion) = fix_map.get(&m.package_name) {
                result["fixes"] = json!([{
                    "description": {
                        "text": format!(
                            "Update {} from {} to {} to fix vulnerability {}",
                            fix_suggestion.package_name,
                            fix_suggestion.current_version,
                            fix_suggestion.suggested_version,
                            fix_suggestion.vulnerability_id
                        )
                    }
                }]);
            }

            results.push(result);
        }

        debug!("Created {} SARIF results", results.len());
        results
    }

    /// Find rule index by ID
    fn find_rule_index(&self, rule_id: &str) -> Option<usize> {
        self.rules.iter().position(|r| r["id"] == rule_id)
    }

    /// Create locations for a vulnerability match
    fn create_locations_for_match(&self, m: &VulnerabilityMatch) -> Vec<Value> {
        let mut locations = Vec::new();

        // Try to find specific locations from cache
        let package_name = &m.package_name;

        // Check pyproject.toml first (for direct dependencies)
        if let Some(pyproject_locations) = self
            .location_cache
            .get(&format!("pyproject.toml:{package_name}"))
        {
            for loc_info in pyproject_locations {
                locations.push(Self::create_location_from_info(loc_info, m));
            }
        }

        // Add uv.lock location (for all dependencies)
        if let Some(lock_locations) = self.location_cache.get(&format!("uv.lock:{package_name}")) {
            for loc_info in lock_locations {
                locations.push(Self::create_location_from_info(loc_info, m));
            }
        }

        // If no specific locations found, create generic ones
        if locations.is_empty() {
            // Create a generic location pointing to the appropriate file
            let file_path = if m.is_direct {
                "pyproject.toml"
            } else {
                "uv.lock"
            };

            locations.push(json!({
                "physicalLocation": {
                    "artifactLocation": {
                        "uri": file_path
                    }
                },
                "logicalLocations": [{
                    "name": package_name.to_string(),
                    "kind": "package"
                }]
            }));
        }

        locations
    }

    /// Create location from location info
    fn create_location_from_info(loc_info: &LocationInfo, m: &VulnerabilityMatch) -> Value {
        let mut location = json!({
            "physicalLocation": {
                "artifactLocation": {
                    "uri": loc_info.file_path
                }
            },
            "logicalLocations": [{
                "name": m.package_name.to_string(),
                "kind": "package"
            }]
        });

        // Add region if we have line/column information
        if let (Some(line), Some(column)) = (loc_info.line, loc_info.column) {
            location["physicalLocation"]["region"] = json!({
                "startLine": line,
                "startColumn": column,
                "endLine": line,
                "endColumn": column + u32::try_from(m.package_name.to_string().len()).unwrap_or(0)
            });
        }

        // Add context message if available
        if let Some(context) = &loc_info.context {
            location["message"] = json!({
                "text": context
            });
        }

        location
    }

    /// Build complete SARIF document
    fn build_sarif_document(
        &self,
        results: &[Value],
        dependency_stats: &DependencyStats,
        database_stats: &DatabaseStats,
        warnings: &[String],
    ) -> Value {
        let sarif = json!({
            "version": "2.1.0",
            "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "runs": [{
                "tool": {
                    "driver": {
                        "name": "pysentry",
                        "version": env!("CARGO_PKG_VERSION"),
                        "informationUri": "https://github.com/nyudenkov/pysentry",
                        "semanticVersion": env!("CARGO_PKG_VERSION"),
                        "shortDescription": {
                            "text": "Security vulnerability scanner for Python dependencies"
                        },
                        "fullDescription": {
                            "text": "pysentry scans Python project dependencies for known security vulnerabilities using various databases (PyPA, PyPI, OSV)"
                        },
                        "rules": self.rules,
                        "properties": {
                            "scan_stats": {
                                "total_packages": dependency_stats.total_packages,
                                "direct_packages": dependency_stats.direct_packages,
                                "transitive_packages": dependency_stats.transitive_packages,
                                "database_vulnerabilities": database_stats.total_vulnerabilities,
                                "database_packages": database_stats.total_packages
                            }
                        }
                    }
                },
                "results": results,
                "invocations": [{
                    "commandLine": "pysentry",
                    "startTimeUtc": Utc::now().to_rfc3339(),
                    "executionSuccessful": true,
                    "exitCode": i32::from(!results.is_empty())
                }],
                "properties": {
                    "project_root": self.project_root.to_string_lossy(),
                    "dependency_sources": {},
                    "warnings": warnings
                }
            }]
        });

        sarif
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::Version;
    use crate::vulnerability::database::Vulnerability;
    use std::str::FromStr;
    use tempfile::TempDir;

    fn create_test_vulnerability() -> Vulnerability {
        Vulnerability {
            id: "GHSA-test-1234".to_string(),
            summary: "Test SQL injection vulnerability".to_string(),
            description: Some("A test SQL injection vulnerability in the test package".to_string()),
            severity: Severity::High,
            affected_versions: vec![],
            fixed_versions: vec![Version::from_str("2.0.0").unwrap()],
            references: vec![
                "https://github.com/advisories/GHSA-test-1234".to_string(),
                "https://nvd.nist.gov/vuln/detail/CVE-2023-12345".to_string(),
            ],
            cvss_score: Some(8.5),
            published: None,
            modified: None,
            source: Some("test".to_string()),
            withdrawn: None,
        }
    }

    fn create_test_match() -> VulnerabilityMatch {
        VulnerabilityMatch {
            package_name: PackageName::from_str("test-package").unwrap(),
            installed_version: Version::from_str("1.5.0").unwrap(),
            vulnerability: create_test_vulnerability(),
            is_direct: true,
        }
    }

    #[test]
    fn test_sarif_generator_creation() {
        let temp_dir = TempDir::new().unwrap();
        let generator = SarifGenerator::new(temp_dir.path());

        assert_eq!(generator.project_root, temp_dir.path());
        assert!(generator.location_cache.is_empty());
        assert!(generator.rules.is_empty());
    }

    #[test]
    fn test_severity_to_sarif_level() {
        let temp_dir = TempDir::new().unwrap();
        let _generator = SarifGenerator::new(temp_dir.path());

        assert_eq!(
            SarifGenerator::severity_to_sarif_level(Severity::Critical),
            "error"
        );
        assert_eq!(
            SarifGenerator::severity_to_sarif_level(Severity::High),
            "error"
        );
        assert_eq!(
            SarifGenerator::severity_to_sarif_level(Severity::Medium),
            "warning"
        );
        assert_eq!(
            SarifGenerator::severity_to_sarif_level(Severity::Low),
            "note"
        );
    }

    #[test]
    fn test_security_severity_score() {
        let temp_dir = TempDir::new().unwrap();
        let _generator = SarifGenerator::new(temp_dir.path());

        assert_eq!(
            SarifGenerator::get_security_severity_score(Severity::Critical),
            "10.0"
        );
        assert_eq!(
            SarifGenerator::get_security_severity_score(Severity::High),
            "8.0"
        );
        assert_eq!(
            SarifGenerator::get_security_severity_score(Severity::Medium),
            "5.0"
        );
        assert_eq!(
            SarifGenerator::get_security_severity_score(Severity::Low),
            "2.0"
        );
    }

    #[test]
    fn test_rule_generation() {
        let temp_dir = TempDir::new().unwrap();
        let mut generator = SarifGenerator::new(temp_dir.path());

        let matches = vec![create_test_match()];
        generator.generate_rules(&matches);

        assert_eq!(generator.rules.len(), 1);
        assert_eq!(generator.rules[0]["id"], "GHSA-test-1234");
        assert!(generator.rules[0]["shortDescription"].is_object());
        assert!(generator.rules[0]["help"].is_object());
    }

    #[test]
    fn test_extract_primary_reference() {
        let temp_dir = TempDir::new().unwrap();
        let _generator = SarifGenerator::new(temp_dir.path());

        let references = vec![
            "https://example.com/advisory".to_string(),
            "https://github.com/advisories/GHSA-1234".to_string(),
            "https://nvd.nist.gov/vuln/detail/CVE-2023-1234".to_string(),
        ];

        let primary = SarifGenerator::extract_primary_reference(&references);
        assert_eq!(
            primary,
            Some("https://github.com/advisories/GHSA-1234".to_string())
        );
    }

    #[test]
    fn test_full_sarif_generation() {
        let temp_dir = TempDir::new().unwrap();
        let mut generator = SarifGenerator::new(temp_dir.path());

        let matches = vec![create_test_match()];
        let dependency_stats = DependencyStats {
            total_packages: 5,
            direct_packages: 3,
            transitive_packages: 2,
            by_type: std::collections::HashMap::new(),
            by_source: std::collections::HashMap::new(),
        };
        let database_stats = DatabaseStats {
            total_vulnerabilities: 100,
            total_packages: 50,
            severity_counts: std::collections::HashMap::new(),
            packages_with_most_vulns: vec![],
        };
        let fix_suggestions = vec![];
        let warnings = vec!["Test warning".to_string()];
        let maintenance_issues = vec![];

        let sarif_json = generator
            .generate_report(
                &matches,
                &dependency_stats,
                &database_stats,
                &fix_suggestions,
                &warnings,
                &maintenance_issues,
            )
            .unwrap();

        // Verify it's valid JSON
        let sarif: serde_json::Value = serde_json::from_str(&sarif_json).unwrap();

        // Check SARIF structure
        assert_eq!(sarif["version"], "2.1.0");
        assert!(sarif["runs"].is_array());
        assert_eq!(sarif["runs"][0]["tool"]["driver"]["name"], "pysentry");
        assert!(sarif["runs"][0]["results"].is_array());
        assert_eq!(sarif["runs"][0]["results"][0]["ruleId"], "GHSA-test-1234");
    }

    #[test]
    fn test_location_parsing_with_pyproject() {
        let temp_dir = TempDir::new().unwrap();
        let pyproject_path = temp_dir.path().join("pyproject.toml");

        // Create a test pyproject.toml with proper dependencies section
        std::fs::write(
            &pyproject_path,
            r#"[project]
name = "test-project"
dependencies = [
    "test-package>=1.0.0",
    "other-package==2.0.0"
]

[project.optional-dependencies]
dev = [
    "pytest>=6.0.0"
]
"#,
        )
        .unwrap();

        let generator = SarifGenerator::new(temp_dir.path());
        let mut packages = HashSet::new();
        packages.insert(PackageName::from_str("test-package").unwrap());

        let locations = generator.parse_pyproject_locations(&packages).unwrap();

        // Verify we found the location
        assert!(!locations.is_empty());

        if let Some(test_package_locations) =
            locations.get(&PackageName::from_str("test-package").unwrap())
        {
            assert!(!test_package_locations.is_empty());
            assert_eq!(test_package_locations[0].file_path, "pyproject.toml");
            assert!(test_package_locations[0].line.is_some());
        }
    }

    #[test]
    fn test_maintenance_rule_indexing() {
        let temp_dir = TempDir::new().unwrap();
        let mut generator = SarifGenerator::new(temp_dir.path());

        // Create maintenance issues for each type
        let issues = vec![
            MaintenanceIssue::new(
                PackageName::from_str("archived-pkg").unwrap(),
                Version::from_str("1.0.0").unwrap(),
                MaintenanceIssueType::Archived,
                Some("No longer maintained".to_string()),
                true,
                Some("pyproject.toml".to_string()),
            ),
            MaintenanceIssue::new(
                PackageName::from_str("deprecated-pkg").unwrap(),
                Version::from_str("2.0.0").unwrap(),
                MaintenanceIssueType::Deprecated,
                Some("Use new-pkg instead".to_string()),
                false,
                Some("uv.lock".to_string()),
            ),
            MaintenanceIssue::new(
                PackageName::from_str("quarantined-pkg").unwrap(),
                Version::from_str("3.0.0").unwrap(),
                MaintenanceIssueType::Quarantined,
                Some("Malware detected".to_string()),
                true,
                Some("poetry.lock".to_string()),
            ),
        ];

        // Generate maintenance rules
        generator.generate_maintenance_rules(&issues);

        // Verify rules were added (one per unique type)
        assert_eq!(generator.rules.len(), 3);

        // Verify find_rule_index works for each maintenance rule type
        let archived_idx = generator.find_rule_index("PEP792-ARCHIVED");
        let deprecated_idx = generator.find_rule_index("PEP792-DEPRECATED");
        let quarantined_idx = generator.find_rule_index("PEP792-QUARANTINED");

        assert!(archived_idx.is_some(), "Should find ARCHIVED rule");
        assert!(deprecated_idx.is_some(), "Should find DEPRECATED rule");
        assert!(quarantined_idx.is_some(), "Should find QUARANTINED rule");

        // Verify indices are unique
        let indices: std::collections::HashSet<_> = [archived_idx, deprecated_idx, quarantined_idx]
            .into_iter()
            .flatten()
            .collect();
        assert_eq!(indices.len(), 3, "All indices should be unique");

        // Verify non-existent rule returns None
        assert!(generator.find_rule_index("PEP792-NONEXISTENT").is_none());
    }

    #[test]
    fn test_maintenance_sarif_results_creation() {
        let temp_dir = TempDir::new().unwrap();
        let mut generator = SarifGenerator::new(temp_dir.path());

        let issues = vec![MaintenanceIssue::new(
            PackageName::from_str("bad-pkg").unwrap(),
            Version::from_str("1.0.0").unwrap(),
            MaintenanceIssueType::Quarantined,
            Some("Security compromise".to_string()),
            true,
            Some("pyproject.toml".to_string()),
        )];

        // Must generate rules first (as done in generate_report)
        generator.generate_maintenance_rules(&issues);

        // Create results
        let results = generator.create_maintenance_results(&issues);

        assert_eq!(results.len(), 1);
        assert_eq!(results[0]["ruleId"], "PEP792-QUARANTINED");
        assert_eq!(results[0]["level"], "error");
        assert!(results[0]["message"]["text"]
            .as_str()
            .unwrap()
            .contains("bad-pkg"));
        assert!(results[0]["message"]["text"]
            .as_str()
            .unwrap()
            .contains("Security compromise"));
    }
}
