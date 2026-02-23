// SPDX-License-Identifier: MIT

//! SARIF (Static Analysis Results Interchange Format) report generation for pysentry
//!
//! This module implements comprehensive SARIF 2.1.0 compliant output for security
//! vulnerability reports, optimized for GitHub Security and GitLab Security integration.

use crate::maintenance::{MaintenanceIssue, MaintenanceIssueType};
use crate::parsers::DependencyStats;
use crate::types::PackageName;
use crate::vulnerability::database::{Severity, Vulnerability, VulnerabilityMatch};
use crate::vulnerability::matcher::DatabaseStats;
use crate::{AuditError, Result};
use chrono::{DateTime, SecondsFormat, Utc};
use serde_json::{json, Value};
use serde_sarif::sarif::{
    ArtifactLocation as SarifArtifactLocation, Invocation as SarifInvocation,
    Location as SarifLocation, LogicalLocation as SarifLogicalLocation, Message as SarifMessage,
    MultiformatMessageString, PhysicalLocation as SarifPhysicalLocation, PropertyBag,
    Region as SarifRegion, ReportingConfiguration, ReportingDescriptor, Result as SarifResult,
    ResultLevel, Run as SarifRun, Sarif, Tool as SarifTool, ToolComponent as SarifToolComponent,
};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::{Path, PathBuf};
use tracing::{debug, info};

/// Generator for SARIF 2.1.0 compliant security reports
pub struct SarifGenerator {
    /// Project root directory for relative path resolution
    project_root: PathBuf,
    /// Cache for parsed file locations
    location_cache: HashMap<String, Vec<LocationInfo>>,
    /// Rules (vulnerability definitions) generated for this report
    rules: Vec<ReportingDescriptor>,
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
    pub fn generate_report(&mut self, report: &super::model::AuditReport) -> Result<String> {
        let start_time = Utc::now();

        info!(
            "Generating SARIF 2.1.0 report with {} vulnerabilities and {} maintenance issues",
            report.matches.len(),
            report.maintenance_issues.len()
        );

        self.preprocess_locations(&report.matches);
        self.generate_rules(&report.matches);
        self.generate_maintenance_rules(&report.maintenance_issues);

        let mut results = self.create_sarif_results(&report.matches);
        results.extend(self.create_maintenance_results(&report.maintenance_issues));

        let sarif = self.build_sarif_document(
            results,
            &report.dependency_stats,
            &report.database_stats,
            &report.warnings,
            start_time,
        )?;

        let json_output = serde_json::to_string_pretty(&sarif).map_err(AuditError::Json)?;

        info!("SARIF report generated successfully");
        Ok(json_output)
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

        if let Ok(locations) = self.parse_pyproject_locations(&packages_to_locate) {
            for (package, locs) in locations {
                self.location_cache
                    .insert(format!("pyproject.toml:{package}"), locs);
            }
        }

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

        let mut in_dependencies = false;
        let mut current_section = None;

        for (line_idx, line) in lines.iter().enumerate() {
            let line_num = u32::try_from(line_idx + 1).unwrap_or(0);
            let trimmed = line.trim();

            if trimmed.starts_with('[') && trimmed.ends_with(']') {
                in_dependencies = false;

                if trimmed == "[project]" {
                    current_section = Some(trimmed.to_string());
                    continue;
                }

                current_section = Some(trimmed.to_string());
                continue;
            }

            if current_section.as_deref() == Some("[project]") && trimmed == "dependencies = [" {
                in_dependencies = true;
                continue;
            }

            if in_dependencies && trimmed == "]" {
                in_dependencies = false;
                continue;
            }

            if in_dependencies && !trimmed.is_empty() && !trimmed.starts_with('#') {
                for package in packages {
                    let package_str = package.to_string();

                    if trimmed.contains(&package_str) {
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

        for (line_idx, line) in lines.iter().enumerate() {
            let line_num = u32::try_from(line_idx + 1).unwrap_or(0);
            let trimmed = line.trim();

            if let Some(name_start) = trimmed.find("name = \"") {
                if let Some(name_end) = trimmed[name_start + 8..].find('"') {
                    let package_name_str = &trimmed[name_start + 8..name_start + 8 + name_end];

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

            // Use actual CVSS score for GitHub security-severity when available
            let security_severity = match m.vulnerability.cvss_score {
                Some(cvss) => format!("{cvss:.1}"),
                None => Self::get_security_severity_score(m.vulnerability.severity).to_string(),
            };

            let severity_str = Self::severity_str(m.vulnerability.severity);

            // Build tags: base tags + CVE aliases in external/cve/ format (CodeQL convention)
            let mut tags: Vec<String> = vec![
                "security".to_string(),
                "vulnerability".to_string(),
                severity_str.clone(),
            ];
            for alias in &m.vulnerability.aliases {
                if alias.starts_with("CVE-") {
                    tags.push(format!("external/cve/{}", alias.to_lowercase()));
                }
            }
            if m.vulnerability.withdrawn.is_some() {
                tags.push("withdrawn".to_string());
            }

            let mut additional_properties: BTreeMap<String, Value> = BTreeMap::new();
            additional_properties.insert(
                "security-severity".to_string(),
                Value::String(security_severity),
            );
            additional_properties.insert(
                "vulnerability_id".to_string(),
                Value::String(rule_id.clone()),
            );
            additional_properties.insert("severity".to_string(), Value::String(severity_str));
            // exact version matching = very-high confidence
            additional_properties.insert(
                "precision".to_string(),
                Value::String("very-high".to_string()),
            );

            if let Some(cvss) = m.vulnerability.cvss_score {
                additional_properties.insert(
                    "cvss_score".to_string(),
                    json!((f64::from(cvss) * 10.0).round() / 10.0),
                );
            }
            if let Some(cvss_version) = m.vulnerability.cvss_version {
                additional_properties.insert("cvss_version".to_string(), json!(cvss_version));
            }
            if let Some(source) = &m.vulnerability.source {
                additional_properties.insert("source".to_string(), Value::String(source.clone()));
            }
            if let Some(withdrawn_date) = &m.vulnerability.withdrawn {
                additional_properties.insert(
                    "withdrawn".to_string(),
                    Value::String(withdrawn_date.to_rfc3339_opts(SecondsFormat::Secs, true)),
                );
            }
            if let Some(published) = &m.vulnerability.published {
                additional_properties.insert(
                    "published_date".to_string(),
                    Value::String(published.to_rfc3339_opts(SecondsFormat::Secs, true)),
                );
            }
            if let Some(modified) = &m.vulnerability.modified {
                additional_properties.insert(
                    "modified_date".to_string(),
                    Value::String(modified.to_rfc3339_opts(SecondsFormat::Secs, true)),
                );
            }
            if !m.vulnerability.aliases.is_empty() {
                additional_properties
                    .insert("aliases".to_string(), json!(&m.vulnerability.aliases));
            }

            let properties = PropertyBag::builder()
                .tags(tags)
                .additional_properties(additional_properties)
                .build();

            let plain_help = Self::create_help_text_plain(&m.vulnerability);
            let markdown_help = Self::create_help_text_markdown(&m.vulnerability);
            let help = MultiformatMessageString::builder()
                .text(plain_help)
                .markdown(markdown_help)
                .build();

            let default_config = ReportingConfiguration::builder()
                .level(json!(Self::severity_to_sarif_level(
                    m.vulnerability.severity
                )))
                .build();

            let mut rule = ReportingDescriptor::builder()
                .id(rule_id.clone())
                .name(format!("Security vulnerability {rule_id}"))
                .short_description(
                    MultiformatMessageString::builder()
                        .text(m.vulnerability.summary.clone())
                        .build(),
                )
                .default_configuration(default_config)
                .help(help)
                .properties(properties)
                .build();

            rule.full_description = m.vulnerability.description.as_ref().map(|desc| {
                let truncated = if desc.chars().count() > 1024 {
                    let mut text: String = desc.chars().take(1021).collect();
                    text.push_str("...");
                    text
                } else {
                    desc.clone()
                };
                MultiformatMessageString::builder().text(truncated).build()
            });
            rule.help_uri = Self::extract_primary_reference(&m.vulnerability.references);

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

            let (level_str, severity_score, description) = match issue.issue_type {
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

            let issue_type_lower = issue.issue_type.to_string().to_lowercase();

            let plain_help = format!(
                "This package has been marked as {} per PEP 792 Project Status Markers. {}",
                issue_type_lower, description
            );
            let markdown_help = format!(
                "## PEP 792: {} Package\n\n{}\n\nSee [PEP 792](https://peps.python.org/pep-0792/) for more information.",
                issue.issue_type, description
            );

            let help = MultiformatMessageString::builder()
                .text(plain_help)
                .markdown(markdown_help)
                .build();

            let mut additional_properties: BTreeMap<String, Value> = BTreeMap::new();
            additional_properties.insert(
                "security-severity".to_string(),
                Value::String(severity_score.to_string()),
            );
            additional_properties.insert(
                "maintenance_status".to_string(),
                Value::String(issue_type_lower.clone()),
            );

            let properties = PropertyBag::builder()
                .tags(vec![
                    "maintenance".to_string(),
                    "pep792".to_string(),
                    issue_type_lower.clone(),
                ])
                .additional_properties(additional_properties)
                .build();

            let default_config = ReportingConfiguration::builder()
                .level(json!(level_str))
                .build();

            let rule = ReportingDescriptor::builder()
                .id(rule_id)
                .name(format!("PEP 792 {} Package", issue.issue_type))
                .short_description(
                    MultiformatMessageString::builder()
                        .text(format!("Package is {}", issue_type_lower))
                        .build(),
                )
                .full_description(
                    MultiformatMessageString::builder()
                        .text(description.to_string())
                        .build(),
                )
                .help(help)
                .help_uri("https://peps.python.org/pep-0792/".to_string())
                .default_configuration(default_config)
                .properties(properties)
                .build();

            self.rules.push(rule);
        }

        debug!("Generated {} maintenance rules (PEP 792)", seen_types.len());
    }

    /// Get the SARIF rule ID for a maintenance issue type
    fn maintenance_rule_id(issue_type: &MaintenanceIssueType) -> String {
        format!("PEP792-{}", issue_type.to_string().to_uppercase())
    }

    /// Create SARIF results for maintenance issues
    fn create_maintenance_results(&self, issues: &[MaintenanceIssue]) -> Vec<SarifResult> {
        let mut results = Vec::new();

        for issue in issues {
            let rule_id = Self::maintenance_rule_id(&issue.issue_type);

            let level = match issue.issue_type {
                MaintenanceIssueType::Quarantined => ResultLevel::Error,
                MaintenanceIssueType::Deprecated => ResultLevel::Warning,
                MaintenanceIssueType::Archived => ResultLevel::Note,
            };

            let message_text = if let Some(reason) = &issue.reason {
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

            let file_path = issue.source_file.as_deref().unwrap_or(if issue.is_direct {
                "pyproject.toml"
            } else {
                "uv.lock"
            });

            let physical_location = SarifPhysicalLocation::builder()
                .artifact_location(Self::artifact_location(file_path))
                .build();

            let logical_location = SarifLogicalLocation::builder()
                .name(issue.package_name.to_string())
                .kind("package".to_string())
                .build();

            let location = SarifLocation::builder()
                .physical_location(physical_location)
                .logical_locations(vec![logical_location])
                .build();

            // Fingerprint for stable cross-scan deduplication
            let fingerprint_input = format!(
                "{}:{}:{}",
                rule_id, issue.package_name, issue.installed_version
            );
            let hash = format!("{:x}", Sha256::digest(fingerprint_input.as_bytes()));
            let mut fingerprints: BTreeMap<String, String> = BTreeMap::new();
            fingerprints.insert("pysentry/maintenance/v1".to_string(), hash);

            let mut additional_properties: BTreeMap<String, Value> = BTreeMap::new();
            additional_properties.insert(
                "package_name".to_string(),
                Value::String(issue.package_name.to_string()),
            );
            additional_properties.insert(
                "installed_version".to_string(),
                Value::String(issue.installed_version.to_string()),
            );
            additional_properties.insert(
                "is_direct_dependency".to_string(),
                Value::Bool(issue.is_direct),
            );
            additional_properties.insert(
                "dependency_type".to_string(),
                Value::String(dep_type.to_string()),
            );
            additional_properties.insert(
                "maintenance_status".to_string(),
                Value::String(issue.issue_type.to_string().to_lowercase()),
            );
            if let Some(reason) = &issue.reason {
                additional_properties.insert("reason".to_string(), Value::String(reason.clone()));
            }

            let properties = PropertyBag::builder()
                .additional_properties(additional_properties)
                .build();

            let mut result = SarifResult::builder()
                .rule_id(rule_id.clone())
                .message(SarifMessage::builder().text(message_text).build())
                .level(level)
                .locations(vec![location])
                .partial_fingerprints(fingerprints)
                .properties(properties)
                .build();

            if let Some(idx) = self.find_rule_index(&rule_id) {
                result.rule_index = Some(idx);
            }

            results.push(result);
        }

        debug!("Created {} maintenance SARIF results", results.len());
        results
    }

    /// Create plain text help for a vulnerability (no markdown formatting)
    fn create_help_text_plain(vulnerability: &Vulnerability) -> String {
        use std::fmt::Write;
        let mut help_text = format!("{}\n\n", vulnerability.summary);

        if let Some(description) = &vulnerability.description {
            write!(help_text, "Description: {description}\n\n").unwrap();
        }

        if let Some(cvss) = vulnerability.cvss_score {
            let version_tag = vulnerability
                .cvss_version
                .map(|v| format!(" (CVSS v{v})"))
                .unwrap_or_default();
            write!(help_text, "CVSS Score: {cvss:.1}{version_tag}\n\n").unwrap();
        }

        if !vulnerability.fixed_versions.is_empty() {
            help_text.push_str("Fixed Versions:\n");
            for version in &vulnerability.fixed_versions {
                writeln!(help_text, "- {version}").unwrap();
            }
            help_text.push('\n');
        }

        if !vulnerability.references.is_empty() {
            help_text.push_str("References:\n");
            for reference in &vulnerability.references {
                writeln!(help_text, "- {reference}").unwrap();
            }
        }

        help_text
    }

    /// Create markdown-formatted help for a vulnerability
    fn create_help_text_markdown(vulnerability: &Vulnerability) -> String {
        use std::fmt::Write;
        let mut help_text = format!("## {}\n\n", vulnerability.summary);

        if let Some(description) = &vulnerability.description {
            write!(help_text, "**Description:** {description}\n\n").unwrap();
        }

        if let Some(cvss) = vulnerability.cvss_score {
            let version_tag = vulnerability
                .cvss_version
                .map(|v| format!(" (v{v})"))
                .unwrap_or_default();
            write!(help_text, "**CVSS Score:** `{cvss:.1}`{version_tag}\n\n").unwrap();
        }

        if !vulnerability.fixed_versions.is_empty() {
            help_text.push_str("**Fixed Versions:**\n");
            for version in &vulnerability.fixed_versions {
                writeln!(help_text, "- `{version}`").unwrap();
            }
            help_text.push('\n');
        }

        if !vulnerability.references.is_empty() {
            help_text.push_str("**References:**\n");
            for reference in &vulnerability.references {
                writeln!(help_text, "- [{reference}]({reference})").unwrap();
            }
        }

        help_text
    }

    /// Extract primary reference URL
    fn extract_primary_reference(references: &[String]) -> Option<String> {
        references
            .iter()
            .find(|r| r.contains("github.com/advisories/") || r.contains("cve.mitre.org"))
            .or_else(|| references.iter().find(|r| r.starts_with("https://")))
            .cloned()
    }

    /// Convert severity to SARIF level string (used for ReportingConfiguration.level which is Value)
    fn severity_to_sarif_level(severity: Severity) -> &'static str {
        match severity {
            Severity::Critical | Severity::High => "error",
            Severity::Medium | Severity::Unknown => "warning",
            Severity::Low => "note",
        }
    }

    /// Serialize a Severity value to its lowercase string representation
    fn severity_str(severity: Severity) -> String {
        serde_json::to_value(severity)
            .ok()
            .and_then(|v| v.as_str().map(str::to_string))
            .unwrap_or_else(|| "unknown".to_string())
    }

    /// Convert severity to typed ResultLevel enum (used for Result.level)
    fn severity_to_result_level(severity: Severity) -> ResultLevel {
        match severity {
            Severity::Critical | Severity::High => ResultLevel::Error,
            Severity::Medium | Severity::Unknown => ResultLevel::Warning,
            Severity::Low => ResultLevel::Note,
        }
    }

    /// Get security severity score for GitHub integration (fallback when no CVSS score)
    fn get_security_severity_score(severity: Severity) -> &'static str {
        match severity {
            Severity::Critical => "10.0",
            Severity::High => "8.0",
            Severity::Medium => "5.0",
            Severity::Low => "2.0",
            Severity::Unknown => "5.0",
        }
    }

    /// Create SARIF results from vulnerability matches
    fn create_sarif_results(&self, matches: &[VulnerabilityMatch]) -> Vec<SarifResult> {
        let mut results = Vec::new();

        for m in matches {
            let message_text = format!(
                "Package '{}' version {} has vulnerability {}: {}",
                m.package_name, m.installed_version, m.vulnerability.id, m.vulnerability.summary
            );

            let locations = self.create_locations_for_match(m);

            // Fingerprint for stable alert identity across scans (prevents duplicate alerts)
            let fingerprint_input = format!(
                "{}:{}:{}",
                m.vulnerability.id, m.package_name, m.installed_version
            );
            let hash = format!("{:x}", Sha256::digest(fingerprint_input.as_bytes()));
            let mut fingerprints: BTreeMap<String, String> = BTreeMap::new();
            fingerprints.insert("pysentry/vuln/v1".to_string(), hash);

            let severity_str = Self::severity_str(m.vulnerability.severity);

            let mut additional_properties: BTreeMap<String, Value> = BTreeMap::new();
            additional_properties.insert(
                "package_name".to_string(),
                Value::String(m.package_name.to_string()),
            );
            additional_properties.insert(
                "installed_version".to_string(),
                Value::String(m.installed_version.to_string()),
            );
            additional_properties
                .insert("is_direct_dependency".to_string(), Value::Bool(m.is_direct));
            additional_properties.insert(
                "vulnerability_severity".to_string(),
                Value::String(severity_str),
            );

            if let Some(cvss) = m.vulnerability.cvss_score {
                additional_properties.insert(
                    "cvss_score".to_string(),
                    json!((f64::from(cvss) * 10.0).round() / 10.0),
                );
            }
            if let Some(cvss_version) = m.vulnerability.cvss_version {
                additional_properties.insert("cvss_version".to_string(), json!(cvss_version));
            }
            if let Some(source) = &m.vulnerability.source {
                additional_properties.insert("source".to_string(), Value::String(source.clone()));
            }
            if !m.vulnerability.fixed_versions.is_empty() {
                let fixed_versions: Vec<Value> = m
                    .vulnerability
                    .fixed_versions
                    .iter()
                    .map(|v| Value::String(v.to_string()))
                    .collect();
                additional_properties
                    .insert("fixed_versions".to_string(), Value::Array(fixed_versions));
            }

            let properties = PropertyBag::builder()
                .additional_properties(additional_properties)
                .build();

            let mut result = SarifResult::builder()
                .rule_id(m.vulnerability.id.clone())
                .message(SarifMessage::builder().text(message_text).build())
                .level(Self::severity_to_result_level(m.vulnerability.severity))
                .locations(locations)
                .partial_fingerprints(fingerprints)
                .properties(properties)
                .build();

            if let Some(idx) = self.find_rule_index(&m.vulnerability.id) {
                result.rule_index = Some(idx);
            }

            results.push(result);
        }

        debug!("Created {} SARIF results", results.len());
        results
    }

    /// Find rule index by ID (returns i64 to match SarifResult.rule_index type)
    fn find_rule_index(&self, rule_id: &str) -> Option<i64> {
        self.rules
            .iter()
            .position(|r| r.id == rule_id)
            .and_then(|idx| i64::try_from(idx).ok())
    }

    /// Build an artifact location with %SRCROOT% base for portable path resolution
    fn artifact_location(uri: &str) -> SarifArtifactLocation {
        SarifArtifactLocation::builder()
            .uri(uri.to_string())
            .uri_base_id("%SRCROOT%".to_string())
            .build()
    }

    /// Create locations for a vulnerability match
    fn create_locations_for_match(&self, m: &VulnerabilityMatch) -> Vec<SarifLocation> {
        let mut locations = Vec::new();
        let package_name = &m.package_name;

        if let Some(pyproject_locations) = self
            .location_cache
            .get(&format!("pyproject.toml:{package_name}"))
        {
            for loc_info in pyproject_locations {
                locations.push(Self::create_location_from_info(loc_info, m));
            }
        }

        if let Some(lock_locations) = self.location_cache.get(&format!("uv.lock:{package_name}")) {
            for loc_info in lock_locations {
                locations.push(Self::create_location_from_info(loc_info, m));
            }
        }

        if locations.is_empty() {
            let file_path = if m.is_direct {
                "pyproject.toml"
            } else {
                "uv.lock"
            };

            let physical_location = SarifPhysicalLocation::builder()
                .artifact_location(Self::artifact_location(file_path))
                .build();

            let logical_location = SarifLogicalLocation::builder()
                .name(package_name.to_string())
                .kind("package".to_string())
                .build();

            locations.push(
                SarifLocation::builder()
                    .physical_location(physical_location)
                    .logical_locations(vec![logical_location])
                    .build(),
            );
        }

        locations
    }

    /// Create location from location info
    fn create_location_from_info(loc_info: &LocationInfo, m: &VulnerabilityMatch) -> SarifLocation {
        let physical_location = if let (Some(line), Some(column)) = (loc_info.line, loc_info.column)
        {
            let end_column = column + u32::try_from(m.package_name.to_string().len()).unwrap_or(0);
            let region = SarifRegion::builder()
                .start_line(i64::from(line))
                .start_column(i64::from(column))
                .end_line(i64::from(line))
                .end_column(i64::from(end_column))
                .build();
            SarifPhysicalLocation::builder()
                .artifact_location(Self::artifact_location(&loc_info.file_path))
                .region(region)
                .build()
        } else {
            SarifPhysicalLocation::builder()
                .artifact_location(Self::artifact_location(&loc_info.file_path))
                .build()
        };

        let logical_location = SarifLogicalLocation::builder()
            .name(m.package_name.to_string())
            .kind("package".to_string())
            .build();

        let mut location = SarifLocation::builder()
            .physical_location(physical_location)
            .logical_locations(vec![logical_location])
            .build();

        if let Some(context) = &loc_info.context {
            location.message = Some(SarifMessage::builder().text(context.clone()).build());
        }

        location
    }

    /// Build complete SARIF document
    fn build_sarif_document(
        &mut self,
        results: Vec<SarifResult>,
        dependency_stats: &DependencyStats,
        database_stats: &DatabaseStats,
        warnings: &[String],
        start_time: DateTime<Utc>,
    ) -> Result<Sarif> {

        // originalUriBaseIds enables portable path resolution across CI environments.
        // SARIF Errata 01 §3.14.14 requires a file:// URI with trailing slash here.
        let project_root_uri = format!("file://{}/", self.project_root.to_string_lossy());
        let mut uri_bases: BTreeMap<String, SarifArtifactLocation> = BTreeMap::new();
        uri_bases.insert(
            "%SRCROOT%".to_string(),
            SarifArtifactLocation::builder()
                .uri(project_root_uri)
                .build(),
        );

        let end_time = Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true);
        let mut invocation = SarifInvocation::builder()
            .execution_successful(true)
            .command_line("pysentry".to_string())
            .start_time_utc(start_time.to_rfc3339_opts(SecondsFormat::Secs, true))
            .exit_code(i64::from(!results.is_empty()))
            .build();
        invocation.end_time_utc = Some(end_time);

        let mut scan_stats: BTreeMap<String, Value> = BTreeMap::new();
        scan_stats.insert(
            "total_packages".to_string(),
            json!(dependency_stats.total_packages),
        );
        scan_stats.insert(
            "direct_packages".to_string(),
            json!(dependency_stats.direct_packages),
        );
        scan_stats.insert(
            "transitive_packages".to_string(),
            json!(dependency_stats.transitive_packages),
        );
        scan_stats.insert(
            "database_vulnerabilities".to_string(),
            json!(database_stats.total_vulnerabilities),
        );
        scan_stats.insert(
            "database_packages".to_string(),
            json!(database_stats.total_packages),
        );

        let mut driver_additional: BTreeMap<String, Value> = BTreeMap::new();
        driver_additional.insert("scan_stats".to_string(), json!(scan_stats));

        let driver_properties = PropertyBag::builder()
            .additional_properties(driver_additional)
            .build();

        let driver = SarifToolComponent::builder()
            .name("pysentry".to_string())
            .version(env!("CARGO_PKG_VERSION").to_string())
            .information_uri("https://github.com/nyudenkov/pysentry".to_string())
            .semantic_version(env!("CARGO_PKG_VERSION").to_string())
            .short_description(
                MultiformatMessageString::builder()
                    .text("Security vulnerability scanner for Python dependencies".to_string())
                    .build(),
            )
            .full_description(
                MultiformatMessageString::builder()
                    .text("pysentry scans Python project dependencies for known security vulnerabilities using various databases (PyPA, PyPI, OSV)".to_string())
                    .build(),
            )
            .rules(std::mem::take(&mut self.rules))
            .properties(driver_properties)
            .build();

        let tool = SarifTool::builder().driver(driver).build();

        let mut run_additional: BTreeMap<String, Value> = BTreeMap::new();
        run_additional.insert(
            "project_root".to_string(),
            Value::String(self.project_root.to_string_lossy().into_owned()),
        );
        run_additional.insert("warnings".to_string(), json!(warnings));

        let run_properties = PropertyBag::builder()
            .additional_properties(run_additional)
            .build();

        let run = SarifRun::builder()
            .tool(tool)
            .results(results)
            .invocations(vec![invocation])
            .original_uri_base_ids(uri_bases)
            .properties(run_properties)
            .build();

        let sarif = Sarif::builder()
            .version(json!("2.1.0"))
            .schema("https://json.schemastore.org/sarif-2.1.0.json".to_string())
            .runs(vec![run])
            .build();

        Ok(sarif)
    }
}

use super::model::AuditReport;

pub(crate) fn generate_sarif_report(
    report: &AuditReport,
    project_root: Option<&Path>,
) -> std::result::Result<String, Box<dyn std::error::Error>> {
    let root = project_root.unwrap_or_else(|| Path::new("."));
    let mut generator = SarifGenerator::new(root);
    Ok(generator.generate_report(report)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::output::model::test_helpers::create_test_report;
    use crate::types::Version;
    use crate::vulnerability::database::Vulnerability;
    use std::str::FromStr;
    use tempfile::TempDir;

    #[test]
    fn test_generate_sarif_report() {
        let report = create_test_report();
        let output = generate_sarif_report(&report, Some(std::path::Path::new("."))).unwrap();
        let sarif: serde_json::Value = serde_json::from_str(&output).unwrap();
        assert_eq!(sarif["version"], "2.1.0");
        assert_eq!(sarif["runs"][0]["tool"]["driver"]["name"], "pysentry");
        assert_eq!(sarif["runs"][0]["results"][0]["ruleId"], "GHSA-test-1234");
    }

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
            cvss_version: None,
            published: None,
            modified: None,
            source: Some("test".to_string()),
            withdrawn: None,
            aliases: vec![],
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
        assert_eq!(
            SarifGenerator::severity_to_sarif_level(Severity::Unknown),
            "warning"
        );
    }

    #[test]
    fn test_severity_to_result_level() {
        assert!(matches!(
            SarifGenerator::severity_to_result_level(Severity::Critical),
            ResultLevel::Error
        ));
        assert!(matches!(
            SarifGenerator::severity_to_result_level(Severity::High),
            ResultLevel::Error
        ));
        assert!(matches!(
            SarifGenerator::severity_to_result_level(Severity::Medium),
            ResultLevel::Warning
        ));
        assert!(matches!(
            SarifGenerator::severity_to_result_level(Severity::Low),
            ResultLevel::Note
        ));
        assert!(matches!(
            SarifGenerator::severity_to_result_level(Severity::Unknown),
            ResultLevel::Warning
        ));
    }

    #[test]
    fn test_security_severity_score() {
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
        assert_eq!(
            SarifGenerator::get_security_severity_score(Severity::Unknown),
            "5.0"
        );
    }

    #[test]
    fn test_actual_cvss_in_security_severity() {
        let temp_dir = TempDir::new().unwrap();
        let mut generator = SarifGenerator::new(temp_dir.path());

        let mut vuln = create_test_vulnerability();
        vuln.cvss_score = Some(8.5);
        let test_match = VulnerabilityMatch {
            package_name: PackageName::from_str("test-package").unwrap(),
            installed_version: Version::from_str("1.5.0").unwrap(),
            vulnerability: vuln,
            is_direct: true,
        };

        generator.generate_rules(&[test_match]);

        let rule = &generator.rules[0];
        let security_severity = rule
            .properties
            .as_ref()
            .and_then(|p| p.additional_properties.get("security-severity"))
            .and_then(|v| v.as_str())
            .unwrap_or("");
        assert_eq!(
            security_severity, "8.5",
            "Should use actual CVSS score, not generic bucket value"
        );
    }

    #[test]
    fn test_rule_generation() {
        let temp_dir = TempDir::new().unwrap();
        let mut generator = SarifGenerator::new(temp_dir.path());

        let matches = vec![create_test_match()];
        generator.generate_rules(&matches);

        assert_eq!(generator.rules.len(), 1);
        assert_eq!(generator.rules[0].id, "GHSA-test-1234");
        assert!(generator.rules[0].short_description.is_some());
        assert!(generator.rules[0].help.is_some());
    }

    #[test]
    fn test_extract_primary_reference() {
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
        let report = create_test_report();
        let temp_dir = TempDir::new().unwrap();
        let mut generator = SarifGenerator::new(temp_dir.path());
        let sarif_json = generator.generate_report(&report).unwrap();

        let sarif: serde_json::Value = serde_json::from_str(&sarif_json).unwrap();

        assert_eq!(sarif["version"], "2.1.0");
        assert!(sarif["runs"].is_array());
        assert_eq!(sarif["runs"][0]["tool"]["driver"]["name"], "pysentry");
        assert!(sarif["runs"][0]["results"].is_array());
        assert_eq!(sarif["runs"][0]["results"][0]["ruleId"], "GHSA-test-1234");
    }

    #[test]
    fn test_partial_fingerprints_present() {
        let report = create_test_report();
        let temp_dir = TempDir::new().unwrap();
        let mut generator = SarifGenerator::new(temp_dir.path());
        let sarif_json = generator.generate_report(&report).unwrap();

        let sarif: serde_json::Value = serde_json::from_str(&sarif_json).unwrap();
        let results = &sarif["runs"][0]["results"];
        assert!(results.is_array());
        if let Some(first_result) = results.as_array().and_then(|r| r.first()) {
            assert!(
                first_result["partialFingerprints"].is_object(),
                "Results should have partialFingerprints"
            );
        }
    }

    #[test]
    fn test_help_text_vs_markdown_differ() {
        let vuln = create_test_vulnerability();
        let plain = SarifGenerator::create_help_text_plain(&vuln);
        let markdown = SarifGenerator::create_help_text_markdown(&vuln);

        assert!(
            !plain.contains("**"),
            "Plain text should not contain bold markers"
        );
        assert!(
            !plain.contains("##"),
            "Plain text should not contain headers"
        );
        assert!(markdown.contains("##"), "Markdown should contain headers");
        assert!(
            markdown.contains("**"),
            "Markdown should contain bold markers"
        );
    }

    #[test]
    fn test_original_uri_base_ids() {
        let report = create_test_report();
        let temp_dir = TempDir::new().unwrap();
        let mut generator = SarifGenerator::new(temp_dir.path());
        let sarif_json = generator.generate_report(&report).unwrap();

        let sarif: serde_json::Value = serde_json::from_str(&sarif_json).unwrap();
        assert!(
            sarif["runs"][0]["originalUriBaseIds"].is_object(),
            "Run should have originalUriBaseIds"
        );
        assert!(
            sarif["runs"][0]["originalUriBaseIds"]["%SRCROOT%"].is_object(),
            "Should have %SRCROOT% base ID entry"
        );
    }

    #[test]
    fn test_location_parsing_with_pyproject() {
        let temp_dir = TempDir::new().unwrap();
        let pyproject_path = temp_dir.path().join("pyproject.toml");

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

        generator.generate_maintenance_rules(&issues);

        assert_eq!(generator.rules.len(), 3);

        let archived_idx = generator.find_rule_index("PEP792-ARCHIVED");
        let deprecated_idx = generator.find_rule_index("PEP792-DEPRECATED");
        let quarantined_idx = generator.find_rule_index("PEP792-QUARANTINED");

        assert!(archived_idx.is_some(), "Should find ARCHIVED rule");
        assert!(deprecated_idx.is_some(), "Should find DEPRECATED rule");
        assert!(quarantined_idx.is_some(), "Should find QUARANTINED rule");

        let indices: std::collections::HashSet<_> = [archived_idx, deprecated_idx, quarantined_idx]
            .into_iter()
            .flatten()
            .collect();
        assert_eq!(indices.len(), 3, "All indices should be unique");

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

        generator.generate_maintenance_rules(&issues);
        let results = generator.create_maintenance_results(&issues);

        assert_eq!(results.len(), 1);
        assert_eq!(results[0].rule_id.as_deref(), Some("PEP792-QUARANTINED"));
        assert!(matches!(results[0].level, Some(ResultLevel::Error)));
        let msg_text = results[0].message.text.as_deref().unwrap_or("");
        assert!(msg_text.contains("bad-pkg"));
        assert!(msg_text.contains("Security compromise"));
    }

    #[test]
    fn test_no_fixes_in_sarif_results() {
        let report = create_test_report();
        let temp_dir = TempDir::new().unwrap();
        let mut generator = SarifGenerator::new(temp_dir.path());
        let sarif_json = generator.generate_report(&report).unwrap();

        let sarif: serde_json::Value = serde_json::from_str(&sarif_json).unwrap();
        let results = sarif["runs"][0]["results"].as_array().unwrap();
        for result in results {
            assert!(
                result.get("fixes").is_none(),
                "No result should have a 'fixes' key (schema violation: empty artifactChanges)"
            );
        }
    }

    #[test]
    fn test_srcroot_uri_format() {
        let report = create_test_report();
        let temp_dir = TempDir::new().unwrap();
        let mut generator = SarifGenerator::new(temp_dir.path());
        let sarif_json = generator.generate_report(&report).unwrap();

        let sarif: serde_json::Value = serde_json::from_str(&sarif_json).unwrap();
        let srcroot_uri = sarif["runs"][0]["originalUriBaseIds"]["%SRCROOT%"]["uri"]
            .as_str()
            .expect("%SRCROOT% uri must be a string");

        assert!(
            srcroot_uri.starts_with("file:///"),
            "originalUriBaseIds %SRCROOT% must use file:// scheme, got: {srcroot_uri}"
        );
        assert!(
            srcroot_uri.ends_with('/'),
            "originalUriBaseIds %SRCROOT% must end with trailing slash (SARIF Errata 01), got: {srcroot_uri}"
        );
    }

    #[test]
    fn test_cvss_score_precision() {
        let temp_dir = TempDir::new().unwrap();
        let mut generator = SarifGenerator::new(temp_dir.path());

        // 9.3 is a classic f32 precision victim: 9.300000190734863
        let mut vuln = create_test_vulnerability();
        vuln.cvss_score = Some(9.3_f32);
        let test_match = VulnerabilityMatch {
            package_name: PackageName::from_str("test-package").unwrap(),
            installed_version: Version::from_str("1.5.0").unwrap(),
            vulnerability: vuln,
            is_direct: true,
        };

        generator.generate_rules(std::slice::from_ref(&test_match));
        let results = generator.create_sarif_results(std::slice::from_ref(&test_match));

        let rule_cvss = generator.rules[0]
            .properties
            .as_ref()
            .and_then(|p| p.additional_properties.get("cvss_score"))
            .expect("rule should have cvss_score");
        let rule_cvss_str = rule_cvss.to_string();
        assert!(
            !rule_cvss_str.contains("00000"),
            "Rule cvss_score must not have f32 precision artifacts, got: {rule_cvss_str}"
        );

        let result_cvss = results[0]
            .properties
            .as_ref()
            .and_then(|p| p.additional_properties.get("cvss_score"))
            .expect("result should have cvss_score");
        let result_cvss_str = result_cvss.to_string();
        assert!(
            !result_cvss_str.contains("00000"),
            "Result cvss_score must not have f32 precision artifacts, got: {result_cvss_str}"
        );
    }

    #[test]
    fn test_timestamp_format() {
        let report = create_test_report();
        let temp_dir = TempDir::new().unwrap();
        let mut generator = SarifGenerator::new(temp_dir.path());
        let sarif_json = generator.generate_report(&report).unwrap();

        let sarif: serde_json::Value = serde_json::from_str(&sarif_json).unwrap();
        let invocation = &sarif["runs"][0]["invocations"][0];

        let start = invocation["startTimeUtc"]
            .as_str()
            .expect("startTimeUtc must be present");
        assert!(
            start.ends_with('Z'),
            "startTimeUtc must end with 'Z', got: {start}"
        );
        assert!(
            !start.contains('.'),
            "startTimeUtc must not contain sub-second precision, got: {start}"
        );

        assert!(
            invocation.get("endTimeUtc").is_some(),
            "endTimeUtc must be present in invocation"
        );
        let end = invocation["endTimeUtc"]
            .as_str()
            .expect("endTimeUtc must be a string");
        assert!(
            end.ends_with('Z'),
            "endTimeUtc must end with 'Z', got: {end}"
        );
    }
}
