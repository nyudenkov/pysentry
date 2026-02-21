// SPDX-License-Identifier: MIT

use super::sarif::SarifGenerator;
use super::styles::{maintenance_icon, severity_icon, OutputStyles};
use crate::maintenance::{MaintenanceCheckConfig, MaintenanceIssue, MaintenanceSummary};
use crate::parsers::DependencyStats;
use crate::types::AuditFormat;
use crate::vulnerability::database::{Severity, VulnerabilityMatch};
use crate::vulnerability::matcher::{DatabaseStats, FixAnalysis};
use chrono::{DateTime, Utc};
use owo_colors::OwoColorize;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};
use std::fmt::Write;
use std::path::Path;

/// Controls how much detail is included in the human-readable report
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DetailLevel {
    /// Summary + one-liner per vulnerability, no descriptions
    Compact,
    /// Standard output (default)
    Normal,
    /// Full vulnerability descriptions
    Detailed,
}

/// A complete audit report containing all findings
#[derive(Debug, Clone)]
pub struct AuditReport {
    /// Timestamp when the audit was performed
    pub scan_time: DateTime<Utc>,
    /// Statistics about dependencies scanned
    pub dependency_stats: DependencyStats,
    /// Statistics about the vulnerability database
    pub database_stats: DatabaseStats,
    /// All vulnerability matches found
    pub matches: Vec<VulnerabilityMatch>,
    /// Analysis of available fixes
    pub fix_analysis: FixAnalysis,
    /// Warnings generated during the audit
    pub warnings: Vec<String>,
    /// PEP 792 maintenance issues (archived, deprecated, quarantined packages)
    pub maintenance_issues: Vec<MaintenanceIssue>,
}

impl AuditReport {
    /// Create a new audit report
    pub fn new(
        dependency_stats: DependencyStats,
        database_stats: DatabaseStats,
        matches: Vec<VulnerabilityMatch>,
        fix_analysis: FixAnalysis,
        warnings: Vec<String>,
        maintenance_issues: Vec<MaintenanceIssue>,
    ) -> Self {
        Self {
            scan_time: Utc::now(),
            dependency_stats,
            database_stats,
            matches,
            fix_analysis,
            warnings,
            maintenance_issues,
        }
    }

    /// Check if there are any maintenance issues
    pub fn has_maintenance_issues(&self) -> bool {
        !self.maintenance_issues.is_empty()
    }

    /// Get maintenance summary
    pub fn maintenance_summary(&self) -> MaintenanceSummary {
        MaintenanceSummary::from_issues(&self.maintenance_issues)
    }

    /// Check if the audit should fail based on maintenance config
    pub fn should_fail_on_maintenance(&self, config: &MaintenanceCheckConfig) -> bool {
        self.maintenance_summary().should_fail(config)
    }

    /// Check if the audit found any vulnerabilities
    pub fn has_vulnerabilities(&self) -> bool {
        !self.matches.is_empty()
    }

    /// Get summary statistics
    pub fn summary(&self) -> AuditSummary {
        let mut severity_counts = BTreeMap::new();
        let mut package_counts = HashMap::new();

        for m in &self.matches {
            *severity_counts.entry(m.vulnerability.severity).or_insert(0) += 1;
            *package_counts.entry(m.package_name.clone()).or_insert(0) += 1;
        }

        AuditSummary {
            total_packages_scanned: self.dependency_stats.total_packages,
            vulnerable_packages: package_counts.len(),
            total_vulnerabilities: self.matches.len(),
            severity_counts,
            fixable_vulnerabilities: self.fix_analysis.fixable,
            unfixable_vulnerabilities: self.fix_analysis.unfixable,
        }
    }
}

/// Summary statistics for an audit
#[derive(Debug, Clone)]
pub struct AuditSummary {
    pub total_packages_scanned: usize,
    pub vulnerable_packages: usize,
    pub total_vulnerabilities: usize,
    pub severity_counts: BTreeMap<Severity, usize>,
    pub fixable_vulnerabilities: usize,
    pub unfixable_vulnerabilities: usize,
}

/// Report generator for different output formats
pub struct ReportGenerator;

impl ReportGenerator {
    /// Generate a report in the specified format
    pub fn generate(
        report: &AuditReport,
        format: AuditFormat,
        project_root: Option<&Path>,
        detail_level: DetailLevel,
        styles: &OutputStyles,
    ) -> Result<String, Box<dyn std::error::Error>> {
        match format {
            AuditFormat::Human => Self::generate_human_report(report, detail_level, styles),
            AuditFormat::Json => Self::generate_json_report(report),
            AuditFormat::Sarif => Self::generate_sarif_report(report, project_root),
            AuditFormat::Markdown => Self::generate_markdown_report(report),
        }
    }

    fn generate_human_report(
        report: &AuditReport,
        detail_level: DetailLevel,
        styles: &OutputStyles,
    ) -> Result<String, Box<dyn std::error::Error>> {
        let mut output = String::new();
        let summary = report.summary();
        let is_compact = detail_level == DetailLevel::Compact;
        let is_detailed = detail_level == DetailLevel::Detailed;

        if !is_compact {
            writeln!(output, "{}", "PYSENTRY SECURITY AUDIT".style(styles.header))?;
            writeln!(output, "=======================")?;
            writeln!(output)?;
        }

        writeln!(
            output,
            "{}: {} packages scanned • {} vulnerable • {} vulnerabilities found",
            "SUMMARY".style(styles.header),
            summary.total_packages_scanned,
            summary.vulnerable_packages,
            summary.total_vulnerabilities
        )?;
        writeln!(output)?;

        if !summary.severity_counts.is_empty() {
            write!(output, "{}: ", "SEVERITY".style(styles.header))?;
            let mut first = true;
            for severity in [
                Severity::Critical,
                Severity::High,
                Severity::Medium,
                Severity::Low,
                Severity::Unknown,
            ] {
                if let Some(count) = summary.severity_counts.get(&severity) {
                    if !first {
                        write!(output, "    ")?;
                    }
                    let text = format!("{count} {severity}");
                    write!(output, " {}", text.style(*styles.severity(&severity)))?;
                    first = false;
                }
            }
            writeln!(output)?;
            writeln!(output)?;
        }

        if report.fix_analysis.total_matches > 0 {
            if report.fix_analysis.fixable > 0 {
                writeln!(
                    output,
                    "{}: {} vulnerabilities can be fixed by upgrading packages",
                    "FIXABLE".style(styles.header),
                    report
                        .fix_analysis
                        .fixable
                        .to_string()
                        .style(styles.fix_suggestion)
                )?;
            }
            if report.fix_analysis.unfixable > 0 {
                writeln!(
                    output,
                    "{}: {} vulnerabilities cannot be fixed",
                    "UNFIXABLE".style(styles.header),
                    report.fix_analysis.unfixable
                )?;
            }
            writeln!(output)?;
        }

        if !report.warnings.is_empty() {
            writeln!(output, "{}", "WARNINGS".style(styles.header))?;
            for warning in &report.warnings {
                writeln!(output, "  {warning}")?;
            }
            writeln!(output)?;
        }

        if !report.matches.is_empty() {
            writeln!(output, "{}", "VULNERABILITIES".style(styles.header))?;

            if is_compact {
                writeln!(output)?;
                for m in &report.matches {
                    let withdrawn_tag = if m.vulnerability.withdrawn.is_some() {
                        format!(" {}", "(WITHDRAWN)".style(styles.withdrawn_tag))
                    } else {
                        String::new()
                    };
                    writeln!(
                        output,
                        "  {}{}  {} v{}  [{}]",
                        m.vulnerability.id.style(styles.vuln_id),
                        withdrawn_tag,
                        m.package_name.to_string().style(styles.package),
                        m.installed_version,
                        format!("{}", m.vulnerability.severity)
                            .style(*styles.severity(&m.vulnerability.severity)),
                    )?;
                }
                writeln!(output)?;
            } else {
                writeln!(output, "---------------")?;
                writeln!(output)?;

                for (i, m) in report.matches.iter().enumerate() {
                    let source_tag = if let Some(source) = &m.vulnerability.source {
                        format!(" [source: {source}]")
                    } else {
                        String::new()
                    };

                    let withdrawn_tag = if m.vulnerability.withdrawn.is_some() {
                        format!(" {}", "(WITHDRAWN)".style(styles.withdrawn_tag))
                    } else {
                        String::new()
                    };

                    writeln!(
                        output,
                        " {}. {}{}  {} v{}  [{}]{}",
                        i + 1,
                        m.vulnerability.id.style(styles.vuln_id),
                        withdrawn_tag,
                        m.package_name.to_string().style(styles.package),
                        m.installed_version,
                        format!("{}", m.vulnerability.severity)
                            .style(*styles.severity(&m.vulnerability.severity)),
                        source_tag
                    )?;

                    if is_detailed {
                        writeln!(output, "    {}", m.vulnerability.summary)?;
                        if let Some(description) = &m.vulnerability.description {
                            if description != &m.vulnerability.summary {
                                writeln!(output, "    {description}")?;
                            }
                        }
                    } else if !m.vulnerability.summary.is_empty() {
                        writeln!(output, "    {}", m.vulnerability.summary)?;
                    } else if let Some(description) = &m.vulnerability.description {
                        let truncated = description.chars().take(117).collect::<String>();
                        writeln!(output, "    {truncated}...")?;
                    }

                    if !m.vulnerability.fixed_versions.is_empty() {
                        let Some(fixed_version) = m.vulnerability.fixed_versions.first() else {
                            continue;
                        };
                        writeln!(
                            output,
                            "    {} {}",
                            "→ Fix:".style(styles.fix_arrow),
                            format!("Upgrade to {fixed_version}+").style(styles.fix_suggestion)
                        )?;
                    }
                    writeln!(output)?;
                }
            }
        } else {
            writeln!(
                output,
                "{} No vulnerabilities found!",
                "✓".style(styles.success_check)
            )?;
        }

        if !report.fix_analysis.fix_suggestions.is_empty() {
            let mut package_fixes: BTreeMap<String, Vec<String>> = BTreeMap::new();
            for suggestion in &report.fix_analysis.fix_suggestions {
                let package = suggestion.package_name.to_string();
                let version_info = format!(
                    "{} → {}",
                    suggestion.current_version, suggestion.suggested_version
                );
                package_fixes.entry(package).or_default().push(version_info);
            }

            if is_compact {
                writeln!(output)?;
                writeln!(output, "{}", "FIX SUGGESTIONS".style(styles.header))?;
            } else {
                writeln!(output, "{}", "FIX SUGGESTIONS".style(styles.header))?;
                writeln!(output, "---------------")?;
            }

            let indent = if is_compact { "  " } else { "" };

            for (package, fixes) in &package_fixes {
                if fixes.len() == 1 {
                    let Some(fix) = fixes.first() else {
                        continue;
                    };
                    writeln!(
                        output,
                        "{}{}: {}",
                        indent,
                        package.style(styles.package),
                        fix.style(styles.fix_suggestion)
                    )?;
                } else {
                    let Some(best_fix) = fixes.first() else {
                        continue;
                    };
                    writeln!(
                        output,
                        "{}{}: {} (fixes {} vulnerabilities)",
                        indent,
                        package.style(styles.package),
                        best_fix.style(styles.fix_suggestion),
                        fixes.len()
                    )?;
                }
            }

            if !is_compact {
                writeln!(output)?;
            }
        }

        // Maintenance issues section (PEP 792)
        if !report.maintenance_issues.is_empty() {
            if is_compact {
                writeln!(output)?;
                writeln!(output, "{}", "MAINTENANCE".style(styles.header))?;
                for issue in &report.maintenance_issues {
                    let status_text = issue.issue_type.to_string();
                    let status_tag = status_text.style(*styles.maintenance(&issue.issue_type));
                    writeln!(
                        output,
                        "  {}  {} v{}",
                        status_tag,
                        issue.package_name.to_string().style(styles.package),
                        issue.installed_version,
                    )?;
                }
            } else {
                writeln!(output)?;
                writeln!(
                    output,
                    "{}",
                    "MAINTENANCE ISSUES (PEP 792)".style(styles.header)
                )?;
                writeln!(output, "----------------------------")?;
                writeln!(output)?;

                let maint_summary = report.maintenance_summary();
                writeln!(
                    output,
                    "{}: {} issues found ({} archived, {} deprecated, {} quarantined)",
                    "SUMMARY".style(styles.header),
                    maint_summary.total_issues,
                    maint_summary.archived_count,
                    maint_summary.deprecated_count,
                    maint_summary.quarantined_count
                )?;
                writeln!(output)?;

                for (i, issue) in report.maintenance_issues.iter().enumerate() {
                    let status_text = issue.issue_type.to_string();
                    let status_tag = status_text.style(*styles.maintenance(&issue.issue_type));

                    let dep_type = if issue.is_direct {
                        "[direct]"
                    } else {
                        "[transitive]"
                    };

                    write!(
                        output,
                        " {}. {}  {} v{}  {}",
                        i + 1,
                        status_tag,
                        issue.package_name.to_string().style(styles.package),
                        issue.installed_version,
                        dep_type.style(styles.dimmed)
                    )?;

                    if let Some(reason) = &issue.reason {
                        writeln!(output, " - {}", reason)?;
                    } else {
                        writeln!(output)?;
                    }
                }
                writeln!(output)?;
            }
        }

        if is_compact {
            let has_findings = !report.matches.is_empty() || !report.maintenance_issues.is_empty();
            if has_findings {
                writeln!(output, "Run pysentry --detailed for full descriptions")?;
            }
        } else {
            // Clean footer
            writeln!(
                output,
                "Scan completed {}",
                report
                    .scan_time
                    .format("%Y-%m-%d %H:%M:%S UTC")
                    .to_string()
                    .style(styles.dimmed)
            )?;
        }

        Ok(output)
    }

    fn generate_markdown_report(
        report: &AuditReport,
    ) -> Result<String, Box<dyn std::error::Error>> {
        let mut output = String::new();
        let summary = report.summary();

        writeln!(output, "# 🛡️ pysentry report")?;
        writeln!(output)?;

        writeln!(output, "## 📊 Scan Summary")?;
        writeln!(output)?;
        writeln!(
            output,
            "- **Scanned:** {} packages",
            summary.total_packages_scanned
        )?;
        writeln!(
            output,
            "- **Vulnerable:** {} packages",
            summary.vulnerable_packages
        )?;
        writeln!(
            output,
            "- **Vulnerabilities:** {}",
            summary.total_vulnerabilities
        )?;
        writeln!(output)?;

        if !summary.severity_counts.is_empty() {
            writeln!(output, "## 🚨 Severity Breakdown")?;
            writeln!(output)?;
            for severity in [
                Severity::Critical,
                Severity::High,
                Severity::Medium,
                Severity::Low,
                Severity::Unknown,
            ] {
                if let Some(count) = summary.severity_counts.get(&severity) {
                    let icon = severity_icon(&severity);
                    writeln!(output, "- {icon} **{severity}:** {count}")?;
                }
            }
            writeln!(output)?;
        }

        if report.fix_analysis.total_matches > 0 {
            writeln!(output, "## 🔧 Fix Analysis")?;
            writeln!(output)?;
            writeln!(output, "- **Fixable:** {}", report.fix_analysis.fixable)?;
            writeln!(output, "- **Unfixable:** {}", report.fix_analysis.unfixable)?;
            writeln!(output)?;
        }

        if !report.warnings.is_empty() {
            writeln!(output, "## ⚠️ Warnings")?;
            writeln!(output)?;
            for warning in &report.warnings {
                writeln!(output, "- {warning}")?;
            }
            writeln!(output)?;
        }

        if !report.matches.is_empty() {
            writeln!(output, "## 🐛 Vulnerabilities Found")?;
            writeln!(output)?;

            for (i, m) in report.matches.iter().enumerate() {
                let icon = severity_icon(&m.vulnerability.severity);

                let source_tag = if let Some(source) = &m.vulnerability.source {
                    format!(" *[source: {source}]*")
                } else {
                    String::new()
                };

                let withdrawn_tag = if m.vulnerability.withdrawn.is_some() {
                    " ⚠️ **WITHDRAWN**"
                } else {
                    ""
                };

                writeln!(
                    output,
                    "### {}. {} `{}`{}{}",
                    i + 1,
                    icon,
                    m.vulnerability.id,
                    withdrawn_tag,
                    source_tag
                )?;
                writeln!(output)?;

                writeln!(
                    output,
                    "- **Package:** `{}` v`{}`",
                    m.package_name, m.installed_version
                )?;
                writeln!(output, "- **Severity:** {}", m.vulnerability.severity)?;

                if let Some(cvss) = m.vulnerability.cvss_score {
                    writeln!(output, "- **CVSS Score:** {cvss:.1}")?;
                }

                if let Some(withdrawn_date) = &m.vulnerability.withdrawn {
                    writeln!(
                        output,
                        "- **⚠️ Withdrawn:** {}",
                        withdrawn_date.format("%Y-%m-%d")
                    )?;
                }

                writeln!(output, "- **Summary:** {}", m.vulnerability.summary)?;

                if let Some(description) = &m.vulnerability.description {
                    writeln!(output, "- **Description:**")?;
                    writeln!(output, "~~~")?;
                    writeln!(output, "{description}")?;
                    writeln!(output, "~~~")?;
                }

                if !m.vulnerability.fixed_versions.is_empty() {
                    let fixed_versions = m
                        .vulnerability
                        .fixed_versions
                        .iter()
                        .map(|v| format!("`{v}`"))
                        .collect::<Vec<_>>()
                        .join(", ");
                    writeln!(output, "- **Fixed in:** {fixed_versions}")?;
                }

                if !m.vulnerability.references.is_empty() {
                    writeln!(output, "- **References:**")?;
                    for ref_url in &m.vulnerability.references {
                        if ref_url.starts_with("http") {
                            writeln!(output, "  - <{ref_url}>")?;
                        } else {
                            writeln!(output, "  - {ref_url}")?;
                        }
                    }
                }

                writeln!(output)?;
            }
        } else {
            writeln!(output, "## ✅ No vulnerabilities found!")?;
            writeln!(output)?;
        }

        // Maintenance issues section (PEP 792)
        if !report.maintenance_issues.is_empty() {
            writeln!(output, "## 🔧 Maintenance Issues (PEP 792)")?;
            writeln!(output)?;

            let maint_summary = report.maintenance_summary();
            writeln!(
                output,
                "**Summary:** {} issues found ({} archived, {} deprecated, {} quarantined)",
                maint_summary.total_issues,
                maint_summary.archived_count,
                maint_summary.deprecated_count,
                maint_summary.quarantined_count
            )?;
            writeln!(output)?;

            for (i, issue) in report.maintenance_issues.iter().enumerate() {
                let icon = maintenance_icon(&issue.issue_type);
                let status = issue.issue_type.to_string();

                let dep_type = if issue.is_direct {
                    "direct"
                } else {
                    "transitive"
                };

                writeln!(
                    output,
                    "### {}. {} **{}** `{}`",
                    i + 1,
                    icon,
                    status,
                    issue.package_name
                )?;
                writeln!(output)?;
                writeln!(
                    output,
                    "- **Package:** `{}` v`{}`",
                    issue.package_name, issue.installed_version
                )?;
                writeln!(output, "- **Type:** {}", dep_type)?;
                if let Some(reason) = &issue.reason {
                    writeln!(output, "- **Reason:** {}", reason)?;
                }
                writeln!(output)?;
            }
        }

        if !report.fix_analysis.fix_suggestions.is_empty() {
            writeln!(output, "## 💡 Fix Suggestions")?;
            writeln!(output)?;

            for suggestion in &report.fix_analysis.fix_suggestions {
                writeln!(output, "- {suggestion}")?;
            }
            writeln!(output)?;
        }

        writeln!(output, "---")?;
        writeln!(
            output,
            "*Scan completed at {}*",
            report.scan_time.format("%Y-%m-%d %H:%M:%S UTC")
        )?;

        Ok(output)
    }

    /// Generate a JSON report
    fn generate_json_report(report: &AuditReport) -> Result<String, Box<dyn std::error::Error>> {
        let summary = report.summary();

        let json_report = JsonReport {
            scan_time: report.scan_time.to_rfc3339().to_string(),
            total_packages: summary.total_packages_scanned,
            vulnerable_packages: summary.vulnerable_packages,
            total_vulnerabilities: summary.total_vulnerabilities,
            vulnerabilities: report
                .matches
                .iter()
                .map(|m| JsonVulnerability {
                    id: m.vulnerability.id.clone(),
                    package_name: m.package_name.to_string(),
                    installed_version: m.installed_version.to_string(),
                    severity: m.vulnerability.severity.as_str_lowercase().to_string(),
                    summary: m.vulnerability.summary.clone(),
                    description: m.vulnerability.description.clone(),
                    cvss_score: m.vulnerability.cvss_score,
                    fixed_versions: m
                        .vulnerability
                        .fixed_versions
                        .iter()
                        .map(ToString::to_string)
                        .collect(),
                    references: m.vulnerability.references.clone(),
                    is_direct: m.is_direct,
                    source: m.vulnerability.source.clone(),
                    withdrawn: m.vulnerability.withdrawn.map(|dt| dt.to_rfc3339()),
                })
                .collect(),
            fix_suggestions: report
                .fix_analysis
                .fix_suggestions
                .iter()
                .map(|s| JsonFixSuggestion {
                    package_name: s.package_name.to_string(),
                    current_version: s.current_version.to_string(),
                    suggested_version: s.suggested_version.to_string(),
                    vulnerability_id: s.vulnerability_id.clone(),
                })
                .collect(),
            warnings: report.warnings.clone(),
            maintenance_issues: report
                .maintenance_issues
                .iter()
                .map(|issue| JsonMaintenanceIssue {
                    package_name: issue.package_name.to_string(),
                    installed_version: issue.installed_version.to_string(),
                    issue_type: format!("{}", issue.issue_type),
                    reason: issue.reason.clone(),
                    is_direct: issue.is_direct,
                    source_file: issue.source_file.clone(),
                })
                .collect(),
        };

        Ok(serde_json::to_string_pretty(&json_report)?)
    }

    /// Generate a SARIF report using the comprehensive `SarifGenerator`
    fn generate_sarif_report(
        report: &AuditReport,
        project_root: Option<&Path>,
    ) -> Result<String, Box<dyn std::error::Error>> {
        let project_root = project_root.unwrap_or_else(|| Path::new("."));
        let mut generator = SarifGenerator::new(project_root);

        let sarif_json = generator.generate_report(
            &report.matches,
            &report.dependency_stats,
            &report.database_stats,
            &report.fix_analysis.fix_suggestions,
            &report.warnings,
            &report.maintenance_issues,
        )?;

        Ok(sarif_json)
    }
}

// JSON report structures
#[derive(Serialize, Deserialize)]
struct JsonReport {
    scan_time: String,
    total_packages: usize,
    vulnerable_packages: usize,
    total_vulnerabilities: usize,
    vulnerabilities: Vec<JsonVulnerability>,
    fix_suggestions: Vec<JsonFixSuggestion>,
    warnings: Vec<String>,
    maintenance_issues: Vec<JsonMaintenanceIssue>,
}

#[derive(Serialize, Deserialize)]
struct JsonVulnerability {
    id: String,
    package_name: String,
    installed_version: String,
    severity: String,
    summary: String,
    description: Option<String>,
    cvss_score: Option<f32>,
    fixed_versions: Vec<String>,
    references: Vec<String>,
    is_direct: bool,
    source: Option<String>,
    withdrawn: Option<String>,
}

#[derive(Serialize, Deserialize)]
struct JsonFixSuggestion {
    package_name: String,
    current_version: String,
    suggested_version: String,
    vulnerability_id: String,
}

#[derive(Serialize, Deserialize)]
struct JsonMaintenanceIssue {
    package_name: String,
    installed_version: String,
    issue_type: String,
    reason: Option<String>,
    is_direct: bool,
    source_file: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{PackageName, Version};
    use crate::vulnerability::database::Vulnerability;
    use std::collections::HashMap;
    use std::str::FromStr;

    fn create_test_report() -> AuditReport {
        let dependency_stats = DependencyStats {
            total_packages: 10,
            direct_packages: 5,
            transitive_packages: 5,
            by_type: HashMap::new(),
            by_source: {
                let mut map = HashMap::new();
                map.insert("Registry".to_string(), 10);
                map
            },
        };

        let database_stats = DatabaseStats {
            total_vulnerabilities: 100,
            total_packages: 50,
            severity_counts: HashMap::new(),
            packages_with_most_vulns: vec![],
        };

        let vulnerability = Vulnerability {
            id: "GHSA-test-1234".to_string(),
            summary: "Test vulnerability".to_string(),
            description: Some("A test vulnerability for unit testing".to_string()),
            severity: Severity::High,
            affected_versions: vec![],
            fixed_versions: vec![Version::from_str("1.5.0").unwrap()],
            references: vec!["https://example.com/advisory".to_string()],
            cvss_score: Some(7.5),
            cvss_version: None,
            published: None,
            modified: None,
            source: Some("test".to_string()),
            withdrawn: None,
            aliases: vec![],
        };

        let matches = vec![VulnerabilityMatch {
            package_name: PackageName::from_str("test-package").unwrap(),
            installed_version: Version::from_str("1.0.0").unwrap(),
            vulnerability,
            is_direct: true,
        }];

        let fix_analysis = FixAnalysis {
            total_matches: 1,
            fixable: 1,
            unfixable: 0,
            fix_suggestions: vec![],
        };

        AuditReport::new(
            dependency_stats,
            database_stats,
            matches,
            fix_analysis,
            vec!["Test warning".to_string()],
            Vec::new(),
        )
    }

    #[test]
    fn test_audit_summary() {
        let report = create_test_report();
        let summary = report.summary();

        assert_eq!(summary.total_packages_scanned, 10);
        assert_eq!(summary.vulnerable_packages, 1);
        assert_eq!(summary.total_vulnerabilities, 1);
        assert_eq!(summary.fixable_vulnerabilities, 1);
        assert_eq!(summary.unfixable_vulnerabilities, 0);
    }

    #[test]
    fn test_human_report_generation() {
        let report = create_test_report();
        let output = ReportGenerator::generate_human_report(
            &report,
            DetailLevel::Normal,
            &OutputStyles::default(),
        )
        .unwrap();

        assert!(output.contains("PYSENTRY SECURITY AUDIT"));
        assert!(output.contains("SUMMARY") && output.contains("10 packages scanned"));
        assert!(output.contains("1 vulnerable • 1 vulnerabilities found"));
        assert!(output.contains("GHSA-test-1234"));
        assert!(output.contains("test-package"));
        assert!(output.contains("VULNERABILITIES"));
        assert!(output.contains("HIGH"));
    }

    #[test]
    fn test_markdown_report_generation() {
        let report = create_test_report();
        let output = ReportGenerator::generate_markdown_report(&report).unwrap();

        assert!(output.contains("# 🛡️ pysentry report"));
        assert!(output.contains("## 📊 Scan Summary"));
        assert!(output.contains("- **Scanned:** 10 packages"));
        assert!(output.contains("### 1. 🟠 `GHSA-test-1234`"));
        assert!(output.contains("- **Package:** `test-package`"));
        assert!(output.contains("- **Severity:** HIGH"));
        assert!(output.contains("- **Description:**"));
        assert!(output.contains("~~~"));
        assert!(output.contains("A test vulnerability for unit testing"));
        assert!(output.contains("*Scan completed at"));
    }

    #[test]
    fn test_json_report_generation() {
        let report = create_test_report();
        let output = ReportGenerator::generate_json_report(&report).unwrap();

        let json: serde_json::Value = serde_json::from_str(&output).unwrap();
        assert_eq!(json["total_packages"], 10);
        assert_eq!(json["vulnerable_packages"], 1);
        assert_eq!(json["total_vulnerabilities"], 1);
        assert_eq!(json["vulnerabilities"][0]["id"], "GHSA-test-1234");
    }

    #[test]
    fn test_sarif_report_generation() {
        let report = create_test_report();
        let output =
            ReportGenerator::generate_sarif_report(&report, Some(std::path::Path::new(".")))
                .unwrap();

        let sarif: serde_json::Value = serde_json::from_str(&output).unwrap();
        assert_eq!(sarif["version"], "2.1.0");
        assert_eq!(sarif["runs"][0]["tool"]["driver"]["name"], "pysentry");
        assert_eq!(sarif["runs"][0]["results"][0]["ruleId"], "GHSA-test-1234");
    }

    #[test]
    fn test_report_generator_all_formats() {
        let report = create_test_report();
        let project_root = Some(std::path::Path::new("."));

        let styles = OutputStyles::default();

        // Test Human format
        let human_output = ReportGenerator::generate(
            &report,
            AuditFormat::Human,
            project_root,
            DetailLevel::Normal,
            &styles,
        )
        .unwrap();
        assert!(human_output.contains("PYSENTRY SECURITY AUDIT"));
        assert!(human_output.contains("GHSA-test-1234"));

        // Test JSON format
        let json_output = ReportGenerator::generate(
            &report,
            AuditFormat::Json,
            project_root,
            DetailLevel::Normal,
            &styles,
        )
        .unwrap();
        let json: serde_json::Value = serde_json::from_str(&json_output).unwrap();
        assert_eq!(json["total_packages"], 10);

        // Test SARIF format
        let sarif_output = ReportGenerator::generate(
            &report,
            AuditFormat::Sarif,
            project_root,
            DetailLevel::Normal,
            &styles,
        )
        .unwrap();
        let sarif: serde_json::Value = serde_json::from_str(&sarif_output).unwrap();
        assert_eq!(sarif["version"], "2.1.0");

        // Test Markdown format
        let markdown_output = ReportGenerator::generate(
            &report,
            AuditFormat::Markdown,
            project_root,
            DetailLevel::Normal,
            &styles,
        )
        .unwrap();
        assert!(markdown_output.contains("# 🛡️ pysentry report"));
        assert!(markdown_output.contains("### 1. 🟠 `GHSA-test-1234`"));
    }

    #[test]
    fn test_empty_report() {
        let dependency_stats = DependencyStats {
            total_packages: 5,
            direct_packages: 5,
            transitive_packages: 0,
            by_type: HashMap::new(),
            by_source: HashMap::new(),
        };

        let database_stats = DatabaseStats {
            total_vulnerabilities: 0,
            total_packages: 0,
            severity_counts: HashMap::new(),
            packages_with_most_vulns: vec![],
        };

        let fix_analysis = FixAnalysis {
            total_matches: 0,
            fixable: 0,
            unfixable: 0,
            fix_suggestions: vec![],
        };

        let report = AuditReport::new(
            dependency_stats,
            database_stats,
            vec![],
            fix_analysis,
            vec![],
            Vec::new(),
        );

        assert!(!report.has_vulnerabilities());

        let output = ReportGenerator::generate_human_report(
            &report,
            DetailLevel::Normal,
            &OutputStyles::default(),
        )
        .unwrap();
        assert!(output.contains("No vulnerabilities found"));
    }

    #[test]
    fn test_compact_report_no_header_no_footer() {
        let report = create_test_report();
        let output = ReportGenerator::generate_human_report(
            &report,
            DetailLevel::Compact,
            &OutputStyles::default(),
        )
        .unwrap();

        assert!(!output.contains("PYSENTRY SECURITY AUDIT"));
        assert!(!output.contains("Scan completed"));
    }

    #[test]
    fn test_compact_report_contains_summary() {
        let report = create_test_report();
        let output = ReportGenerator::generate_human_report(
            &report,
            DetailLevel::Compact,
            &OutputStyles::default(),
        )
        .unwrap();

        assert!(output.contains("SUMMARY"));
        assert!(output.contains("10 packages scanned"));
        assert!(output.contains("1 vulnerable"));
    }

    #[test]
    fn test_compact_report_condensed_vulns() {
        let report = create_test_report();
        let output = ReportGenerator::generate_human_report(
            &report,
            DetailLevel::Compact,
            &OutputStyles::default(),
        )
        .unwrap();

        // Vuln ID should be present
        assert!(output.contains("GHSA-test-1234"));
        // No description text
        assert!(!output.contains("Test vulnerability"));
        assert!(!output.contains("A test vulnerability"));
        // No fix arrow
        assert!(!output.contains("→ Fix:"));
        // No numbering
        assert!(!output.contains(" 1. "));
    }

    #[test]
    fn test_compact_report_no_fix_suggestions_when_empty() {
        let report = create_test_report();
        let output = ReportGenerator::generate_human_report(
            &report,
            DetailLevel::Compact,
            &OutputStyles::default(),
        )
        .unwrap();

        assert!(!output.contains("FIX SUGGESTIONS"));
    }

    #[test]
    fn test_compact_report_fix_suggestions() {
        use crate::vulnerability::matcher::FixSuggestion;

        let mut report = create_test_report();
        report.fix_analysis.fix_suggestions = vec![FixSuggestion {
            package_name: PackageName::from_str("requests").unwrap(),
            current_version: Version::from_str("2.28.0").unwrap(),
            suggested_version: Version::from_str("2.31.0").unwrap(),
            vulnerability_id: "GHSA-j8r2-6x86-q33q".to_string(),
        }];

        let output = ReportGenerator::generate_human_report(
            &report,
            DetailLevel::Compact,
            &OutputStyles::default(),
        )
        .unwrap();

        assert!(output.contains("FIX SUGGESTIONS"));
        assert!(output.contains("requests"));
        assert!(output.contains("2.28.0"));
        assert!(output.contains("2.31.0"));
        // Compact mode: no underline dashes
        assert!(!output.contains("---------------"));
    }

    #[test]
    fn test_compact_report_hint_line() {
        let report = create_test_report();
        let output = ReportGenerator::generate_human_report(
            &report,
            DetailLevel::Compact,
            &OutputStyles::default(),
        )
        .unwrap();

        assert!(output.contains("Run pysentry --detailed for full descriptions"));
    }

    #[test]
    fn test_compact_report_no_hint_when_clean() {
        let dependency_stats = DependencyStats {
            total_packages: 5,
            direct_packages: 5,
            transitive_packages: 0,
            by_type: HashMap::new(),
            by_source: HashMap::new(),
        };

        let database_stats = DatabaseStats {
            total_vulnerabilities: 0,
            total_packages: 0,
            severity_counts: HashMap::new(),
            packages_with_most_vulns: vec![],
        };

        let fix_analysis = FixAnalysis {
            total_matches: 0,
            fixable: 0,
            unfixable: 0,
            fix_suggestions: vec![],
        };

        let clean_report = AuditReport::new(
            dependency_stats,
            database_stats,
            vec![],
            fix_analysis,
            vec![],
            Vec::new(),
        );

        let output = ReportGenerator::generate_human_report(
            &clean_report,
            DetailLevel::Compact,
            &OutputStyles::default(),
        )
        .unwrap();

        assert!(!output.contains("Run pysentry --detailed"));
    }

    #[test]
    fn test_compact_report_maintenance_summary() {
        use crate::maintenance::MaintenanceIssueType;

        let dependency_stats = DependencyStats {
            total_packages: 5,
            direct_packages: 3,
            transitive_packages: 2,
            by_type: HashMap::new(),
            by_source: HashMap::new(),
        };

        let database_stats = DatabaseStats {
            total_vulnerabilities: 0,
            total_packages: 0,
            severity_counts: HashMap::new(),
            packages_with_most_vulns: vec![],
        };

        let fix_analysis = FixAnalysis {
            total_matches: 0,
            fixable: 0,
            unfixable: 0,
            fix_suggestions: vec![],
        };

        let maintenance_issue = MaintenanceIssue::new(
            PackageName::from_str("old-package").unwrap(),
            Version::from_str("1.2.3").unwrap(),
            MaintenanceIssueType::Deprecated,
            Some("Use new-package instead".to_string()),
            true,
            Some("requirements.txt".to_string()),
        );

        let report = AuditReport::new(
            dependency_stats,
            database_stats,
            vec![],
            fix_analysis,
            vec![],
            vec![maintenance_issue],
        );

        let output = ReportGenerator::generate_human_report(
            &report,
            DetailLevel::Compact,
            &OutputStyles::default(),
        )
        .unwrap();

        // Compact mode shows per-issue one-liners under MAINTENANCE header
        assert!(output.contains("MAINTENANCE"));
        assert!(output.contains("DEPRECATED"));
        assert!(output.contains("old-package"));

        // Full maintenance listing must NOT appear in compact mode
        assert!(!output.contains("MAINTENANCE ISSUES (PEP 792)"));

        // No numbered individual entries
        assert!(!output.contains(" 1. "));

        // Hint line appears because there are findings
        assert!(output.contains("Run pysentry --detailed"));
    }

    #[test]
    fn test_detailed_report_shows_full_description() {
        let report = create_test_report();
        let output = ReportGenerator::generate_human_report(
            &report,
            DetailLevel::Detailed,
            &OutputStyles::default(),
        )
        .unwrap();

        // Both summary and the distinct description text must appear
        assert!(output.contains("Test vulnerability"));
        assert!(output.contains("A test vulnerability for unit testing"));

        // Header and footer are not suppressed in detailed mode
        assert!(output.contains("PYSENTRY SECURITY AUDIT"));
        assert!(output.contains("Scan completed"));
    }

    #[test]
    fn test_compact_report_withdrawn_tag() {
        let dependency_stats = DependencyStats {
            total_packages: 3,
            direct_packages: 3,
            transitive_packages: 0,
            by_type: HashMap::new(),
            by_source: HashMap::new(),
        };

        let database_stats = DatabaseStats {
            total_vulnerabilities: 0,
            total_packages: 0,
            severity_counts: HashMap::new(),
            packages_with_most_vulns: vec![],
        };

        let withdrawn_vuln = Vulnerability {
            id: "GHSA-withdrawn-0001".to_string(),
            summary: "Withdrawn advisory".to_string(),
            description: None,
            severity: Severity::Low,
            affected_versions: vec![],
            fixed_versions: vec![],
            references: vec![],
            cvss_score: None,
            cvss_version: None,
            published: None,
            modified: None,
            source: None,
            withdrawn: Some(Utc::now()),
            aliases: vec![],
        };

        let matches = vec![VulnerabilityMatch {
            package_name: PackageName::from_str("some-pkg").unwrap(),
            installed_version: Version::from_str("0.1.0").unwrap(),
            vulnerability: withdrawn_vuln,
            is_direct: true,
        }];

        let fix_analysis = FixAnalysis {
            total_matches: 1,
            fixable: 0,
            unfixable: 1,
            fix_suggestions: vec![],
        };

        let report = AuditReport::new(
            dependency_stats,
            database_stats,
            matches,
            fix_analysis,
            vec![],
            vec![],
        );

        let output = ReportGenerator::generate_human_report(
            &report,
            DetailLevel::Compact,
            &OutputStyles::default(),
        )
        .unwrap();

        assert!(output.contains("GHSA-withdrawn-0001"));
        assert!(output.contains("WITHDRAWN"));
    }
}
