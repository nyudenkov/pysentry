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

use super::sarif::SarifGenerator;
use crate::parsers::DependencyStats;
use crate::types::AuditFormat;
use crate::vulnerability::database::{Severity, VulnerabilityMatch};
use crate::vulnerability::matcher::{DatabaseStats, FixAnalysis};
use chrono::{DateTime, Utc};
use owo_colors::OwoColorize;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt::Write;
use std::path::Path;

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
}

impl AuditReport {
    /// Create a new audit report
    pub fn new(
        dependency_stats: DependencyStats,
        database_stats: DatabaseStats,
        matches: Vec<VulnerabilityMatch>,
        fix_analysis: FixAnalysis,
        warnings: Vec<String>,
    ) -> Self {
        Self {
            scan_time: Utc::now(),
            dependency_stats,
            database_stats,
            matches,
            fix_analysis,
            warnings,
        }
    }

    /// Check if the audit found any vulnerabilities
    pub fn has_vulnerabilities(&self) -> bool {
        !self.matches.is_empty()
    }

    /// Check if the audit should fail based on the given severity threshold
    pub fn should_fail_on_severity(&self, fail_on_severity: &crate::types::SeverityLevel) -> bool {
        let min_severity = match fail_on_severity {
            crate::types::SeverityLevel::Low => Severity::Low,
            crate::types::SeverityLevel::Medium => Severity::Medium,
            crate::types::SeverityLevel::High => Severity::High,
            crate::types::SeverityLevel::Critical => Severity::Critical,
        };

        self.matches
            .iter()
            .any(|m| m.vulnerability.severity >= min_severity)
    }

    /// Get summary statistics
    pub fn summary(&self) -> AuditSummary {
        let mut severity_counts = HashMap::new();
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
    pub severity_counts: HashMap<Severity, usize>,
    pub fixable_vulnerabilities: usize,
    pub unfixable_vulnerabilities: usize,
}

struct ColoredOutput;

impl ColoredOutput {
    fn severity(severity: &Severity) -> String {
        match severity {
            Severity::Critical => "CRITICAL".on_red().white().bold().to_string(),
            Severity::High => "HIGH".red().bold().to_string(),
            Severity::Medium => "MEDIUM".yellow().bold().to_string(),
            Severity::Low => "LOW".green().bold().to_string(),
        }
    }

    fn severity_count(count: usize, severity: &Severity) -> String {
        let text = format!("{count} {severity:?}").to_uppercase();
        match severity {
            Severity::Critical => text.on_red().white().bold().to_string(),
            Severity::High => text.red().bold().to_string(),
            Severity::Medium => text.yellow().bold().to_string(),
            Severity::Low => text.green().bold().to_string(),
        }
    }

    fn package_name(name: &str) -> String {
        name.bold().to_string()
    }

    fn vulnerability_id(id: &str) -> String {
        id.cyan().bold().to_string()
    }

    fn header(text: &str) -> String {
        text.bold().to_string()
    }

    fn fix_suggestion(text: &str) -> String {
        text.blue().to_string()
    }
}

/// Report generator for different output formats
pub struct ReportGenerator;

impl ReportGenerator {
    /// Generate a report in the specified format
    pub fn generate(
        report: &AuditReport,
        format: AuditFormat,
        project_root: Option<&Path>,
        detailed: bool,
    ) -> Result<String, Box<dyn std::error::Error>> {
        match format {
            AuditFormat::Human => Self::generate_human_report(report, detailed),
            AuditFormat::Json => Self::generate_json_report(report),
            AuditFormat::Sarif => Self::generate_sarif_report(report, project_root),
            AuditFormat::Markdown => Self::generate_markdown_report(report),
        }
    }

    fn generate_human_report(
        report: &AuditReport,
        detailed: bool,
    ) -> Result<String, Box<dyn std::error::Error>> {
        let mut output = String::new();
        let summary = report.summary();

        writeln!(
            output,
            "{}",
            ColoredOutput::header("PYSENTRY SECURITY AUDIT")
        )?;
        writeln!(output, "=======================")?;
        writeln!(output)?;

        writeln!(
            output,
            "{}: {} packages scanned • {} vulnerable • {} vulnerabilities found",
            ColoredOutput::header("SUMMARY"),
            summary.total_packages_scanned,
            summary.vulnerable_packages,
            summary.total_vulnerabilities
        )?;
        writeln!(output)?;

        if !summary.severity_counts.is_empty() {
            write!(output, "{}: ", ColoredOutput::header("SEVERITY"))?;
            let mut first = true;
            for severity in [
                Severity::Critical,
                Severity::High,
                Severity::Medium,
                Severity::Low,
            ] {
                if let Some(count) = summary.severity_counts.get(&severity) {
                    if !first {
                        write!(output, "    ")?;
                    }
                    write!(
                        output,
                        " {}",
                        ColoredOutput::severity_count(*count, &severity)
                    )?;
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
                    ColoredOutput::header("FIXABLE"),
                    ColoredOutput::fix_suggestion(&report.fix_analysis.fixable.to_string())
                )?;
            }
            if report.fix_analysis.unfixable > 0 {
                writeln!(
                    output,
                    "{}: {} vulnerabilities cannot be fixed",
                    ColoredOutput::header("UNFIXABLE"),
                    report.fix_analysis.unfixable
                )?;
            }
            writeln!(output)?;
        }

        if !report.warnings.is_empty() {
            writeln!(output, "{}", ColoredOutput::header("WARNINGS"))?;
            for warning in &report.warnings {
                writeln!(output, "  {warning}")?;
            }
            writeln!(output)?;
        }

        if !report.matches.is_empty() {
            writeln!(output, "{}", ColoredOutput::header("VULNERABILITIES"))?;
            writeln!(output, "---------------")?;
            writeln!(output)?;

            for (i, m) in report.matches.iter().enumerate() {
                let source_tag = if let Some(source) = &m.vulnerability.source {
                    format!(" [source: {source}]")
                } else {
                    String::new()
                };

                let withdrawn_tag = if m.vulnerability.withdrawn.is_some() {
                    format!(" {}", "(WITHDRAWN)".yellow().bold())
                } else {
                    String::new()
                };

                writeln!(
                    output,
                    " {}. {}{}  {} v{}  [{}]{}",
                    i + 1,
                    ColoredOutput::vulnerability_id(&m.vulnerability.id),
                    withdrawn_tag,
                    ColoredOutput::package_name(&m.package_name.to_string()),
                    m.installed_version,
                    ColoredOutput::severity(&m.vulnerability.severity),
                    source_tag
                )?;

                if detailed {
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
                    let fixed_version = m.vulnerability.fixed_versions.first().unwrap();
                    writeln!(
                        output,
                        "    {} {}",
                        "→ Fix:".cyan(),
                        ColoredOutput::fix_suggestion(&format!("Upgrade to {fixed_version}+"))
                    )?;
                }
                writeln!(output)?;
            }
        } else {
            writeln!(output, "{} No vulnerabilities found!", "✓".green().bold())?;
        }

        if !report.fix_analysis.fix_suggestions.is_empty() {
            writeln!(output, "{}", ColoredOutput::header("FIX SUGGESTIONS"))?;
            writeln!(output, "---------------")?;

            let mut package_fixes: HashMap<String, Vec<String>> = HashMap::new();
            for suggestion in &report.fix_analysis.fix_suggestions {
                let package = suggestion.package_name.to_string();
                let version_info = format!(
                    "{} → {}",
                    suggestion.current_version, suggestion.suggested_version
                );
                package_fixes.entry(package).or_default().push(version_info);
            }

            for (package, fixes) in package_fixes {
                if fixes.len() == 1 {
                    writeln!(
                        output,
                        "{}: {}",
                        ColoredOutput::package_name(&package),
                        ColoredOutput::fix_suggestion(&fixes[0])
                    )?;
                } else {
                    let best_fix = fixes.first().unwrap();
                    writeln!(
                        output,
                        "{}: {} (fixes {} vulnerabilities)",
                        ColoredOutput::package_name(&package),
                        ColoredOutput::fix_suggestion(best_fix),
                        fixes.len()
                    )?;
                }
            }
            writeln!(output)?;
        }

        // Clean footer
        writeln!(
            output,
            "Scan completed {}",
            report
                .scan_time
                .format("%Y-%m-%d %H:%M:%S UTC")
                .to_string()
                .dimmed()
        )?;

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
            ] {
                if let Some(count) = summary.severity_counts.get(&severity) {
                    let icon = match severity {
                        Severity::Critical => "🔴",
                        Severity::High => "🟠",
                        Severity::Medium => "🟡",
                        Severity::Low => "🟢",
                    };
                    writeln!(output, "- {icon} **{severity:?}:** {count}")?;
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
                let severity_icon = match m.vulnerability.severity {
                    Severity::Critical => "🔴",
                    Severity::High => "🟠",
                    Severity::Medium => "🟡",
                    Severity::Low => "🟢",
                };

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
                    severity_icon,
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
                writeln!(output, "- **Severity:** {:?}", m.vulnerability.severity)?;

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
                    severity: format!("{:?}", m.vulnerability.severity),
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
            published: None,
            modified: None,
            source: Some("test".to_string()),
            withdrawn: None,
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
        let output = ReportGenerator::generate_human_report(&report, false).unwrap();

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
        assert!(output.contains("- **Severity:** High"));
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

        // Test Human format
        let human_output =
            ReportGenerator::generate(&report, AuditFormat::Human, project_root, false).unwrap();
        assert!(human_output.contains("PYSENTRY SECURITY AUDIT"));
        assert!(human_output.contains("GHSA-test-1234"));

        // Test JSON format
        let json_output =
            ReportGenerator::generate(&report, AuditFormat::Json, project_root, false).unwrap();
        let json: serde_json::Value = serde_json::from_str(&json_output).unwrap();
        assert_eq!(json["total_packages"], 10);

        // Test SARIF format
        let sarif_output =
            ReportGenerator::generate(&report, AuditFormat::Sarif, project_root, false).unwrap();
        let sarif: serde_json::Value = serde_json::from_str(&sarif_output).unwrap();
        assert_eq!(sarif["version"], "2.1.0");

        // Test Markdown format
        let markdown_output =
            ReportGenerator::generate(&report, AuditFormat::Markdown, project_root, false).unwrap();
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
        );

        assert!(!report.has_vulnerabilities());

        let output = ReportGenerator::generate_human_report(&report, false).unwrap();
        assert!(output.contains("No vulnerabilities found"));
    }

    #[test]
    fn test_should_fail_on_severity() {
        use crate::types::SeverityLevel;

        let report = create_test_report();

        assert!(report.should_fail_on_severity(&SeverityLevel::Low));
        assert!(report.should_fail_on_severity(&SeverityLevel::Medium));
        assert!(report.should_fail_on_severity(&SeverityLevel::High));

        assert!(!report.should_fail_on_severity(&SeverityLevel::Critical));
    }

    #[test]
    fn test_should_fail_on_severity_with_low_severity() {
        use crate::types::SeverityLevel;

        let mut report = create_test_report();
        report.matches[0].vulnerability.severity = Severity::Low;

        assert!(report.should_fail_on_severity(&SeverityLevel::Low));
        assert!(!report.should_fail_on_severity(&SeverityLevel::Medium));
        assert!(!report.should_fail_on_severity(&SeverityLevel::High));
        assert!(!report.should_fail_on_severity(&SeverityLevel::Critical));
    }

    #[test]
    fn test_should_fail_on_severity_with_no_vulnerabilities() {
        use crate::types::SeverityLevel;

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
        );

        assert!(!report.should_fail_on_severity(&SeverityLevel::Low));
        assert!(!report.should_fail_on_severity(&SeverityLevel::Medium));
        assert!(!report.should_fail_on_severity(&SeverityLevel::High));
        assert!(!report.should_fail_on_severity(&SeverityLevel::Critical));
    }
}
