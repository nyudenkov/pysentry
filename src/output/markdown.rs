// SPDX-License-Identifier: MIT

use super::model::AuditReport;
use super::styles::{maintenance_icon, severity_icon};
use crate::vulnerability::database::Severity;
use crate::vulnerability::matcher::FixSuggestion;
use std::collections::BTreeMap;
use std::fmt::Write;
use tabled::{builder::Builder, settings::Style};

pub(crate) fn generate_markdown_report(
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
            let dep_type = if m.is_direct { "direct" } else { "transitive" };
            writeln!(output, "- **Dependency:** {dep_type}")?;
            writeln!(output, "- **Severity:** {}", m.vulnerability.severity)?;

            if let Some(cvss) = m.vulnerability.cvss_score {
                let version_tag = m
                    .vulnerability
                    .cvss_version
                    .map(|v| format!(" (v{v})"))
                    .unwrap_or_default();
                writeln!(output, "- **CVSS Score:** {cvss:.1}{version_tag}")?;
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

        let mut package_fixes: BTreeMap<String, Vec<&FixSuggestion>> = BTreeMap::new();
        for suggestion in &report.fix_analysis.fix_suggestions {
            package_fixes
                .entry(suggestion.package_name.to_string())
                .or_default()
                .push(suggestion);
        }
        for fixes in package_fixes.values_mut() {
            fixes.sort_by(|a, b| {
                a.suggested_version
                    .partial_cmp(&b.suggested_version)
                    .unwrap_or(std::cmp::Ordering::Equal)
            });
        }

        let mut builder = Builder::new();
        builder.push_record(["Package", "Fix", "Vulnerabilities"]);
        for (package, fixes) in &package_fixes {
            let (fix_str, count_str) = if fixes.len() == 1 {
                let Some(fix) = fixes.first() else { continue; };
                (
                    format!("{} → {}", fix.current_version, fix.suggested_version),
                    "1 vulnerability".to_string(),
                )
            } else {
                let Some(best) = fixes.last() else { continue; };
                (
                    format!("{} → {}", best.current_version, best.suggested_version),
                    format!("fixes {} vulnerabilities", fixes.len()),
                )
            };
            builder.push_record([package.as_str(), &fix_str, &count_str]);
        }
        let table = builder.build().with(Style::markdown()).to_string();
        writeln!(output, "{table}")?;
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::output::model::test_helpers::{
        create_test_report, create_test_report_with_extras, create_test_report_with_multiple_fixes,
    };

    #[test]
    fn test_markdown_report_generation() {
        let report = create_test_report();
        let output = generate_markdown_report(&report).unwrap();

        assert!(output.contains("# 🛡️ pysentry report"));
        assert!(output.contains("## 📊 Scan Summary"));
        assert!(output.contains("- **Scanned:** 10 packages"));
        assert!(output.contains("### 1. 🟠 `GHSA-test-1234`"));
        assert!(output.contains("- **Package:** `test-package`"));
        // Dependency type must appear (test data is_direct = true)
        assert!(output.contains("- **Dependency:** direct"));
        assert!(output.contains("- **Severity:** HIGH"));
        // CVSS score without version tag (test data cvss_version = None)
        assert!(output.contains("- **CVSS Score:** 7.5"));
        assert!(output.contains("- **Description:**"));
        assert!(output.contains("~~~"));
        assert!(output.contains("A test vulnerability for unit testing"));
        assert!(output.contains("*Scan completed at"));
    }

    #[test]
    fn test_markdown_transitive_and_cvss_version() {
        let report = create_test_report_with_extras();
        let output = generate_markdown_report(&report).unwrap();

        // Both dependency type labels must appear
        assert!(output.contains("- **Dependency:** direct"));
        assert!(output.contains("- **Dependency:** transitive"));

        // Transitive dep has cvss_version: Some(3) → version tag must appear
        assert!(output.contains("- **CVSS Score:** 5.5 (v3)"));

        // Direct dep has cvss_version: None → plain score, no version tag
        assert!(output.contains("- **CVSS Score:** 7.5"));
        assert!(!output.contains("- **CVSS Score:** 7.5 (v"));
    }

    #[test]
    fn test_markdown_maintenance_section() {
        let report = create_test_report_with_extras();
        let output = generate_markdown_report(&report).unwrap();

        assert!(output.contains("## 🔧 Maintenance Issues (PEP 792)"));
        assert!(output.contains("old-lib"));
        assert!(output.contains("Use new-lib instead"));
        // Maintenance issue is_direct = true → "direct" label
        assert!(output.contains("- **Type:** direct"));
    }

    #[test]
    fn test_markdown_fix_suggestions_table() {
        let report = create_test_report_with_multiple_fixes();
        let output = generate_markdown_report(&report).unwrap();

        assert!(output.contains("## 💡 Fix Suggestions"));
        // Consolidated columns (no per-CVE rows)
        assert!(output.contains("| Package"));
        assert!(output.contains("| Fix"));
        assert!(output.contains("| Vulnerabilities"));
        // flask row: max version (3.0.0) shown with count annotation
        assert!(output.contains("flask"));
        assert!(output.contains("2.3.1 → 3.0.0"));
        assert!(output.contains("fixes 2 vulnerabilities"));
        // requests row: single CVE, plain count
        assert!(output.contains("requests"));
        assert!(output.contains("2.28.0 → 2.31.0"));
        assert!(output.contains("1 vulnerability"));
        // Table header separator row starts with |---
        assert!(output.contains("|---"));
        // CVE IDs are NOT shown in the consolidated view
        assert!(!output.contains("CVE-2023-001"));
        assert!(!output.contains("CVE-2023-002"));
        assert!(!output.contains("GHSA-j8r2-6x86-q33q"));
    }
}
