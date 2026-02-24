// SPDX-License-Identifier: MIT

use super::model::{AuditReport, DetailLevel, DisplayMode};
use super::styles::{get_terminal_width, OutputStyles};
use crate::vulnerability::database::Severity;
use crate::vulnerability::matcher::FixSuggestion;
use owo_colors::OwoColorize;
use std::collections::BTreeMap;
use std::fmt::Write;
use tabled::{builder::Builder, settings::Style};

fn group_and_sort_fixes(
    fix_suggestions: &[FixSuggestion],
) -> BTreeMap<String, Vec<&FixSuggestion>> {
    let mut package_fixes: BTreeMap<String, Vec<&FixSuggestion>> = BTreeMap::new();
    for suggestion in fix_suggestions {
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
    package_fixes
}

/// Returns (from → to version string, fix count) for a sorted group.
/// Returns None only if `fixes` is unexpectedly empty (defensive guard).
fn fix_version_summary(fixes: &[&FixSuggestion]) -> Option<(String, usize)> {
    let best = fixes.last()?;
    Some((
        format!("{} → {}", best.current_version, best.suggested_version),
        fixes.len(),
    ))
}

pub(crate) fn generate_human_report(
    report: &AuditReport,
    detail_level: DetailLevel,
    display_mode: DisplayMode,
    styles: &OutputStyles,
) -> Result<String, Box<dyn std::error::Error>> {
    let mut output = String::new();
    let summary = report.summary();
    let is_compact = detail_level == DetailLevel::Compact;
    let is_detailed = detail_level == DetailLevel::Detailed;
    let use_table = is_compact && display_mode == DisplayMode::Table;

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

        if use_table {
            writeln!(output)?;
            let mut builder = Builder::new();
            builder.push_record(["ID", "Package", "Version", "Severity", "Type"]);
            for m in &report.matches {
                let id_field = if m.vulnerability.withdrawn.is_some() {
                    format!(
                        "{} {}",
                        m.vulnerability.id.style(styles.vuln_id),
                        "(WITHDRAWN)".style(styles.withdrawn_tag)
                    )
                } else {
                    m.vulnerability.id.style(styles.vuln_id).to_string()
                };
                let dep_type = if m.is_direct { "direct" } else { "transitive" };
                builder.push_record([
                    id_field,
                    m.package_name.to_string().style(styles.package).to_string(),
                    format!("v{}", m.installed_version),
                    m.vulnerability
                        .severity
                        .to_string()
                        .style(*styles.severity(&m.vulnerability.severity))
                        .to_string(),
                    dep_type.style(styles.dimmed).to_string(),
                ]);
            }
            let table = builder.build().with(Style::rounded()).to_string();
            writeln!(output, "{table}")?;
        } else if is_compact {
            writeln!(output)?;
            for m in &report.matches {
                let withdrawn_tag = if m.vulnerability.withdrawn.is_some() {
                    format!(" {}", "(WITHDRAWN)".style(styles.withdrawn_tag))
                } else {
                    String::new()
                };
                let dep_type = if m.is_direct { "direct" } else { "transitive" };
                writeln!(
                    output,
                    "  {}{}  {} v{}  [{}] {}",
                    m.vulnerability.id.style(styles.vuln_id),
                    withdrawn_tag,
                    m.package_name.to_string().style(styles.package),
                    m.installed_version,
                    m.vulnerability
                        .severity
                        .to_string()
                        .style(*styles.severity(&m.vulnerability.severity)),
                    dep_type.style(styles.dimmed)
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

                let dep_type = if m.is_direct {
                    "[direct]"
                } else {
                    "[transitive]"
                };

                writeln!(
                    output,
                    " {}. {}{}  {} v{}  [{}] {}{}",
                    i + 1,
                    m.vulnerability.id.style(styles.vuln_id),
                    withdrawn_tag,
                    m.package_name.to_string().style(styles.package),
                    m.installed_version,
                    m.vulnerability
                        .severity
                        .to_string()
                        .style(*styles.severity(&m.vulnerability.severity)),
                    dep_type.style(styles.dimmed),
                    source_tag
                )?;

                if is_detailed {
                    writeln!(output, "    {}", m.vulnerability.summary)?;
                    if let Some(description) = &m.vulnerability.description {
                        if description != &m.vulnerability.summary {
                            writeln!(output, "    {description}")?;
                        }
                    }
                    if let Some(cvss) = m.vulnerability.cvss_score {
                        let version_tag = m
                            .vulnerability
                            .cvss_version
                            .map(|v| format!(" (v{v})"))
                            .unwrap_or_default();
                        writeln!(output, "    CVSS: {cvss:.1}{version_tag}")?;
                    }
                    if !m.vulnerability.references.is_empty() {
                        writeln!(output, "    References:")?;
                        for ref_url in &m.vulnerability.references {
                            writeln!(output, "      {ref_url}")?;
                        }
                    }
                } else if !m.vulnerability.summary.is_empty() {
                    writeln!(output, "    {}", m.vulnerability.summary)?;
                } else if let Some(description) = &m.vulnerability.description {
                    const DESCRIPTION_INDENT: usize = 4;
                    const DESCRIPTION_ELLIPSIS: usize = 3;
                    let max_desc_width = get_terminal_width()
                        .saturating_sub(DESCRIPTION_INDENT + DESCRIPTION_ELLIPSIS);
                    let truncated = description.chars().take(max_desc_width).collect::<String>();
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
        let package_fixes = group_and_sort_fixes(&report.fix_analysis.fix_suggestions);

        if use_table {
            writeln!(output)?;
            writeln!(output, "{}", "FIX SUGGESTIONS".style(styles.header))?;
            let mut builder = Builder::new();
            builder.push_record(["Package", "Suggested Fix"]);
            for (package, fixes) in &package_fixes {
                let Some((version_str, count)) = fix_version_summary(fixes) else {
                    continue;
                };
                let fix_text = if count == 1 {
                    version_str.style(styles.fix_suggestion).to_string()
                } else {
                    format!(
                        "{} (fixes {} vulnerabilities)",
                        version_str.style(styles.fix_suggestion),
                        count
                    )
                };
                builder.push_record([package.style(styles.package).to_string(), fix_text]);
            }
            let table = builder.build().with(Style::rounded()).to_string();
            writeln!(output, "{table}")?;
        } else if is_compact {
            writeln!(output)?;
            writeln!(output, "{}", "FIX SUGGESTIONS".style(styles.header))?;
            for (package, fixes) in &package_fixes {
                let Some((version_str, count)) = fix_version_summary(fixes) else {
                    continue;
                };
                let version_info = if count == 1 {
                    version_str.style(styles.fix_suggestion).to_string()
                } else {
                    format!(
                        "{} (fixes {} vulnerabilities)",
                        version_str.style(styles.fix_suggestion),
                        count
                    )
                };
                writeln!(
                    output,
                    "  {}: {}",
                    package.style(styles.package),
                    version_info
                )?;
            }
        } else {
            writeln!(output, "{}", "FIX SUGGESTIONS".style(styles.header))?;
            writeln!(output, "---------------")?;
            for (package, fixes) in &package_fixes {
                let Some((version_str, count)) = fix_version_summary(fixes) else {
                    continue;
                };
                if count == 1 {
                    writeln!(
                        output,
                        "{}: {}",
                        package.style(styles.package),
                        version_str.style(styles.fix_suggestion)
                    )?;
                } else {
                    writeln!(
                        output,
                        "{}: {} (fixes {} vulnerabilities)",
                        package.style(styles.package),
                        version_str.style(styles.fix_suggestion),
                        count
                    )?;
                }
            }
            writeln!(output)?;
        }
    }

    // Maintenance issues section (PEP 792)
    if !report.maintenance_issues.is_empty() {
        if use_table {
            writeln!(output)?;
            writeln!(output, "{}", "MAINTENANCE".style(styles.header))?;
            let mut builder = Builder::new();
            builder.push_record(["Status", "Package", "Version", "Type"]);
            for issue in &report.maintenance_issues {
                let status_text = issue.issue_type.to_string();
                let dep_type = if issue.is_direct {
                    "direct"
                } else {
                    "transitive"
                };
                builder.push_record([
                    status_text
                        .style(*styles.maintenance(&issue.issue_type))
                        .to_string(),
                    issue
                        .package_name
                        .to_string()
                        .style(styles.package)
                        .to_string(),
                    format!("v{}", issue.installed_version),
                    dep_type.style(styles.dimmed).to_string(),
                ]);
            }
            let table = builder.build().with(Style::rounded()).to_string();
            writeln!(output, "{table}")?;
        } else if is_compact {
            writeln!(output)?;
            writeln!(output, "{}", "MAINTENANCE".style(styles.header))?;
            for issue in &report.maintenance_issues {
                let status_text = issue.issue_type.to_string();
                let dep_type = if issue.is_direct {
                    "direct"
                } else {
                    "transitive"
                };
                writeln!(
                    output,
                    "  {}  {} v{}  {}",
                    status_text.style(*styles.maintenance(&issue.issue_type)),
                    issue.package_name.to_string().style(styles.package),
                    issue.installed_version,
                    dep_type.style(styles.dimmed)
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::maintenance::{MaintenanceIssue, MaintenanceIssueType};
    use crate::output::model::test_helpers::{create_test_report, create_test_report_with_extras};
    use crate::parsers::DependencyStats;
    use crate::types::{PackageName, Version};
    use crate::vulnerability::matcher::{DatabaseStats, FixAnalysis, FixSuggestion};
    use std::collections::HashMap;
    use std::str::FromStr;

    #[test]
    fn test_human_report_generation() {
        let report = create_test_report();
        let output = generate_human_report(
            &report,
            DetailLevel::Normal,
            DisplayMode::Table,
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
        // Dependency type tag must appear on every vulnerability entry
        assert!(output.contains("[direct]"));
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

        let report = crate::output::model::AuditReport::new(
            dependency_stats,
            database_stats,
            vec![],
            fix_analysis,
            vec![],
            Vec::new(),
        );

        assert!(!report.has_vulnerabilities());

        let output = generate_human_report(
            &report,
            DetailLevel::Normal,
            DisplayMode::Table,
            &OutputStyles::default(),
        )
        .unwrap();
        assert!(output.contains("No vulnerabilities found"));
    }

    #[test]
    fn test_compact_report_no_header_no_footer() {
        let report = create_test_report();
        let output = generate_human_report(
            &report,
            DetailLevel::Compact,
            DisplayMode::Table,
            &OutputStyles::default(),
        )
        .unwrap();

        assert!(!output.contains("PYSENTRY SECURITY AUDIT"));
        assert!(!output.contains("Scan completed"));
    }

    #[test]
    fn test_compact_report_contains_summary() {
        let report = create_test_report();
        let output = generate_human_report(
            &report,
            DetailLevel::Compact,
            DisplayMode::Table,
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
        let output = generate_human_report(
            &report,
            DetailLevel::Compact,
            DisplayMode::Table,
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
        // Dependency type appears in table (no brackets in tabled compact mode)
        assert!(output.contains("direct"));
        // Table structure is present
        assert!(output.contains("│"));
    }

    #[test]
    fn test_compact_report_no_fix_suggestions_when_empty() {
        let report = create_test_report();
        let output = generate_human_report(
            &report,
            DetailLevel::Compact,
            DisplayMode::Table,
            &OutputStyles::default(),
        )
        .unwrap();

        assert!(!output.contains("FIX SUGGESTIONS"));
    }

    #[test]
    fn test_compact_report_fix_suggestions() {
        let mut report = create_test_report();
        report.fix_analysis.fix_suggestions = vec![FixSuggestion {
            package_name: PackageName::from_str("requests").unwrap(),
            current_version: Version::from_str("2.28.0").unwrap(),
            suggested_version: Version::from_str("2.31.0").unwrap(),
            vulnerability_id: "GHSA-j8r2-6x86-q33q".to_string(),
        }];

        let output = generate_human_report(
            &report,
            DetailLevel::Compact,
            DisplayMode::Table,
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
        let output = generate_human_report(
            &report,
            DetailLevel::Compact,
            DisplayMode::Table,
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

        let clean_report = crate::output::model::AuditReport::new(
            dependency_stats,
            database_stats,
            vec![],
            fix_analysis,
            vec![],
            Vec::new(),
        );

        let output = generate_human_report(
            &clean_report,
            DetailLevel::Compact,
            DisplayMode::Table,
            &OutputStyles::default(),
        )
        .unwrap();

        assert!(!output.contains("Run pysentry --detailed"));
    }

    #[test]
    fn test_compact_report_maintenance_summary() {
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

        let report = crate::output::model::AuditReport::new(
            dependency_stats,
            database_stats,
            vec![],
            fix_analysis,
            vec![],
            vec![maintenance_issue],
        );

        let output = generate_human_report(
            &report,
            DetailLevel::Compact,
            DisplayMode::Table,
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
        let output = generate_human_report(
            &report,
            DetailLevel::Detailed,
            DisplayMode::Table,
            &OutputStyles::default(),
        )
        .unwrap();

        // Both summary and the distinct description text must appear
        assert!(output.contains("Test vulnerability"));
        assert!(output.contains("A test vulnerability for unit testing"));

        // Header and footer are not suppressed in detailed mode
        assert!(output.contains("PYSENTRY SECURITY AUDIT"));
        assert!(output.contains("Scan completed"));

        // Dependency type tag must appear in detailed mode
        assert!(output.contains("[direct]"));

        // CVSS score must appear in detailed mode (test data has cvss_score: Some(7.5))
        assert!(output.contains("CVSS: 7.5"));

        // References must appear in detailed mode (test data has one reference)
        assert!(output.contains("References:"));
        assert!(output.contains("https://example.com/advisory"));
    }

    #[test]
    fn test_detailed_report_cvss_version_tag() {
        let report = create_test_report_with_extras();
        let output = generate_human_report(
            &report,
            DetailLevel::Detailed,
            DisplayMode::Table,
            &OutputStyles::default(),
        )
        .unwrap();

        // Transitive dep has cvss_version: Some(3) → version tag must appear
        assert!(output.contains("CVSS: 5.5 (v3)"));
        // Direct dep has cvss_version: None → plain score, no version tag
        assert!(output.contains("CVSS: 7.5"));
        assert!(!output.contains("CVSS: 7.5 (v"));
    }

    #[test]
    fn test_normal_report_transitive_tag() {
        let report = create_test_report_with_extras();
        let output = generate_human_report(
            &report,
            DetailLevel::Normal,
            DisplayMode::Table,
            &OutputStyles::default(),
        )
        .unwrap();

        assert!(output.contains("[direct]"));
        assert!(output.contains("[transitive]"));
    }

    #[test]
    fn test_compact_report_transitive_tag() {
        let report = create_test_report_with_extras();
        let output = generate_human_report(
            &report,
            DetailLevel::Compact,
            DisplayMode::Table,
            &OutputStyles::default(),
        )
        .unwrap();

        // In compact tabled mode, values appear without brackets
        assert!(output.contains("direct"));
        assert!(output.contains("transitive"));
    }

    #[test]
    fn test_compact_table_has_headers() {
        let report = create_test_report();
        let output = generate_human_report(
            &report,
            DetailLevel::Compact,
            DisplayMode::Table,
            &OutputStyles::default(),
        )
        .unwrap();

        assert!(output.contains("ID"));
        assert!(output.contains("Package"));
        assert!(output.contains("Version"));
        assert!(output.contains("Severity"));
        assert!(output.contains("Type"));
    }

    #[test]
    fn test_compact_fix_suggestions_table() {
        let mut report = create_test_report();
        report.fix_analysis.fix_suggestions = vec![FixSuggestion {
            package_name: PackageName::from_str("requests").unwrap(),
            current_version: Version::from_str("2.28.0").unwrap(),
            suggested_version: Version::from_str("2.31.0").unwrap(),
            vulnerability_id: "GHSA-j8r2-6x86-q33q".to_string(),
        }];

        let output = generate_human_report(
            &report,
            DetailLevel::Compact,
            DisplayMode::Table,
            &OutputStyles::default(),
        )
        .unwrap();

        assert!(output.contains("FIX SUGGESTIONS"));
        assert!(output.contains("Package"));
        assert!(output.contains("Suggested Fix"));
        assert!(output.contains("requests"));
        assert!(output.contains("2.28.0"));
        assert!(output.contains("2.31.0"));
        assert!(output.contains("│"));
    }

    #[test]
    fn test_fix_suggestions_multi_cve_shows_max_version() {
        let mut report = create_test_report();
        report.fix_analysis.fix_suggestions = vec![
            FixSuggestion {
                package_name: PackageName::from_str("flask").unwrap(),
                current_version: Version::from_str("2.3.1").unwrap(),
                suggested_version: Version::from_str("2.4.0").unwrap(),
                vulnerability_id: "CVE-2023-002".to_string(),
            },
            FixSuggestion {
                package_name: PackageName::from_str("flask").unwrap(),
                current_version: Version::from_str("2.3.1").unwrap(),
                suggested_version: Version::from_str("3.0.0").unwrap(),
                vulnerability_id: "CVE-2023-001".to_string(),
            },
        ];

        let output1 = generate_human_report(
            &report,
            DetailLevel::Compact,
            DisplayMode::Table,
            &OutputStyles::default(),
        )
        .unwrap();
        let output2 = generate_human_report(
            &report,
            DetailLevel::Compact,
            DisplayMode::Table,
            &OutputStyles::default(),
        )
        .unwrap();

        // Output must be identical across multiple calls (deterministic)
        assert_eq!(output1, output2);
        // Multi-CVE: the maximum fix version must be shown (covers all vulnerabilities)
        assert!(output1.contains("3.0.0"), "Maximum fix version must appear");
        // The lower version is not shown separately when a higher fix covers it
        assert!(
            !output1.contains("2.4.0"),
            "Minimum version must not appear when a higher fix exists"
        );
        assert!(
            output1.contains("fixes 2 vulnerabilities"),
            "Count of addressed vulnerabilities must appear"
        );
    }

    #[test]
    fn test_compact_maintenance_table() {
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

        use crate::maintenance::{MaintenanceIssue, MaintenanceIssueType};
        let maintenance_issue = MaintenanceIssue::new(
            PackageName::from_str("old-pkg").unwrap(),
            Version::from_str("1.0.0").unwrap(),
            MaintenanceIssueType::Archived,
            None,
            true,
            None,
        );

        let report = crate::output::model::AuditReport::new(
            dependency_stats,
            database_stats,
            vec![],
            fix_analysis,
            vec![],
            vec![maintenance_issue],
        );

        let output = generate_human_report(
            &report,
            DetailLevel::Compact,
            DisplayMode::Table,
            &OutputStyles::default(),
        )
        .unwrap();

        assert!(output.contains("MAINTENANCE"));
        assert!(output.contains("Status"));
        assert!(output.contains("Package"));
        assert!(output.contains("Version"));
        assert!(output.contains("Type"));
        assert!(output.contains("ARCHIVED"));
        assert!(output.contains("old-pkg"));
        assert!(output.contains("direct"));
        assert!(output.contains("│"));
    }

    #[test]
    fn test_description_truncation_uses_terminal_width() {
        use crate::vulnerability::database::{Severity, Vulnerability, VulnerabilityMatch};

        let long_description = "A".repeat(200);

        let dependency_stats = DependencyStats {
            total_packages: 1,
            direct_packages: 1,
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

        let vulnerability = Vulnerability {
            id: "CVE-2023-trunc".to_string(),
            summary: String::new(),
            description: Some(long_description),
            severity: Severity::Low,
            affected_versions: vec![],
            fixed_versions: vec![],
            references: vec![],
            cvss_score: None,
            cvss_version: None,
            published: None,
            modified: None,
            source: None,
            withdrawn: None,
            aliases: vec![],
        };

        let matches = vec![VulnerabilityMatch {
            package_name: PackageName::from_str("pkg").unwrap(),
            installed_version: Version::from_str("1.0.0").unwrap(),
            vulnerability,
            is_direct: true,
        }];

        let fix_analysis = FixAnalysis {
            total_matches: 1,
            fixable: 0,
            unfixable: 1,
            fix_suggestions: vec![],
        };

        let report = crate::output::model::AuditReport::new(
            dependency_stats,
            database_stats,
            matches,
            fix_analysis,
            vec![],
            vec![],
        );

        let output = generate_human_report(
            &report,
            DetailLevel::Normal,
            DisplayMode::Table,
            &OutputStyles::default(),
        )
        .unwrap();

        // Description must be truncated with "..." suffix (not the full 200 chars)
        assert!(output.contains("..."));
        // The raw 200-char description must NOT appear verbatim
        assert!(!output.contains(&"A".repeat(200)));
    }

    #[test]
    fn test_compact_report_withdrawn_tag() {
        use crate::vulnerability::database::{Severity, Vulnerability, VulnerabilityMatch};
        use chrono::Utc;

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

        let report = crate::output::model::AuditReport::new(
            dependency_stats,
            database_stats,
            matches,
            fix_analysis,
            vec![],
            vec![],
        );

        let output = generate_human_report(
            &report,
            DetailLevel::Compact,
            DisplayMode::Table,
            &OutputStyles::default(),
        )
        .unwrap();

        assert!(output.contains("GHSA-withdrawn-0001"));
        assert!(output.contains("WITHDRAWN"));
    }

    #[test]
    fn test_compact_text_display_no_table_borders() {
        let report = create_test_report();
        let output = generate_human_report(
            &report,
            DetailLevel::Compact,
            DisplayMode::Text,
            &OutputStyles::default(),
        )
        .unwrap();

        // Text mode uses bracket syntax for severity and dep type
        assert!(output.contains("GHSA-test-1234"));
        assert!(output.contains("[HIGH]"));
        assert!(output.contains("direct"));
        // No table borders
        assert!(!output.contains('│'));
        assert!(!output.contains('╭'));
        assert!(!output.contains("──"));
    }

    #[test]
    fn test_compact_table_display_has_borders() {
        let report = create_test_report();
        let output = generate_human_report(
            &report,
            DetailLevel::Compact,
            DisplayMode::Table,
            &OutputStyles::default(),
        )
        .unwrap();

        // Table mode uses tabled borders
        assert!(output.contains("GHSA-test-1234"));
        assert!(output.contains('│'));
        assert!(output.contains('╭'));
    }

    #[test]
    fn test_table_display_ignored_in_normal_mode() {
        let report = create_test_report();
        let table_output = generate_human_report(
            &report,
            DetailLevel::Normal,
            DisplayMode::Table,
            &OutputStyles::default(),
        )
        .unwrap();
        let text_output = generate_human_report(
            &report,
            DetailLevel::Normal,
            DisplayMode::Text,
            &OutputStyles::default(),
        )
        .unwrap();

        // DisplayMode is irrelevant outside compact mode — output must be identical
        assert_eq!(table_output, text_output);
    }

    #[test]
    fn test_table_display_ignored_in_detailed_mode() {
        let report = create_test_report();
        let table_output = generate_human_report(
            &report,
            DetailLevel::Detailed,
            DisplayMode::Table,
            &OutputStyles::default(),
        )
        .unwrap();
        let text_output = generate_human_report(
            &report,
            DetailLevel::Detailed,
            DisplayMode::Text,
            &OutputStyles::default(),
        )
        .unwrap();

        assert_eq!(table_output, text_output);
    }
}
