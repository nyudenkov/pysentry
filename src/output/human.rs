// SPDX-License-Identifier: MIT

use super::model::{AuditReport, DetailLevel};
use super::styles::OutputStyles;
use crate::vulnerability::database::Severity;
use owo_colors::OwoColorize;
use std::collections::BTreeMap;
use std::fmt::Write;

pub(crate) fn generate_human_report(
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::maintenance::{MaintenanceIssue, MaintenanceIssueType};
    use crate::output::model::test_helpers::create_test_report;
    use crate::parsers::DependencyStats;
    use crate::types::{PackageName, Version};
    use crate::vulnerability::matcher::{DatabaseStats, FixAnalysis, FixSuggestion};
    use std::collections::HashMap;
    use std::str::FromStr;

    #[test]
    fn test_human_report_generation() {
        let report = create_test_report();
        let output = generate_human_report(&report, DetailLevel::Normal, &OutputStyles::default())
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

        let output =
            generate_human_report(&report, DetailLevel::Normal, &OutputStyles::default()).unwrap();
        assert!(output.contains("No vulnerabilities found"));
    }

    #[test]
    fn test_compact_report_no_header_no_footer() {
        let report = create_test_report();
        let output =
            generate_human_report(&report, DetailLevel::Compact, &OutputStyles::default()).unwrap();

        assert!(!output.contains("PYSENTRY SECURITY AUDIT"));
        assert!(!output.contains("Scan completed"));
    }

    #[test]
    fn test_compact_report_contains_summary() {
        let report = create_test_report();
        let output =
            generate_human_report(&report, DetailLevel::Compact, &OutputStyles::default()).unwrap();

        assert!(output.contains("SUMMARY"));
        assert!(output.contains("10 packages scanned"));
        assert!(output.contains("1 vulnerable"));
    }

    #[test]
    fn test_compact_report_condensed_vulns() {
        let report = create_test_report();
        let output =
            generate_human_report(&report, DetailLevel::Compact, &OutputStyles::default()).unwrap();

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
        let output =
            generate_human_report(&report, DetailLevel::Compact, &OutputStyles::default()).unwrap();

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

        let output =
            generate_human_report(&report, DetailLevel::Compact, &OutputStyles::default()).unwrap();

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
        let output =
            generate_human_report(&report, DetailLevel::Compact, &OutputStyles::default()).unwrap();

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

        let output =
            generate_human_report(&clean_report, DetailLevel::Compact, &OutputStyles::default())
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

        let output =
            generate_human_report(&report, DetailLevel::Compact, &OutputStyles::default()).unwrap();

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
        let output =
            generate_human_report(&report, DetailLevel::Detailed, &OutputStyles::default())
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
        use chrono::Utc;
        use crate::vulnerability::database::{Severity, Vulnerability, VulnerabilityMatch};

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

        let output =
            generate_human_report(&report, DetailLevel::Compact, &OutputStyles::default()).unwrap();

        assert!(output.contains("GHSA-withdrawn-0001"));
        assert!(output.contains("WITHDRAWN"));
    }
}
