// SPDX-License-Identifier: MIT

use super::model::AuditReport;
use crate::maintenance::MaintenanceIssue;
use crate::vulnerability::database::VulnerabilityMatch;
use crate::vulnerability::matcher::FixSuggestion;
use chrono::{DateTime, Utc};
use serde::Serialize;

pub(crate) fn generate_json_report(
    report: &AuditReport,
) -> Result<String, Box<dyn std::error::Error>> {
    let summary = report.summary();
    let view = JsonReportView {
        scan_time: &report.scan_time,
        total_packages: summary.total_packages_scanned,
        vulnerable_packages: summary.vulnerable_packages,
        total_vulnerabilities: summary.total_vulnerabilities,
        vulnerabilities: &report.matches,
        fix_suggestions: &report.fix_analysis.fix_suggestions,
        warnings: &report.warnings,
        maintenance_issues: &report.maintenance_issues,
    };
    Ok(serde_json::to_string_pretty(&view)?)
}

/// Zero-copy view over AuditReport that defines the JSON output shape.
///
/// This struct borrows from the report instead of copying data. It exists
/// because the JSON shape differs from AuditReport's struct shape: summary
/// fields are inlined at the top level, and `matches` is renamed to
/// `vulnerabilities`.
#[derive(Serialize)]
struct JsonReportView<'a> {
    scan_time: &'a DateTime<Utc>,
    total_packages: usize,
    vulnerable_packages: usize,
    total_vulnerabilities: usize,
    vulnerabilities: &'a [VulnerabilityMatch],
    fix_suggestions: &'a [FixSuggestion],
    warnings: &'a [String],
    maintenance_issues: &'a [MaintenanceIssue],
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::maintenance::{MaintenanceIssue, MaintenanceIssueType};
    use crate::output::model::test_helpers::{create_test_report, create_test_report_with_extras};
    use crate::parsers::DependencyStats;
    use crate::types::{PackageName, Version};
    use crate::vulnerability::matcher::{DatabaseStats, FixAnalysis};
    use std::collections::HashMap;
    use std::str::FromStr;

    #[test]
    fn test_json_report_generation() {
        let report = create_test_report();
        let output = generate_json_report(&report).unwrap();
        let json: serde_json::Value = serde_json::from_str(&output).unwrap();
        assert_eq!(json["total_packages"], 10);
        assert_eq!(json["vulnerable_packages"], 1);
        assert_eq!(json["total_vulnerabilities"], 1);
        assert_eq!(json["vulnerabilities"][0]["id"], "GHSA-test-1234");
        // Severity serializes as lowercase via #[serde(rename_all = "lowercase")]
        assert_eq!(json["vulnerabilities"][0]["severity"], "high");
        // New fields exposed via flatten (additive changes)
        assert!(json["vulnerabilities"][0]["cvss_score"].is_number());
        assert!(json["vulnerabilities"][0]["aliases"].is_array());
        assert!(json["vulnerabilities"][0]["affected_versions"].is_array());
    }

    #[test]
    fn test_json_severity_lowercase() {
        let report = create_test_report();
        let output = generate_json_report(&report).unwrap();
        let json: serde_json::Value = serde_json::from_str(&output).unwrap();
        // All severity values must be lowercase
        for vuln in json["vulnerabilities"].as_array().unwrap() {
            let severity = vuln["severity"].as_str().unwrap();
            assert_eq!(
                severity,
                severity.to_lowercase(),
                "severity must be lowercase"
            );
        }
    }

    #[test]
    fn test_json_scan_time_is_rfc3339() {
        let report = create_test_report();
        let output = generate_json_report(&report).unwrap();
        let json: serde_json::Value = serde_json::from_str(&output).unwrap();
        // scan_time must be a valid RFC 3339 string
        let scan_time = json["scan_time"]
            .as_str()
            .expect("scan_time must be a string");
        assert!(
            chrono::DateTime::parse_from_rfc3339(scan_time).is_ok(),
            "scan_time must be RFC 3339 format"
        );
    }

    #[test]
    fn test_json_maintenance_issue_type_lowercase() {
        // Regression test: Phase 3 switched from Display (.to_string() → "DEPRECATED")
        // to direct serde serialization (→ "deprecated"). Verifies the serde path.
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
        let fix_analysis = FixAnalysis {
            total_matches: 0,
            fixable: 0,
            unfixable: 0,
            fix_suggestions: vec![],
        };
        let issues = vec![
            MaintenanceIssue::new(
                PackageName::from_str("pkg-a").unwrap(),
                Version::from_str("1.0.0").unwrap(),
                MaintenanceIssueType::Archived,
                None,
                true,
                None,
            ),
            MaintenanceIssue::new(
                PackageName::from_str("pkg-b").unwrap(),
                Version::from_str("2.0.0").unwrap(),
                MaintenanceIssueType::Deprecated,
                None,
                true,
                None,
            ),
            MaintenanceIssue::new(
                PackageName::from_str("pkg-c").unwrap(),
                Version::from_str("3.0.0").unwrap(),
                MaintenanceIssueType::Quarantined,
                None,
                true,
                None,
            ),
        ];
        let report = crate::output::model::AuditReport::new(
            dependency_stats,
            database_stats,
            vec![],
            fix_analysis,
            vec![],
            issues,
        );

        let output = generate_json_report(&report).unwrap();
        let json: serde_json::Value = serde_json::from_str(&output).unwrap();

        assert_eq!(json["maintenance_issues"][0]["issue_type"], "archived");
        assert_eq!(json["maintenance_issues"][1]["issue_type"], "deprecated");
        assert_eq!(json["maintenance_issues"][2]["issue_type"], "quarantined");
    }

    #[test]
    fn test_json_transitive_dependency() {
        let report = create_test_report_with_extras();
        let output = generate_json_report(&report).unwrap();
        let json: serde_json::Value = serde_json::from_str(&output).unwrap();

        assert_eq!(json["vulnerabilities"][0]["is_direct"], true);
        assert_eq!(json["vulnerabilities"][1]["is_direct"], false);
    }

    #[test]
    fn test_json_cvss_version_serialized() {
        let report = create_test_report_with_extras();
        let output = generate_json_report(&report).unwrap();
        let json: serde_json::Value = serde_json::from_str(&output).unwrap();

        // Direct dep has cvss_version: None → should serialize as JSON null
        assert!(json["vulnerabilities"][0]["cvss_version"].is_null());
        // Transitive dep has cvss_version: Some(3) → should serialize as integer 3
        assert_eq!(json["vulnerabilities"][1]["cvss_version"], 3);
    }
}
