// SPDX-License-Identifier: MIT

use super::model::AuditReport;
use serde::Serialize;

pub(crate) fn generate_json_report(
    report: &AuditReport,
) -> Result<String, Box<dyn std::error::Error>> {
    let summary = report.summary();

    let json_report = JsonReport {
        scan_time: report.scan_time.to_rfc3339(),
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
                issue_type: issue.issue_type.to_string(),
                reason: issue.reason.clone(),
                is_direct: issue.is_direct,
                source_file: issue.source_file.clone(),
            })
            .collect(),
    };

    Ok(serde_json::to_string_pretty(&json_report)?)
}

#[derive(Serialize)]
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

#[derive(Serialize)]
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

#[derive(Serialize)]
struct JsonFixSuggestion {
    package_name: String,
    current_version: String,
    suggested_version: String,
    vulnerability_id: String,
}

#[derive(Serialize)]
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
    use crate::output::model::test_helpers::create_test_report;

    #[test]
    fn test_json_report_generation() {
        let report = create_test_report();
        let output = generate_json_report(&report).unwrap();
        let json: serde_json::Value = serde_json::from_str(&output).unwrap();
        assert_eq!(json["total_packages"], 10);
        assert_eq!(json["vulnerable_packages"], 1);
        assert_eq!(json["total_vulnerabilities"], 1);
        assert_eq!(json["vulnerabilities"][0]["id"], "GHSA-test-1234");
    }
}
