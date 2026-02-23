// SPDX-License-Identifier: MIT

use crate::maintenance::{MaintenanceCheckConfig, MaintenanceIssue, MaintenanceSummary};
use crate::parsers::DependencyStats;
use crate::vulnerability::database::Severity;
use crate::vulnerability::database::VulnerabilityMatch;
use crate::vulnerability::matcher::{DatabaseStats, FixAnalysis};
use chrono::{DateTime, Utc};
use std::collections::{BTreeMap, HashMap};
use std::sync::OnceLock;

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
#[derive(Debug)]
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
    cached_summary: OnceLock<AuditSummary>,
}

impl Clone for AuditReport {
    fn clone(&self) -> Self {
        Self {
            scan_time: self.scan_time,
            dependency_stats: self.dependency_stats.clone(),
            database_stats: self.database_stats.clone(),
            matches: self.matches.clone(),
            fix_analysis: self.fix_analysis.clone(),
            warnings: self.warnings.clone(),
            maintenance_issues: self.maintenance_issues.clone(),
            cached_summary: OnceLock::new(),
        }
    }
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
            cached_summary: OnceLock::new(),
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

    /// Get summary statistics (cached)
    pub fn summary(&self) -> &AuditSummary {
        self.cached_summary.get_or_init(|| {
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
        })
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

#[cfg(test)]
pub(crate) mod test_helpers {
    use super::*;
    use crate::maintenance::{MaintenanceIssue, MaintenanceIssueType};
    use crate::parsers::DependencyStats;
    use crate::types::{PackageName, Version};
    use crate::vulnerability::database::{Severity, Vulnerability, VulnerabilityMatch};
    use crate::vulnerability::matcher::{DatabaseStats, FixAnalysis};
    use std::collections::HashMap;
    use std::str::FromStr;

    pub fn create_test_report() -> AuditReport {
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

    /// Extended fixture with transitive deps, CVSS version data, and a maintenance issue.
    ///
    /// Used to test branches that `create_test_report` cannot reach:
    /// - `[transitive]` dependency tag
    /// - `cvss_version: Some(n)` version tag formatting
    /// - maintenance issue serialization (including the lowercase serde path)
    pub fn create_test_report_with_extras() -> AuditReport {
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

        let direct_vulnerability = Vulnerability {
            id: "GHSA-test-1234".to_string(),
            summary: "Direct vulnerability".to_string(),
            description: None,
            severity: Severity::High,
            affected_versions: vec![],
            fixed_versions: vec![],
            references: vec![],
            cvss_score: Some(7.5),
            cvss_version: None,
            published: None,
            modified: None,
            source: None,
            withdrawn: None,
            aliases: vec![],
        };

        let transitive_vulnerability = Vulnerability {
            id: "GHSA-trans-5678".to_string(),
            summary: "Transitive vulnerability".to_string(),
            description: None,
            severity: Severity::Medium,
            affected_versions: vec![],
            fixed_versions: vec![],
            references: vec![],
            cvss_score: Some(5.5),
            cvss_version: Some(3),
            published: None,
            modified: None,
            source: None,
            withdrawn: None,
            aliases: vec![],
        };

        let matches = vec![
            VulnerabilityMatch {
                package_name: PackageName::from_str("test-package").unwrap(),
                installed_version: Version::from_str("1.0.0").unwrap(),
                vulnerability: direct_vulnerability,
                is_direct: true,
            },
            VulnerabilityMatch {
                package_name: PackageName::from_str("transitive-package").unwrap(),
                installed_version: Version::from_str("0.9.0").unwrap(),
                vulnerability: transitive_vulnerability,
                is_direct: false,
            },
        ];

        let fix_analysis = FixAnalysis {
            total_matches: 2,
            fixable: 0,
            unfixable: 2,
            fix_suggestions: vec![],
        };

        let maintenance_issue = MaintenanceIssue::new(
            PackageName::from_str("old-lib").unwrap(),
            Version::from_str("2.0.0").unwrap(),
            MaintenanceIssueType::Deprecated,
            Some("Use new-lib instead".to_string()),
            true,
            Some("requirements.txt".to_string()),
        );

        AuditReport::new(
            dependency_stats,
            database_stats,
            matches,
            fix_analysis,
            vec![],
            vec![maintenance_issue],
        )
    }
}

#[cfg(test)]
mod tests {
    use super::test_helpers::create_test_report;

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
}
