// SPDX-License-Identifier: MIT

//! PEP 792 Project Status Markers types
//!
//! This module defines types for handling PEP 792 project status markers
//! that indicate the maintenance state of packages in the Python ecosystem.
//! See: https://peps.python.org/pep-0792/

use crate::types::{PackageName, Version};
use serde::{Deserialize, Serialize};
use std::fmt;

/// Project status as defined by PEP 792
///
/// These markers indicate the maintenance state of a package on PyPI:
/// - `Active`: Under active development (default)
/// - `Archived`: No future updates expected
/// - `Deprecated`: Obsolete, possibly superseded
/// - `Quarantined`: Unsafe (malware/compromised)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum ProjectState {
    /// Under active development (default)
    #[default]
    Active,
    /// No future updates expected
    Archived,
    /// Obsolete, possibly superseded by another package
    Deprecated,
    /// Unsafe - identified as malware, compromised, or otherwise dangerous
    Quarantined,
}

impl fmt::Display for ProjectState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ProjectState::Active => write!(f, "active"),
            ProjectState::Archived => write!(f, "archived"),
            ProjectState::Deprecated => write!(f, "deprecated"),
            ProjectState::Quarantined => write!(f, "quarantined"),
        }
    }
}

/// Project status with optional reason as returned by PyPI Simple Index API
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProjectStatus {
    /// The current status of the project
    pub status: ProjectState,
    /// Optional explanation for the status (e.g., successor package name)
    pub reason: Option<String>,
}

impl Default for ProjectStatus {
    fn default() -> Self {
        Self {
            status: ProjectState::Active,
            reason: None,
        }
    }
}

/// Metadata from the Simple Index API response
#[derive(Debug, Clone, Deserialize)]
pub struct IndexMeta {
    /// API version
    #[serde(rename = "api-version")]
    pub api_version: String,
}

/// Package index response from PyPI Simple Index API
///
/// Represents the JSON response from `GET https://pypi.org/simple/{package}/`
/// with `Accept: application/vnd.pypi.simple.v1+json` header
#[derive(Debug, Clone, Deserialize)]
pub struct PackageIndex {
    /// Metadata about the API response
    pub meta: IndexMeta,
    /// Normalized package name
    pub name: String,
    /// Project status marker (PEP 792) - may be absent for active projects
    #[serde(rename = "project-status", default)]
    pub project_status: Option<ProjectStatus>,
    /// List of available versions/files (not fully parsed - we only need status)
    #[serde(default)]
    pub versions: Vec<String>,
}

impl PackageIndex {
    /// Get the effective project status, defaulting to Active if not specified
    pub fn effective_status(&self) -> ProjectStatus {
        self.project_status.clone().unwrap_or_default()
    }
}

/// Type of maintenance issue detected
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum MaintenanceIssueType {
    /// Package is archived and won't receive updates
    Archived,
    /// Package is deprecated (obsolete)
    Deprecated,
    /// Package is quarantined (malware/compromised)
    Quarantined,
}

impl MaintenanceIssueType {
    /// Get the corresponding project state
    pub fn as_project_state(&self) -> ProjectState {
        match self {
            MaintenanceIssueType::Archived => ProjectState::Archived,
            MaintenanceIssueType::Deprecated => ProjectState::Deprecated,
            MaintenanceIssueType::Quarantined => ProjectState::Quarantined,
        }
    }

    /// Check if this issue type should cause failure based on forbid settings
    pub fn should_fail(&self, config: &MaintenanceCheckConfig) -> bool {
        match self {
            MaintenanceIssueType::Archived => config.forbid_archived,
            MaintenanceIssueType::Deprecated => config.forbid_deprecated,
            MaintenanceIssueType::Quarantined => config.forbid_quarantined,
        }
    }
}

impl fmt::Display for MaintenanceIssueType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MaintenanceIssueType::Archived => write!(f, "ARCHIVED"),
            MaintenanceIssueType::Deprecated => write!(f, "DEPRECATED"),
            MaintenanceIssueType::Quarantined => write!(f, "QUARANTINED"),
        }
    }
}

/// A maintenance issue detected for a package
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MaintenanceIssue {
    /// The package name
    pub package_name: PackageName,
    /// The installed version of the package
    pub installed_version: Version,
    /// Type of maintenance issue
    pub issue_type: MaintenanceIssueType,
    /// Optional reason provided by PyPI for the status
    pub reason: Option<String>,
    /// Whether this is a direct dependency (vs transitive)
    pub is_direct: bool,
    /// Source file where this dependency was parsed from (e.g., "uv.lock", "poetry.lock")
    pub source_file: Option<String>,
}

impl MaintenanceIssue {
    /// Create a new maintenance issue
    pub fn new(
        package_name: PackageName,
        installed_version: Version,
        issue_type: MaintenanceIssueType,
        reason: Option<String>,
        is_direct: bool,
        source_file: Option<String>,
    ) -> Self {
        Self {
            package_name,
            installed_version,
            issue_type,
            reason,
            is_direct,
            source_file,
        }
    }
}

/// Configuration for maintenance checks
#[derive(Debug, Clone, Default)]
pub struct MaintenanceCheckConfig {
    /// Whether to fail on archived packages
    pub forbid_archived: bool,
    /// Whether to fail on deprecated packages
    pub forbid_deprecated: bool,
    /// Whether to fail on quarantined packages (user must opt-in)
    pub forbid_quarantined: bool,
    /// Only check direct dependencies (skip transitive)
    pub check_direct_only: bool,
}

/// Summary of maintenance issues for reporting
#[derive(Debug, Clone, Default)]
pub struct MaintenanceSummary {
    /// Number of archived packages found
    pub archived_count: usize,
    /// Number of deprecated packages found
    pub deprecated_count: usize,
    /// Number of quarantined packages found
    pub quarantined_count: usize,
    /// Total number of issues
    pub total_issues: usize,
    /// Number of issues affecting direct dependencies
    pub direct_issues: usize,
    /// Number of issues affecting transitive dependencies
    pub transitive_issues: usize,
}

impl MaintenanceSummary {
    /// Create a summary from a list of maintenance issues
    pub fn from_issues(issues: &[MaintenanceIssue]) -> Self {
        let mut summary = Self::default();

        for issue in issues {
            summary.total_issues += 1;

            match issue.issue_type {
                MaintenanceIssueType::Archived => summary.archived_count += 1,
                MaintenanceIssueType::Deprecated => summary.deprecated_count += 1,
                MaintenanceIssueType::Quarantined => summary.quarantined_count += 1,
            }

            if issue.is_direct {
                summary.direct_issues += 1;
            } else {
                summary.transitive_issues += 1;
            }
        }

        summary
    }

    /// Check if there are any issues
    pub fn has_issues(&self) -> bool {
        self.total_issues > 0
    }

    /// Check if any issues should cause failure based on config
    pub fn should_fail(&self, config: &MaintenanceCheckConfig) -> bool {
        (config.forbid_archived && self.archived_count > 0)
            || (config.forbid_deprecated && self.deprecated_count > 0)
            || (config.forbid_quarantined && self.quarantined_count > 0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    #[test]
    fn test_project_state_serialization() {
        assert_eq!(
            serde_json::to_string(&ProjectState::Active).unwrap(),
            "\"active\""
        );
        assert_eq!(
            serde_json::to_string(&ProjectState::Archived).unwrap(),
            "\"archived\""
        );
        assert_eq!(
            serde_json::to_string(&ProjectState::Deprecated).unwrap(),
            "\"deprecated\""
        );
        assert_eq!(
            serde_json::to_string(&ProjectState::Quarantined).unwrap(),
            "\"quarantined\""
        );
    }

    #[test]
    fn test_project_state_deserialization() {
        assert_eq!(
            serde_json::from_str::<ProjectState>("\"active\"").unwrap(),
            ProjectState::Active
        );
        assert_eq!(
            serde_json::from_str::<ProjectState>("\"archived\"").unwrap(),
            ProjectState::Archived
        );
        assert_eq!(
            serde_json::from_str::<ProjectState>("\"deprecated\"").unwrap(),
            ProjectState::Deprecated
        );
        assert_eq!(
            serde_json::from_str::<ProjectState>("\"quarantined\"").unwrap(),
            ProjectState::Quarantined
        );
    }

    #[test]
    fn test_project_state_default() {
        assert_eq!(ProjectState::default(), ProjectState::Active);
    }

    #[test]
    fn test_project_state_display() {
        assert_eq!(ProjectState::Active.to_string(), "active");
        assert_eq!(ProjectState::Archived.to_string(), "archived");
        assert_eq!(ProjectState::Deprecated.to_string(), "deprecated");
        assert_eq!(ProjectState::Quarantined.to_string(), "quarantined");
    }

    #[test]
    fn test_package_index_parsing_with_status() {
        let json = r#"{
            "meta": {"api-version": "1.0"},
            "name": "some-package",
            "project-status": {
                "status": "archived",
                "reason": "Package is no longer maintained"
            },
            "versions": ["1.0.0", "2.0.0"]
        }"#;

        let index: PackageIndex = serde_json::from_str(json).unwrap();
        assert_eq!(index.name, "some-package");
        assert!(index.project_status.is_some());
        let status = index.project_status.unwrap();
        assert_eq!(status.status, ProjectState::Archived);
        assert_eq!(
            status.reason,
            Some("Package is no longer maintained".to_string())
        );
    }

    #[test]
    fn test_package_index_parsing_without_status() {
        let json = r#"{
            "meta": {"api-version": "1.0"},
            "name": "active-package",
            "versions": ["1.0.0"]
        }"#;

        let index: PackageIndex = serde_json::from_str(json).unwrap();
        assert_eq!(index.name, "active-package");
        assert!(index.project_status.is_none());
        let effective = index.effective_status();
        assert_eq!(effective.status, ProjectState::Active);
    }

    #[test]
    fn test_package_index_parsing_quarantined() {
        let json = r#"{
            "meta": {"api-version": "1.0"},
            "name": "malicious-pkg",
            "project-status": {
                "status": "quarantined",
                "reason": "Package identified as malware"
            },
            "versions": []
        }"#;

        let index: PackageIndex = serde_json::from_str(json).unwrap();
        let status = index.effective_status();
        assert_eq!(status.status, ProjectState::Quarantined);
        assert_eq!(
            status.reason,
            Some("Package identified as malware".to_string())
        );
    }

    #[test]
    fn test_maintenance_issue_type_display() {
        assert_eq!(MaintenanceIssueType::Archived.to_string(), "ARCHIVED");
        assert_eq!(MaintenanceIssueType::Deprecated.to_string(), "DEPRECATED");
        assert_eq!(MaintenanceIssueType::Quarantined.to_string(), "QUARANTINED");
    }

    #[test]
    fn test_maintenance_summary_from_issues() {
        let issues = vec![
            MaintenanceIssue::new(
                PackageName::from_str("pkg1").unwrap(),
                Version::from_str("1.0.0").unwrap(),
                MaintenanceIssueType::Archived,
                None,
                true,
                None,
            ),
            MaintenanceIssue::new(
                PackageName::from_str("pkg2").unwrap(),
                Version::from_str("2.0.0").unwrap(),
                MaintenanceIssueType::Quarantined,
                Some("Malware detected".to_string()),
                false,
                None,
            ),
            MaintenanceIssue::new(
                PackageName::from_str("pkg3").unwrap(),
                Version::from_str("3.0.0").unwrap(),
                MaintenanceIssueType::Deprecated,
                None,
                true,
                None,
            ),
        ];

        let summary = MaintenanceSummary::from_issues(&issues);
        assert_eq!(summary.total_issues, 3);
        assert_eq!(summary.archived_count, 1);
        assert_eq!(summary.deprecated_count, 1);
        assert_eq!(summary.quarantined_count, 1);
        assert_eq!(summary.direct_issues, 2);
        assert_eq!(summary.transitive_issues, 1);
    }

    #[test]
    fn test_maintenance_summary_should_fail() {
        let issues = vec![MaintenanceIssue::new(
            PackageName::from_str("pkg").unwrap(),
            Version::from_str("1.0.0").unwrap(),
            MaintenanceIssueType::Archived,
            None,
            true,
            None,
        )];

        let summary = MaintenanceSummary::from_issues(&issues);

        // Default config doesn't fail on archived
        let default_config = MaintenanceCheckConfig::default();
        assert!(!summary.should_fail(&default_config));

        // Config with forbid_archived should fail
        let strict_config = MaintenanceCheckConfig {
            forbid_archived: true,
            ..Default::default()
        };
        assert!(summary.should_fail(&strict_config));
    }

    #[test]
    fn test_maintenance_check_config_default() {
        let config = MaintenanceCheckConfig::default();
        assert!(!config.forbid_archived);
        assert!(!config.forbid_deprecated);
        assert!(!config.forbid_quarantined); // User must opt-in
        assert!(!config.check_direct_only);
    }

    #[test]
    fn test_issue_type_should_fail() {
        // Default config doesn't fail on any issue type (user must opt-in)
        let default_config = MaintenanceCheckConfig::default();
        assert!(!MaintenanceIssueType::Archived.should_fail(&default_config));
        assert!(!MaintenanceIssueType::Deprecated.should_fail(&default_config));
        assert!(!MaintenanceIssueType::Quarantined.should_fail(&default_config));

        // Config with forbid_quarantined should fail on quarantined
        let strict_config = MaintenanceCheckConfig {
            forbid_quarantined: true,
            ..Default::default()
        };
        assert!(!MaintenanceIssueType::Archived.should_fail(&strict_config));
        assert!(!MaintenanceIssueType::Deprecated.should_fail(&strict_config));
        assert!(MaintenanceIssueType::Quarantined.should_fail(&strict_config));
    }
}
