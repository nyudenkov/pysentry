// SPDX-License-Identifier: MIT

//! PEP 792 Project Status Markers support
//!
//! This module provides support for detecting and reporting PEP 792 project
//! status markers (archived, deprecated, quarantined) for Python packages.
//!
//! See: https://peps.python.org/pep-0792/

pub mod client;
pub mod types;

pub use client::SimpleIndexClient;
pub use types::{
    MaintenanceCheckConfig, MaintenanceIssue, MaintenanceIssueType, MaintenanceSummary,
    PackageIndex, ProjectState, ProjectStatus,
};
