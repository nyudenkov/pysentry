// SPDX-License-Identifier: MIT

//! Output generation module

pub use report::{AuditReport, AuditSummary, DetailLevel, ReportGenerator};
pub use sarif::SarifGenerator;

pub mod report;
pub mod sarif;
