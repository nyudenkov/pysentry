//! Output generation module

pub use report::{AuditReport, AuditSummary, ReportGenerator};
pub use sarif::SarifGenerator;

pub mod report;
pub mod sarif;
