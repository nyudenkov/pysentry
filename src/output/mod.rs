// SPDX-License-Identifier: MIT

//! Output generation module

pub use report::{AuditReport, AuditSummary, DetailLevel, ReportGenerator};
pub use sarif::SarifGenerator;
pub use styles::OutputStyles;

pub mod report;
pub mod sarif;
pub mod styles;
