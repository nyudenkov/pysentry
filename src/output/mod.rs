// SPDX-License-Identifier: MIT

//! Output generation module

pub use model::{AuditReport, AuditSummary, DetailLevel, DisplayMode};
pub use styles::OutputStyles;

pub(crate) mod human;
pub(crate) mod json;
pub(crate) mod markdown;
pub(crate) mod model;
pub(crate) mod sarif;
pub(crate) mod styles;

use crate::types::AuditFormat;
use human::generate_human_report;
use json::generate_json_report;
use markdown::generate_markdown_report;
use sarif::generate_sarif_report;
use std::path::Path;

pub fn generate_report(
    report: &AuditReport,
    format: AuditFormat,
    project_root: Option<&Path>,
    detail_level: DetailLevel,
    display_mode: DisplayMode,
    styles: &OutputStyles,
) -> Result<String, Box<dyn std::error::Error>> {
    match format {
        AuditFormat::Human => generate_human_report(report, detail_level, display_mode, styles),
        AuditFormat::Json => generate_json_report(report),
        AuditFormat::Markdown => generate_markdown_report(report),
        AuditFormat::Sarif => generate_sarif_report(report, project_root),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::output::model::test_helpers::create_test_report;
    use crate::types::AuditFormat;

    #[test]
    fn test_generate_report_all_formats() {
        let report = create_test_report();
        let project_root = Some(std::path::Path::new("."));
        let styles = OutputStyles::default();

        let human_output = generate_report(
            &report,
            AuditFormat::Human,
            project_root,
            DetailLevel::Normal,
            DisplayMode::Table,
            &styles,
        )
        .unwrap();
        assert!(human_output.contains("PYSENTRY SECURITY AUDIT"));
        assert!(human_output.contains("GHSA-test-1234"));

        let json_output = generate_report(
            &report,
            AuditFormat::Json,
            project_root,
            DetailLevel::Normal,
            DisplayMode::Table,
            &styles,
        )
        .unwrap();
        let json: serde_json::Value = serde_json::from_str(&json_output).unwrap();
        assert_eq!(json["total_packages"], 10);

        let sarif_output = generate_report(
            &report,
            AuditFormat::Sarif,
            project_root,
            DetailLevel::Normal,
            DisplayMode::Table,
            &styles,
        )
        .unwrap();
        let sarif: serde_json::Value = serde_json::from_str(&sarif_output).unwrap();
        assert_eq!(sarif["version"], "2.1.0");

        let markdown_output = generate_report(
            &report,
            AuditFormat::Markdown,
            project_root,
            DetailLevel::Normal,
            DisplayMode::Table,
            &styles,
        )
        .unwrap();
        assert!(markdown_output.contains("# 🛡️ pysentry report"));
    }
}
