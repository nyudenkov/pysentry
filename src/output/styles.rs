// SPDX-License-Identifier: MIT

use crate::maintenance::MaintenanceIssueType;
use crate::vulnerability::database::Severity;
use owo_colors::Style;

/// Centralized stylesheet for terminal output styling.
///
/// Use `OutputStyles::colorized()` when colors are desired, `OutputStyles::default()`
/// for plain text (NO_COLOR, piped output, --color=never).
#[derive(Debug)]
pub struct OutputStyles {
    pub critical_bg: Style,
    pub high: Style,
    pub medium: Style,
    pub low: Style,
    pub unknown: Style,
    pub package: Style,
    pub vuln_id: Style,
    pub header: Style,
    pub fix_arrow: Style,
    pub fix_suggestion: Style,
    pub dimmed: Style,
    pub success_check: Style,
    pub withdrawn_tag: Style,
    pub maintenance_quarantined: Style,
    pub maintenance_archived: Style,
    pub maintenance_deprecated: Style,
}

impl Default for OutputStyles {
    fn default() -> Self {
        Self {
            critical_bg: Style::new(),
            high: Style::new(),
            medium: Style::new(),
            low: Style::new(),
            unknown: Style::new(),
            package: Style::new(),
            vuln_id: Style::new(),
            header: Style::new(),
            fix_arrow: Style::new(),
            fix_suggestion: Style::new(),
            dimmed: Style::new(),
            success_check: Style::new(),
            withdrawn_tag: Style::new(),
            maintenance_quarantined: Style::new(),
            maintenance_archived: Style::new(),
            maintenance_deprecated: Style::new(),
        }
    }
}

impl OutputStyles {
    /// Colorized stylesheet matching the current color scheme.
    pub fn colorized() -> Self {
        Self {
            critical_bg: Style::new().on_red().white().bold(),
            high: Style::new().red().bold(),
            medium: Style::new().yellow().bold(),
            low: Style::new().green().bold(),
            unknown: Style::new().blue().dimmed(),
            package: Style::new().bold(),
            vuln_id: Style::new().cyan().bold(),
            header: Style::new().bold(),
            fix_arrow: Style::new().cyan(),
            fix_suggestion: Style::new().blue(),
            dimmed: Style::new().dimmed(),
            success_check: Style::new().green().bold(),
            withdrawn_tag: Style::new().yellow().bold(),
            maintenance_quarantined: Style::new().on_red().white().bold(),
            maintenance_archived: Style::new().yellow().bold(),
            maintenance_deprecated: Style::new().blue().bold(),
        }
    }

    /// Returns the text style for a severity level (used for inline severity labels).
    pub fn severity(&self, s: &Severity) -> &Style {
        match s {
            Severity::Critical => &self.critical_bg,
            Severity::High => &self.high,
            Severity::Medium => &self.medium,
            Severity::Low => &self.low,
            Severity::Unknown => &self.unknown,
        }
    }

    /// Returns the style for maintenance issue type labels.
    pub fn maintenance(&self, t: &MaintenanceIssueType) -> &Style {
        match t {
            MaintenanceIssueType::Quarantined => &self.maintenance_quarantined,
            MaintenanceIssueType::Archived => &self.maintenance_archived,
            MaintenanceIssueType::Deprecated => &self.maintenance_deprecated,
        }
    }
}

/// Emoji icon for a severity level, used in markdown and compact output.
pub fn severity_icon(s: &Severity) -> &'static str {
    match s {
        Severity::Critical => "🔴",
        Severity::High => "🟠",
        Severity::Medium => "🟡",
        Severity::Low => "🟢",
        Severity::Unknown => "⚪",
    }
}

/// Emoji icon for a maintenance issue type.
pub fn maintenance_icon(t: &MaintenanceIssueType) -> &'static str {
    match t {
        MaintenanceIssueType::Quarantined => "🔴",
        MaintenanceIssueType::Archived => "📦",
        MaintenanceIssueType::Deprecated => "⚠️",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use owo_colors::OwoColorize;

    #[test]
    fn test_default_styles_produce_no_ansi() {
        let styles = OutputStyles::default();
        let text = "CRITICAL";
        let styled = format!("{}", text.style(styles.critical_bg));
        assert_eq!(styled, text, "Default styles should produce no ANSI codes");
    }

    #[test]
    fn test_colorized_styles_produce_ansi() {
        let styles = OutputStyles::colorized();
        let text = "CRITICAL";
        let styled = format!("{}", text.style(styles.critical_bg));
        assert!(
            styled.contains('\x1b'),
            "Colorized styles should contain ANSI escape codes"
        );
    }

    #[test]
    fn test_severity_style_mapping() {
        let styles = OutputStyles::default();
        // Should not panic for any variant
        let _ = styles.severity(&Severity::Critical);
        let _ = styles.severity(&Severity::High);
        let _ = styles.severity(&Severity::Medium);
        let _ = styles.severity(&Severity::Low);
        let _ = styles.severity(&Severity::Unknown);
    }

    #[test]
    fn test_maintenance_style_mapping() {
        let styles = OutputStyles::default();
        let _ = styles.maintenance(&MaintenanceIssueType::Quarantined);
        let _ = styles.maintenance(&MaintenanceIssueType::Archived);
        let _ = styles.maintenance(&MaintenanceIssueType::Deprecated);
    }

    #[test]
    fn test_severity_icon() {
        assert_eq!(severity_icon(&Severity::Critical), "🔴");
        assert_eq!(severity_icon(&Severity::High), "🟠");
        assert_eq!(severity_icon(&Severity::Medium), "🟡");
        assert_eq!(severity_icon(&Severity::Low), "🟢");
        assert_eq!(severity_icon(&Severity::Unknown), "⚪");
    }
}
