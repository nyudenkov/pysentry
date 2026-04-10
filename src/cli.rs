// SPDX-License-Identifier: MIT

//! CLI interface definitions shared between binary and Python bindings

use crate::logging::AppVerbosity;
use crate::types::ResolverType;
use anyhow::Result;
use clap::{Parser, Subcommand, ValueEnum};

#[derive(Debug, Clone, PartialEq, ValueEnum)]
pub enum AuditFormat {
    #[value(name = "human")]
    Human,
    #[value(name = "json")]
    Json,
    #[value(name = "sarif")]
    Sarif,
    #[value(name = "markdown")]
    Markdown,
}

#[derive(Debug, Clone, PartialEq, ValueEnum)]
pub enum SeverityLevel {
    #[value(name = "low")]
    Low,
    #[value(name = "medium")]
    Medium,
    #[value(name = "high")]
    High,
    #[value(name = "critical")]
    Critical,
}

#[derive(Debug, Clone, ValueEnum, PartialEq)]
pub enum VulnerabilitySourceType {
    #[value(name = "pypa")]
    Pypa,
    #[value(name = "pypi")]
    Pypi,
    #[value(name = "osv")]
    Osv,
}

#[derive(Debug, Clone, PartialEq, ValueEnum)]
pub enum ResolverTypeArg {
    #[value(name = "uv")]
    Uv,
    #[value(name = "pip-tools")]
    PipTools,
}

#[derive(Debug, Clone, Copy, PartialEq, ValueEnum, Default)]
pub enum ColorChoice {
    /// Auto-detect: use colors when stdout is a terminal and NO_COLOR is unset
    #[default]
    Auto,
    /// Always emit ANSI color codes
    Always,
    /// Never emit ANSI color codes
    Never,
}

#[derive(Debug, Clone, Copy, PartialEq, ValueEnum, Default)]
pub enum DisplayModeArg {
    /// Traditional text-based formatting (indented lines, manual spacing)
    #[value(name = "text")]
    Text,
    /// Structured table rendering (default, compact mode only)
    #[default]
    #[value(name = "table")]
    Table,
}

/// Resolve an `OutputStyles` instance from a `ColorChoice`.
///
/// `Always` → colorized (forces ANSI on); `Never` → plain (forces ANSI off);
/// `Auto` delegates entirely to `supports-color`, which handles `NO_COLOR`
/// (any value, including empty), `FORCE_COLOR`, `isatty`, CI environments,
/// and `TERM=dumb` per the terminal standards specs.
pub fn resolve_styles(color: ColorChoice) -> crate::output::OutputStyles {
    match color {
        ColorChoice::Always => {
            owo_colors::set_override(true);
            crate::output::OutputStyles::colorized()
        }
        ColorChoice::Never => {
            owo_colors::set_override(false);
            crate::output::OutputStyles::default()
        }
        ColorChoice::Auto => {
            // supports-color handles NO_COLOR, FORCE_COLOR, isatty, CI, TERM=dumb
            crate::output::OutputStyles::colorized()
        }
    }
}

#[derive(Parser)]
#[command(
    name = "pysentry",
    about = "Security vulnerability auditing for Python packages",
    version
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Option<Commands>,

    /// Control color output
    #[arg(long, value_enum, default_value = "auto", global = true)]
    pub color: ColorChoice,

    /// Audit arguments (used when no subcommand specified)
    #[command(flatten)]
    pub audit_args: AuditArgs,
}

#[derive(Debug, Subcommand)]
pub enum Commands {
    /// Check available dependency resolvers
    Resolvers(ResolversArgs),
    /// Check if a newer version is available
    CheckVersion(CheckVersionArgs),
    /// Configuration management
    #[command(subcommand)]
    Config(ConfigCommands),
}

#[derive(Debug, Subcommand)]
pub enum ConfigCommands {
    /// Initialize a new configuration file
    Init(ConfigInitArgs),
    /// Validate configuration file
    Validate(ConfigValidateArgs),
    /// Show effective configuration
    Show(ConfigShowArgs),
    /// Show configuration file path
    Path(ConfigPathArgs),
}

#[derive(Debug, Clone, Parser)]
pub struct AuditArgs {
    /// Path to the project directory to audit
    #[arg(value_name = "PATH", default_value = ".")]
    pub path: std::path::PathBuf,

    /// Output format
    #[arg(long, value_enum, default_value = "human")]
    pub format: AuditFormat,

    /// Fail (exit non-zero) if vulnerabilities of this level or higher are found
    #[arg(long, value_enum, default_value = "medium")]
    pub fail_on: SeverityLevel,

    /// Vulnerability IDs to ignore (can be specified multiple times)
    #[arg(long = "ignore", value_name = "ID")]
    pub ignore_ids: Vec<String>,

    /// Vulnerability IDs to ignore only while no fix is available (can be specified multiple times)
    #[arg(long = "ignore-while-no-fix", value_name = "ID")]
    pub ignore_while_no_fix: Vec<String>,

    /// Output file path (defaults to stdout)
    #[arg(long, short, value_name = "FILE")]
    pub output: Option<std::path::PathBuf>,

    /// Exclude extra dependencies (dev, optional, etc - only include main dependencies)
    #[arg(long)]
    pub exclude_extra: bool,

    /// Only check direct dependencies (exclude transitive)
    #[arg(long)]
    pub direct_only: bool,

    /// Include withdrawn vulnerabilities in results
    #[arg(long)]
    pub include_withdrawn: bool,

    /// Disable caching
    #[arg(long)]
    pub no_cache: bool,

    /// Custom cache directory
    #[arg(long, value_name = "DIR")]
    pub cache_dir: Option<std::path::PathBuf>,

    /// Resolution cache TTL in hours (default: 24)
    #[arg(long, value_name = "HOURS", default_value = "24")]
    pub resolution_cache_ttl: u64,

    /// Disable resolution caching only
    #[arg(long)]
    pub no_resolution_cache: bool,

    /// Clear resolution cache on startup
    #[arg(long)]
    pub clear_resolution_cache: bool,

    /// Vulnerability data sources (can be specified multiple times or comma-separated)
    #[arg(long = "sources", value_name = "SOURCE")]
    pub sources: Vec<String>,

    /// Dependency resolver for requirements.txt files
    #[arg(long, value_enum, default_value = "uv")]
    pub resolver: ResolverTypeArg,

    /// Specific requirements files to audit (disables auto-discovery)
    #[arg(long = "requirements-files", value_name = "FILE", num_args = 1..)]
    pub requirements_files: Vec<std::path::PathBuf>,

    /// Verbosity level: use -v, -vv, -vvv for more output, -q for quiet
    #[command(flatten)]
    pub verbosity: AppVerbosity,

    /// Set to true when `output.quiet = true` is read from config (not a CLI arg).
    #[arg(skip)]
    pub config_quiet: bool,

    /// Show detailed vulnerability descriptions (full text instead of truncated)
    #[arg(long, conflicts_with = "compact")]
    pub detailed: bool,

    /// Compact output: summary + one-liner per vulnerability, no descriptions
    #[arg(long, conflicts_with = "detailed")]
    pub compact: bool,

    /// Display mode for human output. Only affects compact mode (`--compact`).
    #[arg(long, value_enum)]
    pub display: Option<DisplayModeArg>,

    /// Custom configuration file path
    #[arg(long, value_name = "FILE")]
    pub config: Option<std::path::PathBuf>,

    /// Disable configuration file loading
    #[arg(long)]
    pub no_config: bool,

    // PEP 792 Project Status Markers options
    /// Disable PEP 792 project status checks
    #[arg(long)]
    pub no_maintenance_check: bool,

    /// Fail on archived packages (not receiving updates)
    #[arg(long)]
    pub forbid_archived: bool,

    /// Fail on deprecated packages (obsolete)
    #[arg(long)]
    pub forbid_deprecated: bool,

    /// Fail on quarantined packages (malware/compromised)
    #[arg(long)]
    pub forbid_quarantined: bool,

    /// Fail on any unmaintained packages (enables --forbid-archived, --forbid-deprecated, --forbid-quarantined)
    #[arg(long)]
    pub forbid_unmaintained: bool,

    /// Only check direct dependencies for maintenance status (skip transitive)
    #[arg(long)]
    pub maintenance_direct_only: bool,

    /// Don't fail on vulnerabilities with unknown level
    #[arg(long)]
    pub no_fail_on_unknown: bool,

    /// Disable automatic CI environment detection
    #[arg(long)]
    pub no_ci_detect: bool,

    /// Skip dependency resolution; audit pinned packages (package==version) as-is.
    /// Unpinned packages are skipped. Implies --direct-only.
    #[arg(long)]
    pub no_resolver: bool,
}

impl AuditArgs {
    /// Resolve the effective detail level from --compact / --detailed flags.
    pub fn detail_level(&self) -> crate::DetailLevel {
        if self.compact {
            crate::DetailLevel::Compact
        } else if self.detailed {
            crate::DetailLevel::Detailed
        } else {
            crate::DetailLevel::Normal
        }
    }

    /// Resolve the effective display mode from --display flag.
    pub fn display_mode(&self) -> crate::DisplayMode {
        self.display.unwrap_or(DisplayModeArg::Table).into()
    }

    /// Check if quiet mode is enabled (either via -q flag or config).
    pub fn is_quiet(&self) -> bool {
        self.config_quiet || crate::logging::is_quiet(&self.verbosity)
    }

    /// Check if verbose mode is enabled (via -v flags or config).
    pub fn is_verbose(&self) -> bool {
        crate::logging::is_verbose(&self.verbosity)
    }

    fn include_all_dependencies(&self) -> bool {
        !self.exclude_extra
    }

    pub fn include_dev(&self) -> bool {
        self.include_all_dependencies()
    }

    pub fn include_optional(&self) -> bool {
        self.include_all_dependencies()
    }

    /// Check if maintenance checks are enabled
    pub fn maintenance_enabled(&self) -> bool {
        !self.no_maintenance_check
    }

    /// Create a MaintenanceCheckConfig from CLI args
    pub fn maintenance_check_config(&self) -> crate::MaintenanceCheckConfig {
        crate::MaintenanceCheckConfig {
            forbid_archived: self.forbid_archived || self.forbid_unmaintained,
            forbid_deprecated: self.forbid_deprecated || self.forbid_unmaintained,
            forbid_quarantined: self.forbid_quarantined || self.forbid_unmaintained,
            check_direct_only: self.maintenance_direct_only,
        }
    }

    pub fn ci_environment(&self) -> crate::ci::CiEnvironment {
        if self.no_ci_detect {
            crate::ci::CiEnvironment::None
        } else {
            crate::ci::detect()
        }
    }

    pub fn scope_description(&self) -> &'static str {
        if self.include_all_dependencies() {
            "all (main + dev,optional,prod,etc)"
        } else {
            "main only (extras excluded)"
        }
    }

    pub fn resolve_sources(&self) -> Result<Vec<VulnerabilitySourceType>, String> {
        if self.sources.is_empty() {
            return Ok(vec![
                VulnerabilitySourceType::Pypa,
                VulnerabilitySourceType::Pypi,
                VulnerabilitySourceType::Osv,
            ]);
        }

        let mut resolved_sources = Vec::new();
        for source_arg in &self.sources {
            for source_str in source_arg.split(',') {
                let source_str = source_str.trim();
                if source_str.is_empty() {
                    continue;
                }
                let source_type = match source_str {
                    "pypa" => VulnerabilitySourceType::Pypa,
                    "pypi" => VulnerabilitySourceType::Pypi,
                    "osv" => VulnerabilitySourceType::Osv,
                    _ => {
                        return Err(format!(
                            "Invalid vulnerability source: '{source_str}'. Valid sources: pypa, pypi, osv"
                        ))
                    }
                };
                if !resolved_sources.contains(&source_type) {
                    resolved_sources.push(source_type);
                }
            }
        }

        Ok(resolved_sources)
    }
}

#[derive(Debug, Parser)]
pub struct ResolversArgs {
    /// Verbosity level: use -v, -vv, -vvv for more output, -q for quiet
    #[command(flatten)]
    pub verbosity: AppVerbosity,
}

impl ResolversArgs {
    pub fn is_verbose(&self) -> bool {
        crate::logging::is_verbose(&self.verbosity)
    }

    pub fn is_quiet(&self) -> bool {
        crate::logging::is_quiet(&self.verbosity)
    }
}

#[derive(Debug, Parser)]
pub struct CheckVersionArgs {
    /// Verbosity level: use -v, -vv, -vvv for more output, -q for quiet
    #[command(flatten)]
    pub verbosity: AppVerbosity,
}

impl CheckVersionArgs {
    pub fn is_verbose(&self) -> bool {
        crate::logging::is_verbose(&self.verbosity)
    }

    pub fn is_quiet(&self) -> bool {
        crate::logging::is_quiet(&self.verbosity)
    }
}

#[derive(Debug, Parser)]
pub struct ConfigInitArgs {
    #[arg(long, short, value_name = "FILE")]
    pub output: Option<std::path::PathBuf>,

    #[arg(long)]
    pub force: bool,

    #[arg(long)]
    pub minimal: bool,

    /// Verbosity level: use -v, -vv, -vvv for more output, -q for quiet
    #[command(flatten)]
    pub verbosity: AppVerbosity,
}

impl ConfigInitArgs {
    pub fn is_verbose(&self) -> bool {
        crate::logging::is_verbose(&self.verbosity)
    }

    pub fn is_quiet(&self) -> bool {
        crate::logging::is_quiet(&self.verbosity)
    }
}

#[derive(Debug, Parser)]
pub struct ConfigValidateArgs {
    #[arg(value_name = "FILE")]
    pub config: Option<std::path::PathBuf>,

    /// Verbosity level: use -v, -vv, -vvv for more output, -q for quiet
    #[command(flatten)]
    pub verbosity: AppVerbosity,
}

impl ConfigValidateArgs {
    pub fn is_verbose(&self) -> bool {
        crate::logging::is_verbose(&self.verbosity)
    }

    pub fn is_quiet(&self) -> bool {
        crate::logging::is_quiet(&self.verbosity)
    }
}

#[derive(Debug, Parser)]
pub struct ConfigShowArgs {
    #[arg(long, value_name = "FILE")]
    pub config: Option<std::path::PathBuf>,

    #[arg(long)]
    pub toml: bool,

    /// Verbosity level: use -v, -vv, -vvv for more output, -q for quiet
    #[command(flatten)]
    pub verbosity: AppVerbosity,
}

impl ConfigShowArgs {
    pub fn is_verbose(&self) -> bool {
        crate::logging::is_verbose(&self.verbosity)
    }

    pub fn is_quiet(&self) -> bool {
        crate::logging::is_quiet(&self.verbosity)
    }
}

#[derive(Debug, Parser)]
pub struct ConfigPathArgs {
    /// Verbosity level: use -v, -vv, -vvv for more output, -q for quiet
    #[command(flatten)]
    pub verbosity: AppVerbosity,
}

impl ConfigPathArgs {
    pub fn is_verbose(&self) -> bool {
        crate::logging::is_verbose(&self.verbosity)
    }
}

impl From<AuditFormat> for crate::AuditFormat {
    fn from(format: AuditFormat) -> Self {
        match format {
            AuditFormat::Human => crate::AuditFormat::Human,
            AuditFormat::Json => crate::AuditFormat::Json,
            AuditFormat::Sarif => crate::AuditFormat::Sarif,
            AuditFormat::Markdown => crate::AuditFormat::Markdown,
        }
    }
}

impl From<SeverityLevel> for crate::SeverityLevel {
    fn from(level: SeverityLevel) -> Self {
        match level {
            SeverityLevel::Low => crate::SeverityLevel::Low,
            SeverityLevel::Medium => crate::SeverityLevel::Medium,
            SeverityLevel::High => crate::SeverityLevel::High,
            SeverityLevel::Critical => crate::SeverityLevel::Critical,
        }
    }
}

impl From<VulnerabilitySourceType> for crate::VulnerabilitySourceType {
    fn from(source: VulnerabilitySourceType) -> Self {
        match source {
            VulnerabilitySourceType::Pypa => crate::VulnerabilitySourceType::Pypa,
            VulnerabilitySourceType::Pypi => crate::VulnerabilitySourceType::Pypi,
            VulnerabilitySourceType::Osv => crate::VulnerabilitySourceType::Osv,
        }
    }
}

impl From<ResolverTypeArg> for ResolverType {
    fn from(resolver: ResolverTypeArg) -> Self {
        match resolver {
            ResolverTypeArg::Uv => ResolverType::Uv,
            ResolverTypeArg::PipTools => ResolverType::PipTools,
        }
    }
}

impl From<DisplayModeArg> for crate::DisplayMode {
    fn from(mode: DisplayModeArg) -> Self {
        match mode {
            DisplayModeArg::Text => crate::DisplayMode::Text,
            DisplayModeArg::Table => crate::DisplayMode::Table,
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::DetailLevel;

    fn parse_audit_args(args: &[&str]) -> AuditArgs {
        let cli = Cli::try_parse_from(std::iter::once("pysentry").chain(args.iter().copied()))
            .expect("valid CLI args");
        cli.audit_args
    }

    #[test]
    fn test_detail_level_defaults_to_normal() {
        let args = parse_audit_args(&["."]);
        assert_eq!(args.detail_level(), DetailLevel::Normal);
    }

    #[test]
    fn test_detail_level_compact() {
        let args = parse_audit_args(&["--compact", "."]);
        assert_eq!(args.detail_level(), DetailLevel::Compact);
    }

    #[test]
    fn test_detail_level_detailed() {
        let args = parse_audit_args(&["--detailed", "."]);
        assert_eq!(args.detail_level(), DetailLevel::Detailed);
    }

    #[test]
    fn test_display_defaults_to_table() {
        let args = parse_audit_args(&["."]);
        assert_eq!(args.display, None);
    }

    #[test]
    fn test_display_text_flag() {
        let args = parse_audit_args(&["--display", "text", "."]);
        assert_eq!(args.display, Some(DisplayModeArg::Text));
    }

    #[test]
    fn test_no_resolver_flag_parsed() {
        let args = parse_audit_args(&["--no-resolver", "."]);
        assert!(args.no_resolver);
    }

    #[test]
    fn test_no_resolver_default_is_false() {
        let args = parse_audit_args(&["."]);
        assert!(!args.no_resolver);
    }

    #[test]
    fn test_no_resolver_without_requirements_files_has_empty_requirements_files() {
        let args = parse_audit_args(&["--no-resolver", "."]);
        // Standalone --no-resolver must NOT auto-populate requirements_files at arg-parse time.
        // The downstream conditions `|| audit_args.no_resolver` exist precisely because
        // requirements_files is empty in this case.
        assert!(args.requirements_files.is_empty());
        assert!(args.no_resolver);
    }

    #[test]
    fn test_no_resolver_with_requirements_files() {
        let args = parse_audit_args(&["--no-resolver", "--requirements-files", "req.txt", "."]);
        assert!(!args.requirements_files.is_empty());
        assert!(args.no_resolver);
    }
}
