/*
 * pysentry - Python security vulnerability scanner
 * Copyright (C) 2025 nyudenkov <nyudenkov@pm.me>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

//! CLI interface definitions shared between binary and Python bindings

use anyhow::{Context, Result};
use clap::{Parser, Subcommand, ValueEnum};
use futures::future::try_join_all;
use std::path::Path;
use std::sync::Once;

use crate::dependency::resolvers::ResolverRegistry;
use crate::parsers::{requirements::RequirementsParser, DependencyStats};
use crate::types::{ResolverType, Version};
use crate::{
    AuditCache, AuditReport, Config, ConfigLoader, DependencyScanner, MatcherConfig,
    ReportGenerator, VulnerabilityDatabase, VulnerabilityMatcher, VulnerabilitySource,
};
use std::str::FromStr;

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

#[derive(Parser)]
#[command(
    name = "pysentry",
    about = "Security vulnerability auditing for Python packages",
    version
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Option<Commands>,

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

    /// Minimum severity level to report
    #[arg(long, value_enum, default_value = "low")]
    pub severity: SeverityLevel,

    /// Fail (exit non-zero) if vulnerabilities of this severity or higher are found
    #[arg(long, value_enum, default_value = "medium")]
    pub fail_on: SeverityLevel,

    /// Vulnerability IDs to ignore (can be specified multiple times)
    #[arg(long = "ignore", value_name = "ID")]
    pub ignore_ids: Vec<String>,

    /// Output file path (defaults to stdout)
    #[arg(long, short, value_name = "FILE")]
    pub output: Option<std::path::PathBuf>,

    /// Include ALL dependencies (main + dev, optional, etc) [DEPRECATED: use --all-extras instead]
    #[arg(long, hide = true)]
    pub all: bool,

    /// Include ALL extra dependencies (main + dev, optional, etc)
    #[arg(long)]
    pub all_extras: bool,

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

    /// Vulnerability data source [DEPRECATED: use --sources instead]
    #[arg(long, value_enum, default_value = "pypa", hide = true)]
    pub source: VulnerabilitySourceType,

    /// Vulnerability data sources (can be specified multiple times or comma-separated)
    #[arg(long = "sources", value_name = "SOURCE")]
    pub sources: Vec<String>,

    /// Dependency resolver for requirements.txt files
    #[arg(long, value_enum, default_value = "uv")]
    pub resolver: ResolverTypeArg,

    /// Specific requirements files to audit (disables auto-discovery)
    #[arg(long = "requirements-files", value_name = "FILE", num_args = 1..)]
    pub requirements_files: Vec<std::path::PathBuf>,

    /// Enable verbose output
    #[arg(long, short)]
    pub verbose: bool,

    /// Suppress non-error output
    #[arg(long, short)]
    pub quiet: bool,

    /// Show detailed vulnerability descriptions (full text instead of truncated)
    #[arg(long)]
    pub detailed: bool,

    /// Custom configuration file path
    #[arg(long, value_name = "FILE")]
    pub config: Option<std::path::PathBuf>,

    /// Disable configuration file loading
    #[arg(long)]
    pub no_config: bool,
}

impl AuditArgs {
    fn include_all_dependencies(&self) -> bool {
        static DEPRECATION_WARNING_SHOWN: Once = Once::new();

        if self.all && self.all_extras {
            DEPRECATION_WARNING_SHOWN.call_once(|| {
                eprintln!("Warning: Both --all and --all-extras flags are specified. Using --all-extras only. The --all flag is deprecated.");
            });
            return true;
        }

        if self.all {
            DEPRECATION_WARNING_SHOWN.call_once(|| {
                eprintln!("Warning: --all flag is deprecated and will be removed in a future version. Use --all-extras instead.");
            });
            return true;
        }

        self.all_extras
    }

    pub fn include_dev(&self) -> bool {
        self.include_all_dependencies()
    }

    pub fn include_optional(&self) -> bool {
        self.include_all_dependencies()
    }

    pub fn scope_description(&self) -> &'static str {
        if self.include_all_dependencies() {
            "all (main + dev,optional,prod,etc)"
        } else {
            "main only"
        }
    }

    pub fn filter_dependencies(
        &self,
        dependencies: Vec<crate::parsers::ParsedDependency>,
    ) -> Vec<crate::parsers::ParsedDependency> {
        if self.include_all_dependencies() {
            dependencies
        } else {
            dependencies
                .into_iter()
                .filter(|dep| matches!(dep.dependency_type, crate::parsers::DependencyType::Main))
                .collect()
        }
    }

    pub fn resolve_sources(&self) -> Result<Vec<VulnerabilitySourceType>, String> {
        use std::sync::Once;
        static DEPRECATION_WARNING_SHOWN: Once = Once::new();

        let mut resolved_sources = Vec::new();

        if !self.sources.is_empty() {
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
                    resolved_sources.push(source_type);
                }
            }
        }

        if resolved_sources.is_empty() {
            if self.source != VulnerabilitySourceType::Pypa {
                DEPRECATION_WARNING_SHOWN.call_once(|| {
                    eprintln!("Warning: --source flag is deprecated and will be removed in a future version. Use --sources instead.");
                });
                resolved_sources.push(self.source.clone());
            } else {
                resolved_sources.push(VulnerabilitySourceType::Pypa);
            }
        }

        let mut unique_sources = Vec::new();
        for source in resolved_sources {
            if !unique_sources.contains(&source) {
                unique_sources.push(source);
            }
        }

        Ok(unique_sources)
    }

    pub fn load_and_merge_config(&self) -> Result<(Self, Option<Config>)> {
        let config_loader = if let Some(ref config_path) = self.config {
            ConfigLoader::load_from_file(config_path)?
        } else {
            ConfigLoader::load_with_options(self.no_config)?
        };

        let config = config_loader.config.clone();
        let merged_args = self.merge_with_config(&config);

        Ok((merged_args, Some(config)))
    }

    pub fn merge_with_config(&self, config: &Config) -> Self {
        let mut merged = self.clone();

        if self.format == AuditFormat::Human && config.defaults.format != "human" {
            merged.format = match config.defaults.format.as_str() {
                "json" => AuditFormat::Json,
                "sarif" => AuditFormat::Sarif,
                "markdown" => AuditFormat::Markdown,
                _ => AuditFormat::Human, // fallback
            };
        }

        if self.severity == SeverityLevel::Low && config.defaults.severity != "low" {
            merged.severity = match config.defaults.severity.as_str() {
                "medium" => SeverityLevel::Medium,
                "high" => SeverityLevel::High,
                "critical" => SeverityLevel::Critical,
                _ => SeverityLevel::Low, // fallback
            };
        }

        if self.fail_on == SeverityLevel::Medium && config.defaults.fail_on != "medium" {
            merged.fail_on = match config.defaults.fail_on.as_str() {
                "low" => SeverityLevel::Low,
                "high" => SeverityLevel::High,
                "critical" => SeverityLevel::Critical,
                _ => SeverityLevel::Medium, // fallback
            };
        }

        if !self.all && !self.all_extras && config.defaults.scope == "all" {
            merged.all_extras = true;
        }

        if !self.direct_only {
            merged.direct_only = config.defaults.direct_only;
        }

        if !self.detailed {
            merged.detailed = config.defaults.detailed;
        }

        if !self.include_withdrawn {
            merged.include_withdrawn = config.defaults.include_withdrawn;
        }

        if self.resolver == ResolverTypeArg::Uv && config.resolver.resolver_type != "uv" {
            merged.resolver = match config.resolver.resolver_type.as_str() {
                "pip-tools" => ResolverTypeArg::PipTools,
                _ => ResolverTypeArg::Uv, // fallback
            };
        }

        if !self.no_cache && !config.cache.enabled {
            merged.no_cache = true;
        }

        if self.cache_dir.is_none() {
            if let Some(ref cache_dir) = config.cache.directory {
                merged.cache_dir = Some(std::path::PathBuf::from(cache_dir));
            }
        }

        if self.resolution_cache_ttl == 24 {
            merged.resolution_cache_ttl = config.cache.resolution_ttl;
        }

        if self.sources.is_empty() && !config.sources.enabled.is_empty() {
            merged.sources = config.sources.enabled.clone();
        }

        let mut ignore_ids = self.ignore_ids.clone();
        ignore_ids.extend(config.ignore.ids.clone());
        merged.ignore_ids = ignore_ids;

        if !self.quiet {
            merged.quiet = config.output.quiet;
        }
        if !self.verbose {
            merged.verbose = config.output.verbose;
        }

        merged
    }
}

#[derive(Debug, Parser)]
pub struct ResolversArgs {
    #[arg(long, short)]
    pub verbose: bool,
}

#[derive(Debug, Parser)]
pub struct CheckVersionArgs {
    #[arg(long, short)]
    pub verbose: bool,
}

#[derive(Debug, Parser)]
pub struct ConfigInitArgs {
    #[arg(long, short, value_name = "FILE")]
    pub output: Option<std::path::PathBuf>,

    #[arg(long)]
    pub force: bool,

    #[arg(long)]
    pub minimal: bool,
}

#[derive(Debug, Parser)]
pub struct ConfigValidateArgs {
    #[arg(value_name = "FILE")]
    pub config: Option<std::path::PathBuf>,

    #[arg(long, short)]
    pub verbose: bool,
}

#[derive(Debug, Parser)]
pub struct ConfigShowArgs {
    #[arg(long, value_name = "FILE")]
    pub config: Option<std::path::PathBuf>,

    #[arg(long)]
    pub toml: bool,
}

#[derive(Debug, Parser)]
pub struct ConfigPathArgs {
    #[arg(long, short)]
    pub verbose: bool,
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
    fn from(severity: SeverityLevel) -> Self {
        match severity {
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

pub async fn check_resolvers(verbose: bool) -> Result<()> {
    if !verbose {
        println!("Checking available dependency resolvers...");
        println!();
    }

    let all_resolvers = vec![ResolverType::Uv, ResolverType::PipTools];

    let mut available_resolvers = Vec::new();
    let mut unavailable_resolvers = Vec::new();

    for resolver_type in all_resolvers {
        if verbose {
            println!("Checking {resolver_type}...");
        }

        let resolver = ResolverRegistry::create_resolver(resolver_type);
        let is_available = resolver.is_available().await;

        if is_available {
            available_resolvers.push(resolver_type);
        } else {
            unavailable_resolvers.push(resolver_type);
        }
    }

    if !available_resolvers.is_empty() {
        println!("✓ Available resolvers ({}):", available_resolvers.len());
        for resolver in &available_resolvers {
            println!("  {resolver}");
        }
        println!();
    }

    if !unavailable_resolvers.is_empty() {
        println!("✗ Unavailable resolvers ({}):", unavailable_resolvers.len());
        for resolver in &unavailable_resolvers {
            println!("  {resolver} - not installed or not in PATH");
        }
        println!();
    }

    if available_resolvers.is_empty() {
        println!("⚠️  No dependency resolvers are available!");
        println!("Please install at least one resolver:");
        println!("  • UV (recommended): https://docs.astral.sh/uv/");
        println!("  • pip-tools: pip install pip-tools");
        return Ok(());
    }

    match ResolverRegistry::detect_best_resolver().await {
        Ok(best) => {
            println!("🎯 Auto-detected resolver: {best}");
        }
        Err(_) => {
            println!("⚠️  No resolver can be auto-detected");
        }
    }

    Ok(())
}

pub async fn check_version(verbose: bool) -> Result<()> {
    const CURRENT_VERSION: &str = env!("CARGO_PKG_VERSION");
    const GITHUB_REPO: &str = "nyudenkov/pysentry";

    if verbose {
        println!("Checking for updates...");
        println!("Current version: {CURRENT_VERSION}");
        println!("Repository: {GITHUB_REPO}");
    } else {
        println!("Checking for updates...");
    }

    let client = reqwest::Client::new();
    let url = format!("https://api.github.com/repos/{GITHUB_REPO}/releases/latest");

    if verbose {
        println!("Fetching: {url}");
    }

    let response = match client
        .get(&url)
        .header("User-Agent", format!("pysentry/{CURRENT_VERSION}"))
        .header("Accept", "application/vnd.github+json")
        .send()
        .await
    {
        Ok(response) => response,
        Err(e) => {
            eprintln!("Failed to check for updates: {e}");
            return Ok(());
        }
    };

    if !response.status().is_success() {
        eprintln!("Failed to check for updates: HTTP {}", response.status());
        return Ok(());
    }

    let release_info: serde_json::Value = match response.json().await {
        Ok(json) => json,
        Err(e) => {
            eprintln!("Failed to parse release information: {e}");
            return Ok(());
        }
    };

    let latest_tag = match release_info["tag_name"].as_str() {
        Some(tag) => tag,
        None => {
            eprintln!("Failed to get latest version information");
            return Ok(());
        }
    };

    let latest_version_str = latest_tag.strip_prefix('v').unwrap_or(latest_tag);

    if verbose {
        println!("Latest release tag: {latest_tag}");
    }

    let current_version = match Version::from_str(CURRENT_VERSION) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("Failed to parse current version: {e}");
            return Ok(());
        }
    };

    let latest_version = match Version::from_str(latest_version_str) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("Failed to parse latest version '{latest_version_str}': {e}");
            return Ok(());
        }
    };

    if latest_version > current_version {
        println!("✨ Update available!");
        println!("Current version: {CURRENT_VERSION}");
        println!("Latest version:  {latest_version_str}");
        println!();
        println!("To update:");
        println!("  • Rust CLI: cargo install pysentry");
        println!("  • Python package: pip install --upgrade pysentry-rs");
        if let Some(release_url) = release_info["html_url"].as_str() {
            println!("  • Release notes: {release_url}");
        }
    } else if latest_version < current_version {
        println!("🚀 You're running a development version!");
        println!("Current version: {CURRENT_VERSION}");
        println!("Latest stable:   {latest_version_str}");
    } else {
        println!("✅ You're running the latest version!");
        println!("Current version: {CURRENT_VERSION}");
    }

    Ok(())
}

pub async fn check_for_update_silent() -> Result<Option<String>> {
    const CURRENT_VERSION: &str = env!("CARGO_PKG_VERSION");
    const GITHUB_REPO: &str = "nyudenkov/pysentry";

    let client = reqwest::Client::new();
    let url = format!("https://api.github.com/repos/{GITHUB_REPO}/releases/latest");

    let response = match client
        .get(&url)
        .header("User-Agent", format!("pysentry/{CURRENT_VERSION}"))
        .header("Accept", "application/vnd.github+json")
        .timeout(std::time::Duration::from_secs(5))
        .send()
        .await
    {
        Ok(response) => response,
        Err(_) => {
            return Ok(None);
        }
    };

    if !response.status().is_success() {
        return Ok(None);
    }

    let release_info: serde_json::Value = match response.json().await {
        Ok(json) => json,
        Err(_) => {
            return Ok(None);
        }
    };

    let latest_tag = match release_info["tag_name"].as_str() {
        Some(tag) => tag,
        None => {
            return Ok(None);
        }
    };

    let latest_version_str = latest_tag.strip_prefix('v').unwrap_or(latest_tag);

    let current_version = match Version::from_str(CURRENT_VERSION) {
        Ok(v) => v,
        Err(_) => {
            return Ok(None);
        }
    };

    let latest_version = match Version::from_str(latest_version_str) {
        Ok(v) => v,
        Err(_) => {
            return Ok(None);
        }
    };

    if latest_version > current_version {
        Ok(Some(latest_version_str.to_string()))
    } else {
        Ok(None)
    }
}

pub async fn audit(audit_args: &AuditArgs, cache_dir: &Path) -> Result<i32> {
    if audit_args.verbose {
        eprintln!(
            "Auditing dependencies for vulnerabilities in {}...",
            audit_args.path.display()
        );
    }

    if audit_args.verbose {
        eprintln!(
            "Configuration: format={:?}, severity={:?}, fail_on={:?}, source={:?}, scope='{}', direct_only={}",
            audit_args.format,
            audit_args.severity,
            audit_args.fail_on,
            audit_args.source,
            audit_args.scope_description(),
            audit_args.direct_only
        );
        eprintln!("Cache directory: {}", cache_dir.display());

        if !audit_args.ignore_ids.is_empty() {
            eprintln!(
                "Ignoring vulnerability IDs: {}",
                audit_args.ignore_ids.join(", ")
            );
        }
    }

    let audit_result = perform_audit(audit_args, cache_dir).await;

    let report = match audit_result {
        Ok(report) => report,
        Err(e) => {
            eprintln!("Error: Audit failed: {e}");
            return Ok(1);
        }
    };

    let report_output = ReportGenerator::generate(
        &report,
        audit_args.format.clone().into(),
        Some(&audit_args.path),
        audit_args.detailed,
    )
    .map_err(|e| anyhow::anyhow!("Failed to generate report: {e}"))?;

    if let Some(output_path) = &audit_args.output {
        fs_err::write(output_path, &report_output)?;
        if !audit_args.quiet {
            eprintln!("Audit results written to: {}", output_path.display());
        }
    } else {
        println!("{report_output}");
    }

    // Show feedback message (once per day)
    if !audit_args.quiet {
        let audit_cache = AuditCache::new(cache_dir.to_path_buf());
        if audit_cache.should_show_feedback().await {
            println!("\n💬 Found a bug? Have ideas for improvements? Or maybe PySentry saved you some time?");
            println!("   I welcome all feedback, suggestions, and collaboration ideas at nikita@pysentry.com");

            if let Err(e) = audit_cache.record_feedback_shown().await {
                tracing::debug!("Failed to record feedback shown: {}", e);
            }
        }

        // Check for updates (once per day)
        if audit_cache.should_check_for_updates().await {
            if let Ok(Some(latest_version)) = check_for_update_silent().await {
                const CURRENT_VERSION: &str = env!("CARGO_PKG_VERSION");
                println!("\n✨ Update available! PySentry {latest_version} is now available (you're running {CURRENT_VERSION})");
            }

            if let Err(e) = audit_cache.record_update_check().await {
                tracing::debug!("Failed to record update check: {}", e);
            }
        }
    }

    if report.should_fail_on_severity(&audit_args.fail_on.clone().into()) {
        Ok(1)
    } else {
        Ok(0)
    }
}

async fn perform_audit(audit_args: &AuditArgs, cache_dir: &Path) -> Result<AuditReport> {
    std::fs::create_dir_all(cache_dir)?;
    let audit_cache = AuditCache::new(cache_dir.to_path_buf());

    let source_types = match audit_args.resolve_sources() {
        Ok(sources) => sources,
        Err(e) => {
            return Err(anyhow::anyhow!("Invalid vulnerability sources: {}", e));
        }
    };

    let vuln_sources: Vec<_> = source_types
        .iter()
        .map(|source_type| {
            VulnerabilitySource::new(
                source_type.clone().into(),
                audit_cache.clone(),
                audit_args.no_cache,
            )
        })
        .collect();

    let source_names: Vec<_> = vuln_sources.iter().map(|s| s.name()).collect();
    if audit_args.verbose {
        if source_names.len() == 1 {
            eprintln!("Fetching vulnerability data from {}...", source_names[0]);
        } else {
            eprintln!(
                "Fetching vulnerability data from {} sources: {}...",
                source_names.len(),
                source_names.join(", ")
            );
        }
    }

    if audit_args.verbose {
        eprintln!("Scanning project dependencies...");
    }

    let (dependencies, skipped_packages, detected_parser_name) =
        if !audit_args.requirements_files.is_empty() {
            if !audit_args.quiet {
                eprintln!(
                    "Using explicit requirements files: {}",
                    audit_args
                        .requirements_files
                        .iter()
                        .map(|p| p.display().to_string())
                        .collect::<Vec<_>>()
                        .join(", ")
                );
            }
            (
                scan_explicit_requirements(
                    &audit_args.requirements_files,
                    audit_args.include_dev(),
                    audit_args.include_optional(),
                    audit_args.direct_only,
                    audit_args.resolver.clone(),
                )
                .await?,
                Vec::new(), // No skipped packages for explicit requirements files
                "requirements.txt".to_string(),
            )
        } else {
            let resolver_type: ResolverType = audit_args.resolver.clone().into();

            let parse_dev = audit_args.include_dev();
            let parse_optional = audit_args.include_optional();

            use crate::parsers::{DependencyType, ParserRegistry};
            let parser_registry = ParserRegistry::new(Some(resolver_type));
            let (raw_parsed_deps, skipped_packages, parser_name) = parser_registry
                .parse_project(
                    &audit_args.path,
                    parse_dev,
                    parse_optional,
                    audit_args.direct_only,
                )
                .await?;

            if audit_args.verbose {
                eprintln!(
                    "Raw parsed dependencies before filtering: {} (from {})",
                    raw_parsed_deps.len(),
                    parser_name
                );
                let (main_count, optional_count) =
                    raw_parsed_deps
                        .iter()
                        .fold((0, 0), |(m, o), dep| match dep.dependency_type {
                            DependencyType::Main => (m + 1, o),
                            DependencyType::Optional => (m, o + 1),
                        });
                eprintln!("  Main: {main_count}, Optional: {optional_count}");
            }

            let filtered_parsed_deps = audit_args.filter_dependencies(raw_parsed_deps);

            if audit_args.verbose {
                eprintln!(
                    "Filtered dependencies after scope filtering: {}",
                    filtered_parsed_deps.len()
                );
                eprintln!("  Scope: {}", audit_args.scope_description());
            }

            (
                filtered_parsed_deps
                    .into_iter()
                    .map(|dep| crate::dependency::scanner::ScannedDependency {
                        name: dep.name,
                        version: dep.version,
                        is_direct: dep.is_direct,
                        source: dep.source.into(),
                        path: dep.path,
                    })
                    .collect(),
                skipped_packages,
                parser_name.to_string(),
            )
        };

    let dependency_stats = if !audit_args.requirements_files.is_empty() {
        calculate_dependency_stats(&dependencies)
    } else {
        let scanner = DependencyScanner::new(
            audit_args.include_dev(),
            audit_args.include_optional(),
            audit_args.direct_only,
            None,
        );
        scanner.get_stats(&dependencies)
    };

    if audit_args.verbose {
        eprintln!("{dependency_stats}");
    }

    let warnings = if !audit_args.requirements_files.is_empty() {
        if dependencies.is_empty() {
            vec!["No dependencies found in specified requirements files.".to_string()]
        } else {
            vec![]
        }
    } else {
        let scanner = DependencyScanner::new(
            audit_args.include_dev(),
            audit_args.include_optional(),
            audit_args.direct_only,
            None,
        );
        scanner.validate_dependencies(&dependencies, &skipped_packages, &detected_parser_name)
    };

    for warning in &warnings {
        if !audit_args.quiet {
            eprintln!("Warning: {warning}");
        }
    }

    let packages: Vec<(String, String)> = dependencies
        .iter()
        .map(|dep| (dep.name.to_string(), dep.version.to_string()))
        .collect();

    if audit_args.verbose {
        if source_names.len() == 1 {
            eprintln!(
                "Fetching vulnerabilities for {} packages from {}...",
                packages.len(),
                source_names[0]
            );
        } else {
            eprintln!(
                "Fetching vulnerabilities for {} packages from {} sources concurrently...",
                packages.len(),
                source_names.len()
            );
        }
    }

    let fetch_tasks = vuln_sources.into_iter().map(|source| {
        let packages = packages.clone();
        async move { source.fetch_vulnerabilities(&packages).await }
    });

    let databases = try_join_all(fetch_tasks).await?;

    let database = if databases.len() == 1 {
        databases.into_iter().next().unwrap()
    } else {
        if !audit_args.quiet {
            eprintln!(
                "Merging vulnerability data from {} sources...",
                databases.len()
            );
        }
        VulnerabilityDatabase::merge(databases)
    };

    if audit_args.verbose {
        eprintln!("Matching against vulnerability database...");
    }
    let matcher_config = MatcherConfig::new(
        audit_args.severity.clone().into(),
        audit_args.ignore_ids.to_vec(),
        audit_args.direct_only,
        audit_args.include_withdrawn,
    );
    let matcher = VulnerabilityMatcher::new(database, matcher_config);

    let matches = matcher.find_vulnerabilities(&dependencies)?;
    let filtered_matches = matcher.filter_matches(matches);

    let database_stats = matcher.get_database_stats();
    let fix_analysis = matcher.analyze_fixes(&filtered_matches);

    let report = AuditReport::new(
        dependency_stats,
        database_stats,
        filtered_matches,
        fix_analysis,
        warnings,
    );

    let summary = report.summary();
    if audit_args.verbose {
        eprintln!(
            "Audit complete: {} vulnerabilities found in {} packages",
            summary.total_vulnerabilities, summary.vulnerable_packages
        );
    }

    Ok(report)
}

async fn scan_explicit_requirements(
    requirements_files: &[std::path::PathBuf],
    _dev: bool,
    _optional: bool,
    direct_only: bool,
    resolver: ResolverTypeArg,
) -> Result<Vec<crate::dependency::scanner::ScannedDependency>> {
    let resolver_type: ResolverType = resolver.into();

    let parser = RequirementsParser::new(Some(resolver_type));

    let parsed_deps = parser
        .parse_explicit_files(requirements_files, direct_only)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to parse requirements files: {}", e))?;

    let scanned_dependencies: Vec<crate::dependency::scanner::ScannedDependency> = parsed_deps
        .into_iter()
        .map(|dep| crate::dependency::scanner::ScannedDependency {
            name: dep.name,
            version: dep.version,
            is_direct: dep.is_direct,
            source: dep.source.into(),
            path: dep.path,
        })
        .collect();

    Ok(scanned_dependencies)
}

fn calculate_dependency_stats(
    dependencies: &[crate::dependency::scanner::ScannedDependency],
) -> DependencyStats {
    let parsed_deps: Vec<crate::parsers::ParsedDependency> = dependencies
        .iter()
        .map(|dep| crate::parsers::ParsedDependency {
            name: dep.name.clone(),
            version: dep.version.clone(),
            is_direct: dep.is_direct,
            source: dep.source.clone().into(),
            path: dep.path.clone(),
            dependency_type: crate::parsers::DependencyType::Main,
        })
        .collect();

    DependencyStats::from_dependencies(&parsed_deps)
}

// Config command handlers

pub async fn config_init(args: &ConfigInitArgs) -> Result<()> {
    let output_path = args
        .output
        .clone()
        .unwrap_or_else(|| std::path::PathBuf::from(".pysentry.toml"));

    if output_path.exists() && !args.force {
        anyhow::bail!(
            "Configuration file already exists: {}. Use --force to overwrite.",
            output_path.display()
        );
    }

    let config_content = if args.minimal {
        generate_minimal_config()
    } else {
        Config::generate_default_toml()
    };

    fs_err::write(&output_path, config_content)?;

    println!("Created configuration file: {}", output_path.display());
    println!();
    println!("You can now customize your settings in this file.");
    println!("Configuration reference:");
    println!("- Format: human, json, sarif, markdown");
    println!("- Severity: low, medium, high, critical");
    println!("- Sources: pypa, pypi, osv");
    println!("- Resolver: uv, pip-tools");
    println!("- Include withdrawn: true/false");

    Ok(())
}

pub async fn config_validate(args: &ConfigValidateArgs) -> Result<()> {
    let config_loader = if let Some(ref config_path) = args.config {
        ConfigLoader::load_from_file(config_path)?
    } else {
        ConfigLoader::load()?
    };

    let config_path = config_loader.config_path_display();

    if args.verbose {
        println!("Validating configuration file: {config_path}");
    }

    // The configuration is already validated during loading
    // If we get here, validation passed

    if config_loader.config_path.is_some() {
        println!("✅ Configuration is valid: {config_path}");

        if args.verbose {
            println!("Configuration details:");
            println!("  Version: {}", config_loader.config.version);
            println!("  Format: {}", config_loader.config.defaults.format);
            println!("  Severity: {}", config_loader.config.defaults.severity);
            println!(
                "  Sources: {}",
                config_loader.config.sources.enabled.join(", ")
            );
            println!(
                "  Resolver: {}",
                config_loader.config.resolver.resolver_type
            );
            println!("  Cache enabled: {}", config_loader.config.cache.enabled);
        }
    } else {
        println!("No configuration file found. Using built-in defaults.");
    }

    Ok(())
}

pub async fn config_show(args: &ConfigShowArgs) -> Result<()> {
    let config_loader = if let Some(ref config_path) = args.config {
        ConfigLoader::load_from_file(config_path)?
    } else {
        ConfigLoader::load()?
    };

    if args.toml {
        // Show raw TOML format
        let toml_content = toml::to_string_pretty(&config_loader.config)
            .context("Failed to serialize configuration to TOML")?;
        println!("{toml_content}");
    } else {
        // Show human-readable format
        println!(
            "Configuration loaded from: {}",
            config_loader.config_path_display()
        );
        println!();
        println!("Effective configuration:");
        println!("  Version: {}", config_loader.config.version);
        println!("  Format: {}", config_loader.config.defaults.format);
        println!("  Severity: {}", config_loader.config.defaults.severity);
        println!("  Fail on: {}", config_loader.config.defaults.fail_on);
        println!("  Scope: {}", config_loader.config.defaults.scope);
        println!(
            "  Direct only: {}",
            config_loader.config.defaults.direct_only
        );
        println!("  Detailed: {}", config_loader.config.defaults.detailed);
        println!(
            "  Include withdrawn: {}",
            config_loader.config.defaults.include_withdrawn
        );
        println!();
        println!(
            "  Sources: {}",
            config_loader.config.sources.enabled.join(", ")
        );
        println!();
        println!(
            "  Resolver: {} (fallback: {})",
            config_loader.config.resolver.resolver_type, config_loader.config.resolver.fallback
        );
        println!();
        println!("  Cache enabled: {}", config_loader.config.cache.enabled);
        if let Some(ref cache_dir) = config_loader.config.cache.directory {
            println!("  Cache directory: {cache_dir}");
        }
        println!(
            "  Resolution cache TTL: {} hours",
            config_loader.config.cache.resolution_ttl
        );
        println!(
            "  Vulnerability cache TTL: {} hours",
            config_loader.config.cache.vulnerability_ttl
        );
        println!();
        println!("  Output quiet: {}", config_loader.config.output.quiet);
        println!("  Output verbose: {}", config_loader.config.output.verbose);
        println!("  Output color: {}", config_loader.config.output.color);
        println!();
        if !config_loader.config.ignore.ids.is_empty() {
            println!(
                "  Ignored IDs: {}",
                config_loader.config.ignore.ids.join(", ")
            );
        }
        if !config_loader.config.ignore.patterns.is_empty() {
            println!(
                "  Ignored patterns: {}",
                config_loader.config.ignore.patterns.join(", ")
            );
        }
        if !config_loader.config.projects.is_empty() {
            println!(
                "  Project overrides: {} configured",
                config_loader.config.projects.len()
            );
        }
        println!();
        println!("  CI enabled: {}", config_loader.config.ci.enabled);
        println!("  CI format: {}", config_loader.config.ci.format);
        println!("  CI fail on: {}", config_loader.config.ci.fail_on);
        println!("  CI annotations: {}", config_loader.config.ci.annotations);
    }

    Ok(())
}

pub async fn config_path(args: &ConfigPathArgs) -> Result<()> {
    let config_loader = ConfigLoader::load()?;

    if let Some(config_path) = config_loader.config_path {
        println!("{}", config_path.display());

        if args.verbose {
            println!();
            println!("Configuration file found and loaded successfully.");

            // Show file size and modification time
            if let Ok(metadata) = fs_err::metadata(&config_path) {
                println!("Size: {} bytes", metadata.len());
                if let Ok(modified) = metadata.modified() {
                    println!("Modified: {modified:?}");
                }
            }
        }
    } else if args.verbose {
        println!("No configuration file found.");
        println!("Using built-in defaults.");
        println!();
        println!("To create a configuration file, run:");
        println!("  pysentry config init");
    } else {
        // Exit with code 1 to indicate no config file found
        std::process::exit(1);
    }

    Ok(())
}

fn generate_minimal_config() -> String {
    r#"# PySentry minimal configuration
version = 1

[defaults]
# Set your preferred severity level
severity = "medium"
fail_on = "high"

# Uncomment to include dev/optional dependencies
# scope = "all"

# Uncomment to include withdrawn vulnerabilities by default
# include_withdrawn = true

[sources]
# Choose your vulnerability sources
enabled = ["pypa"]

# Uncomment to add more sources
# enabled = ["pypa", "pypi", "osv"]

[ignore]
# Add vulnerability IDs to ignore
ids = []

# Example:
# ids = ["GHSA-1234-5678-90ab", "CVE-2024-12345"]
"#
    .to_string()
}
