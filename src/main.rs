use std::path::Path;

use anyhow::Result;
use clap::{Parser, ValueEnum};
use tracing_subscriber::EnvFilter;

use pysentry::{
    AuditCache, AuditReport, DependencyScanner, MatcherConfig, ReportGenerator,
    VulnerabilityMatcher, VulnerabilitySource,
};

#[derive(Debug, Clone, ValueEnum)]
pub enum AuditFormat {
    #[value(name = "human")]
    Human,
    #[value(name = "json")]
    Json,
    #[value(name = "sarif")]
    Sarif,
}

#[derive(Debug, Clone, ValueEnum)]
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

#[derive(Debug, Clone, ValueEnum)]
pub enum VulnerabilitySourceType {
    #[value(name = "pypa")]
    Pypa,
    #[value(name = "pypi")]
    Pypi,
    #[value(name = "osv")]
    Osv,
}

#[derive(Parser)]
#[command(
    name = "pysentry",
    about = "Security vulnerability auditing for Python packages",
    version
)]
pub struct Cli {
    /// Path to the project directory to audit
    #[arg(value_name = "PATH", default_value = ".")]
    pub path: std::path::PathBuf,

    /// Output format
    #[arg(long, value_enum, default_value = "human")]
    pub format: AuditFormat,

    /// Minimum severity level to report
    #[arg(long, value_enum, default_value = "low")]
    pub severity: SeverityLevel,

    /// Vulnerability IDs to ignore (can be specified multiple times)
    #[arg(long = "ignore", value_name = "ID")]
    pub ignore_ids: Vec<String>,

    /// Output file path (defaults to stdout)
    #[arg(long, short, value_name = "FILE")]
    pub output: Option<std::path::PathBuf>,

    /// Include development dependencies
    #[arg(long)]
    pub dev: bool,

    /// Include optional dependencies
    #[arg(long)]
    pub optional: bool,

    /// Only check direct dependencies (exclude transitive)
    #[arg(long)]
    pub direct_only: bool,

    /// Disable caching
    #[arg(long)]
    pub no_cache: bool,

    /// Custom cache directory
    #[arg(long, value_name = "DIR")]
    pub cache_dir: Option<std::path::PathBuf>,

    /// Vulnerability data source
    #[arg(long, value_enum, default_value = "pypa")]
    pub source: VulnerabilitySourceType,

    /// Enable verbose output
    #[arg(long, short)]
    pub verbose: bool,

    /// Suppress non-error output
    #[arg(long, short)]
    pub quiet: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Cli::parse();

    // Initialize logging
    let log_level = if args.verbose {
        "debug"
    } else if args.quiet {
        "error"
    } else {
        "info"
    };

    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env().add_directive(log_level.parse()?))
        .init();

    // Create cache directory
    let cache_dir = args.cache_dir.clone().unwrap_or_else(|| {
        dirs::cache_dir()
            .unwrap_or_else(std::env::temp_dir)
            .join("pysentry")
    });

    let exit_code = audit(
        &args.path,
        args.format,
        args.severity,
        &args.ignore_ids,
        args.output.as_deref(),
        args.dev,
        args.optional,
        args.direct_only,
        args.no_cache,
        args.cache_dir.as_deref(),
        args.source,
        &cache_dir,
        args.verbose,
        args.quiet,
    )
    .await?;

    std::process::exit(exit_code);
}

#[allow(clippy::fn_params_excessive_bools, clippy::too_many_arguments)]
async fn audit(
    path: &Path,
    format: AuditFormat,
    severity: SeverityLevel,
    ignore_ids: &[String],
    output: Option<&Path>,
    dev: bool,
    optional: bool,
    direct_only: bool,
    no_cache: bool,
    _cache_dir: Option<&Path>,
    source: VulnerabilitySourceType,
    cache_dir: &Path,
    verbose: bool,
    quiet: bool,
) -> Result<i32> {
    if !quiet {
        eprintln!(
            "Auditing dependencies for vulnerabilities in {}...",
            path.display()
        );
    }

    if verbose {
        eprintln!("Configuration: format={format:?}, severity={severity:?}, source={source:?}, dev={dev}, optional={optional}, direct_only={direct_only}");
        eprintln!("Cache directory: {}", cache_dir.display());

        if !ignore_ids.is_empty() {
            eprintln!("Ignoring vulnerability IDs: {}", ignore_ids.join(", "));
        }
    }

    let audit_result = perform_audit(
        path,
        severity,
        ignore_ids,
        dev,
        optional,
        direct_only,
        no_cache,
        source,
        cache_dir,
        verbose,
        quiet,
    )
    .await;

    let report = match audit_result {
        Ok(report) => report,
        Err(e) => {
            eprintln!("Error: Audit failed: {e}");
            return Ok(1);
        }
    };

    let report_output = ReportGenerator::generate(&report, format.into(), Some(path))
        .map_err(|e| anyhow::anyhow!("Failed to generate report: {e}"))?;

    if let Some(output_path) = output {
        fs_err::write(output_path, &report_output)?;
        if !quiet {
            eprintln!("Audit results written to: {}", output_path.display());
        }
    } else {
        println!("{report_output}");
    }

    if report.has_vulnerabilities() {
        Ok(1)
    } else {
        Ok(0)
    }
}

#[allow(clippy::fn_params_excessive_bools, clippy::too_many_arguments)]
async fn perform_audit(
    project_dir: &Path,
    severity: SeverityLevel,
    ignore_ids: &[String],
    dev: bool,
    optional: bool,
    direct_only: bool,
    no_cache: bool,
    source: VulnerabilitySourceType,
    cache_dir: &Path,
    verbose: bool,
    quiet: bool,
) -> Result<AuditReport> {
    // Create cache directory if it doesn't exist
    std::fs::create_dir_all(cache_dir)?;
    let audit_cache = AuditCache::new(cache_dir.to_path_buf());

    // Create the vulnerability source
    let vuln_source = VulnerabilitySource::new(source.into(), audit_cache, no_cache);

    // Get source name for display
    let source_name = vuln_source.name();
    if !quiet {
        eprintln!("Fetching vulnerability data from {source_name}...");
    }

    if !quiet {
        eprintln!("Scanning project dependencies...");
    }
    let scanner = DependencyScanner::new(dev, optional, direct_only);
    let dependencies = scanner.scan_project(project_dir).await?;

    let dependency_stats = scanner.get_stats(&dependencies);

    if verbose {
        eprintln!("{dependency_stats}");
    }

    let warnings = scanner.validate_dependencies(&dependencies);
    for warning in &warnings {
        if !quiet {
            eprintln!("Warning: {warning}");
        }
    }

    // Prepare package list for vulnerability fetching
    let packages: Vec<(String, String)> = dependencies
        .iter()
        .map(|dep| (dep.name.to_string(), dep.version.to_string()))
        .collect();

    // Fetch vulnerabilities from the selected source
    if !quiet {
        eprintln!(
            "Fetching vulnerabilities for {} packages from {}...",
            packages.len(),
            source_name
        );
    }
    let database = vuln_source.fetch_vulnerabilities(&packages).await?;

    if !quiet {
        eprintln!("Matching against vulnerability database...");
    }
    let matcher_config = MatcherConfig::new(severity.into(), ignore_ids.to_vec(), direct_only);
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
    if !quiet {
        eprintln!(
            "Audit complete: {} vulnerabilities found in {} packages",
            summary.total_vulnerabilities, summary.vulnerable_packages
        );
    }

    Ok(report)
}

impl From<AuditFormat> for pysentry::AuditFormat {
    fn from(format: AuditFormat) -> Self {
        match format {
            AuditFormat::Human => pysentry::AuditFormat::Human,
            AuditFormat::Json => pysentry::AuditFormat::Json,
            AuditFormat::Sarif => pysentry::AuditFormat::Sarif,
        }
    }
}

impl From<SeverityLevel> for pysentry::SeverityLevel {
    fn from(severity: SeverityLevel) -> Self {
        match severity {
            SeverityLevel::Low => pysentry::SeverityLevel::Low,
            SeverityLevel::Medium => pysentry::SeverityLevel::Medium,
            SeverityLevel::High => pysentry::SeverityLevel::High,
            SeverityLevel::Critical => pysentry::SeverityLevel::Critical,
        }
    }
}

impl From<VulnerabilitySourceType> for pysentry::VulnerabilitySourceType {
    fn from(source: VulnerabilitySourceType) -> Self {
        match source {
            VulnerabilitySourceType::Pypa => pysentry::VulnerabilitySourceType::Pypa,
            VulnerabilitySourceType::Pypi => pysentry::VulnerabilitySourceType::Pypi,
            VulnerabilitySourceType::Osv => pysentry::VulnerabilitySourceType::Osv,
        }
    }
}
