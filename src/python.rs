use crate::dependency::resolvers::{ResolverRegistry, ResolverType};
use crate::output::report::ReportGenerator;
use crate::types::{AuditFormat, SeverityLevel, VulnerabilitySourceType};
use crate::{
    AuditCache, AuditEngine, DependencyScanner, MatcherConfig, VulnerabilityMatcher,
    VulnerabilitySource,
};
use pyo3::exceptions::PyRuntimeError;
use pyo3::prelude::*;
use std::path::Path;

#[pyfunction]
#[pyo3(signature = (path, format=None))]
fn audit_python(path: String, format: Option<String>) -> PyResult<String> {
    let rt = tokio::runtime::Runtime::new()
        .map_err(|e| PyRuntimeError::new_err(format!("Failed to create async runtime: {e}")))?;

    rt.block_on(async {
        let temp_dir = std::env::temp_dir().join("pysentry-cache");
        let cache = AuditCache::new(temp_dir);
        let engine = AuditEngine::new().with_cache(cache);

        let audit_format = match format.as_deref() {
            Some("json") => AuditFormat::Json,
            Some("sarif") => AuditFormat::Sarif,
            _ => AuditFormat::Human,
        };

        let vulnerability_source = VulnerabilitySourceType::Pypa;
        let min_severity = SeverityLevel::Low;
        let ignore_ids: Vec<String> = vec![];

        match engine
            .audit_project(&path, vulnerability_source, min_severity, &ignore_ids)
            .await
        {
            Ok(report) => {
                let project_path = Path::new(&path);
                match ReportGenerator::generate(&report, audit_format, Some(project_path)) {
                    Ok(output) => Ok(output),
                    Err(e) => Err(PyRuntimeError::new_err(format!(
                        "Failed to generate report: {e}"
                    ))),
                }
            }
            Err(e) => Err(PyRuntimeError::new_err(format!("Audit failed: {e}"))),
        }
    })
}

#[pyfunction]
#[pyo3(signature = (
    path,
    format=None,
    source=None,
    min_severity=None,
    ignore_ids=None,
    output=None,
    dev=false,
    optional=false,
    direct_only=false,
    no_cache=false,
    cache_dir=None,
    resolver=None,
    requirements_files=None,
    verbose=false,
    quiet=false
))]
#[allow(clippy::fn_params_excessive_bools, clippy::too_many_arguments)]
fn audit_with_options(
    path: String,
    format: Option<String>,
    source: Option<String>,
    min_severity: Option<String>,
    ignore_ids: Option<Vec<String>>,
    output: Option<String>,
    dev: bool,
    optional: bool,
    direct_only: bool,
    no_cache: bool,
    cache_dir: Option<String>,
    resolver: Option<String>,
    requirements_files: Option<Vec<String>>,
    verbose: bool,
    quiet: bool,
) -> PyResult<String> {
    let rt = tokio::runtime::Runtime::new()
        .map_err(|e| PyRuntimeError::new_err(format!("Failed to create async runtime: {e}")))?;

    rt.block_on(async {
        let cache_path = if let Some(dir) = cache_dir {
            std::path::PathBuf::from(dir)
        } else {
            dirs::cache_dir()
                .unwrap_or_else(std::env::temp_dir)
                .join("pysentry")
        };

        std::fs::create_dir_all(&cache_path).map_err(|e| {
            PyRuntimeError::new_err(format!("Failed to create cache directory: {e}"))
        })?;

        let audit_cache = AuditCache::new(cache_path.clone());
        let vuln_source_type = match source.as_deref() {
            Some("pypi") => VulnerabilitySourceType::Pypi,
            Some("osv") => VulnerabilitySourceType::Osv,
            _ => VulnerabilitySourceType::Pypa,
        };

        let vuln_source = VulnerabilitySource::new(vuln_source_type.clone(), audit_cache, no_cache);

        let audit_format = match format.as_deref() {
            Some("json") => AuditFormat::Json,
            Some("sarif") => AuditFormat::Sarif,
            _ => AuditFormat::Human,
        };

        let severity_level = match min_severity.as_deref() {
            Some("critical") => SeverityLevel::Critical,
            Some("high") => SeverityLevel::High,
            Some("medium") => SeverityLevel::Medium,
            _ => SeverityLevel::Low,
        };

        let ignore_list = ignore_ids.unwrap_or_default();
        let resolver_type = match resolver.as_deref() {
            Some("pip-tools") => ResolverType::PipTools,
            _ => ResolverType::Uv,
        };

        if !quiet {
            eprintln!("Auditing dependencies for vulnerabilities in {path}...");
        }
        if verbose {
            eprintln!("Using resolver: {resolver_type}");
            eprintln!("Vulnerability source: {vuln_source_type:?}");
            eprintln!("Minimum severity level: {severity_level:?}");
        }

        // Scan dependencies
        let dependencies = if let Some(req_files) = requirements_files {
            // Handle explicit requirements files
            use crate::parsers::requirements::RequirementsParser;
            let req_paths: Vec<std::path::PathBuf> =
                req_files.iter().map(std::path::PathBuf::from).collect();
            let parser = RequirementsParser::new(Some(resolver_type));
            let parsed_deps = parser
                .parse_explicit_files(&req_paths, direct_only)
                .await
                .map_err(|e| {
                    PyRuntimeError::new_err(format!("Failed to parse requirements files: {e}"))
                })?;

            // Convert ParsedDependency to ScannedDependency
            parsed_deps
                .into_iter()
                .map(|dep| crate::dependency::scanner::ScannedDependency {
                    name: dep.name,
                    version: dep.version,
                    is_direct: dep.is_direct,
                    source: dep.source.into(),
                    path: dep.path,
                })
                .collect()
        } else {
            let scanner = DependencyScanner::new(dev, optional, direct_only, Some(resolver_type));
            let project_path = Path::new(&path);
            scanner
                .scan_project(project_path)
                .await
                .map_err(|e| PyRuntimeError::new_err(format!("Failed to scan project: {e}")))?
        };

        if !quiet {
            eprintln!("Fetching vulnerability data from {}...", vuln_source.name());
        }
        if verbose {
            let dep_count = dependencies.len();
            eprintln!("Found {dep_count} dependencies to check");
            let cache_display = cache_path.display();
            eprintln!("Cache directory: {cache_display}");
        }

        // Prepare packages for vulnerability fetching
        let packages: Vec<(String, String)> = dependencies
            .iter()
            .map(|dep| (dep.name.to_string(), dep.version.to_string()))
            .collect();

        // Fetch vulnerabilities
        let database = vuln_source
            .fetch_vulnerabilities(&packages)
            .await
            .map_err(|e| {
                PyRuntimeError::new_err(format!("Failed to fetch vulnerabilities: {e}"))
            })?;

        if !quiet {
            eprintln!("Matching against vulnerability database...");
        }

        // Match vulnerabilities
        let matcher_config = MatcherConfig::new(severity_level, ignore_list, direct_only);
        let matcher = VulnerabilityMatcher::new(database, matcher_config);
        let matches = matcher.find_vulnerabilities(&dependencies).map_err(|e| {
            PyRuntimeError::new_err(format!("Failed to match vulnerabilities: {e}"))
        })?;
        let filtered_matches = matcher.filter_matches(matches);

        if verbose {
            let match_count = filtered_matches.len();
            eprintln!("Found {match_count} vulnerability matches");
        }

        // Generate report
        let scanner = DependencyScanner::new(dev, optional, direct_only, None);
        let dependency_stats = scanner.get_stats(&dependencies);
        let database_stats = matcher.get_database_stats();
        let fix_analysis = matcher.analyze_fixes(&filtered_matches);
        let warnings = scanner.validate_dependencies(&dependencies);

        let report = crate::AuditReport::new(
            dependency_stats,
            database_stats,
            filtered_matches,
            fix_analysis,
            warnings,
        );

        let project_path = Path::new(&path);
        let report_output = ReportGenerator::generate(&report, audit_format, Some(project_path))
            .map_err(|e| PyRuntimeError::new_err(format!("Failed to generate report: {e}")))?;

        // Handle output
        if let Some(output_path) = output {
            std::fs::write(&output_path, &report_output).map_err(|e| {
                PyRuntimeError::new_err(format!("Failed to write output file: {e}"))
            })?;
            if !quiet {
                eprintln!("Audit results written to: {output_path}");
            }
            Ok(format!("Report written to {output_path}"))
        } else {
            Ok(report_output)
        }
    })
}

#[pyfunction]
fn check_version(verbose: bool) -> PyResult<String> {
    let rt = tokio::runtime::Runtime::new()
        .map_err(|e| PyRuntimeError::new_err(format!("Failed to create async runtime: {e}")))?;

    rt.block_on(async {
        const CURRENT_VERSION: &str = env!("CARGO_PKG_VERSION");
        const GITHUB_REPO: &str = "nyudenkov/pysentry";

        let mut output = Vec::new();

        if verbose {
            output.push("Checking for updates...".to_string());
            output.push(format!("Current version: {CURRENT_VERSION}"));
            output.push(format!("Repository: {GITHUB_REPO}"));
        } else {
            output.push("Checking for updates...".to_string());
        }

        // Create HTTP client
        let client = reqwest::Client::new();
        let url = format!("https://api.github.com/repos/{GITHUB_REPO}/releases/latest");

        if verbose {
            output.push(format!("Fetching: {url}"));
        }

        // Fetch latest release info
        let response = match client
            .get(&url)
            .header("User-Agent", format!("pysentry/{CURRENT_VERSION}"))
            .header("Accept", "application/vnd.github+json")
            .send()
            .await
        {
            Ok(response) => response,
            Err(e) => {
                return Ok(format!("Failed to check for updates: {e}"));
            }
        };

        if !response.status().is_success() {
            return Ok(format!(
                "Failed to check for updates: HTTP {}",
                response.status()
            ));
        }

        // Parse response
        let release_info: serde_json::Value = match response.json().await {
            Ok(json) => json,
            Err(e) => {
                return Ok(format!("Failed to parse release information: {e}"));
            }
        };

        // Extract tag name (version)
        let latest_tag = match release_info["tag_name"].as_str() {
            Some(tag) => tag,
            None => {
                return Ok("Failed to get latest version information".to_string());
            }
        };

        // Remove 'v' prefix if present
        let latest_version_str = latest_tag.strip_prefix('v').unwrap_or(latest_tag);

        if verbose {
            output.push(format!("Latest release tag: {latest_tag}"));
        }

        // Parse versions for comparison
        use crate::types::Version;
        use std::str::FromStr;
        let current_version = match Version::from_str(CURRENT_VERSION) {
            Ok(v) => v,
            Err(e) => {
                return Ok(format!("Failed to parse current version: {e}"));
            }
        };

        let latest_version = match Version::from_str(latest_version_str) {
            Ok(v) => v,
            Err(e) => {
                return Ok(format!(
                    "Failed to parse latest version '{latest_version_str}': {e}"
                ));
            }
        };

        // Compare versions
        if latest_version > current_version {
            output.push("✨ Update available!".to_string());
            output.push(format!("Current version: {CURRENT_VERSION}"));
            output.push(format!("Latest version:  {latest_version_str}"));
            output.push(String::new());
            output.push("To update:".to_string());
            output.push("  • Rust CLI: cargo install pysentry".to_string());
            output.push("  • Python package: pip install --upgrade pysentry-rs".to_string());
            if let Some(release_url) = release_info["html_url"].as_str() {
                output.push(format!("  • Release notes: {release_url}"));
            }
        } else if latest_version < current_version {
            output.push("🚀 You're running a development version!".to_string());
            output.push(format!("Current version: {CURRENT_VERSION}"));
            output.push(format!("Latest stable:   {latest_version_str}"));
        } else {
            output.push("✅ You're running the latest version!".to_string());
            output.push(format!("Current version: {CURRENT_VERSION}"));
        }

        Ok(output.join("\n"))
    })
}

#[pyfunction]
fn check_resolvers(verbose: bool) -> PyResult<String> {
    let rt = tokio::runtime::Runtime::new()
        .map_err(|e| PyRuntimeError::new_err(format!("Failed to create async runtime: {e}")))?;

    rt.block_on(async {
        let mut output = Vec::new();

        if !verbose {
            output.push("Checking available dependency resolvers...".to_string());
            output.push(String::new());
        }

        let all_resolvers = vec![ResolverType::Uv, ResolverType::PipTools];
        let mut available_resolvers = Vec::new();
        let mut unavailable_resolvers = Vec::new();

        for resolver_type in all_resolvers {
            if verbose {
                output.push(format!("Checking {resolver_type}..."));
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
            let count = available_resolvers.len();
            output.push(format!("✓ Available resolvers ({count}):"));
            for resolver in &available_resolvers {
                output.push(format!("  {resolver}"));
            }
            output.push(String::new());
        }

        if !unavailable_resolvers.is_empty() {
            let count = unavailable_resolvers.len();
            output.push(format!("✗ Unavailable resolvers ({count}):"));
            for resolver in &unavailable_resolvers {
                output.push(format!("  {resolver} - not installed or not in PATH"));
            }
            output.push(String::new());
        }

        if available_resolvers.is_empty() {
            output.push("⚠️  No dependency resolvers are available!".to_string());
            output.push("Please install at least one resolver:".to_string());
            output.push("  • UV (recommended): https://docs.astral.sh/uv/".to_string());
            output.push("  • pip-tools: pip install pip-tools".to_string());
            return Ok(output.join("\n"));
        }

        match ResolverRegistry::detect_best_resolver().await {
            Ok(best) => {
                output.push(format!("🎯 Auto-detected resolver: {best}"));
            }
            Err(_) => {
                output.push("⚠️  No resolver can be auto-detected".to_string());
            }
        }

        Ok(output.join("\n"))
    })
}

#[pymodule]
fn _internal(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(audit_python, m)?)?;
    m.add_function(wrap_pyfunction!(audit_with_options, m)?)?;
    m.add_function(wrap_pyfunction!(check_resolvers, m)?)?;
    m.add_function(wrap_pyfunction!(check_version, m)?)?;
    Ok(())
}
