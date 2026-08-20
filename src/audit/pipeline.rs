// SPDX-License-Identifier: MIT

use crate::audit::merge::calculate_dependency_stats;
use crate::cli::{
    resolve_styles, AuditArgs, ColorChoice, ResolverTypeArg, VulnerabilitySourceType,
};
use crate::commands::version::{check_for_update_silent, CURRENT_VERSION};
use crate::notifications::display::{
    display_notification, fetch_remote_notifications_silent, mark_notification_shown,
};
use crate::output::generate_report;
use crate::parsers::manifest_reader;
use crate::parsers::requirements::RequirementsParser;
use crate::parsers::{ParserRegistry, ProjectParser};
use crate::types::{PackageName, ResolverType};
use crate::vulnerability::database::SuppressionReason;
use crate::{
    AuditCache, AuditReport, DependencyScanner, MatcherConfig, Severity, VulnerabilityDatabase,
    VulnerabilityMatch, VulnerabilityMatcher, VulnerabilitySource,
};
use anyhow::Result;
use futures::future::join_all;
use std::collections::{BTreeMap, HashSet};
use std::path::{Path, PathBuf};

/// Findings at/above the `fail_on` threshold (or failing maintenance issues)
pub const EXIT_VULNERABILITIES_FOUND: i32 = 1;
/// System errors (bad config, network failure, parse failure) — distinguishable
/// from findings so CI can tell "vulnerable" from "audit never ran"
pub const EXIT_ERROR: i32 = 2;

#[cfg_attr(feature = "hotpath", hotpath::measure)]
pub async fn audit(
    audit_args: &AuditArgs,
    cache_dir: &Path,
    http_config: crate::config::HttpConfig,
    vulnerability_ttl: u64,
    notifications_enabled: bool,
    color: ColorChoice,
) -> Result<i32> {
    let styles = resolve_styles(color);

    // Resolve sources early to avoid duplicate resolution and ensure errors are surfaced
    let source_types = match audit_args.resolve_sources() {
        Ok(sources) => sources,
        Err(e) => {
            eprintln!("Error: Invalid vulnerability sources: {e}");
            return Ok(EXIT_ERROR);
        }
    };

    if audit_args.is_verbose() {
        eprintln!(
            "Auditing dependencies for vulnerabilities in {}...",
            audit_args.path.display()
        );
        eprintln!(
            "Configuration: format={:?}, fail_on={:?}, sources={:?}, scope='{}', direct_only={}",
            audit_args.format,
            audit_args.fail_on,
            source_types,
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

        if !audit_args.ignore_while_no_fix.is_empty() {
            eprintln!(
                "Ignoring unfixable vulnerability IDs: {}",
                audit_args.ignore_while_no_fix.join(", ")
            );
        }
    }

    let ci_env = audit_args.ci_environment();

    let audit_result = perform_audit(
        audit_args,
        cache_dir,
        http_config,
        vulnerability_ttl,
        &source_types,
        &ci_env,
    )
    .await;

    let (report, fail_vulns) = match audit_result {
        Ok(result) => result,
        Err(e) => {
            eprintln!("Error: Audit failed: {e}");
            return Ok(EXIT_ERROR);
        }
    };

    let report_output = generate_report(
        &report,
        audit_args.format.clone().into(),
        Some(&audit_args.path),
        audit_args.detail_level(),
        audit_args.display_mode(),
        &styles,
    )
    .map_err(|e| anyhow::anyhow!("Failed to generate report: {e}"))?;

    if let Some(output_path) = &audit_args.output {
        fs_err::write(output_path, &report_output)?;
        if !audit_args.is_quiet() {
            eprintln!("Audit results written to: {}", output_path.display());
        }
    } else {
        println!("{report_output}");
    }

    // Emit CI summary annotation
    if ci_env.is_github_actions() {
        let summary = report.summary();
        let counts = summary.counts_by_level();
        let critical = counts
            .get(&crate::vulnerability::database::Severity::Critical)
            .copied()
            .unwrap_or(0);
        let high = counts
            .get(&crate::vulnerability::database::Severity::High)
            .copied()
            .unwrap_or(0);
        let medium = counts
            .get(&crate::vulnerability::database::Severity::Medium)
            .copied()
            .unwrap_or(0);
        let low = counts
            .get(&crate::vulnerability::database::Severity::Low)
            .copied()
            .unwrap_or(0);
        let unknown = counts
            .get(&crate::vulnerability::database::Severity::Unknown)
            .copied()
            .unwrap_or(0);

        let annotation_message = format!(
            "PySentry found {} vulnerabilities: {} critical, {} high, {} medium, {} low, {} unknown",
            summary.total_vulnerabilities, critical, high, medium, low, unknown
        );

        if summary.total_vulnerabilities > 0 {
            crate::ci::github_warning(&annotation_message);
        } else {
            crate::ci::github_notice(&annotation_message);
        }
    }

    if !audit_args.is_quiet() {
        #[cfg(feature = "hotpath")]
        let _hp_notices =
            hotpath::MeasurementGuardSync::new("audit::post_audit_notices", false, false);
        let audit_cache = AuditCache::new(cache_dir.to_path_buf());

        // Show feedback message (once per day) — suppressed in CI
        if !ci_env.is_ci() && audit_cache.should_show_feedback().await {
            println!("\n\u{1f4ac} Found a bug? Have ideas for improvements? Or maybe PySentry saved you some time?");
            println!("   I welcome all feedback, suggestions, and collaboration ideas at nikita@pysentry.com");

            if let Err(e) = audit_cache.record_feedback_shown().await {
                tracing::debug!("Failed to record feedback shown: {}", e);
            }
        }

        // Check for updates (once per day)
        if audit_cache.should_check_for_updates().await {
            if let Ok(Some(latest_version)) = check_for_update_silent().await {
                if ci_env.is_github_actions() {
                    crate::ci::github_notice(&format!(
                        "Update available! PySentry {latest_version} is now available (you're running {CURRENT_VERSION})"
                    ));
                } else {
                    println!("\n✨ Update available! PySentry {latest_version} is now available (you're running {CURRENT_VERSION})");
                }
            }

            if let Err(e) = audit_cache.record_update_check().await {
                tracing::debug!("Failed to record update check: {}", e);
            }
        }

        // Check for remote notifications
        if notifications_enabled {
            let notifications = fetch_remote_notifications_silent(&audit_cache).await;
            for notification in notifications {
                if ci_env.is_github_actions() {
                    let title = &notification.title;
                    let message = &notification.message;
                    crate::ci::github_notice(&format!("{title}: {message}"));
                } else {
                    display_notification(&notification);
                }
                if notification.show_once {
                    if let Err(e) = mark_notification_shown(&audit_cache, &notification.id).await {
                        tracing::debug!("Failed to mark notification as shown: {}", e);
                    }
                }
            }
        }
    }

    // Check if we should fail due to maintenance issues (PEP 792)
    let maintenance_config = audit_args.maintenance_check_config();
    let fail_maintenance = report.should_fail_on_maintenance(&maintenance_config);

    // Partial scan under strict `fail_on_partial` (the default): a source failed, so the scan
    // is incomplete. Fail-closed with a system error (exit 2) — the report was already printed
    // with the partial marker above, so the incompleteness is visible before we exit.
    if partial_scan_should_fail(
        !report.failed_sources.is_empty(),
        audit_args.no_fail_on_partial,
    ) {
        return Ok(EXIT_ERROR);
    }

    if fail_vulns || fail_maintenance {
        Ok(EXIT_VULNERABILITIES_FOUND)
    } else {
        Ok(0)
    }
}

/// Build the vulnerability matcher configuration for an audit.
///
/// The matcher threshold is fixed at `Low` so every matched severity reaches the report.
/// `fail_on` deliberately never enters here — it selects the exit condition only (see
/// `evaluate_fail_condition`). Gating the matcher on `fail_on` once silently dropped real
/// vulnerabilities below the threshold from the report; this separation guards against it.
fn build_matcher_config(audit_args: &AuditArgs) -> MatcherConfig {
    MatcherConfig::new(
        crate::SeverityLevel::Low,
        audit_args.ignore_ids.to_vec(),
        audit_args.ignore_while_no_fix.to_vec(),
        audit_args.direct_only,
        audit_args.include_withdrawn,
    )
}

/// Whether a partial scan (at least one source failed to fetch) should exit with a system
/// error. Fail-closed by default: leniency (`no_fail_on_partial`) is opt-in.
fn partial_scan_should_fail(has_failed_sources: bool, no_fail_on_partial: bool) -> bool {
    has_failed_sources && !no_fail_on_partial
}

fn severity_level_to_db(level: &crate::SeverityLevel) -> Severity {
    match level {
        crate::SeverityLevel::Low => Severity::Low,
        crate::SeverityLevel::Medium => Severity::Medium,
        crate::SeverityLevel::High => Severity::High,
        crate::SeverityLevel::Critical => Severity::Critical,
    }
}

/// A finding's effective fail threshold under strictest-wins: the minimum (strictest)
/// threshold across every context that reaches its package.
///
/// The contexts are the reaching dependency groups (each contributing its `[groups.*]`
/// threshold) and — only when the package is **main-reachable** — the main/prod context,
/// contributing the global `fail_on`. A package that ships to production therefore keeps
/// `global` as a floor (a permissive group can only tighten it), while a group-only
/// package takes its group threshold outright, which may be *looser* than global (closes
/// #151: "fail only on critical for dev"). With no reaching group carrying a policy, the
/// global default applies.
fn effective_threshold(
    finding: &VulnerabilityMatch,
    global: Severity,
    group_thresholds: &BTreeMap<String, Severity>,
    main_reachable: &HashSet<PackageName>,
) -> Severity {
    let group_min = finding
        .groups
        .iter()
        .filter_map(|group| group_thresholds.get(group).copied())
        .min();

    match group_min {
        // Main-reachable: global is a floor the group policy can only tighten.
        Some(min) if main_reachable.contains(&finding.package_name) => min.min(global),
        // Group-only: the group policy stands alone and may loosen below global.
        Some(min) => min,
        // No reaching group carries a policy → the global default.
        None => global,
    }
}

/// Evaluate whether any (non-suppressed) match triggers the fail_on exit condition.
///
/// `group_thresholds` (normalized group name → severity) applies per-group policy via
/// strictest-wins; `main_reachable` gates whether the global threshold floors a finding
/// (see [`effective_threshold`]). Pass an empty map for global-threshold-only behavior.
/// This selects the exit condition ONLY — it never filters what is reported (the fail_on
/// invariant).
pub(crate) fn evaluate_fail_condition(
    matches: &[VulnerabilityMatch],
    global_fail_on: &crate::SeverityLevel,
    group_thresholds: &BTreeMap<String, Severity>,
    main_reachable: &HashSet<PackageName>,
    fail_on_unknown: bool,
) -> bool {
    let global_db = severity_level_to_db(global_fail_on);

    matches.iter().any(|m| {
        if m.suppressed.is_some() {
            return false;
        }
        // Unknown severity ignores thresholds entirely (pre-policy behavior). Short-circuit
        // BEFORE the min computation: `Unknown` is the lowest Severity variant, so folding it
        // into the effective threshold would collapse any policied finding to fail-on-everything.
        if m.vulnerability.is_level_unknown() {
            return fail_on_unknown;
        }
        m.vulnerability.meets_level(effective_threshold(
            m,
            global_db,
            group_thresholds,
            main_reachable,
        ))
    })
}

/// Suppress findings whose package matches an `[ignore].packages` entry — marked, never
/// dropped, so they still appear in the report but don't trigger the exit condition.
/// Names compared via `PackageName` (PEP 503), never raw strings. A `packages` entry that
/// matches nothing warns, mirroring the unmatched-ignore-id warning.
fn apply_package_ignores(matches: &mut [VulnerabilityMatch], ignore_packages: &[String]) {
    for raw in ignore_packages {
        // invariant: entries are validated in Config::validate, so this normalizes cleanly.
        let ignored = PackageName::new(raw);
        let mut hit = false;
        for m in matches.iter_mut() {
            if m.package_name == ignored {
                m.suppressed = Some(SuppressionReason::IgnoredPackage);
                hit = true;
            }
        }
        if !hit {
            tracing::warn!("ignore package '{}' did not match any finding", raw);
        }
    }
}

#[cfg_attr(feature = "hotpath", hotpath::measure)]
async fn perform_audit(
    audit_args: &AuditArgs,
    cache_dir: &Path,
    http_config: crate::config::HttpConfig,
    vulnerability_ttl: u64,
    source_types: &[VulnerabilitySourceType],
    ci_env: &crate::ci::CiEnvironment,
) -> Result<(AuditReport, bool)> {
    std::fs::create_dir_all(cache_dir)?;

    // --service-url overrides the OSV provider's endpoint, so it only makes sense when OSV is
    // the sole source. Re-checked here post-merge (not via clap conflicts_with) because config
    // can inject sources that clap never sees.
    if audit_args.service_url.is_some() && source_types != [VulnerabilitySourceType::Osv] {
        return Err(anyhow::anyhow!(
            "--service-url is only valid with `--sources osv` (it overrides the OSV \
             provider's endpoint). Re-run with `--sources osv`."
        ));
    }

    // --group is only meaningful for pyproject.toml-based parsers (uv.lock, poetry.lock,
    // pylock.toml). Reject combinations that bypass pyproject.toml parsing up-front so the
    // user sees a clear error before any scanning begins.
    if !audit_args.groups.is_empty() {
        if !audit_args.requirements_files.is_empty() || audit_args.no_resolver {
            return Err(anyhow::anyhow!(
                "--group cannot be combined with --requirements-files or --no-resolver. \
                 requirements.txt has no dependency-group concept. \
                 Use pyproject.toml with [dependency-groups], \
                 [project.optional-dependencies], or [tool.poetry.group.*] to declare groups."
            ));
        }
        if !audit_args.path.join("pyproject.toml").exists() {
            return Err(anyhow::anyhow!(
                "--group requires a pyproject.toml in the project directory, but none was found at {}. \
                 requirements.txt has no dependency-group concept. \
                 Use pyproject.toml with [dependency-groups], \
                 [project.optional-dependencies], or [tool.poetry.group.*] to declare groups.",
                audit_args.path.display()
            ));
        }
        if audit_args.exclude_extra {
            return Err(anyhow::anyhow!(
                "--group cannot be combined with --exclude-extra (or config `scope = \"main\"`). \
                 --group already narrows which groups are scanned; --exclude-extra would then \
                 strip those same groups as optional. Remove one of them."
            ));
        }
        // --group narrows scope via the reachability closure in the group-aware lock
        // parsers: uv.lock, poetry.lock, pylock.toml. Without one of them the registry
        // would fall through to PyProjectParser, which does not accept `groups` and
        // would silently audit the entire dependency tree. Pipfile.lock is deliberately
        // excluded — PipfileLockParser rejects --group outright (Pipfile has no group
        // concept), so listing it here would only delay the error and make the message
        // less actionable. Fail fast with a clear remediation instead.
        // PEP 751 allows named pylock variants (pylock.<name>.toml), which the parser
        // accepts via PyLockParser::can_parse. has_group_aware_lock reuses that detection
        // instead of hardcoding the canonical filename, so a project carrying only e.g.
        // pylock.production.toml is not falsely rejected.
        if !crate::parsers::has_group_aware_lock(&audit_args.path) {
            return Err(anyhow::anyhow!(
                "--group requires a lock file (uv.lock, poetry.lock, or pylock.toml) \
                 alongside pyproject.toml at {}. Generate one first (e.g. `uv lock` or \
                 `poetry lock`) and re-run. Note: Pipfile.lock is not supported — \
                 Pipfile has no dependency-group concept.",
                audit_args.path.display()
            ));
        }
        let pyproject_path = audit_args.path.join("pyproject.toml");
        let available = manifest_reader::list_group_names(&pyproject_path).await?;
        // PEP 735 group names compare by normalized form, so a user's `--group typing-test`
        // must match a declared `typing_test`. Match on normalized names while still
        // displaying the original spellings in the error.
        let available_normalized: HashSet<String> = available
            .iter()
            .map(|name| manifest_reader::normalize_group_name(name))
            .collect();
        for name in &audit_args.groups {
            if !available_normalized.contains(&manifest_reader::normalize_group_name(name)) {
                let mut sorted: Vec<&str> = available.iter().map(String::as_str).collect();
                sorted.sort();
                return Err(anyhow::anyhow!(
                    "group \"{}\" not found; available groups: {}",
                    name,
                    sorted.join(", ")
                ));
            }
        }
    }

    let audit_cache = AuditCache::new(cache_dir.to_path_buf());

    let vuln_sources: Vec<_> = source_types
        .iter()
        .map(|source_type| {
            VulnerabilitySource::new(
                source_type.clone().into(),
                audit_cache.clone(),
                audit_args.no_cache,
                http_config.clone(),
                vulnerability_ttl,
            )
        })
        .collect();

    let source_names: Vec<_> = vuln_sources.iter().map(|s| s.name()).collect();
    if audit_args.is_verbose() {
        if source_names.len() == 1 {
            // invariant: guarded by len() == 1, so index 0 always exists.
            #[allow(clippy::indexing_slicing)]
            let source_name = source_names[0];
            eprintln!("Fetching vulnerability data from {source_name}...");
        } else {
            eprintln!(
                "Fetching vulnerability data from {} sources: {}...",
                source_names.len(),
                source_names.join(", ")
            );
        }
    }

    if audit_args.is_verbose() {
        eprintln!("Scanning project dependencies...");
    }

    let (mut dependencies, mut skipped_packages, detected_parser_name) =
        if !audit_args.requirements_files.is_empty() {
            if !audit_args.is_quiet() {
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
            let (scanned, skipped) = scan_explicit_requirements(
                &audit_args.requirements_files,
                audit_args.direct_only,
                audit_args.resolver.clone(),
                audit_args.no_resolver,
            )
            .await?;
            (scanned, skipped, "requirements.txt".to_string())
        } else if audit_args.no_resolver
            && crate::parsers::pep723::Pep723Parser::new(None).can_parse(&audit_args.path)
        {
            // --no-resolver on a PEP 723 script: a registry with no resolver parses pinned
            // (==) deps directly; unpinned deps are skipped, matching the
            // requirements.txt no-resolver behavior.
            let parser_registry = ParserRegistry::new(None, None);
            let (raw_parsed_deps, skipped, parser_name) = parser_registry
                .parse_project(&audit_args.path, false, false, audit_args.direct_only)
                .await?;
            let scanned = raw_parsed_deps
                .into_iter()
                .map(|dep| crate::dependency::scanner::ScannedDependency {
                    name: dep.name,
                    version: dep.version,
                    is_direct: dep.is_direct,
                    source: dep.source.into(),
                    path: dep.path,
                    source_file: dep.source_file,
                })
                .collect();
            (scanned, skipped, parser_name.to_string())
        } else if audit_args.no_resolver {
            // --no-resolver without --requirements-files: discover requirements.txt files
            let resolver_type: ResolverType = audit_args.resolver.clone().into();
            let parser = crate::parsers::requirements::RequirementsParser::new(Some(resolver_type));
            let req_files =
                parser.find_requirements_files(&audit_args.path, audit_args.include_dev());
            if req_files.is_empty() && audit_args.include_scripts {
                (Vec::new(), Vec::new(), "requirements.txt".to_string())
            } else if req_files.is_empty() {
                return Err(anyhow::anyhow!(
                    "--no-resolver requires requirements.txt files but none were found in {}",
                    audit_args.path.display()
                ));
            } else {
                if !audit_args.is_quiet() {
                    eprintln!(
                        "Using --no-resolver with discovered requirements files: {}",
                        req_files
                            .iter()
                            .map(|p| p.display().to_string())
                            .collect::<Vec<_>>()
                            .join(", ")
                    );
                }
                let (scanned, skipped) =
                    scan_explicit_requirements(&req_files, true, audit_args.resolver.clone(), true)
                        .await?;
                (scanned, skipped, "requirements.txt".to_string())
            }
        } else {
            let resolver_type: ResolverType = audit_args.resolver.clone().into();

            let parse_dev = audit_args.include_dev();
            let parse_optional = audit_args.include_optional();

            let groups_option: Option<HashSet<String>> = if audit_args.groups.is_empty() {
                None
            } else {
                Some(audit_args.groups.iter().cloned().collect())
            };
            let parser_registry = ParserRegistry::new(Some(resolver_type), groups_option);
            let parse_result = parser_registry
                .parse_project(
                    &audit_args.path,
                    parse_dev,
                    parse_optional,
                    audit_args.direct_only,
                )
                .await;

            // A directory with only PEP 723 scripts and no manifest/lock yields
            // NoDependencyInfo; defer to the script scan below instead of failing,
            // mirroring the --no-resolver branch above.
            let (raw_parsed_deps, skipped_packages, parser_name) = match parse_result {
                Err(crate::AuditError::NoDependencyInfo)
                    if audit_args.include_scripts && audit_args.path.is_dir() =>
                {
                    (Vec::new(), Vec::new(), "scripts")
                }
                other => other?,
            };

            if audit_args.is_verbose() {
                eprintln!(
                    "Parsed {} dependencies from {} (scope: {})",
                    raw_parsed_deps.len(),
                    parser_name,
                    audit_args.scope_description()
                );
            }

            (
                raw_parsed_deps
                    .into_iter()
                    .map(|dep| crate::dependency::scanner::ScannedDependency {
                        name: dep.name,
                        version: dep.version,
                        is_direct: dep.is_direct,
                        source: dep.source.into(),
                        path: dep.path,
                        source_file: dep.source_file,
                    })
                    .collect(),
                skipped_packages,
                parser_name.to_string(),
            )
        };

    if audit_args.include_scripts && audit_args.path.is_dir() {
        let resolver = if audit_args.no_resolver {
            None
        } else {
            Some(audit_args.resolver.clone().into())
        };
        let (script_deps, script_skipped, script_count) =
            scan_pep723_scripts(&audit_args.path, resolver, audit_args.direct_only).await?;
        if audit_args.is_verbose() && script_count > 0 {
            eprintln!(
                "Parsed {} dependencies from {} PEP 723 script(s)",
                script_deps.len(),
                script_count
            );
        }
        dependencies.extend(script_deps);
        skipped_packages.extend(script_skipped);
    }

    let dependency_stats = if !audit_args.requirements_files.is_empty() || audit_args.no_resolver {
        calculate_dependency_stats(&dependencies)
    } else {
        let scanner = DependencyScanner::new(
            audit_args.include_dev(),
            audit_args.include_optional(),
            audit_args.direct_only,
            None,
            None,
        );
        scanner.get_stats(&dependencies)
    };

    if audit_args.is_verbose() {
        eprintln!("{dependency_stats}");
    }

    let warnings = if !audit_args.requirements_files.is_empty() || audit_args.no_resolver {
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
            None,
        );
        scanner.validate_dependencies(&dependencies, &skipped_packages, &detected_parser_name)
    };

    for warning in &warnings {
        if ci_env.is_github_actions() {
            crate::ci::github_warning(warning);
        } else if !audit_args.is_quiet() {
            eprintln!("Warning: {warning}");
        }
    }

    let packages: Vec<(String, String)> = dependencies
        .iter()
        .map(|dep| (dep.name.to_string(), dep.version.to_string()))
        .collect();

    if audit_args.is_verbose() {
        if source_names.len() == 1 {
            // invariant: guarded by len() == 1, so index 0 always exists.
            #[allow(clippy::indexing_slicing)]
            let source_name = source_names[0];
            eprintln!(
                "Fetching vulnerabilities for {} packages from {source_name}...",
                packages.len(),
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
        async move {
            let name = source.name();
            (name, source.fetch_vulnerabilities(&packages).await)
        }
    });

    // Fetch maintenance status (PEP 792) in parallel if enabled
    let maintenance_future = async {
        if audit_args.maintenance_enabled() {
            if audit_args.is_verbose() {
                eprintln!("Checking PEP 792 project status markers...");
            }
            let maintenance_client = crate::maintenance::SimpleIndexClient::new_with_cache_ttl(
                http_config.clone(),
                Some(audit_cache.clone()),
                audit_args.maintenance_cache_ttl,
            );
            let config = audit_args.maintenance_check_config();
            maintenance_client
                .check_maintenance_status(&dependencies, &config)
                .await
                .unwrap_or_else(|e| {
                    // Always log failures - quiet mode only affects stdout, not diagnostics
                    tracing::warn!("Failed to check maintenance status: {}", e);
                    if !audit_args.is_quiet() {
                        eprintln!("Warning: Failed to check maintenance status: {}", e);
                    }
                    Vec::new()
                })
        } else {
            Vec::new()
        }
    };

    // Run vulnerability fetching and maintenance checks in parallel. Sources are collected
    // per-source (not `try_join_all` + `?`) so a single source failure does not abort the
    // whole audit: it becomes a "partial" scan whose handling depends on `fail_on_partial`.
    let (fetch_results, maintenance_issues) =
        tokio::join!(join_all(fetch_tasks), maintenance_future);

    let mut databases = Vec::new();
    let mut failures: Vec<(&'static str, anyhow::Error)> = Vec::new();
    for (name, result) in fetch_results {
        match result {
            Ok(db) => databases.push(db),
            Err(e) => failures.push((name, e.into())),
        }
    }

    // Total failure (every source down, or the only source in a single-source run) is always
    // a hard error regardless of `fail_on_partial` — there is nothing to report on.
    if databases.is_empty() {
        return match failures.into_iter().next() {
            Some((name, err)) => {
                Err(err.context(format!("all vulnerability sources failed (first: {name})")))
            }
            // Unreachable: an empty `databases` implies >= 1 failed source, since there is
            // always >= 1 configured source. A defensive error, never a panic.
            None => Err(anyhow::anyhow!("no vulnerability data could be fetched")),
        };
    }

    // Partial scan: some sources failed but at least one succeeded. Warn loudly and carry the
    // failed-source names into the report; the exit gate (`no_fail_on_partial`) is applied by
    // the caller after the report — an incomplete scan is never silent.
    let failed_sources: Vec<String> = failures
        .iter()
        .map(|(name, _)| (*name).to_string())
        .collect();
    for (name, err) in &failures {
        tracing::warn!("vulnerability source '{name}' failed to fetch: {err}");
        if !audit_args.is_quiet() {
            eprintln!("Warning: vulnerability source '{name}' failed to fetch: {err}");
        }
    }

    if databases.len() > 1 && !audit_args.is_quiet() {
        eprintln!(
            "Merging vulnerability data from {} sources...",
            databases.len()
        );
    }
    // Always merge, even for a single source: a source can report the same
    // vulnerability under aliased advisory IDs (e.g. PyPI lists GHSA and PYSEC
    // entries separately). merge collapses aliases per package, so the count
    // reflects distinct vulnerabilities instead of double-counting aliases.
    let database = VulnerabilityDatabase::merge(databases);

    if audit_args.is_verbose() {
        eprintln!("Matching against vulnerability database...");
    }
    let fail_on_level: crate::SeverityLevel = audit_args.fail_on.clone().into();
    let matcher_config = build_matcher_config(audit_args);
    let matcher = VulnerabilityMatcher::new(database, matcher_config);

    let matches = matcher.find_vulnerabilities(&dependencies)?;
    let mut display_matches = matcher.filter_matches(matches);

    for ignore_id in matcher.unmatched_ignore_ids() {
        tracing::warn!("ignore ID '{}' did not match any finding", ignore_id);
    }

    // Per-group attribution and main-reachability are only consumed by per-group policy.
    // When no `[groups.*]` threshold is configured they can never change the outcome, so
    // skip the extra lock/manifest parses entirely (the common case).
    let mut main_reachable: HashSet<PackageName> = HashSet::new();
    if !audit_args.group_fail_on.is_empty() {
        // Tag each finding with the dependency groups (PEP 735 / Poetry) that reach its
        // package, for per-group policy thresholds. Never filters `display_matches`.
        let group_attribution =
            crate::parsers::graph::build_group_attribution(&audit_args.path, &detected_parser_name)
                .await;
        for finding in &mut display_matches {
            if let Some(groups) = group_attribution.get(&finding.package_name) {
                finding.groups = groups.iter().cloned().collect();
            }
        }

        // The main/prod reachability set: a finding in one of these packages keeps the
        // global `fail_on` as a floor, so a permissive group threshold cannot loosen it.
        main_reachable =
            crate::parsers::graph::build_main_reachable(&audit_args.path, &detected_parser_name)
                .await;

        // Per-group policy is set but the project has no group-aware lock, so attribution is
        // empty and the thresholds can never apply. Warn loudly rather than silently ignoring.
        if !crate::parsers::has_group_aware_lock(&audit_args.path) {
            let msg = "per-group fail thresholds ([groups.*]) are configured but this project \
                       has no group-aware lock (uv.lock, poetry.lock, pylock.toml); the \
                       thresholds are ignored";
            tracing::warn!("{msg}");
            if !audit_args.is_quiet() {
                eprintln!("Warning: {msg}");
            }
        }
    }

    // Suppress [ignore].packages matches (marked, never dropped) before evaluating the
    // exit condition, so a suppressed finding is still reported but never fails the run.
    apply_package_ignores(&mut display_matches, &audit_args.ignore_packages);

    let group_thresholds: BTreeMap<String, Severity> = audit_args
        .group_fail_on
        .iter()
        .map(|(name, level)| (name.clone(), severity_level_to_db(&level.clone().into())))
        .collect();
    let fail_vulns = evaluate_fail_condition(
        &display_matches,
        &fail_on_level,
        &group_thresholds,
        &main_reachable,
        !audit_args.no_fail_on_unknown,
    );

    let database_stats = matcher.get_database_stats();
    let fix_analysis = matcher.analyze_fixes(&display_matches);

    let direct_deps = crate::dependency::scanner::ScannedDependency::direct_names(&dependencies);
    let transitive_roots = crate::parsers::graph::build_transitive_roots(
        &audit_args.path,
        &detected_parser_name,
        &direct_deps,
    )
    .await;

    let report = AuditReport::new(
        dependency_stats,
        database_stats,
        display_matches,
        fix_analysis,
        warnings,
        maintenance_issues,
    )
    .with_transitive_roots(transitive_roots)
    .with_failed_sources(failed_sources);

    let summary = report.summary();
    let maint_summary = report.maintenance_summary();
    if audit_args.is_verbose() {
        eprintln!(
            "Audit complete: {} vulnerabilities found in {} packages",
            summary.total_vulnerabilities, summary.vulnerable_packages
        );
        if maint_summary.has_issues() {
            eprintln!(
                "Maintenance issues: {} archived, {} deprecated, {} quarantined",
                maint_summary.archived_count,
                maint_summary.deprecated_count,
                maint_summary.quarantined_count
            );
        }
    }

    Ok((report, fail_vulns))
}

async fn scan_explicit_requirements(
    requirements_files: &[std::path::PathBuf],
    direct_only: bool,
    resolver: ResolverTypeArg,
    no_resolver: bool,
) -> Result<(
    Vec<crate::dependency::scanner::ScannedDependency>,
    Vec<crate::parsers::SkippedPackage>,
)> {
    let resolver_type: ResolverType = resolver.into();
    let parser = RequirementsParser::new(Some(resolver_type));

    let (parsed_deps, skipped_packages) = parser
        .parse_explicit_files(requirements_files, direct_only, no_resolver)
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
            source_file: dep.source_file,
        })
        .collect();

    Ok((scanned_dependencies, skipped_packages))
}

async fn scan_pep723_scripts(
    project_dir: &Path,
    resolver: Option<ResolverType>,
    direct_only: bool,
) -> Result<(
    Vec<crate::dependency::scanner::ScannedDependency>,
    Vec<crate::parsers::SkippedPackage>,
    usize,
)> {
    let scripts = find_python_scripts(project_dir)?;
    let parser = crate::parsers::pep723::Pep723Parser::new(resolver);
    let mut dependencies = Vec::new();
    let mut skipped_packages = Vec::new();
    let mut parsed_scripts = 0;

    for script in scripts {
        if !parser.can_parse(&script) {
            continue;
        }

        let (parsed_deps, skipped) = parser
            .parse_dependencies(&script, false, false, direct_only)
            .await?;
        parsed_scripts += 1;

        // Intentionally overrides Pep723Parser's basename-only source_file with the
        // project-relative path: a script discovered under a tree wants `tools/x.py`,
        // not `x.py`. A directly-pointed script (no project_dir context) keeps the
        // parser's basename, so the two entry paths differ by design.
        let source_file = script
            .strip_prefix(project_dir)
            .unwrap_or(&script)
            .to_string_lossy()
            .to_string();

        dependencies.extend(parsed_deps.into_iter().map(|mut dep| {
            dep.source_file = Some(source_file.clone());
            crate::dependency::scanner::ScannedDependency {
                name: dep.name,
                version: dep.version,
                is_direct: dep.is_direct,
                source: dep.source.into(),
                path: dep.path,
                source_file: dep.source_file,
            }
        }));
        skipped_packages.extend(skipped);
    }

    Ok((dependencies, skipped_packages, parsed_scripts))
}

fn find_python_scripts(project_dir: &Path) -> Result<Vec<PathBuf>> {
    let mut pending = vec![project_dir.to_path_buf()];
    let mut scripts = Vec::new();

    while let Some(dir) = pending.pop() {
        for entry in std::fs::read_dir(&dir)? {
            let entry = entry?;
            let path = entry.path();
            let file_type = entry.file_type()?;
            let file_name = entry.file_name();
            let file_name = file_name.to_string_lossy();

            if file_type.is_dir() {
                if should_skip_script_dir(&file_name) {
                    continue;
                }
                pending.push(path);
            } else if file_type.is_file()
                && path.extension().and_then(|ext| ext.to_str()) == Some("py")
            {
                scripts.push(path);
            }
        }
    }

    scripts.sort();
    Ok(scripts)
}

fn should_skip_script_dir(name: &str) -> bool {
    name.starts_with('.')
        || matches!(
            name,
            "__pycache__" | "build" | "dist" | "node_modules" | "site-packages" | "venv"
        )
}

#[cfg(test)]
mod tests {
    use super::{
        apply_package_ignores, build_matcher_config, evaluate_fail_condition,
        partial_scan_should_fail, scan_pep723_scripts,
    };
    use crate::types::PackageName;
    use crate::vulnerability::database::SuppressionReason;
    use crate::{Severity, VulnerabilityMatch};
    use std::collections::{BTreeMap, HashSet};
    use std::str::FromStr;

    #[test]
    fn test_partial_scan_strict_fails_and_lenient_continues() {
        // Strict (default): a failed source is an incomplete scan → fail (exit 2).
        assert!(partial_scan_should_fail(true, false));
        // Lenient (--no-fail-on-partial): continue by findings despite the failed source.
        assert!(!partial_scan_should_fail(true, true));
        // No failures: the knob is irrelevant, never fail on this account.
        assert!(!partial_scan_should_fail(false, false));
        assert!(!partial_scan_should_fail(false, true));
    }

    // Calling --group on a project with no pyproject.toml must return a clear error
    // before any dependency scanning begins.
    #[tokio::test]
    async fn test_requirements_txt_with_group_errors_clearly() {
        use crate::cli::AuditArgs;
        use clap::Parser;
        use tempfile::TempDir;

        let temp_dir = TempDir::new().unwrap();
        tokio::fs::write(
            temp_dir.path().join("requirements.txt"),
            b"requests==2.28.0\n",
        )
        .await
        .unwrap();

        let project_path_str = temp_dir.path().to_str().unwrap();
        let audit_args =
            AuditArgs::try_parse_from(["pysentry", "--group", "polars", project_path_str]).unwrap();

        let cache_dir = temp_dir.path().join("cache");
        let result = super::perform_audit(
            &audit_args,
            &cache_dir,
            crate::config::HttpConfig::default(),
            3600,
            &[],
            &crate::ci::CiEnvironment::None,
        )
        .await;

        assert!(result.is_err(), "expected error when no pyproject.toml");
        let err = result.unwrap_err();
        assert!(
            err.to_string()
                .contains("requirements.txt has no dependency-group concept"),
            "unexpected error message: {err}"
        );
    }

    #[tokio::test]
    async fn test_service_url_requires_osv_only_source() {
        use crate::cli::{AuditArgs, VulnerabilitySourceType};
        use clap::Parser;
        use tempfile::TempDir;

        let temp_dir = TempDir::new().unwrap();
        let project_path_str = temp_dir.path().to_str().unwrap();
        let audit_args = AuditArgs::try_parse_from([
            "pysentry",
            "--service-url",
            "https://osv.internal/v1",
            project_path_str,
        ])
        .unwrap();

        let cache_dir = temp_dir.path().join("cache");
        // Sources resolve to PyPA (not the required osv-only set) → guard must fire pre-network.
        let result = super::perform_audit(
            &audit_args,
            &cache_dir,
            crate::config::HttpConfig::default(),
            3600,
            &[VulnerabilitySourceType::Pypa],
            &crate::ci::CiEnvironment::None,
        )
        .await;

        assert!(
            result.is_err(),
            "expected error: --service-url without osv-only sources"
        );
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("--service-url is only valid with `--sources osv`"),);
    }

    // A user who passes BOTH --group and explicit --requirements-files is asking for two
    // contradictory things: "filter by named group" AND "ignore pyproject.toml, use these
    // requirements.txt files." Even if a pyproject.toml is present, --requirements-files
    // bypasses it, so --group has nothing to filter. Fail fast with a distinct error that
    // names the flag combination rather than pointing at a missing file.
    #[tokio::test]
    async fn test_group_with_explicit_requirements_files_errors_clearly() {
        use crate::cli::AuditArgs;
        use clap::Parser;
        use tempfile::TempDir;

        let temp_dir = TempDir::new().unwrap();
        // A valid pyproject.toml exists — the error must fire because of the flag combo,
        // not because pyproject is missing.
        tokio::fs::write(
            temp_dir.path().join("pyproject.toml"),
            b"[project]\nname = \"x\"\n\n[dependency-groups]\nprod = [\"httpx>=0.27\"]\n",
        )
        .await
        .unwrap();
        let req_path = temp_dir.path().join("req.txt");
        tokio::fs::write(&req_path, b"requests==2.28.0\n")
            .await
            .unwrap();

        let project_path_str = temp_dir.path().to_str().unwrap();
        let req_path_str = req_path.to_str().unwrap();
        let audit_args = AuditArgs::try_parse_from([
            "pysentry",
            "--group",
            "prod",
            "--requirements-files",
            req_path_str,
            project_path_str,
        ])
        .unwrap();

        let cache_dir = temp_dir.path().join("cache");
        let result = super::perform_audit(
            &audit_args,
            &cache_dir,
            crate::config::HttpConfig::default(),
            3600,
            &[],
            &crate::ci::CiEnvironment::None,
        )
        .await;

        assert!(
            result.is_err(),
            "expected error when combining --group with --requirements-files"
        );
        let err = result.unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("--group cannot be combined with --requirements-files or --no-resolver"),
            "error must name the flag combination, got: {msg}"
        );
    }

    #[tokio::test]
    async fn test_include_scripts_scans_pep723_files_beside_project_files() {
        let project_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/pep723-with-project-files");

        let (deps, skipped, script_count) = scan_pep723_scripts(&project_dir, None, false)
            .await
            .unwrap();

        assert_eq!(script_count, 1);
        assert!(skipped.is_empty());
        assert_eq!(deps.len(), 1);
        let dep = deps
            .first()
            .expect("fixture should produce one script dependency");
        assert_eq!(dep.name.to_string(), "requests");
        assert_eq!(dep.source_file.as_deref(), Some("audit_script.py"));
    }

    fn make_match(vuln_level: Severity) -> VulnerabilityMatch {
        VulnerabilityMatch {
            package_name: crate::types::PackageName::from_str("test-pkg").unwrap(),
            installed_version: crate::types::Version::from_str("1.0.0").unwrap(),
            vulnerability: crate::vulnerability::database::Vulnerability::with_level(vuln_level),
            is_direct: true,
            source_file: None,
            groups: std::collections::BTreeSet::new(),
            suppressed: None,
        }
    }

    fn no_groups() -> BTreeMap<String, Severity> {
        BTreeMap::new()
    }

    // The default finding package ("test-pkg") is treated as group-only (not shipped to
    // prod) unless a test opts it into main-reachability.
    fn no_main() -> HashSet<PackageName> {
        HashSet::new()
    }

    fn make_grouped_match(vuln_level: Severity, groups: &[&str]) -> VulnerabilityMatch {
        let mut m = make_match(vuln_level);
        m.groups = groups.iter().map(|g| g.to_string()).collect();
        m
    }

    // HIGH meets fail_on=Medium → should fail.
    #[test]
    fn test_fail_condition_meets_threshold() {
        let matches = vec![make_match(Severity::High)];
        let fail = evaluate_fail_condition(
            &matches,
            &crate::SeverityLevel::Medium,
            &no_groups(),
            &no_main(),
            true,
        );
        assert!(fail, "HIGH meets fail_on=Medium threshold");
    }

    // LOW does not meet fail_on=High → no failure.
    #[test]
    fn test_fail_condition_below_threshold() {
        let matches = vec![make_match(Severity::Low)];
        let fail = evaluate_fail_condition(
            &matches,
            &crate::SeverityLevel::High,
            &no_groups(),
            &no_main(),
            true,
        );
        assert!(!fail, "LOW does not meet fail_on=High threshold");
    }

    // UNKNOWN triggers failure when fail_on_unknown=true regardless of threshold.
    #[test]
    fn test_fail_condition_unknown_vuln() {
        let matches = vec![make_match(Severity::Unknown)];
        let fail = evaluate_fail_condition(
            &matches,
            &crate::SeverityLevel::Medium,
            &no_groups(),
            &no_main(),
            true,
        );
        assert!(fail, "Unknown causes failure when fail_on_unknown=true");
    }

    // strictest-wins: a dev-only finding with a stricter group threshold (low) fails even
    // though the global fail_on (critical) would not, and a group threshold never loosens
    // below what a second reaching group demands.
    #[test]
    fn test_policy_group_threshold_tightens_below_global() {
        let matches = vec![make_grouped_match(Severity::Medium, &["dev"])];
        let thresholds = BTreeMap::from([("dev".to_string(), Severity::Low)]);
        let fail = evaluate_fail_condition(
            &matches,
            &crate::SeverityLevel::Critical,
            &thresholds,
            &no_main(),
            true,
        );
        assert!(
            fail,
            "MEDIUM meets the group's low threshold despite global=critical"
        );
    }

    #[test]
    fn test_policy_strictest_group_wins_across_groups() {
        // Reachable from prod (medium) and dev (critical): strictest = medium.
        let matches = vec![make_grouped_match(Severity::Medium, &["prod", "dev"])];
        let thresholds = BTreeMap::from([
            ("prod".to_string(), Severity::Medium),
            ("dev".to_string(), Severity::Critical),
        ]);
        let fail = evaluate_fail_condition(
            &matches,
            &crate::SeverityLevel::High,
            &thresholds,
            &no_main(),
            true,
        );
        assert!(
            fail,
            "MEDIUM meets prod's medium (strictest reaching group)"
        );
    }

    // A group with no configured threshold falls back to the global default.
    #[test]
    fn test_policy_unpoliced_group_uses_global() {
        let matches = vec![make_grouped_match(Severity::Medium, &["docs"])];
        let fail = evaluate_fail_condition(
            &matches,
            &crate::SeverityLevel::High,
            &no_groups(),
            &no_main(),
            true,
        );
        assert!(!fail, "MEDIUM below global high, no group override");
    }

    // Loosen (closes #151): a group-ONLY package (not shipped to prod) takes its group's
    // permissive threshold outright — a HIGH dev finding does not fail when the dev policy
    // is `critical`, even though the stricter global `medium` would have failed it.
    #[test]
    fn test_policy_group_only_loosens_below_global() {
        let matches = vec![make_grouped_match(Severity::High, &["dev"])];
        let thresholds = BTreeMap::from([("dev".to_string(), Severity::Critical)]);
        let fail = evaluate_fail_condition(
            &matches,
            &crate::SeverityLevel::Medium,
            &thresholds,
            &no_main(), // dev-only: not main-reachable
            true,
        );
        assert!(
            !fail,
            "HIGH below the dev group's critical threshold; global=medium must not floor a group-only package"
        );
    }

    // Floor: the same permissive group threshold cannot loosen a package that is ALSO
    // main-reachable (ships to prod) — global stays a floor, so the HIGH finding fails.
    #[test]
    fn test_policy_main_reachable_keeps_global_floor() {
        let matches = vec![make_grouped_match(Severity::High, &["dev"])];
        let thresholds = BTreeMap::from([("dev".to_string(), Severity::Critical)]);
        let main_reachable: HashSet<PackageName> =
            std::iter::once(PackageName::new("test-pkg")).collect();
        let fail = evaluate_fail_condition(
            &matches,
            &crate::SeverityLevel::Medium,
            &thresholds,
            &main_reachable,
            true,
        );
        assert!(
            fail,
            "HIGH meets the global medium floor; a prod-shipped package can't be loosened by a group"
        );
    }

    // Unknown short-circuits before the group-threshold min (a configured group must not
    // collapse the effective level to Unknown and fail on everything).
    #[test]
    fn test_policy_unknown_ignores_group_thresholds() {
        let matches = vec![make_grouped_match(Severity::Unknown, &["dev"])];
        let thresholds = BTreeMap::from([("dev".to_string(), Severity::Critical)]);
        let fail = evaluate_fail_condition(
            &matches,
            &crate::SeverityLevel::Critical,
            &thresholds,
            &no_main(),
            false,
        );
        assert!(
            !fail,
            "Unknown with fail_on_unknown=false never fails, group threshold ignored"
        );
    }

    // Suppressed findings are still reported (kept in the slice) but never trigger failure.
    #[test]
    fn test_package_ignore_suppresses_without_dropping() {
        let mut ignored = make_match(Severity::Critical);
        ignored.package_name = PackageName::new("ignored-pkg");
        let mut matches = vec![ignored, make_grouped_match(Severity::High, &["dev"])];
        apply_package_ignores(&mut matches, &["ignored_pkg".to_string()]);

        // Reporting: nothing dropped, and the matched finding is marked suppressed.
        assert_eq!(matches.len(), 2, "suppressed findings stay in the report");
        assert_eq!(
            matches.first().and_then(|m| m.suppressed),
            Some(SuppressionReason::IgnoredPackage),
            "PEP 503 normalization matches ignored_pkg to ignored-pkg"
        );
        assert!(matches.get(1).expect("second finding").suppressed.is_none());

        // Exit: the suppressed critical no longer fails; the other finding still can.
        let fail = evaluate_fail_condition(
            &matches,
            &crate::SeverityLevel::Critical,
            &no_groups(),
            &no_main(),
            true,
        );
        assert!(
            !fail,
            "suppressed critical excluded; high does not meet critical"
        );
        let fail = evaluate_fail_condition(
            &matches,
            &crate::SeverityLevel::High,
            &no_groups(),
            &no_main(),
            true,
        );
        assert!(fail, "the non-suppressed high still fails at fail_on=high");
    }

    // The matcher threshold stays Low regardless of policy — policy touches the exit
    // condition only, never what reaches the report (the fail_on invariant).
    #[test]
    fn test_policy_never_filters_matcher() {
        use clap::Parser;
        let args = crate::cli::AuditArgs::try_parse_from(["pysentry", "."]).unwrap();
        let config = build_matcher_config(&args);
        assert_eq!(config.min_severity, crate::SeverityLevel::Low);
    }

    // Regression guard: fail_on must never narrow the matcher. A v0.4.5 refactor wired fail_on
    // into the matcher's min_severity, so `--fail-on critical` silently dropped every non-critical
    // vulnerability from the report. The matcher threshold must stay Low for every fail_on level.
    #[test]
    fn test_fail_on_never_filters_matcher() {
        use crate::cli::AuditArgs;
        use clap::Parser;

        for level in ["low", "medium", "high", "critical"] {
            let audit_args =
                AuditArgs::try_parse_from(["pysentry", "--fail-on", level, "."]).unwrap();
            let config = super::build_matcher_config(&audit_args);
            assert_eq!(
                config.min_severity,
                crate::SeverityLevel::Low,
                "matcher threshold must stay Low so --fail-on {level} reports all severities"
            );
        }
    }

    // Simulates the post-merge state produced when the user passes --group on the CLI
    // and a .pysentry.toml has `scope = "main"` (which sets exclude_extra=true after merge).
    // Clap's conflicts_with only catches the CLI-only combo; this tests the config-path.
    #[tokio::test]
    async fn test_group_with_exclude_extra_errors_clearly() {
        use crate::cli::AuditArgs;
        use clap::Parser;
        use tempfile::TempDir;

        let temp_dir = TempDir::new().unwrap();
        tokio::fs::write(
            temp_dir.path().join("pyproject.toml"),
            b"[project]\nname = \"x\"\n\n[dependency-groups]\nprod = [\"httpx>=0.27\"]\n",
        )
        .await
        .unwrap();

        let project_path_str = temp_dir.path().to_str().unwrap();
        let mut audit_args =
            AuditArgs::try_parse_from(["pysentry", "--group", "prod", project_path_str]).unwrap();
        audit_args.exclude_extra = true;

        let cache_dir = temp_dir.path().join("cache");
        let result = super::perform_audit(
            &audit_args,
            &cache_dir,
            crate::config::HttpConfig::default(),
            3600,
            &[],
            &crate::ci::CiEnvironment::None,
        )
        .await;

        assert!(result.is_err(), "expected error for groups + exclude_extra");
        let err = result.unwrap_err();
        assert!(
            err.to_string().contains("--exclude-extra"),
            "error must mention --exclude-extra, got: {err}"
        );
    }

    // A named PEP 751 lock file (pylock.<name>.toml, with no canonical pylock.toml) must
    // satisfy the --group lock-file preflight, since PyLockParser handles named variants.
    // We pass a non-existent group so the check proceeds offline to group-name validation:
    // the error must be "group not found", NOT "requires a lock file" — proving the named
    // pylock was detected rather than falsely rejected.
    #[tokio::test]
    async fn test_group_accepts_named_pylock_variant() {
        use crate::cli::AuditArgs;
        use clap::Parser;
        use tempfile::TempDir;

        let temp_dir = TempDir::new().unwrap();
        tokio::fs::write(
            temp_dir.path().join("pyproject.toml"),
            b"[project]\nname = \"x\"\n\n[dependency-groups]\nprod = [\"httpx>=0.27\"]\n",
        )
        .await
        .unwrap();
        // Named variant only — no canonical pylock.toml. Content is irrelevant here; the
        // preflight only checks for the file's presence.
        tokio::fs::write(
            temp_dir.path().join("pylock.production.toml"),
            b"lock-version = \"1.0\"\ncreated-by = \"test\"\n",
        )
        .await
        .unwrap();

        let project_path_str = temp_dir.path().to_str().unwrap();
        let audit_args =
            AuditArgs::try_parse_from(["pysentry", "--group", "missing", project_path_str])
                .unwrap();

        let cache_dir = temp_dir.path().join("cache");
        let result = super::perform_audit(
            &audit_args,
            &cache_dir,
            crate::config::HttpConfig::default(),
            3600,
            &[],
            &crate::ci::CiEnvironment::None,
        )
        .await;

        assert!(result.is_err(), "expected group-not-found error");
        let msg = result.unwrap_err().to_string();
        assert!(
            !msg.contains("requires a lock file"),
            "named pylock variant must satisfy the lock-file preflight, got: {msg}"
        );
        assert!(
            msg.contains("not found") && msg.contains("available groups"),
            "expected group-not-found error, got: {msg}"
        );
    }

    // P3: a manifest whose group names collide after PEP 735 normalization is ambiguous.
    // perform_audit must surface that error from the preflight — offline, before any
    // scanning. A uv.lock is present so the lock-file gate passes and we reach the
    // group-name validation where list_group_names rejects the collision.
    #[tokio::test]
    async fn test_group_rejects_ambiguous_normalized_groups() {
        use crate::cli::AuditArgs;
        use clap::Parser;
        use tempfile::TempDir;

        let temp_dir = TempDir::new().unwrap();
        tokio::fs::write(
            temp_dir.path().join("pyproject.toml"),
            b"[project]\nname = \"x\"\n\n[dependency-groups]\ntyping_test = [\"mypy>=1\"]\ntyping-test = [\"pyright>=1\"]\n",
        )
        .await
        .unwrap();
        tokio::fs::write(temp_dir.path().join("uv.lock"), b"version = 1\n")
            .await
            .unwrap();

        let project_path_str = temp_dir.path().to_str().unwrap();
        let audit_args =
            AuditArgs::try_parse_from(["pysentry", "--group", "typing-test", project_path_str])
                .unwrap();

        let cache_dir = temp_dir.path().join("cache");
        let result = super::perform_audit(
            &audit_args,
            &cache_dir,
            crate::config::HttpConfig::default(),
            3600,
            &[],
            &crate::ci::CiEnvironment::None,
        )
        .await;

        assert!(result.is_err(), "ambiguous normalized groups must error");
        let msg = result.unwrap_err().to_string();
        assert!(
            msg.contains("normalize to the same"),
            "preflight must surface the ambiguity error, got: {msg}"
        );
    }
}
