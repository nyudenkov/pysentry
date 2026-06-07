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
use crate::parsers::ParserRegistry;
use crate::types::ResolverType;
use crate::{
    AuditCache, AuditReport, DependencyScanner, MatcherConfig, Severity, VulnerabilityDatabase,
    VulnerabilityMatch, VulnerabilityMatcher, VulnerabilitySource,
};
use anyhow::Result;
use futures::future::try_join_all;
use std::collections::HashSet;
use std::path::Path;

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
            return Ok(1);
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
            return Ok(1);
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

    if fail_vulns || fail_maintenance {
        Ok(1)
    } else {
        Ok(0)
    }
}

/// Evaluate whether any match triggers the fail_on exit condition.
/// Returns (matches, should_fail).
pub(crate) fn evaluate_fail_condition(
    matches: Vec<VulnerabilityMatch>,
    fail_on: &crate::SeverityLevel,
    fail_on_unknown: bool,
) -> (Vec<VulnerabilityMatch>, bool) {
    let fail_on_db = match fail_on {
        crate::SeverityLevel::Low => Severity::Low,
        crate::SeverityLevel::Medium => Severity::Medium,
        crate::SeverityLevel::High => Severity::High,
        crate::SeverityLevel::Critical => Severity::Critical,
    };

    let fail_vulns = matches.iter().any(|m| {
        if m.vulnerability.is_level_unknown() {
            return fail_on_unknown;
        }
        m.vulnerability.meets_level(fail_on_db)
    });

    (matches, fail_vulns)
}

async fn perform_audit(
    audit_args: &AuditArgs,
    cache_dir: &Path,
    http_config: crate::config::HttpConfig,
    vulnerability_ttl: u64,
    source_types: &[VulnerabilitySourceType],
    ci_env: &crate::ci::CiEnvironment,
) -> Result<(AuditReport, bool)> {
    std::fs::create_dir_all(cache_dir)?;

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
            eprintln!("Fetching vulnerability data from {}...", source_names[0]);
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

    let (dependencies, skipped_packages, detected_parser_name) = if !audit_args
        .requirements_files
        .is_empty()
    {
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
    } else if audit_args.no_resolver {
        // --no-resolver without --requirements-files: discover requirements.txt files
        let resolver_type: ResolverType = audit_args.resolver.clone().into();
        let parser = crate::parsers::requirements::RequirementsParser::new(Some(resolver_type));
        let req_files = parser.find_requirements_files(&audit_args.path, audit_args.include_dev());
        if req_files.is_empty() {
            return Err(anyhow::anyhow!(
                "--no-resolver requires requirements.txt files but none were found in {}",
                audit_args.path.display()
            ));
        }
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
            scan_explicit_requirements(&req_files, true, audit_args.resolver.clone(), true).await?;
        (scanned, skipped, "requirements.txt".to_string())
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
        let (raw_parsed_deps, skipped_packages, parser_name) = parser_registry
            .parse_project(
                &audit_args.path,
                parse_dev,
                parse_optional,
                audit_args.direct_only,
            )
            .await?;

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

    // Fetch maintenance status (PEP 792) in parallel if enabled
    let maintenance_future = async {
        if audit_args.maintenance_enabled() {
            if audit_args.is_verbose() {
                eprintln!("Checking PEP 792 project status markers...");
            }
            let maintenance_client = crate::maintenance::SimpleIndexClient::new(
                http_config.clone(),
                Some(audit_cache.clone()),
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

    // Run vulnerability fetching and maintenance checks in parallel
    let (vuln_result, maintenance_issues) =
        tokio::join!(try_join_all(fetch_tasks), maintenance_future);

    let databases = vuln_result?;

    let database = if databases.len() == 1 {
        databases.into_iter().next().unwrap()
    } else {
        if !audit_args.is_quiet() {
            eprintln!(
                "Merging vulnerability data from {} sources...",
                databases.len()
            );
        }
        VulnerabilityDatabase::merge(databases)
    };

    if audit_args.is_verbose() {
        eprintln!("Matching against vulnerability database...");
    }
    let fail_on_level: crate::SeverityLevel = audit_args.fail_on.clone().into();
    let matcher_config = MatcherConfig::new(
        fail_on_level.clone(),
        audit_args.ignore_ids.to_vec(),
        audit_args.ignore_while_no_fix.to_vec(),
        audit_args.direct_only,
        audit_args.include_withdrawn,
    );
    let matcher = VulnerabilityMatcher::new(database, matcher_config);

    let matches = matcher.find_vulnerabilities(&dependencies)?;
    let filtered_matches = matcher.filter_matches(matches);

    let (display_matches, fail_vulns) = evaluate_fail_condition(
        filtered_matches,
        &fail_on_level,
        !audit_args.no_fail_on_unknown,
    );

    let database_stats = matcher.get_database_stats();
    let fix_analysis = matcher.analyze_fixes(&display_matches);

    let report = AuditReport::new(
        dependency_stats,
        database_stats,
        display_matches,
        fix_analysis,
        warnings,
        maintenance_issues,
    );

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

#[cfg(test)]
mod tests {
    use super::evaluate_fail_condition;
    use crate::{Severity, VulnerabilityMatch};
    use std::str::FromStr;

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

    fn make_match(vuln_level: Severity) -> VulnerabilityMatch {
        VulnerabilityMatch {
            package_name: crate::types::PackageName::from_str("test-pkg").unwrap(),
            installed_version: crate::types::Version::from_str("1.0.0").unwrap(),
            vulnerability: crate::vulnerability::database::Vulnerability::with_level(vuln_level),
            is_direct: true,
        }
    }

    // HIGH meets fail_on=Medium → should fail, match is returned.
    #[test]
    fn test_fail_condition_meets_threshold() {
        let matches = vec![make_match(Severity::High)];
        let (display, fail) = evaluate_fail_condition(matches, &crate::SeverityLevel::Medium, true);
        assert!(fail, "HIGH meets fail_on=Medium threshold");
        assert_eq!(display.len(), 1, "match is returned");
    }

    // LOW does not meet fail_on=High → no failure, match is returned.
    #[test]
    fn test_fail_condition_below_threshold() {
        let matches = vec![make_match(Severity::Low)];
        let (display, fail) = evaluate_fail_condition(matches, &crate::SeverityLevel::High, true);
        assert!(!fail, "LOW does not meet fail_on=High threshold");
        assert_eq!(display.len(), 1, "match is returned");
    }

    // UNKNOWN triggers failure when fail_on_unknown=true regardless of threshold.
    #[test]
    fn test_fail_condition_unknown_vuln() {
        let matches = vec![make_match(Severity::Unknown)];
        let (display, fail) = evaluate_fail_condition(matches, &crate::SeverityLevel::Medium, true);
        assert!(fail, "Unknown causes failure when fail_on_unknown=true");
        assert_eq!(display.len(), 1, "match is returned");
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
