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
use crate::parsers::requirements::RequirementsParser;
use crate::types::ResolverType;
use crate::{
    AuditCache, AuditReport, DependencyScanner, MatcherConfig, Severity, VulnerabilityDatabase,
    VulnerabilityMatch, VulnerabilityMatcher, VulnerabilitySource,
};
use anyhow::Result;
use futures::future::try_join_all;
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

        use crate::parsers::ParserRegistry;
        let parser_registry = ParserRegistry::new(Some(resolver_type));
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
}
