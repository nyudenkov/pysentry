// SPDX-License-Identifier: MIT
//
// Exhaustive config-wiring coverage.
//
// Every field of every config struct must actually take effect — not just
// parse. Three shipped bugs (issue #146 `output.quiet`, the `fail_on`
// semantics, clap `conflicts_with` not covering config values) came from a
// config option that worked on one path but was never wired through the other.
// See CLAUDE.md "Cross-File Invariants" (the config-file / CLI dual-path row).
//
// Fields reach effective settings via two paths:
//   * Group A — merged into `AuditArgs` by `merge_with_config` (src/audit/merge.rs).
//   * Group B — read straight off the loaded `Config` in src/main.rs and handed
//     to `audit()` (http.*, cache.vulnerability_ttl, notifications.enabled).
//     These have no merge step, so loading them IS the wiring; we assert the
//     parsed value.
//
// When you add a config field: set it to a non-default value in
// tests/fixtures/config-wiring/full.pysentry.toml and add an assertion below.
// If neither fires, the field is dead — wire it through merge.rs (Group A) or
// main.rs (Group B) before shipping.

use clap::Parser;
use pysentry::cli::{AuditArgs, AuditFormat, DisplayModeArg, ResolverTypeArg, SeverityLevel};
use pysentry::ConfigLoader;

fn fixture_path() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/config-wiring/full.pysentry.toml")
}

/// Parse the default CLI args (just a path, no flags) so every merged value is
/// attributable to the config file rather than a CLI override.
fn default_audit_args() -> AuditArgs {
    match AuditArgs::try_parse_from(["pysentry", "."]) {
        Ok(args) => args,
        Err(e) => panic!("default args parse: {e}"),
    }
}

const WIRING: &str = "config field not wired through merge.rs — every option must take \
effect via config file, not just CLI (CLAUDE.md Cross-File Invariants)";

#[test]
fn every_config_field_reaches_effective_settings() {
    let loader = ConfigLoader::load_from_file(fixture_path()).expect("fixture loads");
    let config = loader.config.clone();
    let merged = default_audit_args().merge_with_config(&config);

    // ----- Group A: [defaults] -----
    assert_eq!(
        merged.format,
        AuditFormat::Json,
        "defaults.format: {WIRING}"
    );
    assert_eq!(
        merged.fail_on,
        SeverityLevel::Critical,
        "defaults.fail_on: {WIRING}"
    );
    // scope = "main" surfaces as exclude_extra = true.
    assert!(merged.exclude_extra, "defaults.scope: {WIRING}");
    assert!(merged.direct_only, "defaults.direct_only: {WIRING}");
    assert!(merged.detailed, "defaults.detailed: {WIRING}");
    // compact is mutually exclusive with detailed, so it cannot also be set to a
    // non-default value in the same fixture; its wiring is covered by the
    // merge.rs unit tests (test_cli_compact_overrides_config_detailed et al.).
    assert!(
        !merged.compact,
        "compact stays false alongside detailed=true"
    );
    assert_eq!(
        merged.display,
        Some(DisplayModeArg::Text),
        "defaults.display: {WIRING}"
    );
    assert!(
        merged.include_withdrawn,
        "defaults.include_withdrawn: {WIRING}"
    );
    assert!(merged.no_ci_detect, "defaults.no_ci_detect: {WIRING}");
    assert_eq!(merged.groups, vec!["polars"], "defaults.groups: {WIRING}");

    // ----- Group A: [sources] -----
    assert_eq!(merged.sources, vec!["osv"], "sources.enabled: {WIRING}");

    // ----- Group A: [resolver] -----
    assert_eq!(
        merged.resolver,
        ResolverTypeArg::PipTools,
        "resolver.type: {WIRING}"
    );
    assert!(merged.no_resolver, "resolver.no_resolver: {WIRING}");

    // ----- Group A: [cache] (the AuditArgs-bound subset) -----
    // enabled = false surfaces as no_cache = true.
    assert!(merged.no_cache, "cache.enabled: {WIRING}");
    assert_eq!(
        merged.cache_dir.as_deref(),
        Some(std::path::Path::new("/tmp/pysentry-wiring-fixture-cache")),
        "cache.directory: {WIRING}"
    );
    assert_eq!(
        merged.resolution_cache_ttl, 99,
        "cache.resolution_ttl: {WIRING}"
    );

    // ----- Group A: [ignore] -----
    assert_eq!(
        merged.ignore_ids,
        vec!["PYSEC-2024-0001"],
        "ignore.ids: {WIRING}"
    );
    assert_eq!(
        merged.ignore_while_no_fix,
        vec!["GHSA-aaaa-bbbb-cccc"],
        "ignore.while_no_fix: {WIRING}"
    );

    // ----- Group A: [maintenance] (the AuditArgs-bound subset) -----
    // enabled = false surfaces as no_maintenance_check = true.
    assert!(merged.no_maintenance_check, "maintenance.enabled: {WIRING}");
    assert!(
        merged.forbid_archived,
        "maintenance.forbid_archived: {WIRING}"
    );
    assert!(
        merged.forbid_deprecated,
        "maintenance.forbid_deprecated: {WIRING}"
    );
    // forbid_quarantined defaults to true and the merge only ever propagates
    // `true` (it turns flags ON, never off), so true→true is the only state we
    // can observe; a config value of false would be indistinguishable from the
    // CLI default here.
    assert!(
        merged.forbid_quarantined,
        "maintenance.forbid_quarantined: {WIRING}"
    );
    assert!(
        merged.forbid_unmaintained,
        "maintenance.forbid_unmaintained: {WIRING}"
    );
    assert!(
        merged.maintenance_direct_only,
        "maintenance.check_direct_only: {WIRING}"
    );
    assert_eq!(
        merged.maintenance_cache_ttl, 99,
        "maintenance.cache_ttl: {WIRING}"
    );

    // ----- Group A: [output] -----
    assert!(merged.config_quiet, "output.quiet: {WIRING}");

    // ----- Group B: read directly from Config in main.rs -----
    assert_eq!(config.http.timeout, 99, "http.timeout: {WIRING}");
    assert_eq!(
        config.http.connect_timeout, 15,
        "http.connect_timeout: {WIRING}"
    );
    assert_eq!(config.http.max_retries, 7, "http.max_retries: {WIRING}");
    assert_eq!(
        config.http.retry_initial_backoff, 2,
        "http.retry_initial_backoff: {WIRING}"
    );
    assert_eq!(
        config.http.retry_max_backoff, 99,
        "http.retry_max_backoff: {WIRING}"
    );
    assert!(config.http.show_progress, "http.show_progress: {WIRING}");
    assert_eq!(
        config.cache.vulnerability_ttl, 99,
        "cache.vulnerability_ttl: {WIRING}"
    );
    assert!(
        !config.notifications.enabled,
        "notifications.enabled: {WIRING}"
    );
}

/// `deny_unknown_fields` turns a typo'd config key into a hard error instead of
/// a silently ignored line. Without it, `[defaults] formatt = "json"` would
/// leave format at its default and the user would never know.
#[test]
fn unknown_config_key_is_rejected() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join(".pysentry.toml");
    std::fs::write(&path, "version = 1\n\n[defaults]\nformatt = \"json\"\n")
        .expect("write fixture");

    let err = match ConfigLoader::load_from_file(&path) {
        Ok(_) => panic!("a typo'd key must fail to load, not be silently ignored"),
        Err(err) => err,
    };
    let msg = format!("{err:?}");
    assert!(
        msg.contains("formatt") || msg.contains("unknown field"),
        "error should name the offending key, got: {msg}"
    );
}
