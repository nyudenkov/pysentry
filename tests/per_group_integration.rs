// SPDX-License-Identifier: MIT

use pysentry::DependencyScanner;
use std::collections::HashSet;
use std::path::Path;

const FIXTURE_DIR: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/fixtures/per-group-scope"
);

// Test helper, not a `#[test]` fn, so clippy's allow-expect-in-tests does not cover it.
#[allow(clippy::expect_used)]
async fn scan(
    include_dev: bool,
    include_optional: bool,
    direct_only: bool,
    groups: Option<HashSet<String>>,
) -> (HashSet<String>, HashSet<String>) {
    let scanner = DependencyScanner::new(include_dev, include_optional, direct_only, None, groups);
    let (deps, _, _) = scanner
        .scan_project(Path::new(FIXTURE_DIR))
        .await
        .expect("scan_project must succeed for per-group fixture");

    let direct: HashSet<String> = deps
        .iter()
        .filter(|d| d.is_direct)
        .map(|d| d.name.to_string())
        .collect();
    let all: HashSet<String> = deps.iter().map(|d| d.name.to_string()).collect();
    (direct, all)
}

/// (a) No --group flag: all three directly-declared deps (requests, httpx, pytest)
/// are classified as direct, matching today's default behavior.
#[tokio::test]
async fn test_no_group_flag_reports_all() {
    let (direct, _all) = scan(true, true, false, None).await;
    assert!(direct.contains("requests"), "requests must be direct");
    assert!(direct.contains("httpx"), "httpx must be direct");
    assert!(direct.contains("pytest"), "pytest must be direct");
}

/// (b) --group prod: reachability closure from seeds {requests, httpx} pulls in their
/// real transitive graph (urllib3, certifi, idna, charset-normalizer, anyio, httpcore, h11)
/// while excluding the dev group and its transitives (pytest, iniconfig, pluggy).
#[tokio::test]
async fn test_group_prod_closure_includes_transitive_excludes_dev() {
    let groups = Some(["prod".to_string()].into());
    let (direct, all) = scan(true, true, false, groups).await;

    // Main dep + its real transitives.
    assert!(all.contains("requests"), "requests must be included");
    assert!(
        all.contains("urllib3"),
        "urllib3 (transitive of requests) must be included"
    );
    assert!(
        all.contains("charset-normalizer"),
        "charset-normalizer (transitive of requests) must be included"
    );

    // prod group dep + its real transitives. httpx pulls in anyio/httpcore/h11/idna/certifi;
    // httpcore in turn pulls in h11 (not a new node, but confirms graph walk is multi-level).
    assert!(all.contains("httpx"), "httpx must be included");
    assert!(
        all.contains("anyio"),
        "anyio (transitive of httpx) must be included"
    );
    assert!(
        all.contains("httpcore"),
        "httpcore (transitive of httpx) must be included"
    );
    assert!(
        all.contains("h11"),
        "h11 (transitive of httpcore, 2 levels deep) must be included"
    );

    // Shared transitives between requests and httpx — both paths should converge on these
    // without duplication. Reachable from both seeds, only emitted once.
    assert!(
        all.contains("certifi"),
        "certifi (shared transitive) must be included"
    );
    assert!(
        all.contains("idna"),
        "idna (shared transitive) must be included"
    );

    // Dev group and its transitives must be excluded.
    assert!(!all.contains("pytest"), "pytest must be excluded");
    assert!(
        !all.contains("iniconfig"),
        "iniconfig (pytest transitive) must be excluded"
    );
    assert!(
        !all.contains("pluggy"),
        "pluggy (pytest transitive) must be excluded"
    );

    // Only the seeds are labeled direct; everything reached via the graph walk is transitive.
    assert!(
        direct.contains("requests"),
        "requests must be direct (seed)"
    );
    assert!(direct.contains("httpx"), "httpx must be direct (seed)");
    assert!(
        !direct.contains("urllib3"),
        "urllib3 must not be direct (transitive)"
    );
    assert!(
        !direct.contains("anyio"),
        "anyio must not be direct (transitive)"
    );
    assert!(
        !direct.contains("httpcore"),
        "httpcore must not be direct (transitive)"
    );
}

/// (c) --exclude-extra alone (regression): only [project].dependencies and their
/// transitive closure survive; dependency-groups are excluded entirely.
#[tokio::test]
async fn test_exclude_extra_regression() {
    // include_dev=false, include_optional=false mirrors --exclude-extra
    let (direct, all) = scan(false, false, false, None).await;

    assert!(
        direct.contains("requests"),
        "requests (main dep) must be direct with --exclude-extra"
    );
    assert!(
        !all.contains("httpx"),
        "httpx must be absent with --exclude-extra"
    );
    assert!(
        !all.contains("pytest"),
        "pytest must be absent with --exclude-extra"
    );
    // All of requests' transitive closure must survive --exclude-extra, even when those
    // packages are ALSO reachable from the prod or dev groups. A shared transitive is a
    // legitimate main dep and must not be filtered out by the optional-package walker.
    assert!(
        all.contains("urllib3"),
        "urllib3 (requests transitive, not shared) must be included"
    );
    assert!(
        all.contains("charset-normalizer"),
        "charset-normalizer (requests transitive, not shared) must be included"
    );
    assert!(
        all.contains("certifi"),
        "certifi (requests transitive, SHARED with httpx) must still be included"
    );
    assert!(
        all.contains("idna"),
        "idna (requests transitive, SHARED with httpx) must still be included"
    );
}

/// (d) --group unknown_group: binary exits non-zero; stderr contains "available groups:".
#[test]
fn test_unknown_group_errors() {
    assert_cmd::Command::cargo_bin("pysentry")
        .expect("pysentry binary must be compiled")
        .arg(FIXTURE_DIR)
        .args(["--group", "unknown_group"])
        .assert()
        .failure()
        .stderr(predicates::str::contains("available groups:"));
}
