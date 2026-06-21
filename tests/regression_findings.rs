// SPDX-License-Identifier: MIT
//
// Cross-cutting regression guard for the v0.4.7 false-negative fixes.
//
// Each fix lives in the *shape* of the `VersionRange` a provider emits; the
// matcher only ever sees `VersionRange`, so these fixtures mirror that shape
// in code (no network, no vendored JSON) and run the real matcher. A dropped
// finding shrinks the sorted tuple list and fails `assert_eq!`.
//
// Guards:
//   * Stage 2   — alias-based ignore still suppresses (and only the aliased one).
//   * Stage 3.1 — OSV `affected.versions`-only advisory still matches (==v range).
//   * Stage 3.2 — PyPI multi-branch fix: every fixed version yields a range, so a
//                 version between two fix branches stays affected.
//   * Stage 3.3 — PyPI no-range wildcard (`*`) still matches.

// `.expect()` in the module-level fixture builders is fine in test code, but
// clippy's allow-expect-in-tests only covers `#[test]` fns, not these helpers.
#![allow(clippy::expect_used)]

use pysentry::dependency::scanner::{DependencySource, ScannedDependency};
use pysentry::vulnerability::database::{
    Severity, VersionRange, Vulnerability, VulnerabilityDatabase,
};
use pysentry::{MatcherConfig, PackageName, SeverityLevel, Version, VulnerabilityMatcher};
use std::collections::HashMap;
use std::str::FromStr;

fn version(raw: &str) -> Version {
    Version::from_str(raw).expect("test version parses")
}

fn vuln(
    id: &str,
    severity: Severity,
    ranges: Vec<VersionRange>,
    aliases: &[&str],
) -> Vulnerability {
    Vulnerability {
        id: id.to_string(),
        summary: format!("test advisory {id}"),
        description: None,
        severity,
        affected_versions: ranges,
        fixed_versions: vec![],
        references: vec![],
        cvss_score: None,
        cvss_version: None,
        published: None,
        modified: None,
        source: Some("test".to_string()),
        withdrawn: None,
        aliases: aliases.iter().map(|a| a.to_string()).collect(),
    }
}

/// `==v` inclusive single-version range, as OSV emits for `affected.versions`.
fn exact(raw: &str) -> VersionRange {
    VersionRange {
        min: Some(version(raw)),
        max: Some(version(raw)),
        constraint: format!("=={raw}"),
        max_inclusive: true,
    }
}

/// `<fixed` exclusive range, as PyPI emits per `fixed_in` entry.
fn below(raw: &str) -> VersionRange {
    VersionRange {
        min: None,
        max: Some(version(raw)),
        constraint: format!("<{raw}"),
        max_inclusive: false,
    }
}

/// `*` match-all range, as PyPI emits when no fix bounds the range.
fn wildcard() -> VersionRange {
    VersionRange {
        min: None,
        max: None,
        constraint: "*".to_string(),
        max_inclusive: false,
    }
}

fn dependency(name: &str, ver: &str) -> ScannedDependency {
    ScannedDependency {
        name: PackageName::from_str(name).expect("test package name parses"),
        version: version(ver),
        is_direct: true,
        source: DependencySource::Registry,
        path: None,
        source_file: None,
    }
}

#[test]
fn false_negative_fixes_still_produce_every_finding() {
    let database = VulnerabilityDatabase::from_package_map(HashMap::from([
        (
            "aliased-pkg".to_string(),
            vec![
                // Suppressed via its alias, not its primary id (Stage 2).
                vuln(
                    "GHSA-ignored",
                    Severity::High,
                    vec![exact("1.0.0")],
                    &["CVE-2024-IGNORED"],
                ),
                // Same package, not ignored — proves the alias ignore is selective.
                vuln("GHSA-kept", Severity::High, vec![exact("1.0.0")], &[]),
            ],
        ),
        (
            // OSV versions-only advisory: matches only via the ==v range (Stage 3.1).
            "osv-versions-pkg".to_string(),
            vec![vuln(
                "OSV-VERSIONS",
                Severity::Medium,
                vec![exact("2.5.0")],
                &[],
            )],
        ),
        (
            // PyPI multi-branch fix: 3.0.1 sits between branch fixes 2.31.1 and
            // 3.0.2, so it must match the second range (Stage 3.2). Carrying only
            // the first range was the bug.
            "pypi-multibranch-pkg".to_string(),
            vec![vuln(
                "PYPI-MULTI",
                Severity::Critical,
                vec![below("2.31.1"), below("3.0.2")],
                &[],
            )],
        ),
        (
            // PyPI no-fix wildcard: every version is affected (Stage 3.3).
            "pypi-wildcard-pkg".to_string(),
            vec![vuln("PYPI-WILD", Severity::Low, vec![wildcard()], &[])],
        ),
        (
            // Boundary guard: ==2.5.0 must stay exact. Installed 2.5.1 must NOT
            // match — catches an exact range loosened to >=2.5.0.
            "osv-exact-boundary-pkg".to_string(),
            vec![vuln(
                "OSV-EXACT-CLEAN",
                Severity::High,
                vec![exact("2.5.0")],
                &[],
            )],
        ),
        (
            // Boundary guard: the higher fix branch itself (3.0.2) must NOT match
            // — catches a `<` range flipped to `<=` / inclusive.
            "multibranch-boundary-pkg".to_string(),
            vec![vuln(
                "PYPI-MULTI-CLEAN",
                Severity::High,
                vec![below("2.31.1"), below("3.0.2")],
                &[],
            )],
        ),
    ]));

    let config = MatcherConfig::new(
        SeverityLevel::Low,
        vec!["CVE-2024-IGNORED".to_string()],
        vec![],
        false,
        false,
    );
    let matcher = VulnerabilityMatcher::new(database, config);

    let dependencies = vec![
        dependency("aliased-pkg", "1.0.0"),
        dependency("osv-versions-pkg", "2.5.0"),
        dependency("pypi-multibranch-pkg", "3.0.1"),
        dependency("pypi-wildcard-pkg", "9.9.9"),
        // Boundary versions that must produce zero findings.
        dependency("osv-exact-boundary-pkg", "2.5.1"),
        dependency("multibranch-boundary-pkg", "3.0.2"),
    ];

    let matches = matcher
        .find_vulnerabilities(&dependencies)
        .expect("matching succeeds");

    let mut findings: Vec<(String, String, Severity)> = matches
        .iter()
        .map(|m| {
            (
                m.package_name.to_string(),
                m.vulnerability.id.clone(),
                m.vulnerability.severity,
            )
        })
        .collect();
    findings.sort();

    assert_eq!(
        findings,
        vec![
            (
                "aliased-pkg".to_string(),
                "GHSA-kept".to_string(),
                Severity::High
            ),
            (
                "osv-versions-pkg".to_string(),
                "OSV-VERSIONS".to_string(),
                Severity::Medium
            ),
            (
                "pypi-multibranch-pkg".to_string(),
                "PYPI-MULTI".to_string(),
                Severity::Critical
            ),
            (
                "pypi-wildcard-pkg".to_string(),
                "PYPI-WILD".to_string(),
                Severity::Low
            ),
        ],
    );
}
