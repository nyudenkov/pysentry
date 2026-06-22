// SPDX-License-Identifier: MIT

//! Maps each transitive package back to the top-level (direct) dependencies that
//! pull it in, for `transitive (via <dep>)` display.
//!
//! Display enrichment only: every entry point is best-effort and yields an empty map
//! on a missing/unparseable lock or an unsupported format, never an error. Only lock
//! formats that record inter-package edges can answer this — uv.lock, poetry.lock, and
//! pylock.toml. Pipfile.lock is a flat list with no edges; resolver-expanded manifests
//! (requirements/pyproject/Pipfile) likewise carry no graph here, so both render exactly
//! as before.

use crate::parsers::reachability::reachable_closure;
use crate::parsers::{lock, poetry_lock, pylock};
use crate::types::PackageName;
use std::collections::{HashMap, HashSet};
use std::path::Path;

/// child → sorted top-level deps that reach it. `direct` is the set of declared direct
/// dependencies (taken from the already-scanned deps, so it reuses each parser's own
/// is_direct logic rather than re-deriving it). `parser_name` selects the lock reader.
pub async fn build_transitive_roots(
    project_dir: &Path,
    parser_name: &str,
    direct: &HashSet<PackageName>,
) -> HashMap<PackageName, Vec<PackageName>> {
    if direct.is_empty() {
        return HashMap::new();
    }
    // Edge readers union main + ALL optional/dev edges, so a transitive can be attributed
    // to a direct dep via an extra that wasn't activated in this install (a spurious "via"
    // root). Acceptable for display; tighten by intersecting against the activated extras
    // (as lock.rs's group reachability already does) if it misleads.
    let edges = match parser_name {
        "uv.lock" => lock::uv_lock_edges(project_dir).await,
        "poetry.lock" => poetry_lock::poetry_lock_edges(project_dir).await,
        "pylock.toml" => pylock::pylock_edges(project_dir).await,
        _ => return HashMap::new(),
    };
    transitive_roots(direct, &edges)
}

/// Attribute every reachable package to each direct dependency whose subtree contains it.
/// A package reachable from several direct deps lists all of them (sorted). The direct dep
/// itself is never listed as its own root.
fn transitive_roots(
    direct: &HashSet<PackageName>,
    edges: &HashMap<PackageName, HashSet<PackageName>>,
) -> HashMap<PackageName, Vec<PackageName>> {
    let mut roots: HashMap<PackageName, HashSet<PackageName>> = HashMap::new();
    for root in direct {
        let seed: HashSet<PackageName> = std::iter::once(root.clone()).collect();
        for reached in reachable_closure(&seed, edges) {
            if &reached != root {
                roots.entry(reached).or_default().insert(root.clone());
            }
        }
    }
    roots
        .into_iter()
        .map(|(child, set)| {
            let mut sorted: Vec<PackageName> = set.into_iter().collect();
            sorted.sort();
            (child, sorted)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    /// End-to-end through the public dispatcher: a real uv.lock on disk plus a direct set
    /// must produce top-level attribution. Guards the file-read + parser-name dispatch +
    /// algorithm seam that the per-piece tests don't cover (a wrong parser-name string or
    /// path join would silently yield an empty map here, not an error).
    #[tokio::test]
    async fn build_transitive_roots_attributes_through_uv_lock() {
        let lock = r#"
version = 1
requires-python = ">=3.11"

[[package]]
name = "requests"
version = "2.32.0"
source = { registry = "https://pypi.org/simple" }
dependencies = [{ name = "urllib3" }]

[[package]]
name = "urllib3"
version = "2.0.0"
source = { registry = "https://pypi.org/simple" }
"#;
        let dir = TempDir::new().unwrap();
        tokio::fs::write(dir.path().join("uv.lock"), lock)
            .await
            .unwrap();

        let direct: HashSet<PackageName> = std::iter::once(pkg("requests")).collect();
        let roots = build_transitive_roots(dir.path(), "uv.lock", &direct).await;

        assert_eq!(roots.get(&pkg("urllib3")), Some(&vec![pkg("requests")]));
    }

    /// Drives the dispatcher with the parser's real `name()` (not a copy of the match-arm
    /// literal), so a drift between the two is caught. Covers a non-uv arm end-to-end;
    /// pylock's arm is the same shape with its reader tested in `pylock.rs`.
    #[tokio::test]
    async fn build_transitive_roots_dispatches_poetry_by_parser_name() {
        use crate::parsers::ProjectParser;

        let lock = r#"
[[package]]
name = "django"
version = "4.2.0"
optional = false
groups = ["main"]
files = []

[package.dependencies]
certifi = ">=14.5.14"

[[package]]
name = "certifi"
version = "2024.1.1"
optional = false
groups = ["main"]
files = []
"#;
        let dir = TempDir::new().unwrap();
        tokio::fs::write(dir.path().join("poetry.lock"), lock)
            .await
            .unwrap();

        let parser_name = crate::parsers::poetry_lock::PoetryLockParser::new().name();
        let direct: HashSet<PackageName> = std::iter::once(pkg("django")).collect();
        let roots = build_transitive_roots(dir.path(), parser_name, &direct).await;

        assert_eq!(roots.get(&pkg("certifi")), Some(&vec![pkg("django")]));
    }

    #[tokio::test]
    async fn build_transitive_roots_unknown_format_is_empty() {
        let dir = TempDir::new().unwrap();
        let direct: HashSet<PackageName> = std::iter::once(pkg("requests")).collect();
        // A format without a graph reader (e.g. requirements.txt) yields no attribution.
        let roots = build_transitive_roots(dir.path(), "requirements.txt", &direct).await;
        assert!(roots.is_empty());
    }

    #[tokio::test]
    async fn build_transitive_roots_empty_direct_short_circuits() {
        let dir = TempDir::new().unwrap();
        let roots = build_transitive_roots(dir.path(), "uv.lock", &HashSet::new()).await;
        assert!(roots.is_empty());
    }

    fn pkg(name: &str) -> PackageName {
        PackageName::new(name)
    }

    #[test]
    fn diamond_lists_both_roots_and_skips_self() {
        // root_a -> shared, root_b -> shared; deep under root_a -> leaf.
        let direct: HashSet<PackageName> = [pkg("root_a"), pkg("root_b")].into_iter().collect();
        let edges: HashMap<PackageName, HashSet<PackageName>> = [
            (
                pkg("root_a"),
                [pkg("shared"), pkg("mid")].into_iter().collect(),
            ),
            (pkg("root_b"), [pkg("shared")].into_iter().collect()),
            (pkg("mid"), [pkg("leaf")].into_iter().collect()),
        ]
        .into_iter()
        .collect();

        let roots = transitive_roots(&direct, &edges);

        // shared is pulled in by both top-level deps, sorted.
        assert_eq!(
            roots.get(&pkg("shared")),
            Some(&vec![pkg("root_a"), pkg("root_b")])
        );
        // leaf is two hops under root_a but still attributed to the top-level dep.
        assert_eq!(roots.get(&pkg("leaf")), Some(&vec![pkg("root_a")]));
        // direct deps are not their own roots.
        assert!(!roots.contains_key(&pkg("root_a")));
        assert!(!roots.contains_key(&pkg("root_b")));
    }

    #[test]
    fn cycle_terminates() {
        let direct: HashSet<PackageName> = [pkg("a")].into_iter().collect();
        let edges: HashMap<PackageName, HashSet<PackageName>> = [
            (pkg("a"), [pkg("b")].into_iter().collect()),
            (pkg("b"), [pkg("a")].into_iter().collect()),
        ]
        .into_iter()
        .collect();
        let roots = transitive_roots(&direct, &edges);
        assert_eq!(roots.get(&pkg("b")), Some(&vec![pkg("a")]));
    }
}
