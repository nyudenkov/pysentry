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
use crate::parsers::{lock, manifest_reader, poetry_lock, pylock};
use crate::types::PackageName;
use std::collections::{HashMap, HashSet};
use std::path::Path;

/// child → sorted top-level deps that reach it. `direct` is the set of declared direct
/// dependencies (taken from the already-scanned deps, so it reuses each parser's own
/// is_direct logic rather than re-deriving it). `parser_name` selects the lock reader.
#[cfg_attr(feature = "hotpath", hotpath::measure)]
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

/// package → normalized dependency-group names (PEP 735 / Poetry) that reach it, for
/// per-group policy attribution. Runs `reachable_closure` once per group declared in
/// pyproject.toml, seeded from that group's own deps only (see
/// `read_group_only_deps_from_value`) — a package reachable from both main and a group
/// still carries that group, so it never loses its group attribution. Whether the global
/// threshold also floors such a shared package is decided separately, from
/// `build_main_reachable`.
///
/// Only group-aware locks (uv.lock, poetry.lock, pylock.toml) carry group structure;
/// any other parser (or a project with no declared groups) yields an empty map, the
/// same contract as `build_transitive_roots`.
pub async fn build_group_attribution(
    project_dir: &Path,
    parser_name: &str,
) -> HashMap<PackageName, HashSet<String>> {
    let edges = match group_aware_edges(project_dir, parser_name).await {
        Some(edges) => edges,
        None => return HashMap::new(),
    };

    let pyproject_path = project_dir.join("pyproject.toml");
    let Some(doc) = read_pyproject_doc(&pyproject_path).await else {
        return HashMap::new();
    };
    let Ok(group_names) = manifest_reader::list_group_names_from_value(&doc) else {
        return HashMap::new();
    };

    let mut attribution: HashMap<PackageName, HashSet<String>> = HashMap::new();
    for group in &group_names {
        let Ok(seed) = manifest_reader::read_group_only_deps_from_value(&doc, group) else {
            continue;
        };
        if seed.is_empty() {
            continue;
        }
        let normalized = manifest_reader::normalize_group_name(group);
        for reached in reachable_closure(&seed, &edges) {
            attribution
                .entry(reached)
                .or_default()
                .insert(normalized.clone());
        }
    }
    attribution
}

/// Packages reachable from the project's **main** (unconditional) dependencies only —
/// `[project].dependencies` / `[tool.poetry.dependencies]`, excluding every group.
///
/// The policy engine uses this to decide whether a per-group threshold may *loosen* a
/// finding: a package that ships to production (main-reachable) keeps the global `fail_on`
/// as a floor, whereas a group-only package may take its group's threshold freely (below
/// global if the group is more permissive). Same dispatch/empty-map contract as
/// [`build_group_attribution`] — non-group-aware locks yield an empty set.
pub async fn build_main_reachable(project_dir: &Path, parser_name: &str) -> HashSet<PackageName> {
    let edges = match group_aware_edges(project_dir, parser_name).await {
        Some(edges) => edges,
        None => return HashSet::new(),
    };

    let pyproject_path = project_dir.join("pyproject.toml");
    // Empty group filter → main dependencies only (no group passes the filter).
    let main_seed =
        manifest_reader::read_direct_deps_from_pyproject(&pyproject_path, Some(&HashSet::new()))
            .await
            .ok()
            .flatten()
            .unwrap_or_default();

    if main_seed.is_empty() {
        return HashSet::new();
    }
    reachable_closure(&main_seed, &edges)
}

/// Shared dispatch for the two policy-attribution builders: the dependency edge map for a
/// group-aware lock, or `None` for any other parser (or an empty lock).
async fn group_aware_edges(
    project_dir: &Path,
    parser_name: &str,
) -> Option<HashMap<PackageName, HashSet<PackageName>>> {
    let edges = match parser_name {
        "uv.lock" => lock::uv_lock_edges(project_dir).await,
        "poetry.lock" => poetry_lock::poetry_lock_edges(project_dir).await,
        "pylock.toml" => pylock::pylock_edges(project_dir).await,
        _ => return None,
    };
    (!edges.is_empty()).then_some(edges)
}

async fn read_pyproject_doc(pyproject_path: &Path) -> Option<toml::Value> {
    let content = tokio::fs::read_to_string(pyproject_path).await.ok()?;
    toml::from_str(&content).ok()
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

    // Lock: root -> requests, httpx (both main). requests -> certifi. dev group declares
    // {pytest, requests} — requests is declared by BOTH main and dev.
    //
    // requests must still tag `dev`: seeding dev's closure from dev's own deps only (not
    // main ∪ dev) means the shared package isn't erased from the seed, so its transitive
    // (certifi) is correctly attributed to dev too. httpx is main-only and reachable from
    // no group closure, so it gets no attribution entry at all — "main" is never itself a
    // group tag.
    #[tokio::test]
    async fn build_group_attribution_shared_transitive_and_dev_only() {
        let lock_content = r#"
version = 1
requires-python = ">=3.11"

[[package]]
name = "root"
source = { virtual = "." }
dependencies = [{ name = "requests" }, { name = "httpx" }]

[[package]]
name = "requests"
version = "2.31.0"
source = { registry = "https://pypi.org/simple" }
dependencies = [{ name = "certifi" }]

[[package]]
name = "httpx"
version = "0.27.0"
source = { registry = "https://pypi.org/simple" }

[[package]]
name = "certifi"
version = "2024.1.1"
source = { registry = "https://pypi.org/simple" }

[[package]]
name = "pytest"
version = "8.0.0"
source = { registry = "https://pypi.org/simple" }
"#;
        let pyproject_content = r#"
[project]
name = "myapp"
dependencies = ["requests>=2.31", "httpx>=0.27"]

[dependency-groups]
dev = ["pytest>=8", "requests>=2.31"]
"#;

        let dir = TempDir::new().unwrap();
        tokio::fs::write(dir.path().join("uv.lock"), lock_content)
            .await
            .unwrap();
        tokio::fs::write(dir.path().join("pyproject.toml"), pyproject_content)
            .await
            .unwrap();

        let attribution = build_group_attribution(dir.path(), "uv.lock").await;

        let dev: HashSet<String> = ["dev".to_string()].into_iter().collect();
        assert_eq!(
            attribution.get(&pkg("pytest")),
            Some(&dev),
            "pytest is dev-only"
        );
        assert_eq!(
            attribution.get(&pkg("requests")),
            Some(&dev),
            "requests is declared by both main and dev; must still tag dev"
        );
        assert_eq!(
            attribution.get(&pkg("certifi")),
            Some(&dev),
            "certifi is reachable from requests via dev's closure"
        );
        assert!(
            attribution.get(&pkg("httpx")).is_none_or(HashSet::is_empty),
            "httpx is main-only and unreachable from any group closure, got: {:?}",
            attribution.get(&pkg("httpx"))
        );
    }

    #[tokio::test]
    async fn build_group_attribution_unknown_format_is_empty() {
        let dir = TempDir::new().unwrap();
        let attribution = build_group_attribution(dir.path(), "requirements.txt").await;
        assert!(attribution.is_empty());
    }

    #[tokio::test]
    async fn build_group_attribution_no_declared_groups_is_empty() {
        let lock_content = r#"
version = 1
requires-python = ">=3.11"

[[package]]
name = "requests"
version = "2.31.0"
source = { registry = "https://pypi.org/simple" }
"#;
        let pyproject_content = r#"
[project]
name = "myapp"
dependencies = ["requests>=2.31"]
"#;
        let dir = TempDir::new().unwrap();
        tokio::fs::write(dir.path().join("uv.lock"), lock_content)
            .await
            .unwrap();
        tokio::fs::write(dir.path().join("pyproject.toml"), pyproject_content)
            .await
            .unwrap();

        let attribution = build_group_attribution(dir.path(), "uv.lock").await;
        assert!(
            attribution.is_empty(),
            "no [dependency-groups]/[project.optional-dependencies]/poetry groups declared"
        );
    }

    // main = [requests, httpx]; requests -> certifi. dev = [pytest]. main-reachable must be
    // exactly the main closure {requests, httpx, certifi} — never the dev-only pytest.
    #[tokio::test]
    async fn build_main_reachable_covers_main_closure_only() {
        let lock_content = r#"
version = 1
requires-python = ">=3.11"

[[package]]
name = "root"
source = { virtual = "." }
dependencies = [{ name = "requests" }, { name = "httpx" }]

[[package]]
name = "requests"
version = "2.31.0"
source = { registry = "https://pypi.org/simple" }
dependencies = [{ name = "certifi" }]

[[package]]
name = "httpx"
version = "0.27.0"
source = { registry = "https://pypi.org/simple" }

[[package]]
name = "certifi"
version = "2024.1.1"
source = { registry = "https://pypi.org/simple" }

[[package]]
name = "pytest"
version = "8.0.0"
source = { registry = "https://pypi.org/simple" }
"#;
        let pyproject_content = r#"
[project]
name = "myapp"
dependencies = ["requests>=2.31", "httpx>=0.27"]

[dependency-groups]
dev = ["pytest>=8"]
"#;
        let dir = TempDir::new().unwrap();
        tokio::fs::write(dir.path().join("uv.lock"), lock_content)
            .await
            .unwrap();
        tokio::fs::write(dir.path().join("pyproject.toml"), pyproject_content)
            .await
            .unwrap();

        let main_reachable = build_main_reachable(dir.path(), "uv.lock").await;

        assert!(main_reachable.contains(&pkg("requests")), "main direct dep");
        assert!(main_reachable.contains(&pkg("httpx")), "main direct dep");
        assert!(
            main_reachable.contains(&pkg("certifi")),
            "transitive of a main dep"
        );
        assert!(
            !main_reachable.contains(&pkg("pytest")),
            "pytest is dev-only, must not be main-reachable"
        );
    }

    #[tokio::test]
    async fn build_main_reachable_unknown_format_is_empty() {
        let dir = TempDir::new().unwrap();
        assert!(build_main_reachable(dir.path(), "requirements.txt")
            .await
            .is_empty());
    }
}
