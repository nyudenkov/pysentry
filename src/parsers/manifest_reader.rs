// SPDX-License-Identifier: MIT

use crate::types::PackageName;
use crate::{AuditError, Result};
use std::collections::{HashMap, HashSet};
use std::path::Path;

/// Read all directly-declared dependency names from a pyproject.toml.
/// Covers PEP 621 ([project].dependencies, [project.optional-dependencies]),
/// PEP 735 ([dependency-groups] with include-group recursion),
/// Poetry ([tool.poetry.dependencies], [tool.poetry.dev-dependencies],
/// [tool.poetry.group.<name>.dependencies]), and uv ([tool.uv.dev-dependencies]).
/// Returns Ok(empty set) if the file does not exist.
/// Returns Err if the file cannot be read or parsed as TOML.
///
/// When `groups` is `None`, all groups are flattened (current default behavior).
/// When `groups` is `Some(set)`, only [project.optional-dependencies], [dependency-groups],
/// and [tool.poetry.group.*] entries whose name is in `set` are included.
/// [project].dependencies and [tool.poetry.dependencies] are always included — they are
/// production deps, not optional groups. One exception: a `[tool.poetry.dependencies]`
/// entry marked `optional = true` is a legacy Poetry extra (activated via
/// [tool.poetry.extras]), not a production dep, so it is EXCLUDED when `groups` is
/// `Some(set)` — the same way [project.optional-dependencies] are filtered. The legacy dev-deps sections
/// ([tool.poetry.dev-dependencies] and [tool.uv.dev-dependencies]) are the pre-group-era
/// way of declaring dev dependencies; they are treated as an implicit "dev" category and
/// are EXCLUDED when `groups` is `Some(set)`, matching how a user explicitly opting into
/// named groups would expect their dev stuff to be filtered out.
#[cfg_attr(feature = "hotpath", hotpath::measure)]
pub async fn read_direct_deps_from_pyproject(
    path: &Path,
    groups: Option<&HashSet<String>>,
) -> Result<Option<HashSet<PackageName>>> {
    let content = match tokio::fs::read_to_string(path).await {
        Ok(c) => c,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e.into()),
    };
    let doc: toml::Value = toml::from_str(&content)?;

    let mut names = HashSet::new();

    // PEP 621: [project].dependencies — array of PEP 508 strings
    if let Some(project) = doc.get("project") {
        if let Some(deps) = project.get("dependencies").and_then(|v| v.as_array()) {
            for dep in deps {
                if let Some(dep_str) = dep.as_str() {
                    if let Some(name) = extract_package_name(dep_str) {
                        names.insert(name);
                    }
                }
            }
        }

        // PEP 621: [project.optional-dependencies] — table of string arrays, filtered by groups
        if let Some(optional) = project
            .get("optional-dependencies")
            .and_then(|v| v.as_table())
        {
            for (group_name, group_deps) in optional {
                if !group_passes_filter(groups, group_name) {
                    continue;
                }
                if let Some(dep_arr) = group_deps.as_array() {
                    for dep in dep_arr {
                        if let Some(dep_str) = dep.as_str() {
                            if let Some(name) = extract_package_name(dep_str) {
                                names.insert(name);
                            }
                        }
                    }
                }
            }
        }
    }

    // PEP 735: [dependency-groups] — table of mixed arrays (strings + {include-group} tables),
    // filtered by groups
    if let Some(dep_groups) = doc.get("dependency-groups") {
        if let Some(table) = dep_groups.as_table() {
            let mut resolved = Vec::new();
            for (group_name, entries) in table {
                if !group_passes_filter(groups, group_name) {
                    continue;
                }
                if let Some(entry_arr) = entries.as_array() {
                    let mut current_path = Vec::new();
                    collect_group_deps(entry_arr, dep_groups, &mut current_path, &mut resolved)?;
                }
            }
            for dep_str in resolved {
                if let Some(name) = extract_package_name(&dep_str) {
                    names.insert(name);
                }
            }
        }
    }

    // Poetry: [tool.poetry.*] and uv: [tool.uv.dev-dependencies]
    if let Some(tool) = doc.get("tool") {
        if let Some(poetry) = tool.get("poetry") {
            if let Some(deps) = poetry.get("dependencies").and_then(|v| v.as_table()) {
                names.extend(collect_poetry_table_deps(deps, groups.is_some()));
            }
            // Legacy Poetry dev-dependencies are an implicit "dev" bucket — treat them
            // like a named group and exclude under any explicit --group filter.
            if groups.is_none() {
                if let Some(dev_deps) = poetry.get("dev-dependencies").and_then(|v| v.as_table()) {
                    names.extend(collect_poetry_table_deps(dev_deps, false));
                }
            }
            // [tool.poetry.group.*] — filtered by groups
            if let Some(poetry_groups) = poetry.get("group").and_then(|v| v.as_table()) {
                for (group_name, group_val) in poetry_groups {
                    if !group_passes_filter(groups, group_name) {
                        continue;
                    }
                    if let Some(group_deps) =
                        group_val.get("dependencies").and_then(|v| v.as_table())
                    {
                        names.extend(collect_poetry_table_deps(group_deps, false));
                    }
                }
            }
        }
        // Legacy [tool.uv.dev-dependencies] is an implicit "dev" bucket — same rule as
        // [tool.poetry.dev-dependencies]. Excluded under any explicit --group filter.
        if groups.is_none() {
            if let Some(uv) = tool.get("uv") {
                if let Some(dev_deps) = uv.get("dev-dependencies").and_then(|v| v.as_array()) {
                    for dep in dev_deps {
                        if let Some(dep_str) = dep.as_str() {
                            if let Some(name) = extract_package_name(dep_str) {
                                names.insert(name);
                            }
                        }
                    }
                }
            }
        }
    }

    Ok(Some(names))
}

/// Like `read_direct_deps_from_pyproject`, but additionally returns the set of extras
/// requested for each directly-declared dependency (e.g. `httpx[http2]` yields an entry
/// `httpx -> {"http2"}`). Callers use this extras map to activate the corresponding
/// `[package.optional-dependencies.<extra>]` edges in a lock file when walking
/// reachability — without it, extras-only transitives (like `h2` under `httpx[http2]`)
/// are silently dropped from the reachable closure.
///
/// Same filtering rules and return semantics as `read_direct_deps_from_pyproject`.
#[cfg_attr(feature = "hotpath", hotpath::measure)]
pub async fn read_direct_deps_with_extras_from_pyproject(
    path: &Path,
    groups: Option<&HashSet<String>>,
) -> Result<Option<(HashSet<PackageName>, HashMap<PackageName, HashSet<String>>)>> {
    let content = match tokio::fs::read_to_string(path).await {
        Ok(c) => c,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e.into()),
    };
    let doc: toml::Value = toml::from_str(&content)?;

    let mut names: HashSet<PackageName> = HashSet::new();
    let mut extras_map: HashMap<PackageName, HashSet<String>> = HashMap::new();

    // PEP 621: [project].dependencies — always included, not filtered by groups.
    if let Some(project) = doc.get("project") {
        if let Some(deps) = project.get("dependencies").and_then(|v| v.as_array()) {
            for dep in deps {
                if let Some(dep_str) = dep.as_str() {
                    record_pep508(dep_str, &mut names, &mut extras_map);
                }
            }
        }

        // PEP 621: [project.optional-dependencies] — filtered by groups.
        if let Some(optional) = project
            .get("optional-dependencies")
            .and_then(|v| v.as_table())
        {
            for (group_name, group_deps) in optional {
                if !group_passes_filter(groups, group_name) {
                    continue;
                }
                if let Some(dep_arr) = group_deps.as_array() {
                    for dep in dep_arr {
                        if let Some(dep_str) = dep.as_str() {
                            record_pep508(dep_str, &mut names, &mut extras_map);
                        }
                    }
                }
            }
        }
    }

    // PEP 735: [dependency-groups] — filtered by groups, resolves include-group.
    if let Some(dep_groups) = doc.get("dependency-groups") {
        if let Some(table) = dep_groups.as_table() {
            let mut resolved = Vec::new();
            for (group_name, entries) in table {
                if !group_passes_filter(groups, group_name) {
                    continue;
                }
                if let Some(entry_arr) = entries.as_array() {
                    let mut current_path = Vec::new();
                    collect_group_deps(entry_arr, dep_groups, &mut current_path, &mut resolved)?;
                }
            }
            for dep_str in &resolved {
                record_pep508(dep_str, &mut names, &mut extras_map);
            }
        }
    }

    // Poetry and uv: Poetry encodes extras via `mypkg = { extras = ["http2"] }` tables,
    // while [tool.uv.dev-dependencies] is a flat array of PEP 508 strings.
    if let Some(tool) = doc.get("tool") {
        if let Some(poetry) = tool.get("poetry") {
            if let Some(deps) = poetry.get("dependencies").and_then(|v| v.as_table()) {
                collect_poetry_table_deps_with_extras(
                    deps,
                    groups.is_some(),
                    &mut names,
                    &mut extras_map,
                );
            }
            if groups.is_none() {
                if let Some(dev_deps) = poetry.get("dev-dependencies").and_then(|v| v.as_table()) {
                    collect_poetry_table_deps_with_extras(
                        dev_deps,
                        false,
                        &mut names,
                        &mut extras_map,
                    );
                }
            }
            if let Some(poetry_groups) = poetry.get("group").and_then(|v| v.as_table()) {
                for (group_name, group_val) in poetry_groups {
                    if !group_passes_filter(groups, group_name) {
                        continue;
                    }
                    if let Some(group_deps) =
                        group_val.get("dependencies").and_then(|v| v.as_table())
                    {
                        collect_poetry_table_deps_with_extras(
                            group_deps,
                            false,
                            &mut names,
                            &mut extras_map,
                        );
                    }
                }
            }
        }
        if groups.is_none() {
            if let Some(uv) = tool.get("uv") {
                if let Some(dev_deps) = uv.get("dev-dependencies").and_then(|v| v.as_array()) {
                    for dep in dev_deps {
                        if let Some(dep_str) = dep.as_str() {
                            record_pep508(dep_str, &mut names, &mut extras_map);
                        }
                    }
                }
            }
        }
    }

    Ok(Some((names, extras_map)))
}

fn record_pep508(
    dep_str: &str,
    names: &mut HashSet<PackageName>,
    extras_map: &mut HashMap<PackageName, HashSet<String>>,
) {
    if let Some((name, extras)) = extract_package_spec(dep_str) {
        if !extras.is_empty() {
            extras_map.entry(name.clone()).or_default().extend(extras);
        }
        names.insert(name);
    }
}

/// A `[tool.poetry.dependencies]` entry marked `optional = true` (e.g.
/// `redis = { version = "^5", optional = true }`) is a legacy Poetry extra activated via
/// [tool.poetry.extras], not a production dep. Only the table form is recognized — the
/// multi-constraint array form is not handled, matching how the rest of this module reads
/// Poetry tables.
fn is_optional_poetry_dep(val: &toml::Value) -> bool {
    val.as_table()
        .and_then(|spec| spec.get("optional"))
        .and_then(toml::Value::as_bool)
        .unwrap_or(false)
}

fn collect_poetry_table_deps_with_extras(
    table: &toml::map::Map<String, toml::Value>,
    exclude_optional: bool,
    names: &mut HashSet<PackageName>,
    extras_map: &mut HashMap<PackageName, HashSet<String>>,
) {
    for (key, val) in table {
        if key == "python" {
            continue;
        }
        if exclude_optional && is_optional_poetry_dep(val) {
            continue;
        }
        let name = PackageName::new(key);
        // Poetry encodes extras as `mypkg = { extras = ["a", "b"] }`. A plain string
        // value is just a version constraint and has no extras to record.
        if let Some(spec) = val.as_table() {
            if let Some(extras_arr) = spec.get("extras").and_then(|v| v.as_array()) {
                let collected: HashSet<String> = extras_arr
                    .iter()
                    .filter_map(|v| v.as_str().map(normalize_group_name))
                    .collect();
                if !collected.is_empty() {
                    extras_map
                        .entry(name.clone())
                        .or_default()
                        .extend(collected);
                }
            }
        }
        names.insert(name);
    }
}

pub(super) fn extract_package_name(dep_str: &str) -> Option<PackageName> {
    extract_package_spec(dep_str).map(|(name, _)| name)
}

/// Like `extract_package_name`, but also returns the bracketed extras list from a PEP 508
/// spec (e.g. `httpx[http2,socks]>=0.27` -> ("httpx", ["http2","socks"])).
/// Extras are normalized per PEP 685 (lowercase + collapse runs of `. - _` to `-`), the
/// same form lock files key their optional-dependencies tables by.
fn extract_package_spec(dep_str: &str) -> Option<(PackageName, Vec<String>)> {
    let trimmed = dep_str.trim();
    // Name is everything up to the first version operator, extras bracket, marker
    // separator, URL marker, or whitespace.
    let name_end = trimmed
        .find(|c: char| {
            matches!(c, '>' | '<' | '=' | '!' | '~' | '[' | '@' | ';') || c.is_whitespace()
        })
        .unwrap_or(trimmed.len());
    let name = trimmed[..name_end].trim();
    if name.is_empty() {
        return None;
    }

    let mut extras = Vec::new();
    // If the terminator was '[', parse the extras list up to the matching ']'.
    if trimmed.as_bytes().get(name_end).copied() == Some(b'[') {
        if let Some(close_rel) = trimmed[name_end + 1..].find(']') {
            let inside = &trimmed[name_end + 1..name_end + 1 + close_rel];
            for extra in inside.split(',') {
                let e = extra.trim();
                if !e.is_empty() {
                    extras.push(normalize_group_name(e));
                }
            }
        }
    }

    Some((PackageName::new(name), extras))
}

/// Normalize a dependency-group name per PEP 735, which reuses PEP 503 name normalization:
/// lowercase, and collapse every run of `.`, `-`, `_` into a single `-`. Group names "must
/// be normalized before comparisons", so `typing_test`, `typing-test`, and `typing.test`
/// all compare equal. The same algorithm normalizes PEP 685 extras.
pub fn normalize_group_name(name: &str) -> String {
    let mut normalized = String::with_capacity(name.len());
    let mut prev_was_separator = false;
    for ch in name.chars() {
        if matches!(ch, '-' | '_' | '.') {
            if !prev_was_separator {
                normalized.push('-');
                prev_was_separator = true;
            }
        } else {
            normalized.push(ch.to_ascii_lowercase());
            prev_was_separator = false;
        }
    }
    normalized
}

/// Whether `group_name` is selected by the optional-group filter. A `None` filter selects
/// every group (the unfiltered default); otherwise both sides are normalized per PEP 735
/// before comparison so separator/case differences in the user's `--group` value still match.
fn group_passes_filter(filter: Option<&HashSet<String>>, group_name: &str) -> bool {
    match filter {
        None => true,
        Some(selected) => {
            let target = normalize_group_name(group_name);
            selected.iter().any(|s| normalize_group_name(s) == target)
        }
    }
}

fn collect_group_deps(
    entries: &[toml::Value],
    dep_groups: &toml::Value,
    current_path: &mut Vec<String>,
    result: &mut Vec<String>,
) -> Result<()> {
    for entry in entries {
        match entry {
            toml::Value::String(dep_str) => {
                result.push(dep_str.clone());
            }
            toml::Value::Table(table) => {
                if let Some(toml::Value::String(included)) = table.get("include-group") {
                    // PEP 735: include-group references compare by normalized name, and a
                    // reference to a group that does not exist MUST error rather than be
                    // silently ignored — silent skipping would under-scan dependencies.
                    let included_norm = normalize_group_name(included);
                    if current_path.contains(&included_norm) {
                        return Err(AuditError::InvalidDependency(format!(
                            "Circular dependency in include-group: {} -> {}",
                            current_path.join(" -> "),
                            included_norm
                        )));
                    }
                    let referenced = dep_groups.as_table().and_then(|groups_table| {
                        groups_table
                            .iter()
                            .find(|(key, _)| normalize_group_name(key) == included_norm)
                    });
                    match referenced {
                        Some((_, toml::Value::Array(included_entries))) => {
                            current_path.push(included_norm);
                            collect_group_deps(included_entries, dep_groups, current_path, result)?;
                            current_path.pop();
                        }
                        Some((_, _)) => {
                            return Err(AuditError::InvalidDependency(format!(
                                "include-group \"{included}\" does not refer to a list of dependencies"
                            )));
                        }
                        None => {
                            return Err(AuditError::InvalidDependency(format!(
                                "include-group references unknown dependency group \"{included}\""
                            )));
                        }
                    }
                }
            }
            _ => {}
        }
    }
    Ok(())
}

/// Read all directly-declared dependency names from a Pipfile.
/// Extracts package names from [packages] and [dev-packages] table keys.
/// Values are ignored — only keys matter.
/// Returns Ok(empty set) if the file does not exist.
#[cfg_attr(feature = "hotpath", hotpath::measure)]
pub async fn read_direct_deps_from_pipfile(path: &Path) -> Result<Option<HashSet<PackageName>>> {
    let content = match tokio::fs::read_to_string(path).await {
        Ok(c) => c,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e.into()),
    };
    let doc: toml::Value = toml::from_str(&content)?;

    let mut names = HashSet::new();

    for section in &["packages", "dev-packages"] {
        if let Some(table) = doc.get(section).and_then(|v| v.as_table()) {
            for key in table.keys() {
                names.insert(PackageName::new(key));
            }
        }
    }

    Ok(Some(names))
}

/// Return all optional group names declared in a pyproject.toml.
/// Collects names from: PEP 735 [dependency-groups] keys,
/// PEP 621 [project.optional-dependencies] keys,
/// and Poetry [tool.poetry.group.*] keys.
/// Main dependency sections ([project].dependencies, [tool.poetry.dependencies])
/// are excluded — they are production deps, not optional groups.
/// The legacy dev-deps sections ([tool.poetry.dev-dependencies] and
/// [tool.uv.dev-dependencies]) are also excluded: they are implicit "dev"
/// buckets rather than *named* groups and therefore have no name to list.
/// Returns Ok(empty set) if the file does not exist or has no group sections.
/// Returns Err if two distinct group names collide after PEP 735 normalization.
pub async fn list_group_names(path: &Path) -> Result<HashSet<String>> {
    let content = match tokio::fs::read_to_string(path).await {
        Ok(c) => c,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(HashSet::new()),
        Err(e) => return Err(e.into()),
    };
    let doc: toml::Value = toml::from_str(&content)?;

    let mut raw_names: Vec<String> = Vec::new();

    // PEP 621: [project.optional-dependencies] keys
    if let Some(project) = doc.get("project") {
        if let Some(optional) = project
            .get("optional-dependencies")
            .and_then(|v| v.as_table())
        {
            raw_names.extend(optional.keys().cloned());
        }
    }

    // PEP 735: [dependency-groups] keys
    if let Some(dep_groups) = doc.get("dependency-groups").and_then(|v| v.as_table()) {
        raw_names.extend(dep_groups.keys().cloned());
    }

    // Poetry: [tool.poetry.group.*] keys
    if let Some(tool) = doc.get("tool") {
        if let Some(poetry) = tool.get("poetry") {
            if let Some(poetry_groups) = poetry.get("group").and_then(|v| v.as_table()) {
                raw_names.extend(poetry_groups.keys().cloned());
            }
        }
    }

    // PEP 735 (SHOULD): two distinct group names that normalize to the same value make the
    // manifest ambiguous — selecting either would scan the union. Reject rather than silently
    // merge. Identical names appearing across sections are not a collision (they dedup).
    let mut seen: HashMap<String, String> = HashMap::new();
    for raw in &raw_names {
        let normalized = normalize_group_name(raw);
        if let Some(existing) = seen.insert(normalized.clone(), raw.clone()) {
            if &existing != raw {
                return Err(AuditError::InvalidDependency(format!(
                    "ambiguous dependency groups: \"{existing}\" and \"{raw}\" normalize to the same name \"{normalized}\""
                )));
            }
        }
    }

    Ok(raw_names.into_iter().collect())
}

fn collect_poetry_table_deps(
    table: &toml::map::Map<String, toml::Value>,
    exclude_optional: bool,
) -> Vec<PackageName> {
    table
        .iter()
        .filter_map(|(key, val)| {
            let name = PackageName::new(key);
            if name.as_str() == "python" {
                return None;
            }
            if exclude_optional && is_optional_poetry_dep(val) {
                return None;
            }
            Some(name)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    fn write_toml(content: &str) -> NamedTempFile {
        let mut file = NamedTempFile::new().unwrap();
        file.write_all(content.as_bytes()).unwrap();
        file
    }

    #[tokio::test]
    async fn test_pep621_dependencies() {
        let file = write_toml(
            r#"
[project]
name = "myproject"
dependencies = [
    "httpx>=0.24",
    "django>=4.2; os_name != 'nt'",
    "requests[security,socks]>=2.28",
]
"#,
        );
        let result = read_direct_deps_from_pyproject(file.path(), None)
            .await
            .unwrap()
            .unwrap();
        assert!(result.contains(&PackageName::new("httpx")));
        assert!(result.contains(&PackageName::new("django")));
        assert!(result.contains(&PackageName::new("requests")));
        assert_eq!(result.len(), 3);
    }

    #[tokio::test]
    async fn test_pep621_optional_dependencies() {
        let file = write_toml(
            r#"
[project]
name = "myproject"
dependencies = ["httpx>=0.24"]

[project.optional-dependencies]
dev = ["pytest>=7", "coverage"]
docs = ["sphinx>=7"]
"#,
        );
        let result = read_direct_deps_from_pyproject(file.path(), None)
            .await
            .unwrap()
            .unwrap();
        assert!(result.contains(&PackageName::new("httpx")));
        assert!(result.contains(&PackageName::new("pytest")));
        assert!(result.contains(&PackageName::new("coverage")));
        assert!(result.contains(&PackageName::new("sphinx")));
        assert_eq!(result.len(), 4);
    }

    #[tokio::test]
    async fn test_pep735_dependency_groups() {
        let file = write_toml(
            r#"
[dependency-groups]
test = ["pytest>=7", "coverage>=7"]
lint = ["ruff>=0.5", "mypy>=1.10"]
"#,
        );
        let result = read_direct_deps_from_pyproject(file.path(), None)
            .await
            .unwrap()
            .unwrap();
        assert!(result.contains(&PackageName::new("pytest")));
        assert!(result.contains(&PackageName::new("coverage")));
        assert!(result.contains(&PackageName::new("ruff")));
        assert!(result.contains(&PackageName::new("mypy")));
        assert_eq!(result.len(), 4);
    }

    #[tokio::test]
    async fn test_pep735_include_group_resolution() {
        let file = write_toml(
            r#"
[dependency-groups]
test = ["pytest>=7", "coverage>=7"]
lint = ["ruff>=0.5"]
dev = [
    {include-group = "test"},
    {include-group = "lint"},
    "pre-commit",
]
"#,
        );
        let result = read_direct_deps_from_pyproject(file.path(), None)
            .await
            .unwrap()
            .unwrap();
        assert!(result.contains(&PackageName::new("pytest")));
        assert!(result.contains(&PackageName::new("coverage")));
        assert!(result.contains(&PackageName::new("ruff")));
        assert!(result.contains(&PackageName::new("pre-commit")));
    }

    #[tokio::test]
    async fn test_pep735_cycle_detection_returns_err() {
        let file = write_toml(
            r#"
[dependency-groups]
a = [{include-group = "b"}]
b = [{include-group = "a"}]
"#,
        );
        let result = read_direct_deps_from_pyproject(file.path(), None).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_missing_file_returns_none() {
        let path = Path::new("/nonexistent/path/to/pyproject.toml");
        let result = read_direct_deps_from_pyproject(path, None).await.unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn test_file_exists_no_recognized_sections_returns_some_empty() {
        let file = write_toml(
            r#"
[build-system]
requires = ["setuptools"]
build-backend = "setuptools.build_meta"
"#,
        );
        let result = read_direct_deps_from_pyproject(file.path(), None)
            .await
            .unwrap();
        assert!(
            result.is_some(),
            "file exists — should return Some, not None"
        );
        assert!(
            result.unwrap().is_empty(),
            "no dep sections — set should be empty"
        );
    }

    #[tokio::test]
    async fn test_poetry_main_deps_filters_python_key() {
        let file = write_toml(
            r#"
[tool.poetry.dependencies]
python = "^3.11"
django = "^4.2"
httpx = {version = "^0.24", extras = ["http2"]}
"#,
        );
        let result = read_direct_deps_from_pyproject(file.path(), None)
            .await
            .unwrap()
            .unwrap();
        assert!(result.contains(&PackageName::new("django")));
        assert!(result.contains(&PackageName::new("httpx")));
        assert!(!result.contains(&PackageName::new("python")));
        assert_eq!(result.len(), 2);
    }

    #[tokio::test]
    async fn test_poetry_legacy_dev_dependencies() {
        let file = write_toml(
            r#"
[tool.poetry.dependencies]
python = "^3.11"
requests = "^2.28"

[tool.poetry.dev-dependencies]
pytest = "^7"
coverage = "^7"
"#,
        );
        let result = read_direct_deps_from_pyproject(file.path(), None)
            .await
            .unwrap()
            .unwrap();
        assert!(result.contains(&PackageName::new("requests")));
        assert!(result.contains(&PackageName::new("pytest")));
        assert!(result.contains(&PackageName::new("coverage")));
        assert!(!result.contains(&PackageName::new("python")));
        assert_eq!(result.len(), 3);
    }

    #[tokio::test]
    async fn test_poetry_modern_group_dependencies() {
        let file = write_toml(
            r#"
[tool.poetry.dependencies]
python = "^3.11"
flask = "^3"

[tool.poetry.group.dev.dependencies]
pytest = "^7"

[tool.poetry.group.docs.dependencies]
sphinx = "^7"
"#,
        );
        let result = read_direct_deps_from_pyproject(file.path(), None)
            .await
            .unwrap()
            .unwrap();
        assert!(result.contains(&PackageName::new("flask")));
        assert!(result.contains(&PackageName::new("pytest")));
        assert!(result.contains(&PackageName::new("sphinx")));
        assert!(!result.contains(&PackageName::new("python")));
        assert_eq!(result.len(), 3);
    }

    #[tokio::test]
    async fn test_uv_dev_dependencies() {
        let file = write_toml(
            r#"
[project]
name = "myproject"
dependencies = ["httpx>=0.24"]

[tool.uv]
dev-dependencies = ["pytest>=7", "ruff>=0.5"]
"#,
        );
        let result = read_direct_deps_from_pyproject(file.path(), None)
            .await
            .unwrap()
            .unwrap();
        assert!(result.contains(&PackageName::new("httpx")));
        assert!(result.contains(&PackageName::new("pytest")));
        assert!(result.contains(&PackageName::new("ruff")));
        assert_eq!(result.len(), 3);
    }

    #[tokio::test]
    async fn test_pipfile_packages_section() {
        let file = write_toml(
            r#"
[packages]
django = ">=4.2"
requests = "*"
"#,
        );
        let result = read_direct_deps_from_pipfile(file.path())
            .await
            .unwrap()
            .unwrap();
        assert!(result.contains(&PackageName::new("django")));
        assert!(result.contains(&PackageName::new("requests")));
        assert_eq!(result.len(), 2);
    }

    #[tokio::test]
    async fn test_pipfile_dev_packages_section() {
        let file = write_toml(
            r#"
[packages]
django = ">=4.2"

[dev-packages]
pytest = ">=7"
coverage = "*"
"#,
        );
        let result = read_direct_deps_from_pipfile(file.path())
            .await
            .unwrap()
            .unwrap();
        assert!(result.contains(&PackageName::new("django")));
        assert!(result.contains(&PackageName::new("pytest")));
        assert!(result.contains(&PackageName::new("coverage")));
        assert_eq!(result.len(), 3);
    }

    #[tokio::test]
    async fn test_pipfile_table_value_uses_key_as_name() {
        let file = write_toml(
            r#"
[packages]
mypackage = {version = ">=1.0", extras = ["extra1"]}
gitpackage = {git = "https://github.com/org/repo.git", ref = "main"}
"#,
        );
        let result = read_direct_deps_from_pipfile(file.path())
            .await
            .unwrap()
            .unwrap();
        assert!(result.contains(&PackageName::new("mypackage")));
        assert!(result.contains(&PackageName::new("gitpackage")));
        assert_eq!(result.len(), 2);
    }

    #[tokio::test]
    async fn test_pipfile_missing_file_returns_none() {
        let path = Path::new("/nonexistent/path/to/Pipfile");
        let result = read_direct_deps_from_pipfile(path).await.unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn test_poetry_and_pep621_union() {
        let file = write_toml(
            r#"
[project]
name = "myproject"
dependencies = ["httpx>=0.24"]

[tool.poetry.dependencies]
python = "^3.11"
django = "^4.2"

[tool.poetry.dev-dependencies]
pytest = "^7"
"#,
        );
        let result = read_direct_deps_from_pyproject(file.path(), None)
            .await
            .unwrap()
            .unwrap();
        assert!(result.contains(&PackageName::new("httpx")));
        assert!(result.contains(&PackageName::new("django")));
        assert!(result.contains(&PackageName::new("pytest")));
        assert!(!result.contains(&PackageName::new("python")));
        assert_eq!(result.len(), 3);
    }

    #[tokio::test]
    async fn test_filter_none_flattens_all() {
        let file = write_toml(
            r#"
[project]
dependencies = ["requests>=2.31"]

[dependency-groups]
polars = ["polars>=1.30"]
dev = ["pytest>=8"]
"#,
        );
        let result = read_direct_deps_from_pyproject(file.path(), None)
            .await
            .unwrap()
            .unwrap();
        assert!(result.contains(&PackageName::new("requests")));
        assert!(result.contains(&PackageName::new("polars")));
        assert!(result.contains(&PackageName::new("pytest")));
        assert_eq!(result.len(), 3);
    }

    #[tokio::test]
    async fn test_filter_include_single_group() {
        let file = write_toml(
            r#"
[project]
dependencies = ["requests>=2.31"]

[dependency-groups]
polars = ["polars>=1.30"]
dev = ["pytest>=8"]
"#,
        );
        let filter: HashSet<String> = ["polars".to_string()].into();
        let result = read_direct_deps_from_pyproject(file.path(), Some(&filter))
            .await
            .unwrap()
            .unwrap();
        assert!(result.contains(&PackageName::new("requests")));
        assert!(result.contains(&PackageName::new("polars")));
        assert!(!result.contains(&PackageName::new("pytest")));
        assert_eq!(result.len(), 2);
    }

    #[tokio::test]
    async fn test_filter_include_multiple_groups() {
        let file = write_toml(
            r#"
[project]
dependencies = ["requests>=2.31"]

[dependency-groups]
polars = ["polars>=1.30"]
dev = ["pytest>=8"]
docs = ["sphinx>=7"]
"#,
        );
        let filter: HashSet<String> = ["polars".to_string(), "dev".to_string()].into();
        let result = read_direct_deps_from_pyproject(file.path(), Some(&filter))
            .await
            .unwrap()
            .unwrap();
        assert!(result.contains(&PackageName::new("requests")));
        assert!(result.contains(&PackageName::new("polars")));
        assert!(result.contains(&PackageName::new("pytest")));
        assert!(!result.contains(&PackageName::new("sphinx")));
        assert_eq!(result.len(), 3);
    }

    #[tokio::test]
    async fn test_filter_project_deps_always_included() {
        let file = write_toml(
            r#"
[project]
dependencies = ["requests>=2.31"]

[dependency-groups]
dev = ["pytest>=8"]
"#,
        );
        let filter: HashSet<String> = ["nonexistent".to_string()].into();
        let result = read_direct_deps_from_pyproject(file.path(), Some(&filter))
            .await
            .unwrap()
            .unwrap();
        assert!(result.contains(&PackageName::new("requests")));
        assert!(!result.contains(&PackageName::new("pytest")));
        assert_eq!(result.len(), 1);
    }

    #[tokio::test]
    async fn test_filter_pep621_optional_respected() {
        let file = write_toml(
            r#"
[project]
dependencies = ["requests>=2.31"]

[project.optional-dependencies]
extra1 = ["httpx>=0.24"]
extra2 = ["aiohttp>=3"]
"#,
        );
        let filter: HashSet<String> = ["extra1".to_string()].into();
        let result = read_direct_deps_from_pyproject(file.path(), Some(&filter))
            .await
            .unwrap()
            .unwrap();
        assert!(result.contains(&PackageName::new("requests")));
        assert!(result.contains(&PackageName::new("httpx")));
        assert!(!result.contains(&PackageName::new("aiohttp")));
        assert_eq!(result.len(), 2);
    }

    #[tokio::test]
    async fn test_list_groups_pep735() {
        let file = write_toml(
            r#"
[project]
dependencies = ["requests>=2.31"]

[dependency-groups]
polars = ["polars>=1.30"]
dev = ["pytest>=8"]
"#,
        );
        let result = list_group_names(file.path()).await.unwrap();
        assert!(result.contains("polars"));
        assert!(result.contains("dev"));
        assert!(!result.contains("requests"));
        assert_eq!(result.len(), 2);
    }

    #[tokio::test]
    async fn test_list_groups_pep621_optional() {
        let file = write_toml(
            r#"
[project]
dependencies = ["requests>=2.31"]

[project.optional-dependencies]
extra1 = ["httpx>=0.24"]
extra2 = ["aiohttp>=3"]
"#,
        );
        let result = list_group_names(file.path()).await.unwrap();
        assert!(result.contains("extra1"));
        assert!(result.contains("extra2"));
        assert!(!result.contains("requests"));
        assert_eq!(result.len(), 2);
    }

    #[tokio::test]
    async fn test_list_groups_poetry() {
        let file = write_toml(
            r#"
[tool.poetry.dependencies]
python = "^3.11"
flask = "^3"

[tool.poetry.group.docs.dependencies]
sphinx = "^7"

[tool.poetry.group.dev.dependencies]
pytest = "^7"
"#,
        );
        let result = list_group_names(file.path()).await.unwrap();
        assert!(result.contains("docs"));
        assert!(result.contains("dev"));
        assert!(!result.contains("python"));
        assert!(!result.contains("flask"));
        assert_eq!(result.len(), 2);
    }

    #[tokio::test]
    async fn test_list_groups_combined() {
        let file = write_toml(
            r#"
[project]
dependencies = ["requests>=2.31"]

[project.optional-dependencies]
extras = ["httpx>=0.24"]

[dependency-groups]
polars = ["polars>=1.30"]

[tool.poetry.group.docs.dependencies]
sphinx = "^7"
"#,
        );
        let result = list_group_names(file.path()).await.unwrap();
        assert!(result.contains("extras"));
        assert!(result.contains("polars"));
        assert!(result.contains("docs"));
        assert_eq!(result.len(), 3);
    }

    #[tokio::test]
    async fn test_unknown_group_name_error_lists_available() {
        let file = write_toml(
            r#"
[dependency-groups]
polars = ["polars>=1.30"]
dev = ["pytest>=8"]
"#,
        );
        let available = list_group_names(file.path()).await.unwrap();
        let mut sorted: Vec<&String> = available.iter().collect();
        sorted.sort();
        let error_message = format!(
            "group \"{}\" not found; available groups: {}",
            "typo",
            sorted
                .iter()
                .map(|s| s.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        );
        assert!(error_message.contains("available groups:"));
        assert!(error_message.contains("dev"));
        assert!(error_message.contains("polars"));
        assert!(!available.contains("typo"));
    }

    #[tokio::test]
    async fn test_filter_poetry_group_respected() {
        let file = write_toml(
            r#"
[tool.poetry.dependencies]
python = "^3.11"
flask = "^3"

[tool.poetry.group.docs.dependencies]
sphinx = "^7"

[tool.poetry.group.dev.dependencies]
pytest = "^7"
"#,
        );
        let filter: HashSet<String> = ["docs".to_string()].into();
        let result = read_direct_deps_from_pyproject(file.path(), Some(&filter))
            .await
            .unwrap()
            .unwrap();
        assert!(result.contains(&PackageName::new("flask")));
        assert!(result.contains(&PackageName::new("sphinx")));
        assert!(!result.contains(&PackageName::new("pytest")));
        assert!(!result.contains(&PackageName::new("python")));
        assert_eq!(result.len(), 2);
    }

    /// Legacy [tool.poetry.dev-dependencies] is the pre-1.2 way to declare Poetry dev deps.
    /// Under an explicit --group filter, these must be treated as an implicit "dev" bucket
    /// and excluded; only the main `[tool.poetry.dependencies]` survive alongside the
    /// user-selected groups.
    #[tokio::test]
    async fn test_filter_legacy_poetry_dev_dependencies_excluded() {
        let file = write_toml(
            r#"
[tool.poetry.dependencies]
python = "^3.11"
requests = "^2.31"

[tool.poetry.dev-dependencies]
pytest = "^7"
black = "^24"

[tool.poetry.group.docs.dependencies]
sphinx = "^7"
"#,
        );
        let filter: HashSet<String> = ["docs".to_string()].into();
        let result = read_direct_deps_from_pyproject(file.path(), Some(&filter))
            .await
            .unwrap()
            .unwrap();
        assert!(
            result.contains(&PackageName::new("requests")),
            "main poetry dep must always be included"
        );
        assert!(
            result.contains(&PackageName::new("sphinx")),
            "selected group must be included"
        );
        assert!(
            !result.contains(&PackageName::new("pytest")),
            "legacy dev-deps must be excluded under filter"
        );
        assert!(
            !result.contains(&PackageName::new("black")),
            "legacy dev-deps must be excluded under filter"
        );
    }

    /// Legacy [tool.uv.dev-dependencies] is the pre-PEP-735 way to declare uv dev deps.
    /// Same rule as legacy Poetry dev-deps: treat as implicit "dev" bucket and exclude
    /// when a --group filter is active.
    #[tokio::test]
    async fn test_filter_legacy_uv_dev_dependencies_excluded() {
        let file = write_toml(
            r#"
[project]
name = "myproject"
dependencies = ["httpx>=0.24"]

[project.optional-dependencies]
web = ["fastapi>=0.100"]

[tool.uv]
dev-dependencies = ["pytest>=7", "ruff>=0.5"]
"#,
        );
        let filter: HashSet<String> = ["web".to_string()].into();
        let result = read_direct_deps_from_pyproject(file.path(), Some(&filter))
            .await
            .unwrap()
            .unwrap();
        assert!(
            result.contains(&PackageName::new("httpx")),
            "main project dep must always be included"
        );
        assert!(
            result.contains(&PackageName::new("fastapi")),
            "selected optional group must be included"
        );
        assert!(
            !result.contains(&PackageName::new("pytest")),
            "legacy uv dev-deps must be excluded under filter"
        );
        assert!(
            !result.contains(&PackageName::new("ruff")),
            "legacy uv dev-deps must be excluded under filter"
        );
    }

    /// With no filter, legacy dev-deps sections remain included (backward compatibility).
    #[tokio::test]
    async fn test_filter_none_still_includes_legacy_dev_dependencies() {
        let file = write_toml(
            r#"
[project]
name = "myproject"
dependencies = ["httpx>=0.24"]

[tool.uv]
dev-dependencies = ["pytest>=7"]

[tool.poetry.dependencies]
python = "^3.11"
flask = "^3"

[tool.poetry.dev-dependencies]
black = "^24"
"#,
        );
        let result = read_direct_deps_from_pyproject(file.path(), None)
            .await
            .unwrap()
            .unwrap();
        assert!(result.contains(&PackageName::new("httpx")));
        assert!(result.contains(&PackageName::new("pytest")));
        assert!(result.contains(&PackageName::new("flask")));
        assert!(result.contains(&PackageName::new("black")));
    }

    /// PEP 735 include-group recursion under a filter: selecting an outer group should pull
    /// in every nested `include-group` entry transitively, even if those nested groups are
    /// not themselves in the filter set. This is the semantic the design doc §4.4 calls out.
    #[tokio::test]
    async fn test_filter_include_group_recursion() {
        let file = write_toml(
            r#"
[dependency-groups]
polars = ["polars>=1.30"]
benchmark = [
    {include-group = "polars"},
    "anarcii>=2.0",
]
dev = ["pytest>=8"]
"#,
        );
        let filter: HashSet<String> = ["benchmark".to_string()].into();
        let result = read_direct_deps_from_pyproject(file.path(), Some(&filter))
            .await
            .unwrap()
            .unwrap();
        assert!(
            result.contains(&PackageName::new("anarcii")),
            "benchmark direct dep must be included"
        );
        assert!(
            result.contains(&PackageName::new("polars")),
            "include-group brings polars deps in even though polars is not in filter"
        );
        assert!(
            !result.contains(&PackageName::new("pytest")),
            "dev group is unrelated and must be excluded"
        );
    }

    /// A `[tool.poetry.dependencies]` entry marked `optional = true` is a legacy Poetry
    /// extra, not a production dep. Under an explicit --group filter it must NOT be treated
    /// as a main seed; only non-optional main deps and the selected group survive.
    #[tokio::test]
    async fn test_filter_poetry_optional_main_dep_excluded() {
        let file = write_toml(
            r#"
[tool.poetry.dependencies]
python = "^3.11"
requests = "^2.31"
redis = { version = "^5", optional = true }

[tool.poetry.group.docs.dependencies]
sphinx = "^7"
"#,
        );
        let filter: HashSet<String> = ["docs".to_string()].into();
        let result = read_direct_deps_from_pyproject(file.path(), Some(&filter))
            .await
            .unwrap()
            .unwrap();
        assert!(result.contains(&PackageName::new("requests")));
        assert!(result.contains(&PackageName::new("sphinx")));
        assert!(
            !result.contains(&PackageName::new("redis")),
            "optional=true poetry extra must be excluded under a --group filter"
        );
    }

    /// Same guard, but for the extras-aware reader — the one that seeds poetry.lock and
    /// uv.lock reachability (see poetry_lock.rs / lock.rs). This is the path on which the
    /// reported scope-widening bug actually manifests.
    #[tokio::test]
    async fn test_filter_with_extras_poetry_optional_main_dep_excluded() {
        let file = write_toml(
            r#"
[tool.poetry.dependencies]
python = "^3.11"
requests = "^2.31"
redis = { version = "^5", optional = true }

[tool.poetry.group.docs.dependencies]
sphinx = "^7"
"#,
        );
        let filter: HashSet<String> = ["docs".to_string()].into();
        let (names, _extras) =
            read_direct_deps_with_extras_from_pyproject(file.path(), Some(&filter))
                .await
                .unwrap()
                .unwrap();
        assert!(names.contains(&PackageName::new("requests")));
        assert!(names.contains(&PackageName::new("sphinx")));
        assert!(
            !names.contains(&PackageName::new("redis")),
            "optional=true poetry extra must not seed reachability under a --group filter"
        );
    }

    /// With no filter (full audit), an optional=true poetry dep stays included for
    /// backward compatibility — full audit scans the whole tree and only uses the direct
    /// set for is_direct classification.
    #[tokio::test]
    async fn test_poetry_optional_main_dep_included_without_filter() {
        let file = write_toml(
            r#"
[tool.poetry.dependencies]
python = "^3.11"
requests = "^2.31"
redis = { version = "^5", optional = true }
"#,
        );
        let result = read_direct_deps_from_pyproject(file.path(), None)
            .await
            .unwrap()
            .unwrap();
        assert!(result.contains(&PackageName::new("requests")));
        assert!(
            result.contains(&PackageName::new("redis")),
            "optional=true poetry dep must remain included when no --group filter is active"
        );
    }

    #[test]
    fn test_normalize_group_name_pep503() {
        assert_eq!(normalize_group_name("typing_test"), "typing-test");
        assert_eq!(normalize_group_name("typing.test"), "typing-test");
        assert_eq!(normalize_group_name("Typing-Test"), "typing-test");
        assert_eq!(normalize_group_name("a__b.._c"), "a-b-c");
        assert_eq!(normalize_group_name("plain"), "plain");
    }

    /// PEP 735: a `--group typing-test` filter must select a declared `typing_test` group,
    /// since names are compared after normalization.
    #[tokio::test]
    async fn test_filter_group_name_normalized() {
        let file = write_toml(
            r#"
[project]
dependencies = ["requests>=2.31"]

[dependency-groups]
typing_test = ["mypy>=1"]
other = ["ruff>=0.5"]
"#,
        );
        let filter: HashSet<String> = ["typing-test".to_string()].into();
        let result = read_direct_deps_from_pyproject(file.path(), Some(&filter))
            .await
            .unwrap()
            .unwrap();
        assert!(result.contains(&PackageName::new("requests")));
        assert!(
            result.contains(&PackageName::new("mypy")),
            "normalized --group name must select the typing_test group"
        );
        assert!(!result.contains(&PackageName::new("ruff")));
    }

    /// An `include-group` reference resolves by normalized name too: `dev` including
    /// `typing-test` must pull in the declared `typing_test` group's deps.
    #[tokio::test]
    async fn test_include_group_reference_normalized() {
        let file = write_toml(
            r#"
[dependency-groups]
typing_test = ["mypy>=1"]
dev = [{include-group = "typing-test"}]
"#,
        );
        let filter: HashSet<String> = ["dev".to_string()].into();
        let result = read_direct_deps_from_pyproject(file.path(), Some(&filter))
            .await
            .unwrap()
            .unwrap();
        assert!(
            result.contains(&PackageName::new("mypy")),
            "include-group must resolve via the normalized group name"
        );
    }

    /// PEP 735 (SHOULD): an include-group pointing at a group that does not exist must
    /// error rather than be silently ignored — silent skipping would under-scan deps.
    #[tokio::test]
    async fn test_include_group_unknown_reference_errors() {
        let file = write_toml(
            r#"
[dependency-groups]
dev = [{include-group = "does-not-exist"}]
"#,
        );
        let result = read_direct_deps_from_pyproject(file.path(), None).await;
        assert!(
            result.is_err(),
            "unknown include-group reference must error, not silently skip"
        );
        let msg = result.unwrap_err().to_string();
        assert!(
            msg.contains("unknown dependency group"),
            "error must name the missing group, got: {msg}"
        );
    }

    /// PEP 685: a PEP 508 extra is normalized (separators collapsed, lowercased), so the
    /// recorded extra matches the normalized key a lock file uses.
    #[tokio::test]
    async fn test_extras_normalized_pep685() {
        let file = write_toml(
            r#"
[project]
dependencies = ["httpx[My_Extra]>=0.27"]
"#,
        );
        let (_names, extras) = read_direct_deps_with_extras_from_pyproject(file.path(), None)
            .await
            .unwrap()
            .unwrap();
        let httpx_extras = extras
            .get(&PackageName::new("httpx"))
            .expect("httpx extras must be recorded");
        assert!(
            httpx_extras.contains("my-extra"),
            "extra must normalize to my-extra, got: {httpx_extras:?}"
        );
        assert!(!httpx_extras.contains("My_Extra"));
        assert!(!httpx_extras.contains("my_extra"));
    }

    /// Poetry encodes extras as a `{ extras = [...] }` table; those must normalize too.
    #[tokio::test]
    async fn test_poetry_extras_normalized_pep685() {
        let file = write_toml(
            r#"
[tool.poetry.dependencies]
python = "^3.11"
httpx = { version = "^0.27", extras = ["My_Extra"] }
"#,
        );
        let (_names, extras) = read_direct_deps_with_extras_from_pyproject(file.path(), None)
            .await
            .unwrap()
            .unwrap();
        let httpx_extras = extras.get(&PackageName::new("httpx")).unwrap();
        assert!(
            httpx_extras.contains("my-extra"),
            "poetry extra must normalize to my-extra, got: {httpx_extras:?}"
        );
    }

    /// PEP 735 (SHOULD): two group names that normalize to the same value make the manifest
    /// ambiguous and must be rejected rather than silently merged.
    #[tokio::test]
    async fn test_list_group_names_rejects_normalized_duplicates() {
        let file = write_toml(
            r#"
[dependency-groups]
typing_test = ["mypy>=1"]
typing-test = ["pyright>=1"]
"#,
        );
        let result = list_group_names(file.path()).await;
        assert!(
            result.is_err(),
            "groups colliding after normalization must error"
        );
        let msg = result.unwrap_err().to_string();
        assert!(
            msg.contains("normalize to the same"),
            "error must explain the ambiguity, got: {msg}"
        );
    }

    /// The identical name appearing in two different sections is not a collision — it dedups
    /// to a single group and must not error.
    #[tokio::test]
    async fn test_list_group_names_same_name_across_sections_ok() {
        let file = write_toml(
            r#"
[project.optional-dependencies]
dev = ["pytest>=8"]

[tool.poetry.group.dev.dependencies]
black = "^24"
"#,
        );
        let result = list_group_names(file.path()).await.unwrap();
        assert!(result.contains("dev"));
        assert_eq!(result.len(), 1);
    }
}
