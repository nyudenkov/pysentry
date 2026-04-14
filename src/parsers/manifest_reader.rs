// SPDX-License-Identifier: MIT

use crate::types::PackageName;
use crate::{AuditError, Result};
use std::collections::HashSet;
use std::path::Path;

/// Read all directly-declared dependency names from a pyproject.toml.
/// Covers PEP 621 ([project].dependencies, [project.optional-dependencies]),
/// PEP 735 ([dependency-groups] with include-group recursion),
/// Poetry ([tool.poetry.dependencies], [tool.poetry.dev-dependencies],
/// [tool.poetry.group.<name>.dependencies]), and uv ([tool.uv.dev-dependencies]).
/// Returns Ok(empty set) if the file does not exist.
/// Returns Err if the file cannot be read or parsed as TOML.
#[cfg_attr(feature = "hotpath", hotpath::measure)]
pub async fn read_direct_deps_from_pyproject(path: &Path) -> Result<Option<HashSet<PackageName>>> {
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

        // PEP 621: [project.optional-dependencies] — table of string arrays
        if let Some(optional) = project
            .get("optional-dependencies")
            .and_then(|v| v.as_table())
        {
            for (_group, group_deps) in optional {
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

    // PEP 735: [dependency-groups] — table of mixed arrays (strings + {include-group} tables)
    if let Some(dep_groups) = doc.get("dependency-groups") {
        if let Some(table) = dep_groups.as_table() {
            let mut resolved = Vec::new();
            for (_group_name, entries) in table {
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
                names.extend(collect_poetry_table_deps(deps));
            }
            if let Some(dev_deps) = poetry.get("dev-dependencies").and_then(|v| v.as_table()) {
                names.extend(collect_poetry_table_deps(dev_deps));
            }
            if let Some(groups) = poetry.get("group").and_then(|v| v.as_table()) {
                for (_group_name, group_val) in groups {
                    if let Some(group_deps) =
                        group_val.get("dependencies").and_then(|v| v.as_table())
                    {
                        names.extend(collect_poetry_table_deps(group_deps));
                    }
                }
            }
        }
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

    Ok(Some(names))
}

fn extract_package_name(dep_str: &str) -> Option<PackageName> {
    let trimmed = dep_str.trim();
    let end = trimmed
        .find(|c: char| {
            matches!(c, '>' | '<' | '=' | '!' | '~' | '[' | '@' | ';') || c.is_whitespace()
        })
        .unwrap_or(trimmed.len());
    let name = trimmed[..end].trim();
    if name.is_empty() {
        return None;
    }
    Some(PackageName::new(name))
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
                    if current_path.contains(included) {
                        return Err(AuditError::InvalidDependency(format!(
                            "Circular dependency in include-group: {} -> {}",
                            current_path.join(" -> "),
                            included
                        )));
                    }
                    if let Some(included_entries) =
                        dep_groups.get(included).and_then(|v| v.as_array())
                    {
                        current_path.push(included.clone());
                        collect_group_deps(included_entries, dep_groups, current_path, result)?;
                        current_path.pop();
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

fn collect_poetry_table_deps(table: &toml::map::Map<String, toml::Value>) -> Vec<PackageName> {
    table
        .keys()
        .filter_map(|key| {
            let name = PackageName::new(key);
            if name.as_str() == "python" {
                None
            } else {
                Some(name)
            }
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
        let result = read_direct_deps_from_pyproject(file.path())
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
        let result = read_direct_deps_from_pyproject(file.path())
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
        let result = read_direct_deps_from_pyproject(file.path())
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
        let result = read_direct_deps_from_pyproject(file.path())
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
        let result = read_direct_deps_from_pyproject(file.path()).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_missing_file_returns_none() {
        let path = Path::new("/nonexistent/path/to/pyproject.toml");
        let result = read_direct_deps_from_pyproject(path).await.unwrap();
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
        let result = read_direct_deps_from_pyproject(file.path()).await.unwrap();
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
        let result = read_direct_deps_from_pyproject(file.path())
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
        let result = read_direct_deps_from_pyproject(file.path())
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
        let result = read_direct_deps_from_pyproject(file.path())
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
        let result = read_direct_deps_from_pyproject(file.path())
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
        let result = read_direct_deps_from_pyproject(file.path())
            .await
            .unwrap()
            .unwrap();
        assert!(result.contains(&PackageName::new("httpx")));
        assert!(result.contains(&PackageName::new("django")));
        assert!(result.contains(&PackageName::new("pytest")));
        assert!(!result.contains(&PackageName::new("python")));
        assert_eq!(result.len(), 3);
    }
}
