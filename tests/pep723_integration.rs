// SPDX-License-Identifier: MIT

use pysentry::DependencyScanner;
use std::collections::HashSet;
use std::path::Path;

const SCRIPT_FIXTURE: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/fixtures/pep723-script/tool.py"
);
const PROJECT_FIXTURE: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/fixtures/pep723-with-project-files"
);
const PROJECT_SCRIPT_FIXTURE: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/fixtures/pep723-with-project-files/audit_script.py"
);

#[tokio::test]
async fn test_pep723_script_fixture_scans_directly() {
    let scanner = DependencyScanner::new(false, true, false, None, None);
    let result = scanner.scan_project(Path::new(SCRIPT_FIXTURE)).await;
    let (deps, skipped, parser_name) = match result {
        Ok(scan) => scan,
        Err(error) => panic!("PEP 723 script fixture must scan: {error}"),
    };

    let names: HashSet<String> = deps.iter().map(|dep| dep.name.to_string()).collect();

    assert_eq!(parser_name, "PEP 723 script");
    assert!(skipped.is_empty());
    assert_eq!(names.len(), 2);
    assert!(names.contains("requests"));
    assert!(names.contains("click"));
    assert!(deps.iter().all(|dep| dep.is_direct));
    assert!(deps
        .iter()
        .all(|dep| dep.source_file.as_deref() == Some("tool.py")));
}

#[tokio::test]
async fn test_explicit_pep723_script_wins_over_sibling_project_files() {
    let scanner = DependencyScanner::new(false, true, false, None, None);
    let result = scanner
        .scan_project(Path::new(PROJECT_SCRIPT_FIXTURE))
        .await;
    let (deps, skipped, parser_name) = match result {
        Ok(scan) => scan,
        Err(error) => panic!("PEP 723 script beside project files must scan: {error}"),
    };

    let names: HashSet<String> = deps.iter().map(|dep| dep.name.to_string()).collect();

    assert_eq!(parser_name, "PEP 723 script");
    assert!(skipped.is_empty());
    assert_eq!(names, ["requests".to_string()].into());
    assert!(deps
        .iter()
        .all(|dep| dep.source_file.as_deref() == Some("audit_script.py")));
}

#[tokio::test]
async fn test_directory_with_pep723_script_keeps_lock_file_priority() {
    let scanner = DependencyScanner::new(false, true, false, None, None);
    let result = scanner.scan_project(Path::new(PROJECT_FIXTURE)).await;
    let (deps, _skipped, parser_name) = match result {
        Ok(scan) => scan,
        Err(error) => panic!("project fixture with uv.lock must scan: {error}"),
    };

    let names: HashSet<String> = deps.iter().map(|dep| dep.name.to_string()).collect();

    assert_eq!(parser_name, "uv.lock");
    assert!(names.contains("click"));
    assert!(!names.contains("requests"));
}
