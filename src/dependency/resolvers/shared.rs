// SPDX-License-Identifier: MIT

//! Shared utilities for dependency resolvers

use crate::types::ResolvedDependency;
use regex::Regex;
use std::sync::OnceLock;
use tracing::debug;

pub(crate) static PACKAGE_REGEX: OnceLock<Regex> = OnceLock::new();

pub(crate) const FALLBACK_PYTHON_VERSION: &str = "3.12";

pub(crate) fn parse_resolved_dependencies(
    resolved_output: &str,
    source_file: &std::path::Path,
) -> Vec<ResolvedDependency> {
    let mut dependencies = Vec::new();

    let package_regex = PACKAGE_REGEX
        .get_or_init(|| Regex::new(r"^([a-zA-Z0-9_.-]+)==([^;]+)(?:;\s*(.+))?").unwrap());

    for line in resolved_output.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }

        if let Some(captures) = package_regex.captures(trimmed) {
            let Some(name_match) = captures.get(1) else {
                continue;
            };
            let Some(version_match) = captures.get(2) else {
                continue;
            };
            let name = name_match.as_str().to_string();
            let version = version_match.as_str().to_string();
            let markers = captures.get(3).map(|m| m.as_str().to_string());

            dependencies.push(ResolvedDependency {
                name,
                version,
                is_direct: true,
                source_file: source_file.to_path_buf(),
                extras: Vec::new(),
                markers,
            });
        }
    }

    debug!("Parsed {} resolved dependencies", dependencies.len());
    dependencies
}
