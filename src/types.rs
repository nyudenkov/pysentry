// SPDX-License-Identifier: MIT

use serde::{Deserialize, Serialize};
use std::fmt;
use std::str::FromStr;

#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct PackageName(String);

impl PackageName {
    pub fn new(name: &str) -> Self {
        // invariant: full PEP 503 normalization — lowercase, then collapse every run
        // of `-`, `_`, `.` to a single `-` (canonical form is
        // `re.sub(r"[-_.]+", "-", name).lower()`). Comparing raw strings shipped
        // cross-package contamination (v0.4.4); normalizing only `_`→`-` while
        // ignoring dots shipped dot-mismatch false negatives (PEP 503). Always
        // compare via PackageName, never raw strings (CLAUDE.md Critical Rules).
        let lowercased = name.to_lowercase();
        let mut normalized = String::with_capacity(lowercased.len());
        let mut prev_separator = false;
        for ch in lowercased.chars() {
            if matches!(ch, '-' | '_' | '.') {
                if !prev_separator {
                    normalized.push('-');
                    prev_separator = true;
                }
            } else {
                normalized.push(ch);
                prev_separator = false;
            }
        }
        Self(normalized)
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for PackageName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<&str> for PackageName {
    fn from(name: &str) -> Self {
        Self::new(name)
    }
}

impl From<String> for PackageName {
    fn from(name: String) -> Self {
        Self::new(&name)
    }
}

impl FromStr for PackageName {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // Validate Python package names according to PEP 508
        // Package names should only contain letters, numbers, periods, hyphens, and underscores
        if s.is_empty() {
            return Err("Package name cannot be empty".to_string());
        }

        let is_valid = s
            .chars()
            .all(|c| c.is_alphanumeric() || c == '.' || c == '-' || c == '_');

        if is_valid {
            Ok(Self::new(s))
        } else {
            Err(format!("Invalid package name: '{s}'. Package names can only contain letters, numbers, periods, hyphens, and underscores."))
        }
    }
}

/// Version type (using pep440_rs::Version as Version)
pub use pep440_rs::Version;

/// Audit output formats
#[derive(Debug, Clone)]
pub enum AuditFormat {
    Human,
    Json,
    Sarif,
    Markdown,
}

/// Severity levels
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum SeverityLevel {
    Low,
    Medium,
    High,
    Critical,
}

/// Vulnerability sources
#[derive(Debug, Clone)]
pub enum VulnerabilitySource {
    Pypa,
    Pypi,
    Osv,
}

/// Vulnerability source types (for CLI compatibility)
pub type VulnerabilitySourceType = VulnerabilitySource;

/// Resolution cache entry containing resolved output and essential metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResolutionCacheEntry {
    /// The resolved output string
    pub output: String,
    /// Type of resolver used (uv, pip-tools)
    pub resolver_type: ResolverType,
    /// Version of the resolver tool
    pub resolver_version: String,
    /// Python version used for resolution
    pub python_version: String,
    /// List of resolved dependencies
    pub dependencies: Vec<ResolvedDependency>,
}

/// Individual resolved dependency
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResolvedDependency {
    /// Package name
    pub name: String,
    /// Resolved version
    pub version: String,
    /// Whether this is a direct dependency (vs transitive)
    pub is_direct: bool,
    /// Source file that contained this dependency
    pub source_file: std::path::PathBuf,
    /// Any extras specified for this dependency
    pub extras: Vec<String>,
    /// Environment markers for this dependency
    pub markers: Option<String>,
}

/// Resolver types for caching and registry
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ResolverType {
    /// UV resolver (Rust-based, fastest)
    Uv,
    /// pip-tools resolver (Python-based, widely used)
    PipTools,
}

impl fmt::Display for ResolverType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ResolverType::Uv => write!(f, "uv"),
            ResolverType::PipTools => write!(f, "pip-tools"),
        }
    }
}

impl From<&str> for ResolverType {
    fn from(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "uv" => ResolverType::Uv,
            "pip-tools" | "pip_tools" | "piptools" => ResolverType::PipTools,
            _ => ResolverType::Uv, // Default fallback
        }
    }
}

#[cfg(test)]
mod tests {
    use super::PackageName;
    use proptest::prelude::*;

    /// PEP 503 canonical reference: `re.sub(r"[-_.]+", "-", name).lower()`.
    /// PackageName::new must produce exactly this for every input.
    fn pep503_reference(name: &str) -> String {
        use std::sync::OnceLock;
        static RE: OnceLock<regex::Regex> = OnceLock::new();
        let re = RE.get_or_init(|| regex::Regex::new(r"[-_.]+").unwrap());
        re.replace_all(&name.to_lowercase(), "-").into_owned()
    }

    /// Join `segments` with separator `runs` (cycled to cover every gap),
    /// optionally upper-casing the whole spelling. The result is always a
    /// PEP-503-equivalent spelling of the same underlying name.
    fn build_spelling(segments: &[String], runs: &[String], upcase: bool) -> String {
        let mut spelling = String::new();
        // runs is always non-empty (generated with 1..6), so cycle().next() is always Some.
        let mut runs_iter = runs.iter().cycle();
        for (i, segment) in segments.iter().enumerate() {
            if i > 0 {
                if let Some(run) = runs_iter.next() {
                    spelling.push_str(run);
                }
            }
            spelling.push_str(segment);
        }
        if upcase {
            spelling.to_uppercase()
        } else {
            spelling
        }
    }

    fn separator_run() -> impl Strategy<Value = String> {
        prop::collection::vec(prop::sample::select(vec!['-', '_', '.']), 1..4)
            .prop_map(|chars| chars.into_iter().collect())
    }

    #[test]
    fn pep503_concrete_examples() {
        // Examples document; the proptests below cover the space.
        let canonical = PackageName::new("zope-interface");
        assert_eq!(canonical.as_str(), "zope-interface");
        assert_eq!(PackageName::new("zope.interface"), canonical);
        assert_eq!(PackageName::new("Zope_Interface"), canonical);
        assert_eq!(PackageName::new("ZOPE.INTERFACE"), canonical);

        // Runs of mixed separators collapse to a single hyphen.
        assert_eq!(PackageName::new("foo___bar").as_str(), "foo-bar");
        assert_eq!(PackageName::new("a.-_b").as_str(), "a-b");
        assert_eq!(PackageName::new("ruamel.yaml").as_str(), "ruamel-yaml");
    }

    proptest! {
        /// All PEP-503-equivalent spellings of the same name (differing only in
        /// separator choice/runs and case) must construct equal PackageNames.
        /// Pre-fix this FAILED: PackageName::new only mapped `_`→`-` and left dots
        /// and separator runs intact (the v0.4.4 dot-mismatch false negative).
        #[test]
        fn pep503_equivalent_spellings_are_equal(
            segments in prop::collection::vec("[a-zA-Z0-9]{1,8}", 1..6),
            runs_a in prop::collection::vec(separator_run(), 1..6),
            runs_b in prop::collection::vec(separator_run(), 1..6),
            upcase_a in any::<bool>(),
        ) {
            let spelling_a = build_spelling(&segments, &runs_a, upcase_a);
            let spelling_b = build_spelling(&segments, &runs_b, false);
            prop_assert_eq!(
                PackageName::new(&spelling_a),
                PackageName::new(&spelling_b),
                "PEP 503-equivalent spellings must normalize equally: {:?} vs {:?}",
                spelling_a,
                spelling_b
            );
        }

        /// PackageName::new must match the canonical PEP 503 reference exactly.
        #[test]
        fn pep503_matches_reference(name in "[a-zA-Z0-9._-]{1,30}") {
            let normalized = PackageName::new(&name);
            prop_assert_eq!(normalized.as_str(), pep503_reference(&name));
        }
    }
}
