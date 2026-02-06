// SPDX-License-Identifier: MIT

use async_trait::async_trait;
use std::fmt;

use crate::{Result, VulnerabilityDatabase};

pub(crate) use self::osv::OsvSource;
pub(crate) use self::pypa::PypaSource;
pub(crate) use self::pypi::PypiSource;

pub(crate) mod osv;
mod pypa;
mod pypi;
pub(crate) mod retry;

fn truncate_chars(value: &str, max_chars: usize) -> &str {
    for (count, (idx, _)) in value.char_indices().enumerate() {
        if count == max_chars {
            return &value[..idx];
        }
    }
    value
}

fn parse_cvss_score(score_str: &str) -> Option<f32> {
    use polycvss::{Score, Vector};

    if score_str.starts_with("CVSS:") {
        if let Ok(vector) = score_str.parse::<Vector>() {
            return Some(f32::from(Score::from(vector)));
        }
    }

    score_str.parse::<f32>().ok()
}

fn detect_cvss_version(severity_type: &str, score_str: &str) -> u8 {
    if severity_type.contains("V4")
        || severity_type.contains("v4")
        || score_str.starts_with("CVSS:4")
    {
        4
    } else if severity_type.contains("V3")
        || severity_type.contains("v3")
        || score_str.starts_with("CVSS:3")
    {
        3
    } else if severity_type.contains("V2")
        || severity_type.contains("v2")
        || score_str.starts_with("CVSS:2")
    {
        2
    } else {
        0
    }
}

fn extract_best_cvss_score<'a>(
    entries: impl Iterator<Item = (&'a str, &'a str)>,
) -> Option<(f32, u8)> {
    let mut tagged: Vec<(u8, &str, &str)> = entries
        .map(|(stype, score)| (detect_cvss_version(stype, score), stype, score))
        .collect();

    if tagged.is_empty() {
        return None;
    }

    tagged.sort_by(|a, b| b.0.cmp(&a.0));

    let mut current_version = tagged[0].0;
    let mut best_score: Option<f32> = None;
    let mut best_version: u8 = 0;

    for &(version, _stype, score_str) in &tagged {
        if version < current_version {
            if best_score.is_some() {
                break;
            }
            current_version = version;
        }
        if let Some(score) = parse_cvss_score(score_str) {
            match best_score {
                None => {
                    best_score = Some(score);
                    best_version = version;
                }
                Some(current) if score.total_cmp(&current) == std::cmp::Ordering::Greater => {
                    best_score = Some(score);
                    best_version = version;
                }
                _ => {}
            }
        }
    }

    best_score.map(|score| (score, best_version))
}

/// Trait for vulnerability data sources
#[async_trait]
pub trait VulnerabilityProvider: Send + Sync {
    /// Name of the vulnerability source
    fn name(&self) -> &'static str;

    /// Fetch vulnerabilities for the given packages
    async fn fetch_vulnerabilities(
        &self,
        packages: &[(String, String)], // (name, version) pairs
    ) -> Result<VulnerabilityDatabase>;
}

/// Enum representing available vulnerability sources
pub enum VulnerabilitySource {
    /// `PyPA` Advisory Database (ZIP download)
    PypaZip(PypaSource),
    /// PyPI JSON API
    Pypi(PypiSource),
    /// OSV.dev batch API
    Osv(OsvSource),
}

impl VulnerabilitySource {
    /// Create a new vulnerability source from the CLI option
    pub fn new(
        source: crate::types::VulnerabilitySource,
        cache: crate::AuditCache,
        no_cache: bool,
        http_config: crate::config::HttpConfig,
        vulnerability_ttl: u64,
    ) -> Self {
        match source {
            crate::types::VulnerabilitySource::Pypa => VulnerabilitySource::PypaZip(
                PypaSource::new(cache, no_cache, http_config, vulnerability_ttl),
            ),
            crate::types::VulnerabilitySource::Pypi => VulnerabilitySource::Pypi(PypiSource::new(
                cache,
                no_cache,
                http_config,
                vulnerability_ttl,
            )),
            crate::types::VulnerabilitySource::Osv => VulnerabilitySource::Osv(OsvSource::new(
                cache,
                no_cache,
                http_config,
                vulnerability_ttl,
            )),
        }
    }

    /// Get the name of the source
    pub fn name(&self) -> &'static str {
        match self {
            VulnerabilitySource::PypaZip(s) => s.name(),
            VulnerabilitySource::Pypi(s) => s.name(),
            VulnerabilitySource::Osv(s) => s.name(),
        }
    }

    /// Fetch vulnerabilities for the given packages
    pub async fn fetch_vulnerabilities(
        &self,
        packages: &[(String, String)],
    ) -> Result<VulnerabilityDatabase> {
        match self {
            VulnerabilitySource::PypaZip(s) => s.fetch_vulnerabilities(packages).await,
            VulnerabilitySource::Pypi(s) => s.fetch_vulnerabilities(packages).await,
            VulnerabilitySource::Osv(s) => s.fetch_vulnerabilities(packages).await,
        }
    }
}

impl fmt::Debug for VulnerabilitySource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "VulnerabilitySource({})", self.name())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vulnerability::Severity;

    #[test]
    fn test_cvss_version_detection() {
        assert_eq!(detect_cvss_version("CVSS_V4", ""), 4);
        assert_eq!(detect_cvss_version("CVSS_V3", ""), 3);
        assert_eq!(detect_cvss_version("CVSS_V2", ""), 2);
        assert_eq!(
            detect_cvss_version(
                "UNKNOWN",
                "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"
            ),
            4
        );
        assert_eq!(
            detect_cvss_version("UNKNOWN", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
            3
        );
        assert_eq!(detect_cvss_version("UNKNOWN", "7.5"), 0);
    }

    #[test]
    fn test_cvss_prefers_v3_over_v2() {
        let entries = vec![("CVSS_V2", "4.0"), ("CVSS_V3", "7.5")];
        let result = extract_best_cvss_score(entries.into_iter());
        assert_eq!(result, Some((7.5, 3)));
    }

    #[test]
    fn test_cvss_prefers_v4_over_v3() {
        let entries = vec![("CVSS_V3", "9.0"), ("CVSS_V4", "8.5")];
        let result = extract_best_cvss_score(entries.into_iter());
        assert_eq!(result, Some((8.5, 4)));
    }

    #[test]
    fn test_cvss_max_within_same_version() {
        let entries = vec![("CVSS_V3", "5.0"), ("CVSS_V3", "8.5"), ("CVSS_V3", "7.0")];
        let result = extract_best_cvss_score(entries.into_iter());
        assert_eq!(result, Some((8.5, 3)));
    }

    #[test]
    fn test_cvss_empty_entries() {
        let entries: Vec<(&str, &str)> = vec![];
        assert_eq!(extract_best_cvss_score(entries.into_iter()), None);
    }

    #[test]
    fn test_cvss_unparseable_entries() {
        let entries = vec![("UNKNOWN", "not-a-score"), ("UNKNOWN", "CRITICAL")];
        assert_eq!(extract_best_cvss_score(entries.into_iter()), None);
    }

    #[test]
    fn test_cvss_vector_with_version_detection() {
        let entries = vec![("CVSS_V3", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")];
        let result = extract_best_cvss_score(entries.into_iter());
        assert!(result.is_some());
        let (score, version) = result.unwrap();
        assert!(score >= 9.0);
        assert_eq!(version, 3);
    }

    #[test]
    fn test_severity_from_cvss_score_thresholds() {
        assert_eq!(Severity::from_cvss_score(10.0), Severity::Critical);
        assert_eq!(Severity::from_cvss_score(9.0), Severity::Critical);
        assert_eq!(Severity::from_cvss_score(8.9), Severity::High);
        assert_eq!(Severity::from_cvss_score(7.0), Severity::High);
        assert_eq!(Severity::from_cvss_score(6.9), Severity::Medium);
        assert_eq!(Severity::from_cvss_score(4.0), Severity::Medium);
        assert_eq!(Severity::from_cvss_score(3.9), Severity::Low);
        assert_eq!(Severity::from_cvss_score(0.0), Severity::Low);
    }
}
