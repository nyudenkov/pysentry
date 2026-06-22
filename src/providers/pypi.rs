// SPDX-License-Identifier: MIT

use crate::cache::CacheEntry;
use async_trait::async_trait;
use futures::stream::{FuturesUnordered, StreamExt};
use indicatif::{ProgressBar, ProgressStyle};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::str::FromStr;
use std::sync::Arc;
use tracing::{debug, warn};

use super::retry::{is_http_error_retryable, retry_with_backoff};

use crate::types::Version;
use crate::{
    AuditCache, AuditError, Result, Severity, VersionRange, Vulnerability, VulnerabilityDatabase,
    VulnerabilityProvider,
};

/// PyPI JSON API source for vulnerability data
pub struct PypiSource {
    cache: AuditCache,
    no_cache: bool,
    client: reqwest::Client,
    http_config: crate::config::HttpConfig,
    vulnerability_ttl: u64,
}

/// Maximum number of concurrent PyPI vulnerability detail requests.
const PYPI_MAX_CONCURRENT_REQUESTS: usize = 15;

impl PypiSource {
    /// Create a new PyPI source with HTTP configuration
    pub fn new(
        cache: AuditCache,
        no_cache: bool,
        http_config: crate::config::HttpConfig,
        vulnerability_ttl: u64,
    ) -> Self {
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(http_config.timeout))
            .connect_timeout(std::time::Duration::from_secs(http_config.connect_timeout))
            .build()
            .unwrap_or_default();

        Self {
            cache,
            no_cache,
            client,
            http_config,
            vulnerability_ttl,
        }
    }

    /// Get cache entry for a package/version.
    fn cache_entry(&self, name: &str, version: &str) -> CacheEntry {
        // -v2: v0.4.7 changed the converted Vulnerability payload for PyPI advisories:
        // no-fix advisories now emit a wildcard range, and every fixed_in branch emits its
        // own range. Old v1 cache files deserialize successfully but preserve false-negative
        // ranges, so they must not be reused.
        self.cache
            .database_entry(&format!("pypi-v2-{name}-{version}"))
    }

    /// Fetch vulnerability data from PyPI for a single package with retry
    async fn fetch_package_vulnerabilities(
        &self,
        name: &str,
        version: &str,
    ) -> Result<Vec<Vulnerability>> {
        use crate::cache::Freshness;
        use std::time::Duration;

        let cache_entry = self.cache_entry(name, version);
        let ttl = Duration::from_secs(self.vulnerability_ttl * 3600);

        // Check cache freshness first unless no_cache is set
        let cache_is_fresh = if self.no_cache {
            false
        } else {
            matches!(cache_entry.freshness(ttl), Ok(Freshness::Fresh))
        };

        if cache_is_fresh {
            if let Ok(content) = fs_err::read(cache_entry.path()) {
                if let Ok(vulns) = serde_json::from_slice::<Vec<Vulnerability>>(&content) {
                    debug!(
                        "Using cached PyPI vulnerabilities for {} {} (TTL: {} hours)",
                        name, version, self.vulnerability_ttl
                    );
                    return Ok(vulns);
                }
            }
        }

        // Fetch from PyPI API
        let url = format!("https://pypi.org/pypi/{name}/{version}/json");
        debug!("Fetching vulnerabilities from PyPI: {}", url);

        let response = self
            .client
            .get(&url)
            .send()
            .await
            .map_err(|e| AuditError::DatabaseDownload(Box::new(e)))?;

        if !response.status().is_success() {
            if response.status() == 404 {
                // Package not found - return empty vulnerabilities
                return Ok(vec![]);
            }
            return Err(AuditError::other(format!(
                "PyPI API returned error: {}",
                response.status()
            )));
        }

        let data: PypiPackageResponse = response
            .json()
            .await
            .map_err(|e| AuditError::DatabaseDownload(Box::new(e)))?;

        let vulnerabilities = data
            .vulnerabilities
            .unwrap_or_default()
            .into_iter()
            .map(|vuln| Self::convert_pypi_vulnerability(name, vuln))
            .collect::<Vec<_>>();

        // Cache the result
        if !self.no_cache {
            // Directory creation handled by cache entry write
            let content = serde_json::to_vec(&vulnerabilities)?;
            cache_entry.write(&content).await?;
        }

        Ok(vulnerabilities)
    }

    /// Convert PyPI vulnerability format to internal format
    fn convert_pypi_vulnerability(package: &str, vuln: PypiVulnerability) -> Vulnerability {
        let severity = Self::map_severity(&vuln);

        // Extract affected version ranges from details or use current version
        let affected_versions = Self::extract_affected_ranges(&vuln);

        // Convert fixed_in strings to Versions
        let fixed_versions = vuln
            .fixed_in
            .unwrap_or_default()
            .iter()
            .filter_map(|v| Version::from_str(v).ok())
            .collect();

        Vulnerability {
            id: vuln.id.clone(),
            summary: vuln.summary.unwrap_or_else(|| vuln.details.clone()),
            description: Some(vuln.details),
            severity,
            affected_versions,
            fixed_versions,
            references: vec![vuln
                .link
                .unwrap_or_else(|| format!("https://pypi.org/project/{package}/"))],
            cvss_score: None,
            cvss_version: None,
            published: None,
            modified: None,
            source: Some("pypi".to_string()),
            withdrawn: None,
            aliases: vuln.aliases.unwrap_or_default(),
        }
    }

    /// Map PyPI severity to internal severity
    fn map_severity(_vuln: &PypiVulnerability) -> Severity {
        // PyPI provides no CVSS data. The merge logic picks up real severity
        // from PyPA/OSV sources for the same vulnerability ID.
        Severity::Unknown
    }

    /// Extract affected version ranges from vulnerability details
    fn extract_affected_ranges(vuln: &PypiVulnerability) -> Vec<VersionRange> {
        // PyPI doesn't provide structured affected ranges, so each fixed version
        // is treated as the upper bound of an affected range. Carrying every
        // fixed version (not just the first) preserves multi-branch fixes, e.g.
        // a vulnerability fixed in both 2.31.1 and 3.0.2 leaves 3.0.1 affected.
        if let Some(fixed_in) = &vuln.fixed_in {
            let ranges: Vec<VersionRange> = fixed_in
                .iter()
                .filter_map(|raw| {
                    Version::from_str(raw).ok().map(|version| VersionRange {
                        min: None,
                        max: Some(version),
                        constraint: format!("<{raw}"),
                        max_inclusive: false,
                    })
                })
                .collect();
            if !ranges.is_empty() {
                return ranges;
            }
        }

        // No usable fix version to bound a range. The PyPI JSON API is queried
        // per installed version and only returns advisories that apply to that
        // version, so trust the server's assertion with a match-all range rather
        // than emitting an empty list, which the matcher reads as "not affected".
        vec![VersionRange {
            min: None,
            max: None,
            constraint: "*".to_string(),
            max_inclusive: false,
        }]
    }

    /// Create a future for fetching package vulnerabilities with retry
    async fn fetch_package_future(
        &self,
        name: String,
        version: String,
    ) -> (String, String, Result<Vec<Vulnerability>>) {
        let name_clone = name.clone();
        let version_clone = version.clone();
        let context = format!("PyPI query for {} {}", name, version);

        let result = retry_with_backoff(
            self.http_config.max_retries,
            self.http_config.retry_initial_backoff,
            self.http_config.retry_max_backoff,
            is_http_error_retryable,
            || self.fetch_package_vulnerabilities(&name_clone, &version_clone),
            &context,
        )
        .await
        .map_err(|err| AuditError::DatabaseDownloadDetailed {
            resource: format!("PyPI package {} {}", name_clone, version_clone),
            url: format!(
                "https://pypi.org/pypi/{}/{}/json",
                name_clone, version_clone
            ),
            source: Box::new(err),
        });

        (name, version, result)
    }
}

#[async_trait]
impl VulnerabilityProvider for PypiSource {
    fn name(&self) -> &'static str {
        "pypi"
    }

    async fn fetch_vulnerabilities(
        &self,
        packages: &[(String, String)],
    ) -> Result<VulnerabilityDatabase> {
        #[cfg(feature = "hotpath")]
        let _hp_wall =
            hotpath::MeasurementGuardSync::new("pypi::fetch_vulnerabilities", false, false);
        debug!(
            "Fetching vulnerabilities for {} packages from PyPI",
            packages.len()
        );

        // Create progress bar if enabled
        let pb = if self.http_config.show_progress && packages.len() > 1 {
            let bar = ProgressBar::new(packages.len() as u64);
            // invariant: the template string is a compile-time constant known to be valid.
            #[allow(clippy::unwrap_used)]
            bar.set_style(
                ProgressStyle::default_bar()
                    .template("{msg}\n{spinner:.green} [{elapsed_precise}] [{wide_bar:.cyan/blue}] {pos}/{len} packages ({eta})")
                    .unwrap()
                    .progress_chars("#>-"),
            );
            bar.set_message("Querying PyPI for vulnerabilities");
            Some(Arc::new(bar))
        } else {
            None
        };

        // Fetch vulnerabilities for all packages concurrently with rate limiting
        // (cap defined by PYPI_MAX_CONCURRENT_REQUESTS).
        let mut futures = FuturesUnordered::new();
        let mut package_iter = packages.iter().cloned();
        let mut successful_fetches = 0;
        let mut failed_fetches = 0;
        let mut vuln_map = HashMap::new();

        // Start initial batch of requests
        for _ in 0..PYPI_MAX_CONCURRENT_REQUESTS.min(packages.len()) {
            if let Some((name, version)) = package_iter.next() {
                futures.push(self.fetch_package_future(name, version));
            }
        }

        // Process results as they complete, maintaining rate limit
        while let Some((name, version, result)) = futures.next().await {
            // Start a new request if there are more packages to process
            if let Some((next_name, next_version)) = package_iter.next() {
                futures.push(self.fetch_package_future(next_name, next_version));
            }

            match result {
                Ok(vulns) => {
                    successful_fetches += 1;
                    if !vulns.is_empty() {
                        debug!(
                            "Found {} vulnerabilities for {} {}",
                            vulns.len(),
                            name,
                            version
                        );
                        vuln_map.insert(name, vulns);
                    }
                }
                Err(e) => {
                    failed_fetches += 1;
                    warn!(
                        "Failed to fetch vulnerabilities for {} {}: {}",
                        name, version, e
                    );
                }
            }

            // Update progress bar
            if let Some(ref bar) = pb {
                bar.inc(1);
            }
        }

        // Finish progress bar
        if let Some(bar) = pb {
            bar.finish_with_message(format!(
                "Queried PyPI: {} successful, {} failed",
                successful_fetches, failed_fetches
            ));
        }

        debug!(
            "PyPI vulnerability processing complete: {} successful, {} failed, {} packages with vulnerabilities",
            successful_fetches,
            failed_fetches,
            vuln_map.len()
        );

        Ok(VulnerabilityDatabase::from_package_map(vuln_map))
    }
}

/// PyPI API response structure
#[derive(Debug, Deserialize, Serialize)]
struct PypiPackageResponse {
    info: PypiPackageInfo,
    #[serde(default)]
    vulnerabilities: Option<Vec<PypiVulnerability>>,
}

#[derive(Debug, Deserialize, Serialize)]
struct PypiPackageInfo {
    name: String,
    version: String,
}

/// PyPI vulnerability structure
#[derive(Debug, Deserialize, Serialize)]
struct PypiVulnerability {
    id: String,
    #[serde(default)]
    aliases: Option<Vec<String>>,
    details: String,
    #[serde(default)]
    summary: Option<String>,
    #[serde(default)]
    fixed_in: Option<Vec<String>>,
    #[serde(default)]
    link: Option<String>,
}

#[cfg(test)]
mod tests {
    // Indexing into fixtures/parsed results is the norm in tests; a panic on a
    // bad index is an acceptable test failure.
    #![allow(clippy::indexing_slicing)]
    use super::*;

    fn vuln_with_fixed_in(fixed_in: Option<Vec<&str>>) -> PypiVulnerability {
        PypiVulnerability {
            id: "PYSEC-TEST".to_string(),
            aliases: None,
            details: "test".to_string(),
            summary: None,
            fixed_in: fixed_in.map(|v| v.into_iter().map(String::from).collect()),
            link: None,
        }
    }

    #[test]
    fn test_multiple_fixed_versions_cover_all_branches() {
        // Fixed in both 2.31.1 and 3.0.2: 3.0.1 must remain flagged. The old
        // `.first()` logic only emitted <2.31.1 and missed the 3.x branch.
        let vuln = vuln_with_fixed_in(Some(vec!["2.31.1", "3.0.2"]));
        let ranges = PypiSource::extract_affected_ranges(&vuln);

        assert!(ranges
            .iter()
            .any(|range| range.contains(&Version::from_str("3.0.1").unwrap())));
        assert!(ranges
            .iter()
            .any(|range| range.contains(&Version::from_str("2.31.0").unwrap())));
        // Above every fix version, nothing should match.
        assert!(!ranges
            .iter()
            .any(|range| range.contains(&Version::from_str("3.5.0").unwrap())));
    }

    #[test]
    fn test_no_fixed_in_trusts_server_with_wildcard() {
        // PyPI returns this advisory only because it applies to the queried
        // version. With no fix to bound a range, a match-all range keeps it from
        // being silently dropped as "not affected".
        let vuln = vuln_with_fixed_in(None);
        let ranges = PypiSource::extract_affected_ranges(&vuln);

        assert_eq!(ranges.len(), 1);
        assert!(ranges[0].contains(&Version::from_str("1.0.0").unwrap()));
        assert!(ranges[0].contains(&Version::from_str("99.0.0").unwrap()));
    }

    #[test]
    fn test_unparseable_fixed_in_falls_back_to_wildcard() {
        let vuln = vuln_with_fixed_in(Some(vec!["not-a-version"]));
        let ranges = PypiSource::extract_affected_ranges(&vuln);

        assert_eq!(ranges.len(), 1);
        assert!(ranges[0].contains(&Version::from_str("4.2.0").unwrap()));
    }

    #[test]
    fn test_cache_entry_versioned_key_ignores_old_name() {
        let temp_dir = tempfile::tempdir().unwrap();
        let cache = AuditCache::new(temp_dir.path().to_path_buf());
        let source = PypiSource::new(
            cache.clone(),
            false,
            crate::config::HttpConfig::default(),
            48,
        );

        let old_entry = cache.database_entry("pypi-django-4.2.0");
        if let Some(parent) = old_entry.path().parent() {
            std::fs::create_dir_all(parent).unwrap();
        }
        std::fs::write(old_entry.path(), b"old pypi payload").unwrap();

        let versioned_entry = source.cache_entry("django", "4.2.0");
        assert_ne!(versioned_entry.path(), old_entry.path());
        assert!(!versioned_entry.path().exists());
    }
}
