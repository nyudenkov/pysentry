/*
 * pysentry - Python security vulnerability scanner
 * Copyright (C) 2025 nyudenkov <nyudenkov@pm.me>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

use crate::cache::CacheEntry;
use crate::types::Version;
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use futures::stream::{FuturesUnordered, StreamExt};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::str::FromStr;
use tracing::{debug, warn};

use crate::{
    AuditCache, AuditError, Result, Severity, VersionRange, Vulnerability, VulnerabilityDatabase,
    VulnerabilityProvider,
};

/// The OSV API base URL for fetching vulnerability data
const OSV_API_BASE: &str = "https://api.osv.dev/v1";

/// An OSV (Open Source Vulnerabilities) advisory record
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OsvAdvisory {
    /// Unique vulnerability identifier
    pub id: String,

    /// Vulnerability summary (optional - not all OSV records have this)
    pub summary: Option<String>,

    /// Detailed description
    pub details: Option<String>,

    /// Affected packages and versions (defaults to empty if missing)
    #[serde(default)]
    pub affected: Vec<OsvAffected>,

    /// Reference URLs (optional - defaults to empty if missing)
    #[serde(default)]
    pub references: Vec<OsvReference>,

    /// Severity information (optional - not all OSV records have this)
    #[serde(default)]
    pub severity: Vec<OsvSeverity>,

    /// Publication timestamp
    pub published: Option<String>,

    /// Last modification timestamp
    pub modified: Option<String>,

    /// Database-specific fields
    pub database_specific: Option<serde_json::Value>,
}

/// Affected package information in an OSV advisory
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OsvAffected {
    /// Package information
    pub package: OsvPackage,

    /// Version ranges affected
    #[serde(default)]
    pub ranges: Vec<OsvRange>,

    /// Specific versions affected
    pub versions: Option<Vec<String>>,

    /// Ecosystem-specific database information
    pub database_specific: Option<serde_json::Value>,

    /// Ecosystem-specific fields
    pub ecosystem_specific: Option<serde_json::Value>,
}

/// Package information in OSV format
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OsvPackage {
    /// Package ecosystem (e.g., "PyPI")
    pub ecosystem: String,

    /// Package name
    pub name: String,

    /// Package URL if available
    pub purl: Option<String>,
}

/// Version range specification in OSV format
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OsvRange {
    /// Range type (e.g., "ECOSYSTEM")
    #[serde(rename = "type")]
    pub range_type: String,

    /// Repository URL for version control ranges
    pub repo: Option<String>,

    /// Events defining the range (introduced, fixed, etc.)
    #[serde(default)]
    pub events: Vec<OsvEvent>,

    /// Database-specific information
    pub database_specific: Option<serde_json::Value>,
}

/// A version event in an OSV range
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OsvEvent {
    /// Version where event occurs
    pub introduced: Option<String>,

    /// Version where issue is fixed
    pub fixed: Option<String>,

    /// Last affected version
    pub last_affected: Option<String>,

    /// Version limit
    pub limit: Option<String>,
}

/// Reference information in OSV format
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OsvReference {
    /// Reference type (e.g., "ADVISORY", "FIX", "WEB")
    #[serde(rename = "type")]
    pub ref_type: String,

    /// Reference URL
    pub url: String,
}

/// Severity information in OSV format
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OsvSeverity {
    /// Severity type (e.g., `CVSS_V3`)
    #[serde(rename = "type")]
    pub severity_type: String,

    /// Severity score
    pub score: String,
}

/// OSV.dev API source for vulnerability data
pub struct OsvSource {
    cache: AuditCache,
    no_cache: bool,
    client: reqwest::Client,
}

impl OsvSource {
    /// Create a new OSV source
    pub fn new(cache: AuditCache, no_cache: bool) -> Self {
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(60))
            .build()
            .unwrap_or_default();

        Self {
            cache,
            no_cache,
            client,
        }
    }

    /// Get cache entry for OSV batch with package-specific key
    fn cache_entry(&self, packages: &[(String, String)]) -> CacheEntry {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        // Create a hash of the package set to differentiate cache entries
        let mut hasher = DefaultHasher::new();
        for (name, version) in packages {
            name.hash(&mut hasher);
            version.hash(&mut hasher);
        }
        let package_hash = hasher.finish();

        self.cache.database_entry(&format!("osv-{package_hash:x}"))
    }

    /// Convert OSV advisory to internal vulnerability format
    fn convert_osv_vulnerability(advisory: OsvAdvisory) -> Option<Vulnerability> {
        // Extract package name from affected entries
        if advisory.affected.is_empty() {
            return None;
        }
        let first_affected = &advisory.affected[0];

        // Map OSV severity
        let severity = Self::map_osv_severity(&advisory);

        // Extract version ranges
        let affected_versions = Self::extract_osv_ranges(first_affected);

        // Extract fixed versions
        let fixed_versions = Self::extract_fixed_versions(first_affected);

        // Build references
        let mut references = vec![];
        for reference in advisory.references {
            references.push(reference.url);
        }
        // Add OSV URL as a reference
        references.push(format!("https://osv.dev/vulnerability/{}", advisory.id));

        Some(Vulnerability {
            id: advisory.id,
            summary: match (&advisory.summary, &advisory.details) {
                (Some(summary), _) if !summary.is_empty() => summary.clone(),
                (_, Some(details)) => {
                    // Truncate details for summary (first sentence or 100 chars)
                    let summary = details.split('.').next().unwrap_or(details);
                    if summary.len() > 100 {
                        format!("{}...", &summary[..100])
                    } else {
                        summary.to_string()
                    }
                }
                _ => "OSV Advisory".to_string(),
            },
            description: advisory.details,
            severity,
            affected_versions,
            fixed_versions,
            references,
            cvss_score: None,
            published: advisory.published.and_then(|s| {
                DateTime::parse_from_rfc3339(&s)
                    .ok()
                    .map(|dt| dt.with_timezone(&Utc))
            }),
            modified: advisory.modified.and_then(|s| {
                DateTime::parse_from_rfc3339(&s)
                    .ok()
                    .map(|dt| dt.with_timezone(&Utc))
            }),
            source: Some("osv".to_string()),
            withdrawn: None,
        })
    }

    /// Map OSV severity to internal severity
    fn map_osv_severity(advisory: &OsvAdvisory) -> Severity {
        for severity in &advisory.severity {
            let score = &severity.score;
            // CVSS v3 scoring
            if score.contains("CRITICAL") || score.contains("9.") || score.contains("10.") {
                return Severity::Critical;
            }
            if score.contains("HIGH") || score.contains("7.") || score.contains("8.") {
                return Severity::High;
            }
            if score.contains("MEDIUM")
                || score.contains("4.")
                || score.contains("5.")
                || score.contains("6.")
            {
                return Severity::Medium;
            }
            if score.contains("LOW") {
                return Severity::Low;
            }
        }

        // Check database_specific field for severity hints
        if let Some(db_specific) = &advisory.database_specific {
            let data_str = db_specific.to_string().to_uppercase();
            if data_str.contains("CRITICAL") {
                return Severity::Critical;
            }
            if data_str.contains("HIGH") {
                return Severity::High;
            }
            if data_str.contains("MEDIUM") || data_str.contains("MODERATE") {
                return Severity::Medium;
            }
            if data_str.contains("LOW") {
                return Severity::Low;
            }
        }

        Severity::Medium
    }

    /// Extract version ranges from OSV affected entry
    fn extract_osv_ranges(affected: &OsvAffected) -> Vec<VersionRange> {
        let mut ranges = vec![];

        for range in &affected.ranges {
            if range.range_type != "ECOSYSTEM" && range.range_type != "SEMVER" {
                continue;
            }

            let mut min_version = None;
            let mut max_version = None;

            for event in &range.events {
                if let Some(intro) = &event.introduced {
                    if intro != "0" {
                        if let Ok(version) = Version::from_str(intro) {
                            min_version = Some(version);
                        }
                    }
                }
                if let Some(fix) = &event.fixed {
                    if let Ok(version) = Version::from_str(fix) {
                        max_version = Some(version);
                    }
                }
            }

            let constraint = match (&min_version, &max_version) {
                (Some(min), Some(max)) => format!(">={min},<{max}"),
                (Some(min), None) => format!(">={min}"),
                (None, Some(max)) => format!("<{max}"),
                (None, None) => "*".to_string(),
            };

            ranges.push(VersionRange {
                min: min_version,
                max: max_version,
                constraint,
            });
        }

        ranges
    }

    /// Extract fixed versions from OSV affected entry
    fn extract_fixed_versions(affected: &OsvAffected) -> Vec<Version> {
        let mut fixed_versions = vec![];

        for range in &affected.ranges {
            for event in &range.events {
                if let Some(fixed) = &event.fixed {
                    if let Ok(version) = Version::from_str(fixed) {
                        fixed_versions.push(version);
                    }
                }
            }
        }

        fixed_versions
    }

    /// Recovery for malformed OSV JSON
    fn recover_from_malformed_json(
        value: &serde_json::Value,
        vuln_id: &str,
    ) -> Option<OsvAdvisory> {
        let obj = value.as_object()?;

        // Extract basic fields with fallbacks
        let id = obj
            .get("id")
            .and_then(|v| v.as_str())
            .unwrap_or(vuln_id)
            .to_string();

        let summary = obj
            .get("summary")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());

        let details = obj
            .get("details")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());

        // Affected package extraction - just get what we can
        let mut affected = Vec::new();
        if let Some(affected_array) = obj.get("affected").and_then(|v| v.as_array()) {
            for item in affected_array {
                if let Some(item_obj) = item.as_object() {
                    // Try to extract package name and ecosystem
                    if let Some(pkg) = item_obj.get("package").and_then(|p| p.as_object()) {
                        let package = OsvPackage {
                            ecosystem: pkg
                                .get("ecosystem")
                                .and_then(|v| v.as_str())
                                .unwrap_or("PyPI")
                                .to_string(),
                            name: pkg
                                .get("name")
                                .and_then(|v| v.as_str())
                                .unwrap_or("unknown")
                                .to_string(),
                            purl: pkg
                                .get("purl")
                                .and_then(|v| v.as_str())
                                .map(|s| s.to_string()),
                        };

                        // Simple range extraction - just create empty ranges if malformed
                        let ranges = item_obj
                            .get("ranges")
                            .and_then(|r| r.as_array())
                            .map(|arr| {
                                arr.iter()
                                    .filter_map(|range| {
                                        range.as_object().map(|r| OsvRange {
                                            range_type: r
                                                .get("type")
                                                .and_then(|v| v.as_str())
                                                .unwrap_or("ECOSYSTEM")
                                                .to_string(),
                                            repo: r
                                                .get("repo")
                                                .and_then(|v| v.as_str())
                                                .map(|s| s.to_string()),
                                            events: r
                                                .get("events")
                                                .and_then(|e| e.as_array())
                                                .map(|events_arr| {
                                                    events_arr
                                                        .iter()
                                                        .filter_map(|e| e.as_object())
                                                        .map(|e_obj| OsvEvent {
                                                            introduced: e_obj
                                                                .get("introduced")
                                                                .and_then(|v| v.as_str())
                                                                .map(|s| s.to_string()),
                                                            fixed: e_obj
                                                                .get("fixed")
                                                                .and_then(|v| v.as_str())
                                                                .map(|s| s.to_string()),
                                                            last_affected: e_obj
                                                                .get("last_affected")
                                                                .and_then(|v| v.as_str())
                                                                .map(|s| s.to_string()),
                                                            limit: e_obj
                                                                .get("limit")
                                                                .and_then(|v| v.as_str())
                                                                .map(|s| s.to_string()),
                                                        })
                                                        .collect()
                                                })
                                                .unwrap_or_default(),
                                            database_specific: r.get("database_specific").cloned(),
                                        })
                                    })
                                    .collect()
                            })
                            .unwrap_or_default();

                        affected.push(OsvAffected {
                            package,
                            ranges,
                            versions: item_obj.get("versions").and_then(|v| v.as_array()).map(
                                |arr| {
                                    arr.iter()
                                        .filter_map(|v| v.as_str().map(|s| s.to_string()))
                                        .collect()
                                },
                            ),
                            database_specific: item_obj.get("database_specific").cloned(),
                            ecosystem_specific: item_obj.get("ecosystem_specific").cloned(),
                        });
                    }
                }
            }
        }

        // Create minimal affected entry if none found
        if affected.is_empty() {
            affected.push(OsvAffected {
                package: OsvPackage {
                    ecosystem: "PyPI".to_string(),
                    name: "unknown".to_string(),
                    purl: None,
                },
                ranges: vec![],
                versions: None,
                database_specific: None,
                ecosystem_specific: None,
            });
        }

        // Simple reference extraction
        let references = obj
            .get("references")
            .and_then(|r| r.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|ref_item| {
                        ref_item.as_object().map(|r| OsvReference {
                            ref_type: r
                                .get("type")
                                .and_then(|v| v.as_str())
                                .unwrap_or("WEB")
                                .to_string(),
                            url: r
                                .get("url")
                                .and_then(|v| v.as_str())
                                .unwrap_or("")
                                .to_string(),
                        })
                    })
                    .collect()
            })
            .unwrap_or_default();

        let severity = obj
            .get("severity")
            .and_then(|s| s.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|sev_item| {
                        sev_item.as_object().map(|s| OsvSeverity {
                            severity_type: s
                                .get("type")
                                .and_then(|v| v.as_str())
                                .unwrap_or("UNKNOWN")
                                .to_string(),
                            score: s
                                .get("score")
                                .and_then(|v| v.as_str())
                                .unwrap_or("0.0")
                                .to_string(),
                        })
                    })
                    .collect()
            })
            .unwrap_or_default();

        Some(OsvAdvisory {
            id,
            summary,
            details,
            affected,
            references,
            severity,
            published: obj
                .get("published")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string()),
            modified: obj
                .get("modified")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string()),
            database_specific: obj.get("database_specific").cloned(),
        })
    }

    /// Fetch full vulnerability details for a specific vulnerability ID
    async fn fetch_vulnerability_details(&self, vuln_id: &str) -> Result<Option<OsvAdvisory>> {
        let response = self
            .client
            .get(format!("{OSV_API_BASE}/vulns/{vuln_id}"))
            .send()
            .await
            .map_err(|e| AuditError::DatabaseDownload(Box::new(e)))?;

        if response.status() == 404 {
            return Ok(None);
        }

        if !response.status().is_success() {
            warn!(
                "OSV API returned error {} for vulnerability {}",
                response.status(),
                vuln_id
            );
            return Ok(None);
        }

        // Get the raw response text first to debug parsing issues
        let response_text = response
            .text()
            .await
            .map_err(|e| AuditError::DatabaseDownload(Box::new(e)))?;

        // Try to parse the JSON response normally first
        match serde_json::from_str::<OsvAdvisory>(&response_text) {
            Ok(advisory) => Ok(Some(advisory)),
            Err(e) => {
                warn!(
                    "Failed to parse OSV response for vulnerability {}: {}",
                    vuln_id, e
                );
                debug!(
                    "Raw response (first 200 chars): {}",
                    &response_text[..response_text.len().min(200)]
                );

                // Try to recover data from malformed JSON
                if let Ok(generic) = serde_json::from_str::<serde_json::Value>(&response_text) {
                    if let Some(advisory) = Self::recover_from_malformed_json(&generic, vuln_id) {
                        debug!(
                            "Successfully recovered data from malformed OSV response for {}",
                            vuln_id
                        );
                        return Ok(Some(advisory));
                    }
                }

                // If all recovery attempts fail, skip this vulnerability
                debug!(
                    "Unable to recover data from malformed OSV response for {}",
                    vuln_id
                );
                Ok(None)
            }
        }
    }

    /// Create a future for fetching vulnerability details
    async fn fetch_vulnerability_future(
        &self,
        vuln_id: String,
    ) -> (String, Result<Option<OsvAdvisory>>) {
        let result = self.fetch_vulnerability_details(&vuln_id).await;
        (vuln_id, result)
    }
}

#[async_trait]
impl VulnerabilityProvider for OsvSource {
    fn name(&self) -> &'static str {
        "osv"
    }

    async fn fetch_vulnerabilities(
        &self,
        packages: &[(String, String)],
    ) -> Result<VulnerabilityDatabase> {
        let cache_entry = self.cache_entry(packages);

        // Check cache first unless no_cache is set
        if !self.no_cache && cache_entry.path().exists() {
            if let Ok(content) = fs_err::read(cache_entry.path()) {
                if let Ok(db) = serde_json::from_slice::<VulnerabilityDatabase>(&content) {
                    debug!("Using cached OSV vulnerabilities");
                    return Ok(db);
                }
            }
        }

        // Build batch query with version constraints
        let queries: Vec<OsvQuery> = packages
            .iter()
            .map(|(name, version)| {
                debug!(
                    "Building OSV query for package: {} version: {}",
                    name, version
                );
                OsvQuery {
                    package: Some(OsvPackage {
                        name: name.clone(),
                        ecosystem: "PyPI".to_string(),
                        purl: None,
                    }),
                    version: Some(version.clone()),
                }
            })
            .collect();

        debug!("Built {} OSV queries total", queries.len());

        // Split into batches of 1000 (OSV API limit)
        const BATCH_SIZE: usize = 1000;
        let mut all_vulnerability_ids = Vec::new();
        let mut package_vuln_mapping = HashMap::new();

        for batch in queries.chunks(BATCH_SIZE) {
            let request = OsvBatchRequest {
                queries: batch.to_vec(),
            };

            debug!("Querying OSV API with {} packages", batch.len());

            let response = self
                .client
                .post(format!("{OSV_API_BASE}/querybatch"))
                .json(&request)
                .send()
                .await
                .map_err(|e| AuditError::DatabaseDownload(Box::new(e)))?;

            if !response.status().is_success() {
                warn!("OSV API returned error: {}", response.status());
                continue;
            }

            let response_text = response
                .text()
                .await
                .map_err(|e| AuditError::DatabaseDownload(Box::new(e)))?;

            debug!("OSV API response body: {}", response_text);

            let batch_response: OsvBatchResponse =
                serde_json::from_str(&response_text).map_err(|e| {
                    warn!("Failed to parse OSV response: {}", e);
                    warn!("Response text: {}", response_text);
                    AuditError::Json(e)
                })?;

            debug!(
                "Successfully parsed batch response with {} results",
                batch_response.results.len()
            );

            // Collect vulnerability IDs and map them to packages
            for (idx, result) in batch_response.results.into_iter().enumerate() {
                let package_name = if let Some(query) = batch.get(idx) {
                    query
                        .package
                        .as_ref()
                        .map(|p| p.name.clone())
                        .unwrap_or_else(|| "unknown".to_string())
                } else {
                    "unknown".to_string()
                };

                for vuln in result.vulns {
                    debug!(
                        "Found vulnerability {} for package {}",
                        vuln.id, package_name
                    );
                    all_vulnerability_ids.push(vuln.id.clone());
                    package_vuln_mapping.insert(vuln.id, package_name.clone());
                }
            }
        }

        debug!(
            "Found {} vulnerability IDs, fetching full details",
            all_vulnerability_ids.len()
        );

        // Fetch full vulnerability details concurrently
        let mut all_vulnerabilities = HashMap::new();
        let mut successful_fetches = 0;
        let mut failed_fetches = 0;

        // Create concurrent futures with rate limiting
        const MAX_CONCURRENT_REQUESTS: usize = 10; // Limit concurrent requests to avoid overwhelming OSV API
        let mut futures = FuturesUnordered::new();
        let mut vuln_iter = all_vulnerability_ids.clone().into_iter();

        // Start initial batch of requests
        for _ in 0..MAX_CONCURRENT_REQUESTS.min(all_vulnerability_ids.len()) {
            if let Some(vuln_id) = vuln_iter.next() {
                futures.push(self.fetch_vulnerability_future(vuln_id));
            }
        }

        // Process results as they complete, maintaining rate limit
        while let Some((vuln_id, result)) = futures.next().await {
            // Start a new request if there are more vulnerability IDs to process
            if let Some(next_vuln_id) = vuln_iter.next() {
                futures.push(self.fetch_vulnerability_future(next_vuln_id));
            }
            match result {
                Ok(Some(advisory)) => {
                    successful_fetches += 1;
                    match Self::convert_osv_vulnerability(advisory) {
                        Some(vuln) => {
                            let package_name = package_vuln_mapping
                                .get(&vuln_id)
                                .unwrap_or(&"unknown".to_string())
                                .clone();

                            debug!(
                                "Successfully processed vulnerability {} for package {}",
                                vuln_id, package_name
                            );
                            all_vulnerabilities
                                .entry(package_name)
                                .or_insert_with(Vec::new)
                                .push(vuln);
                        }
                        None => {
                            warn!(
                                "Failed to convert OSV advisory to vulnerability: {}",
                                vuln_id
                            );
                        }
                    }
                }
                Ok(None) => {
                    failed_fetches += 1;
                    debug!("No details available for vulnerability: {} (may be malformed or removed from OSV database)", vuln_id);
                }
                Err(e) => {
                    failed_fetches += 1;
                    // Categorize error types to provide better user feedback
                    let error_str = e.to_string();
                    if error_str.contains("timeout") || error_str.contains("connect") {
                        warn!("Network error fetching vulnerability {}: {}", vuln_id, e);
                    } else if error_str.contains("decode") || error_str.contains("json") {
                        debug!("Data parsing issue for vulnerability {} (likely upstream data quality issue): {}", vuln_id, e);
                    } else {
                        debug!("Failed to fetch vulnerability {}: {}", vuln_id, e);
                    }
                }
            }
        }

        debug!(
            "OSV vulnerability processing complete: {} successful, {} failed, {} total packages with vulnerabilities",
            successful_fetches,
            failed_fetches,
            all_vulnerabilities.len()
        );

        // Provide user-friendly summary if there were failures
        if failed_fetches > 0 {
            let success_rate =
                (successful_fetches as f64 / (successful_fetches + failed_fetches) as f64) * 100.0;
            if success_rate < 90.0 {
                warn!(
                    "OSV data quality notice: {}/{} vulnerability records successfully processed ({:.1}%). Some OSV records may contain malformed data.",
                    successful_fetches, successful_fetches + failed_fetches, success_rate
                );
            } else {
                debug!(
                    "OSV processing: {}/{} records processed successfully ({:.1}%)",
                    successful_fetches,
                    successful_fetches + failed_fetches,
                    success_rate
                );
            }
        }

        let db = VulnerabilityDatabase::from_package_map(all_vulnerabilities);

        // Cache the result
        if !self.no_cache {
            // Directory creation handled by cache entry write
            let content = serde_json::to_vec(&db)?;
            cache_entry.write(&content).await?;
        }

        Ok(db)
    }
}

/// OSV batch API request
#[derive(Debug, Clone, Serialize)]
struct OsvBatchRequest {
    queries: Vec<OsvQuery>,
}

/// OSV query structure
#[derive(Debug, Clone, Serialize)]
struct OsvQuery {
    #[serde(skip_serializing_if = "Option::is_none")]
    package: Option<OsvPackage>,
    #[serde(skip_serializing_if = "Option::is_none")]
    version: Option<String>,
}

/// OSV batch API response
#[derive(Debug, Deserialize)]
struct OsvBatchResponse {
    results: Vec<OsvResult>,
}

/// OSV query result - batch API returns lightweight data
#[derive(Debug, Deserialize)]
struct OsvResult {
    #[serde(default)]
    vulns: Vec<OsvLightweightVuln>,
}

/// Lightweight vulnerability data from batch API
#[derive(Debug, Deserialize)]
struct OsvLightweightVuln {
    id: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_osv_advisory_parsing() {
        let json = r#"{
            "id": "GHSA-test-1234",
            "summary": "Test vulnerability",
            "details": "This is a test vulnerability",
            "affected": [
                {
                    "package": {
                        "ecosystem": "PyPI",
                        "name": "test-package"
                    },
                    "ranges": [
                        {
                            "type": "ECOSYSTEM",
                            "events": [
                                {"introduced": "1.0.0"},
                                {"fixed": "1.2.0"}
                            ]
                        }
                    ]
                }
            ],
            "references": [],
            "severity": [],
            "published": "2023-01-01T00:00:00Z"
        }"#;

        let advisory: OsvAdvisory = serde_json::from_str(json).unwrap();
        assert_eq!(advisory.id, "GHSA-test-1234");
        assert_eq!(advisory.summary, Some("Test vulnerability".to_string()));
        assert_eq!(advisory.affected.len(), 1);
    }
}
