// SPDX-License-Identifier: MIT

//! Simple Index API client for PEP 792 project status checks
//!
//! This module provides a client for fetching package metadata from
//! PyPI's Simple Index API to check PEP 792 project status markers.

use crate::cache::AuditCache;
use crate::config::HttpConfig;
use crate::dependency::scanner::ScannedDependency;
use crate::providers::retry::{is_http_error_retryable, retry_with_backoff};
use crate::{AuditError, Result};

use super::types::{
    MaintenanceCheckConfig, MaintenanceIssue, MaintenanceIssueType, PackageIndex, ProjectState,
};

use futures::future::join_all;
use reqwest::Client;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Semaphore;
use tracing::{debug, info, warn};

/// Base URL for PyPI Simple Index API
const PYPI_SIMPLE_BASE_URL: &str = "https://pypi.org/simple";

/// Content type for JSON response from Simple Index API (PEP 691)
const SIMPLE_INDEX_ACCEPT_HEADER: &str = "application/vnd.pypi.simple.v1+json";

/// Maximum concurrent requests to PyPI
const MAX_CONCURRENT_REQUESTS: usize = 15;

/// Default cache TTL for project status (1 hour)
const DEFAULT_STATUS_CACHE_TTL_HOURS: u64 = 1;

/// Client for fetching package status from PyPI Simple Index API
pub struct SimpleIndexClient {
    client: Client,
    http_config: HttpConfig,
    cache: Option<AuditCache>,
    cache_ttl_hours: u64,
    semaphore: Arc<Semaphore>,
}

impl SimpleIndexClient {
    /// Create a new Simple Index client
    pub fn new(http_config: HttpConfig, cache: Option<AuditCache>) -> Self {
        Self::new_with_cache_ttl(http_config, cache, DEFAULT_STATUS_CACHE_TTL_HOURS)
    }

    /// Create a new Simple Index client with custom cache TTL
    pub fn new_with_cache_ttl(
        http_config: HttpConfig,
        cache: Option<AuditCache>,
        cache_ttl_hours: u64,
    ) -> Self {
        let client = Client::builder()
            .user_agent(format!("pysentry/{}", env!("CARGO_PKG_VERSION")))
            .timeout(Duration::from_secs(http_config.timeout))
            .connect_timeout(Duration::from_secs(http_config.connect_timeout))
            .build()
            .unwrap_or_else(|_| Client::new());

        Self {
            client,
            http_config,
            cache,
            cache_ttl_hours,
            semaphore: Arc::new(Semaphore::new(MAX_CONCURRENT_REQUESTS)),
        }
    }

    /// Check maintenance status for a list of dependencies
    ///
    /// Returns a list of maintenance issues found for packages that have
    /// non-active status markers (archived, deprecated, or quarantined).
    pub async fn check_maintenance_status(
        &self,
        dependencies: &[ScannedDependency],
        config: &MaintenanceCheckConfig,
    ) -> Result<Vec<MaintenanceIssue>> {
        info!(
            "Checking PEP 792 project status for {} packages",
            dependencies.len()
        );

        // Filter dependencies if check_direct_only is set
        let deps_to_check: Vec<_> = if config.check_direct_only {
            dependencies.iter().filter(|d| d.is_direct).collect()
        } else {
            dependencies.iter().collect()
        };

        if deps_to_check.is_empty() {
            debug!("No dependencies to check for maintenance status");
            return Ok(Vec::new());
        }

        // Create futures for all package status checks
        let futures: Vec<_> = deps_to_check
            .iter()
            .map(|dep| self.check_package_status(dep))
            .collect();

        // Execute all checks concurrently
        let results = join_all(futures).await;

        // Collect all maintenance issues
        let mut issues = Vec::new();
        for result in results {
            match result {
                Ok(Some(issue)) => issues.push(issue),
                Ok(None) => {} // No issue for this package
                Err(e) => {
                    // Log the error but continue checking other packages
                    warn!("Failed to check package status: {}", e);
                }
            }
        }

        info!(
            "Found {} maintenance issues across {} packages",
            issues.len(),
            deps_to_check.len()
        );

        Ok(issues)
    }

    /// Check the status of a single package
    async fn check_package_status(
        &self,
        dependency: &ScannedDependency,
    ) -> Result<Option<MaintenanceIssue>> {
        let package_name = dependency.name.to_string();

        // Check cache first
        if let Some(ref cache) = self.cache {
            if let Some(status) = self.get_cached_status(&package_name, cache).await? {
                return Ok(self.create_issue_if_needed(dependency, &status));
            }
        }

        // Fetch from API with rate limiting
        let _permit = self
            .semaphore
            .acquire()
            .await
            .map_err(|e| AuditError::Other {
                message: format!("Semaphore acquire failed: {}", e),
            })?;

        let index = self.fetch_package_index(&package_name).await?;
        let status = index.effective_status();

        // Cache the result
        if let Some(ref cache) = self.cache {
            self.cache_status(&package_name, &status, cache).await?;
        }

        Ok(self.create_issue_if_needed(dependency, &status))
    }

    /// Fetch package index from PyPI Simple Index API
    async fn fetch_package_index(&self, package_name: &str) -> Result<PackageIndex> {
        let url = format!("{}/{}/", PYPI_SIMPLE_BASE_URL, package_name);

        debug!("Fetching package index from: {}", url);

        retry_with_backoff(
            self.http_config.max_retries,
            self.http_config.retry_initial_backoff,
            self.http_config.retry_max_backoff,
            is_http_error_retryable,
            || self.fetch_package_index_once(&url),
            &format!("fetch package status for {}", package_name),
        )
        .await
    }

    /// Single attempt to fetch package index
    async fn fetch_package_index_once(&self, url: &str) -> Result<PackageIndex> {
        let response = self
            .client
            .get(url)
            .header("Accept", SIMPLE_INDEX_ACCEPT_HEADER)
            .send()
            .await?;

        if !response.status().is_success() {
            if response.status().as_u16() == 404 {
                // Package not found - return a default "active" status
                // This handles cases where package was removed or never existed
                debug!("Package not found at {}, treating as active", url);
                return Ok(PackageIndex {
                    meta: super::types::IndexMeta {
                        api_version: "1.0".to_string(),
                    },
                    name: String::new(),
                    project_status: None,
                    versions: Vec::new(),
                });
            }
            return Err(AuditError::Http(response.error_for_status().unwrap_err()));
        }

        let index: PackageIndex = response.json().await?;
        Ok(index)
    }

    /// Get cached status if available and fresh
    async fn get_cached_status(
        &self,
        package_name: &str,
        cache: &AuditCache,
    ) -> Result<Option<super::types::ProjectStatus>> {
        // Check if cache entry is fresh
        if cache.should_refresh_project_status(package_name, self.cache_ttl_hours) {
            return Ok(None); // Cache miss or stale
        }

        let entry = cache.project_status_entry(package_name);

        // Read cached data
        if let Ok(data) = entry.read().await {
            if let Ok(status) = serde_json::from_slice::<super::types::ProjectStatus>(&data) {
                debug!("Using cached status for {}", package_name);
                return Ok(Some(status));
            }
        }
        // Cache miss or parse error, will fetch from API

        Ok(None)
    }

    /// Cache the project status
    async fn cache_status(
        &self,
        package_name: &str,
        status: &super::types::ProjectStatus,
        cache: &AuditCache,
    ) -> Result<()> {
        let entry = cache.project_status_entry(package_name);

        let data = serde_json::to_vec(status)?;
        entry.write(&data).await?;

        debug!("Cached status for {}", package_name);
        Ok(())
    }

    /// Create a maintenance issue if the status warrants it
    ///
    /// Always reports non-active statuses for visibility. The `should_fail` check
    /// in `MaintenanceSummary` determines exit code, not whether to show the issue.
    fn create_issue_if_needed(
        &self,
        dependency: &ScannedDependency,
        status: &super::types::ProjectStatus,
    ) -> Option<MaintenanceIssue> {
        let issue_type = match status.status {
            ProjectState::Active => return None,
            ProjectState::Archived => MaintenanceIssueType::Archived,
            ProjectState::Deprecated => MaintenanceIssueType::Deprecated,
            ProjectState::Quarantined => MaintenanceIssueType::Quarantined,
        };

        Some(MaintenanceIssue::new(
            dependency.name.clone(),
            dependency.version.clone(),
            issue_type,
            status.reason.clone(),
            dependency.is_direct,
            dependency.source_file.clone(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dependency::scanner::DependencySource;
    use crate::maintenance::types::ProjectStatus;
    use crate::types::PackageName;
    use pep440_rs::Version;
    use std::str::FromStr;

    fn create_test_dependency(name: &str, version: &str, is_direct: bool) -> ScannedDependency {
        ScannedDependency {
            name: PackageName::from_str(name).unwrap(),
            version: Version::from_str(version).unwrap(),
            is_direct,
            source: DependencySource::Registry,
            path: None,
            source_file: None,
        }
    }

    #[test]
    fn test_client_creation() {
        let config = HttpConfig::default();
        let client = SimpleIndexClient::new(config, None);
        assert_eq!(client.cache_ttl_hours, DEFAULT_STATUS_CACHE_TTL_HOURS);
    }

    #[test]
    fn test_client_with_custom_ttl() {
        let config = HttpConfig::default();
        let client = SimpleIndexClient::new_with_cache_ttl(config, None, 2);
        assert_eq!(client.cache_ttl_hours, 2);
    }

    #[test]
    fn test_create_issue_for_archived() {
        let config = HttpConfig::default();
        let client = SimpleIndexClient::new(config, None);

        let dep = create_test_dependency("old-package", "1.0.0", true);
        let status = ProjectStatus {
            status: ProjectState::Archived,
            reason: Some("No longer maintained".to_string()),
        };

        let issue = client.create_issue_if_needed(&dep, &status);

        assert!(issue.is_some());
        let issue = issue.unwrap();
        assert_eq!(issue.issue_type, MaintenanceIssueType::Archived);
        assert_eq!(issue.reason, Some("No longer maintained".to_string()));
        assert!(issue.is_direct);
    }

    #[test]
    fn test_create_issue_for_quarantined() {
        let config = HttpConfig::default();
        let client = SimpleIndexClient::new(config, None);

        let dep = create_test_dependency("malicious-pkg", "1.0.0", false);
        let status = ProjectStatus {
            status: ProjectState::Quarantined,
            reason: Some("Malware detected".to_string()),
        };

        let issue = client.create_issue_if_needed(&dep, &status);

        assert!(issue.is_some());
        let issue = issue.unwrap();
        assert_eq!(issue.issue_type, MaintenanceIssueType::Quarantined);
        assert!(!issue.is_direct);
    }

    #[test]
    fn test_no_issue_for_active() {
        let config = HttpConfig::default();
        let client = SimpleIndexClient::new(config, None);

        let dep = create_test_dependency("active-package", "1.0.0", true);
        let status = ProjectStatus {
            status: ProjectState::Active,
            reason: None,
        };

        let issue = client.create_issue_if_needed(&dep, &status);

        assert!(issue.is_none());
    }
}
