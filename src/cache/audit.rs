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

use super::storage::{Cache, CacheBucket, CacheEntry, Freshness};
use crate::types::{ResolutionCacheEntry, ResolverType};
use anyhow::Result;
use chrono::{DateTime, Utc};
use rustc_hash::FxHasher;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::hash::Hasher;
use std::time::Duration;

#[derive(Debug, Serialize, Deserialize)]
pub struct DatabaseMetadata {
    pub last_updated: DateTime<Utc>,
    pub version: String,
    pub advisory_count: usize,
}

pub struct AuditCache {
    cache: Cache,
}

impl AuditCache {
    pub fn new(cache_dir: std::path::PathBuf) -> Self {
        Self {
            cache: Cache::new(cache_dir),
        }
    }

    pub fn database_entry(&self, source: &str) -> CacheEntry {
        self.cache.entry(
            CacheBucket::VulnerabilityDatabase,
            &format!("{source}-database"),
        )
    }

    pub fn metadata_entry(&self) -> CacheEntry {
        self.cache.entry(CacheBucket::VulnerabilityDatabase, "meta")
    }

    pub fn index_entry(&self) -> CacheEntry {
        self.cache
            .entry(CacheBucket::VulnerabilityDatabase, "index")
    }

    pub fn should_refresh(&self, ttl_hours: u64) -> Result<bool> {
        let meta_entry = self.metadata_entry();
        let ttl = Duration::from_secs(ttl_hours * 3600);

        match meta_entry.freshness(ttl) {
            Ok(Freshness::Fresh) => Ok(false),
            _ => Ok(true), // Stale or doesn't exist
        }
    }

    pub async fn read_metadata(&self) -> Result<Option<DatabaseMetadata>> {
        let entry = self.metadata_entry();
        let content = match entry.read().await {
            Ok(data) => data,
            Err(_) => return Ok(None),
        };

        let metadata: DatabaseMetadata = serde_json::from_slice(&content)?;
        Ok(Some(metadata))
    }

    pub async fn write_metadata(&self, metadata: &DatabaseMetadata) -> Result<()> {
        let entry = self.metadata_entry();
        let content = serde_json::to_vec_pretty(metadata)?;
        entry.write(&content).await?;
        Ok(())
    }

    // Resolution Cache Methods

    /// Generate cache key for resolution caching
    pub fn generate_resolution_cache_key(
        &self,
        requirements_content: &str,
        resolver_type: &ResolverType,
        resolver_version: &str,
        python_version: &str,
        platform: &str,
        environment_markers: &HashMap<String, String>,
    ) -> String {
        let mut hasher = FxHasher::default();
        hasher.write(requirements_content.as_bytes());
        hasher.write(resolver_type.to_string().as_bytes());
        hasher.write(resolver_version.as_bytes());
        hasher.write(python_version.as_bytes());
        hasher.write(platform.as_bytes());

        let mut marker_items: Vec<_> = environment_markers.iter().collect();
        marker_items.sort_by_key(|(k, _)| *k);
        for (key, value) in marker_items {
            hasher.write(key.as_bytes());
            hasher.write(value.as_bytes());
        }

        let hash = hasher.finish();
        let content_hash = format!("{hash:x}");

        format!(
            "{}-py{}-{}-{}",
            resolver_type, python_version, platform, &content_hash
        )
    }

    pub fn resolution_entry(&self, cache_key: &str) -> CacheEntry {
        self.cache.entry(
            CacheBucket::DependencyResolution,
            &format!("{cache_key}.resolution"),
        )
    }

    pub fn should_refresh_resolution(&self, cache_key: &str, ttl_hours: u64) -> Result<bool> {
        let entry = self.resolution_entry(cache_key);
        let ttl = Duration::from_secs(ttl_hours * 3600);

        match entry.freshness(ttl) {
            Ok(Freshness::Fresh) => Ok(false),
            _ => Ok(true), // Stale or doesn't exist
        }
    }

    pub async fn read_resolution_cache(
        &self,
        cache_key: &str,
    ) -> Result<Option<ResolutionCacheEntry>> {
        let entry = self.resolution_entry(cache_key);
        let content = match entry.read().await {
            Ok(data) => data,
            Err(_) => return Ok(None),
        };

        let cache_entry: ResolutionCacheEntry = serde_json::from_slice(&content)?;
        Ok(Some(cache_entry))
    }

    pub async fn write_resolution_cache(
        &self,
        cache_key: &str,
        cache_entry: &ResolutionCacheEntry,
    ) -> Result<()> {
        let entry = self.resolution_entry(cache_key);
        let content = serde_json::to_vec_pretty(cache_entry)?;
        entry.write(&content).await?;
        Ok(())
    }

    pub async fn clear_resolution_cache_entry(&self, cache_key: &str) -> Result<()> {
        let entry = self.resolution_entry(cache_key);
        let cache_file = entry.path();

        if cache_file.exists() {
            if let Err(e) = tokio::fs::remove_file(&cache_file).await {
                tracing::warn!("Failed to remove cache entry {:?}: {}", cache_file, e);
                return Err(anyhow::anyhow!("Failed to remove cache entry: {}", e));
            } else {
                tracing::debug!("Cleared resolution cache entry: {:?}", cache_file);
            }
        }

        Ok(())
    }

    pub async fn clear_resolution_cache(&self, resolver_type: Option<ResolverType>) -> Result<()> {
        use fs_err as fs;

        let entry = self.cache.entry(CacheBucket::DependencyResolution, "");
        let cache_dir = entry
            .path()
            .parent()
            .ok_or_else(|| anyhow::anyhow!("Invalid cache directory"))?;

        if !cache_dir.exists() {
            return Ok(()); // Nothing to clear
        }

        let entries = fs::read_dir(cache_dir)?;
        for entry in entries {
            let entry = entry?;
            let path = entry.path();

            if let Some(file_name) = path.file_name().and_then(|n| n.to_str()) {
                if file_name.ends_with(".resolution.cache") {
                    if let Some(ref rt) = resolver_type {
                        if !file_name.starts_with(&rt.to_string()) {
                            continue;
                        }
                    }

                    if let Err(e) = fs::remove_file(&path) {
                        tracing::warn!("Failed to remove cache file {:?}: {}", path, e);
                    } else {
                        tracing::debug!("Cleared resolution cache file: {:?}", path);
                    }
                }
            }
        }

        Ok(())
    }

    pub async fn get_resolution_cache_stats(&self) -> Result<ResolutionCacheStats> {
        use fs_err as fs;

        let entry = self.cache.entry(CacheBucket::DependencyResolution, "");
        let cache_dir = entry
            .path()
            .parent()
            .ok_or_else(|| anyhow::anyhow!("Invalid cache directory"))?;

        let mut stats = ResolutionCacheStats::default();

        if !cache_dir.exists() {
            return Ok(stats);
        }

        let entries = fs::read_dir(cache_dir)?;
        for entry in entries.flatten() {
            let path = entry.path();
            if let Some(file_name) = path.file_name().and_then(|n| n.to_str()) {
                if file_name.ends_with(".resolution.cache") {
                    stats.total_entries += 1;
                    if let Ok(metadata) = fs::metadata(&path) {
                        stats.total_size_bytes += metadata.len();

                        // Count by resolver type
                        if file_name.starts_with("uv-") {
                            stats.uv_entries += 1;
                        } else if file_name.starts_with("pip-tools-") {
                            stats.pip_tools_entries += 1;
                        }
                    }
                }
            }
        }

        Ok(stats)
    }
}

/// Resolution cache statistics
#[derive(Debug, Default)]
pub struct ResolutionCacheStats {
    pub total_entries: usize,
    pub total_size_bytes: u64,
    pub uv_entries: usize,
    pub pip_tools_entries: usize,
}

impl AuditCache {
    pub fn feedback_entry(&self) -> CacheEntry {
        self.cache
            .entry(CacheBucket::UserMessages, "last_feedback_shown")
    }

    pub async fn should_show_feedback(&self) -> bool {
        let entry = self.feedback_entry();
        let one_day = Duration::from_secs(24 * 3600);

        match entry.freshness(one_day) {
            Ok(Freshness::Fresh) => false, // Shown recently, don't show
            _ => true,                     // Stale or doesn't exist, show feedback
        }
    }

    pub async fn record_feedback_shown(&self) -> Result<()> {
        let entry = self.feedback_entry();
        let now = Utc::now();
        let timestamp = serde_json::to_vec(&now)?;
        entry.write(&timestamp).await?;
        Ok(())
    }

    pub fn update_check_entry(&self) -> CacheEntry {
        self.cache
            .entry(CacheBucket::UserMessages, "last_update_check")
    }

    pub async fn should_check_for_updates(&self) -> bool {
        let entry = self.update_check_entry();
        let one_day = Duration::from_secs(24 * 3600);

        match entry.freshness(one_day) {
            Ok(Freshness::Fresh) => false, // Checked recently, don't check
            _ => true,                     // Stale or doesn't exist, check for updates
        }
    }

    pub async fn record_update_check(&self) -> Result<()> {
        let entry = self.update_check_entry();
        let now = Utc::now();
        let timestamp = serde_json::to_vec(&now)?;
        entry.write(&timestamp).await?;
        Ok(())
    }
}

impl Clone for AuditCache {
    fn clone(&self) -> Self {
        Self {
            cache: self.cache.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{ResolvedDependency, ResolverType};
    use std::collections::HashMap;
    use tempfile::tempdir;

    #[tokio::test]
    async fn test_resolution_cache_key_generation() {
        let temp_dir = tempdir().unwrap();
        let cache = AuditCache::new(temp_dir.path().to_path_buf());

        let requirements_content = "requests>=2.25.0\nclick==8.0.0";
        let resolver_type = ResolverType::Uv;
        let resolver_version = "0.4.29";
        let python_version = "3.12";
        let platform = "linux-x86_64";
        let environment_markers = HashMap::new();

        let key1 = cache.generate_resolution_cache_key(
            requirements_content,
            &resolver_type,
            resolver_version,
            python_version,
            platform,
            &environment_markers,
        );

        let key2 = cache.generate_resolution_cache_key(
            requirements_content,
            &resolver_type,
            resolver_version,
            python_version,
            platform,
            &environment_markers,
        );

        assert_eq!(key1, key2);
        assert!(key1.starts_with("uv-py3.12-linux-x86_64-"));

        let key3 = cache.generate_resolution_cache_key(
            "different-content",
            &resolver_type,
            resolver_version,
            python_version,
            platform,
            &environment_markers,
        );
        assert_ne!(key1, key3);
    }

    #[tokio::test]
    async fn test_resolution_cache_write_read() {
        let temp_dir = tempdir().unwrap();
        let cache = AuditCache::new(temp_dir.path().to_path_buf());

        let cache_key = "test-cache-key";
        let cache_entry = ResolutionCacheEntry {
            output: "requests==2.31.0".to_string(),
            resolver_type: ResolverType::Uv,
            resolver_version: "0.4.29".to_string(),
            python_version: "3.12".to_string(),
            dependencies: vec![ResolvedDependency {
                name: "requests".to_string(),
                version: "2.31.0".to_string(),
                is_direct: true,
                source_file: std::path::PathBuf::from("requirements.txt"),
                extras: vec![],
                markers: None,
            }],
        };

        cache
            .write_resolution_cache(cache_key, &cache_entry)
            .await
            .unwrap();

        let read_entry = cache
            .read_resolution_cache(cache_key)
            .await
            .unwrap()
            .unwrap();

        assert_eq!(read_entry.output, cache_entry.output);
        assert_eq!(
            read_entry.resolver_type.to_string(),
            cache_entry.resolver_type.to_string()
        );
        assert_eq!(read_entry.resolver_version, cache_entry.resolver_version);
        assert_eq!(read_entry.python_version, cache_entry.python_version);
        assert_eq!(
            read_entry.dependencies.len(),
            cache_entry.dependencies.len()
        );
        assert_eq!(read_entry.dependencies[0].name, "requests");
    }

    #[tokio::test]
    async fn test_resolution_cache_freshness() {
        let temp_dir = tempdir().unwrap();
        let cache = AuditCache::new(temp_dir.path().to_path_buf());

        let cache_key = "test-freshness";

        assert!(cache.should_refresh_resolution(cache_key, 24).unwrap());

        let cache_entry = ResolutionCacheEntry {
            output: "".to_string(),
            resolver_type: ResolverType::Uv,
            resolver_version: "0.4.29".to_string(),
            python_version: "3.12".to_string(),
            dependencies: vec![],
        };

        cache
            .write_resolution_cache(cache_key, &cache_entry)
            .await
            .unwrap();

        assert!(!cache.should_refresh_resolution(cache_key, 24).unwrap());

        assert!(cache.should_refresh_resolution(cache_key, 0).unwrap());
    }

    #[tokio::test]
    async fn test_resolution_cache_clear() {
        let temp_dir = tempdir().unwrap();
        let cache = AuditCache::new(temp_dir.path().to_path_buf());

        let uv_entry = ResolutionCacheEntry {
            output: "uv-test-output".to_string(),
            resolver_type: ResolverType::Uv,
            resolver_version: "0.4.29".to_string(),
            python_version: "3.12".to_string(),
            dependencies: vec![],
        };

        let pip_tools_entry = ResolutionCacheEntry {
            output: "pip-tools-test-output".to_string(),
            resolver_type: ResolverType::PipTools,
            resolver_version: "7.4.1".to_string(),
            python_version: "3.12".to_string(),
            dependencies: vec![],
        };

        cache
            .write_resolution_cache("uv-test", &uv_entry)
            .await
            .unwrap();
        cache
            .write_resolution_cache("pip-tools-test", &pip_tools_entry)
            .await
            .unwrap();

        assert!(cache
            .read_resolution_cache("uv-test")
            .await
            .unwrap()
            .is_some());
        assert!(cache
            .read_resolution_cache("pip-tools-test")
            .await
            .unwrap()
            .is_some());

        cache
            .clear_resolution_cache(Some(ResolverType::Uv))
            .await
            .unwrap();

        assert!(cache
            .read_resolution_cache("uv-test")
            .await
            .unwrap()
            .is_none());
        assert!(cache
            .read_resolution_cache("pip-tools-test")
            .await
            .unwrap()
            .is_some());

        cache.clear_resolution_cache(None).await.unwrap();

        assert!(cache
            .read_resolution_cache("uv-test")
            .await
            .unwrap()
            .is_none());
        assert!(cache
            .read_resolution_cache("pip-tools-test")
            .await
            .unwrap()
            .is_none());
    }

    #[tokio::test]
    async fn test_resolution_cache_stats() {
        let temp_dir = tempdir().unwrap();
        let cache = AuditCache::new(temp_dir.path().to_path_buf());

        let stats = cache.get_resolution_cache_stats().await.unwrap();
        assert_eq!(stats.total_entries, 0);
        assert_eq!(stats.total_size_bytes, 0);
        assert_eq!(stats.uv_entries, 0);
        assert_eq!(stats.pip_tools_entries, 0);

        let uv_entry = ResolutionCacheEntry {
            output: "test-uv-output".to_string(),
            resolver_type: ResolverType::Uv,
            resolver_version: "0.4.29".to_string(),
            python_version: "3.12".to_string(),
            dependencies: vec![],
        };

        cache
            .write_resolution_cache("uv-py3.12-linux-x86_64-abc123", &uv_entry)
            .await
            .unwrap();

        let stats = cache.get_resolution_cache_stats().await.unwrap();
        assert_eq!(stats.total_entries, 1);
        assert!(stats.total_size_bytes > 0);
        assert_eq!(stats.uv_entries, 1);
        assert_eq!(stats.pip_tools_entries, 0);
    }
}
