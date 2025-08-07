use super::storage::{Cache, CacheBucket, CacheEntry, Freshness};
use anyhow::Result;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
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
}

impl Clone for AuditCache {
    fn clone(&self) -> Self {
        Self {
            cache: self.cache.clone(),
        }
    }
}
