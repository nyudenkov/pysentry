// SPDX-License-Identifier: MIT

//! Cache implementation

use anyhow::Result;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

/// Cache bucket types
#[derive(Debug, Clone)]
pub enum CacheBucket {
    VulnerabilityDatabase,
    DependencyResolution,
    UserMessages,
    /// PEP 792 project status cache
    ProjectStatus,
}

impl CacheBucket {
    fn subdir(&self) -> &'static str {
        match self {
            CacheBucket::VulnerabilityDatabase => "vulnerability-db",
            CacheBucket::DependencyResolution => "dependency-resolution",
            CacheBucket::UserMessages => "user-messages",
            CacheBucket::ProjectStatus => "project-status",
        }
    }
}

/// Cache freshness check
pub enum Freshness {
    Fresh,
    Stale,
}

/// Cache entry
pub struct CacheEntry {
    path: PathBuf,
}

impl CacheEntry {
    pub fn path(&self) -> &Path {
        &self.path
    }

    pub async fn read(&self) -> Result<Vec<u8>> {
        Ok(tokio::fs::read(&self.path).await?)
    }

    pub async fn write(&self, data: &[u8]) -> Result<()> {
        if let Some(parent) = self.path.parent() {
            tokio::fs::create_dir_all(parent).await?;
        }
        Ok(tokio::fs::write(&self.path, data).await?)
    }

    pub fn freshness(&self, ttl: Duration) -> Result<Freshness> {
        let metadata = std::fs::metadata(&self.path)?;
        let modified = metadata.modified()?;
        let elapsed = SystemTime::now().duration_since(modified)?;

        if elapsed > ttl {
            Ok(Freshness::Stale)
        } else {
            Ok(Freshness::Fresh)
        }
    }
}

/// Cache implementation
pub struct Cache {
    root: PathBuf,
}

impl Cache {
    pub fn new(root: PathBuf) -> Self {
        Self { root }
    }

    pub fn entry(&self, bucket: CacheBucket, key: &str) -> CacheEntry {
        let path = self.root.join(bucket.subdir()).join(format!("{key}.cache"));

        CacheEntry { path }
    }
}

impl Clone for Cache {
    fn clone(&self) -> Self {
        Self {
            root: self.root.clone(),
        }
    }
}
