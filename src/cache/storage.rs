// SPDX-License-Identifier: MIT

//! Cache implementation

use anyhow::{Context, Result};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};
use tempfile::NamedTempFile;

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

        let target_path = self.path.clone();
        let data_owned = data.to_vec();

        tokio::task::spawn_blocking(move || Self::write_atomic_sync(&target_path, &data_owned))
            .await
            .context("Task join error during atomic write")?
    }

    fn write_atomic_sync(target_path: &Path, data: &[u8]) -> Result<()> {
        let parent_directory = target_path
            .parent()
            .ok_or_else(|| anyhow::anyhow!("Cache path has no parent directory"))?;

        let mut temp_file = NamedTempFile::new_in(parent_directory)
            .context("Failed to create temporary file for atomic write")?;

        temp_file
            .write_all(data)
            .context("Failed to write data to temporary file")?;

        temp_file
            .as_file()
            .sync_all()
            .context("Failed to sync temporary file to disk")?;

        temp_file.persist(target_path).map_err(|error| {
            tracing::debug!("Atomic write failed for {:?}: {}", target_path, error);
            error
        })?;

        Ok(())
    }

    pub async fn delete(&self) -> Result<()> {
        match tokio::fs::remove_file(&self.path).await {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error.into()),
        }
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use tokio::sync::Barrier;

    #[tokio::test]
    async fn test_atomic_write_basic() {
        let temp_dir = tempfile::tempdir().unwrap();
        let cache = Cache::new(temp_dir.path().to_path_buf());
        let entry = cache.entry(CacheBucket::VulnerabilityDatabase, "test-basic");

        let data = b"test data for atomic write";
        entry.write(data).await.unwrap();

        let read_data = entry.read().await.unwrap();
        assert_eq!(read_data, data);
    }

    #[tokio::test]
    async fn test_concurrent_writes_no_corruption() {
        let temp_dir = tempfile::tempdir().unwrap();
        let cache = Arc::new(Cache::new(temp_dir.path().to_path_buf()));
        let entry_path = cache
            .entry(CacheBucket::VulnerabilityDatabase, "concurrent-test")
            .path()
            .to_path_buf();

        let num_writers = 10;
        let iterations_per_writer = 50;
        let barrier = Arc::new(Barrier::new(num_writers));

        let mut handles = Vec::new();

        for writer_id in 0..num_writers {
            let cache_clone = Arc::clone(&cache);
            let barrier_clone = Arc::clone(&barrier);

            let handle = tokio::spawn(async move {
                barrier_clone.wait().await;

                for iteration in 0..iterations_per_writer {
                    let data = format!("writer-{}-iteration-{}", writer_id, iteration);
                    let entry =
                        cache_clone.entry(CacheBucket::VulnerabilityDatabase, "concurrent-test");
                    entry.write(data.as_bytes()).await.unwrap();
                }
            });

            handles.push(handle);
        }

        for handle in handles {
            handle.await.unwrap();
        }

        let final_entry = cache.entry(CacheBucket::VulnerabilityDatabase, "concurrent-test");
        let final_data = final_entry.read().await.unwrap();
        let final_string = String::from_utf8(final_data).unwrap();

        assert!(
            final_string.starts_with("writer-"),
            "Final data should be from one of the writers: {}",
            final_string
        );
        assert!(
            final_string.contains("-iteration-"),
            "Final data should contain iteration marker: {}",
            final_string
        );

        assert!(entry_path.exists(), "Cache file should exist after writes");
    }

    #[tokio::test]
    async fn test_delete_nonexistent_file_succeeds() {
        let temp_dir = tempfile::tempdir().unwrap();
        let cache = Cache::new(temp_dir.path().to_path_buf());
        let entry = cache.entry(CacheBucket::VulnerabilityDatabase, "nonexistent");

        let result = entry.delete().await;
        assert!(result.is_ok(), "Deleting nonexistent file should succeed");
    }

    #[tokio::test]
    async fn test_delete_existing_file() {
        let temp_dir = tempfile::tempdir().unwrap();
        let cache = Cache::new(temp_dir.path().to_path_buf());
        let entry = cache.entry(CacheBucket::VulnerabilityDatabase, "to-delete");

        entry.write(b"data to delete").await.unwrap();
        assert!(entry.path().exists());

        entry.delete().await.unwrap();
        assert!(!entry.path().exists());
    }

    #[tokio::test]
    async fn test_concurrent_deletes_no_error() {
        let temp_dir = tempfile::tempdir().unwrap();
        let cache = Arc::new(Cache::new(temp_dir.path().to_path_buf()));

        {
            let entry = cache.entry(CacheBucket::VulnerabilityDatabase, "concurrent-delete");
            entry.write(b"data").await.unwrap();
        }

        let num_deleters = 10;
        let barrier = Arc::new(Barrier::new(num_deleters));

        let mut handles = Vec::new();

        for _ in 0..num_deleters {
            let cache_clone = Arc::clone(&cache);
            let barrier_clone = Arc::clone(&barrier);

            let handle = tokio::spawn(async move {
                barrier_clone.wait().await;

                let entry =
                    cache_clone.entry(CacheBucket::VulnerabilityDatabase, "concurrent-delete");
                entry.delete().await
            });

            handles.push(handle);
        }

        for handle in handles {
            let result = handle.await.unwrap();
            assert!(
                result.is_ok(),
                "Concurrent delete should not error: {:?}",
                result.err()
            );
        }

        let entry = cache.entry(CacheBucket::VulnerabilityDatabase, "concurrent-delete");
        assert!(!entry.path().exists());
    }

    #[tokio::test]
    async fn test_write_during_read_no_corruption() {
        let temp_dir = tempfile::tempdir().unwrap();
        let cache = Arc::new(Cache::new(temp_dir.path().to_path_buf()));

        {
            let entry = cache.entry(CacheBucket::VulnerabilityDatabase, "read-write");
            entry.write(b"initial-data").await.unwrap();
        }

        let num_readers = 5;
        let num_writers = 5;
        let iterations = 20;
        let barrier = Arc::new(Barrier::new(num_readers + num_writers));

        let mut handles = Vec::new();

        for _ in 0..num_readers {
            let cache_clone = Arc::clone(&cache);
            let barrier_clone = Arc::clone(&barrier);

            let handle = tokio::spawn(async move {
                barrier_clone.wait().await;

                for _ in 0..iterations {
                    let entry = cache_clone.entry(CacheBucket::VulnerabilityDatabase, "read-write");
                    if let Ok(data) = entry.read().await {
                        let string = String::from_utf8_lossy(&data);
                        assert!(
                            string.contains("data") || string.contains("writer"),
                            "Read data should be valid: {}",
                            string
                        );
                    }
                }
            });

            handles.push(handle);
        }

        for writer_id in 0..num_writers {
            let cache_clone = Arc::clone(&cache);
            let barrier_clone = Arc::clone(&barrier);

            let handle = tokio::spawn(async move {
                barrier_clone.wait().await;

                for iteration in 0..iterations {
                    let entry = cache_clone.entry(CacheBucket::VulnerabilityDatabase, "read-write");
                    let data = format!("writer-{}-data-{}", writer_id, iteration);
                    entry.write(data.as_bytes()).await.unwrap();
                }
            });

            handles.push(handle);
        }

        for handle in handles {
            handle.await.unwrap();
        }
    }
}
