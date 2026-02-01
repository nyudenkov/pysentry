// SPDX-License-Identifier: MIT

//! Remote notification client
//!
//! This module provides a client for fetching and managing remote notifications.
//! Notifications are cached locally with a 6-hour TTL.

use super::types::{NotificationsFile, RemoteNotification, ShownNotificationsState};
use crate::cache::AuditCache;
use reqwest::Client;
use std::time::Duration;
use tracing::debug;

/// URL for fetching notifications
const NOTIFICATIONS_URL: &str = "https://raw.githubusercontent.com/pysentry/notifications.pysentry.com/refs/heads/main/notifications.json";

/// HTTP request timeout for notifications
const NOTIFICATION_TIMEOUT_SECS: u64 = 5;

/// Cache TTL for notifications in hours
const NOTIFICATIONS_CACHE_TTL_HOURS: u64 = 6;

/// Client for fetching remote notifications
pub struct NotificationClient {
    client: Client,
    cache: AuditCache,
    url: String,
}

impl NotificationClient {
    /// Create a new notification client with the given cache
    pub fn new(cache: AuditCache) -> Self {
        Self::with_url(cache, NOTIFICATIONS_URL.to_string())
    }

    /// Create a new notification client with a custom URL
    pub fn with_url(cache: AuditCache, url: String) -> Self {
        let client = Client::builder()
            .user_agent(format!("pysentry/{}", env!("CARGO_PKG_VERSION")))
            .timeout(Duration::from_secs(NOTIFICATION_TIMEOUT_SECS))
            .connect_timeout(Duration::from_secs(NOTIFICATION_TIMEOUT_SECS))
            .build()
            .unwrap_or_else(|_| Client::new());

        Self { client, cache, url }
    }

    /// Check if notifications URL is configured
    pub fn is_configured(&self) -> bool {
        !self.url.is_empty()
    }

    /// Fetch notifications from the remote URL or cache
    pub async fn fetch_notifications(&self) -> Option<NotificationsFile> {
        if !self.is_configured() {
            debug!("Notifications URL not configured, skipping fetch");
            return None;
        }

        // Check cache freshness
        if !self.cache.should_refresh_notifications() {
            if let Some(cached) = self.read_cached_notifications().await {
                debug!("Using cached notifications");
                return Some(cached);
            }
        }

        // Fetch from remote
        match self.fetch_from_remote().await {
            Ok(file) => {
                // Cache the response
                if let Err(e) = self.cache_notifications(&file).await {
                    debug!("Failed to cache notifications: {}", e);
                }
                Some(file)
            }
            Err(e) => {
                debug!("Failed to fetch notifications: {}", e);
                // Try to use stale cache as fallback
                self.read_cached_notifications().await
            }
        }
    }

    /// Fetch notifications from the remote URL
    async fn fetch_from_remote(&self) -> anyhow::Result<NotificationsFile> {
        let response = self
            .client
            .get(&self.url)
            .header("Accept", "application/json")
            .send()
            .await?;

        if !response.status().is_success() {
            anyhow::bail!("HTTP error: {}", response.status());
        }

        let file: NotificationsFile = response.json().await?;
        Ok(file)
    }

    /// Read cached notifications
    async fn read_cached_notifications(&self) -> Option<NotificationsFile> {
        let entry = self.cache.notifications_cache_entry();
        let data = entry.read().await.ok()?;
        serde_json::from_slice(&data).ok()
    }

    /// Cache notifications
    async fn cache_notifications(&self, file: &NotificationsFile) -> anyhow::Result<()> {
        let entry = self.cache.notifications_cache_entry();
        let data = serde_json::to_vec(file)?;
        entry.write(&data).await?;
        Ok(())
    }

    /// Get notifications that should be displayed
    ///
    /// Filters notifications by:
    /// - Active time window (between starts_at and expires_at)
    /// - Not already shown (if show_once is true)
    pub async fn get_displayable_notifications(&self) -> Vec<RemoteNotification> {
        let file = match self.fetch_notifications().await {
            Some(f) => f,
            None => return Vec::new(),
        };

        let shown_state = self.read_shown_state().await;

        file.notifications
            .into_iter()
            .filter(|n| n.is_active())
            .filter(|n| !n.show_once || !shown_state.has_been_shown(&n.id))
            .collect()
    }

    /// Read the shown notifications state from cache
    async fn read_shown_state(&self) -> ShownNotificationsState {
        let entry = self.cache.shown_notifications_entry();
        match entry.read().await {
            Ok(data) => serde_json::from_slice(&data).unwrap_or_default(),
            Err(_) => ShownNotificationsState::default(),
        }
    }

    /// Mark a notification as shown
    pub async fn mark_as_shown(&self, notification_id: &str) -> anyhow::Result<()> {
        let mut state = self.read_shown_state().await;
        state.mark_shown(notification_id.to_string());

        let entry = self.cache.shown_notifications_entry();
        let data = serde_json::to_vec(&state)?;
        entry.write(&data).await?;

        debug!("Marked notification '{}' as shown", notification_id);
        Ok(())
    }
}

/// Get the cache TTL for notifications in hours
pub fn notifications_cache_ttl_hours() -> u64 {
    NOTIFICATIONS_CACHE_TTL_HOURS
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[tokio::test]
    async fn test_notification_client_not_configured() {
        let temp_dir = tempdir().unwrap();
        let cache = AuditCache::new(temp_dir.path().to_path_buf());
        let client = NotificationClient::new(cache);

        assert!(!client.is_configured());

        let notifications = client.get_displayable_notifications().await;
        assert!(notifications.is_empty());
    }

    #[tokio::test]
    async fn test_notification_client_with_url() {
        let temp_dir = tempdir().unwrap();
        let cache = AuditCache::new(temp_dir.path().to_path_buf());
        let client =
            NotificationClient::with_url(cache, "https://example.com/notifications.json".into());

        assert!(client.is_configured());
    }

    #[tokio::test]
    async fn test_shown_state_persistence() {
        let temp_dir = tempdir().unwrap();
        let cache = AuditCache::new(temp_dir.path().to_path_buf());
        let client = NotificationClient::new(cache.clone());

        // Initially not shown
        let state = client.read_shown_state().await;
        assert!(!state.has_been_shown("test-notification"));

        // Mark as shown
        client.mark_as_shown("test-notification").await.unwrap();

        // Verify persistence with new client instance
        let client2 = NotificationClient::new(cache);
        let state2 = client2.read_shown_state().await;
        assert!(state2.has_been_shown("test-notification"));
    }
}
