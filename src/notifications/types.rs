// SPDX-License-Identifier: MIT

//! Remote notification types
//!
//! This module defines types for remote notifications fetched from a JSON endpoint.
//! Notifications support time windows and "show once" tracking.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

/// Schema version for notifications file format
pub const CURRENT_SCHEMA_VERSION: u32 = 1;

/// Root structure of the notifications JSON file
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NotificationsFile {
    /// Schema version for backwards compatibility
    pub schema_version: u32,
    /// List of notifications
    #[serde(default)]
    pub notifications: Vec<RemoteNotification>,
}

/// A single remote notification
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemoteNotification {
    /// Unique identifier for the notification
    pub id: String,
    /// Short title displayed prominently
    pub title: String,
    /// Longer message body
    pub message: String,
    /// Optional URL for more information
    pub url: Option<String>,
    /// When the notification becomes active (ISO 8601)
    pub starts_at: DateTime<Utc>,
    /// When the notification expires (ISO 8601)
    pub expires_at: DateTime<Utc>,
    /// If true, only show once per user
    #[serde(default)]
    pub show_once: bool,
}

impl RemoteNotification {
    /// Check if the notification is currently active based on time window
    pub fn is_active(&self) -> bool {
        let now = Utc::now();
        now >= self.starts_at && now < self.expires_at
    }
}

/// Tracks which notifications have been shown to the user
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ShownNotificationsState {
    /// Set of notification IDs that have been shown
    #[serde(default)]
    pub shown_ids: HashSet<String>,
}

impl ShownNotificationsState {
    /// Create a new empty state
    pub fn new() -> Self {
        Self::default()
    }

    /// Check if a notification has been shown
    pub fn has_been_shown(&self, id: &str) -> bool {
        self.shown_ids.contains(id)
    }

    /// Mark a notification as shown
    pub fn mark_shown(&mut self, id: String) {
        self.shown_ids.insert(id);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;

    #[test]
    fn test_notification_is_active_within_window() {
        let now = Utc::now();
        let notification = RemoteNotification {
            id: "test-1".to_string(),
            title: "Test".to_string(),
            message: "Test message".to_string(),
            url: None,
            starts_at: now - Duration::hours(1),
            expires_at: now + Duration::hours(1),
            show_once: false,
        };

        assert!(notification.is_active());
    }

    #[test]
    fn test_notification_is_not_active_before_start() {
        let now = Utc::now();
        let notification = RemoteNotification {
            id: "test-2".to_string(),
            title: "Test".to_string(),
            message: "Test message".to_string(),
            url: None,
            starts_at: now + Duration::hours(1),
            expires_at: now + Duration::hours(2),
            show_once: false,
        };

        assert!(!notification.is_active());
    }

    #[test]
    fn test_notification_is_not_active_after_expiry() {
        let now = Utc::now();
        let notification = RemoteNotification {
            id: "test-3".to_string(),
            title: "Test".to_string(),
            message: "Test message".to_string(),
            url: None,
            starts_at: now - Duration::hours(2),
            expires_at: now - Duration::hours(1),
            show_once: false,
        };

        assert!(!notification.is_active());
    }

    #[test]
    fn test_shown_notifications_state() {
        let mut state = ShownNotificationsState::new();

        assert!(!state.has_been_shown("notification-1"));

        state.mark_shown("notification-1".to_string());
        assert!(state.has_been_shown("notification-1"));
        assert!(!state.has_been_shown("notification-2"));
    }

    #[test]
    fn test_deserialize_notifications_file() {
        let json = r#"{
            "schema_version": 1,
            "notifications": [
                {
                    "id": "survey-2026-01",
                    "title": "Help improve PySentry",
                    "message": "Quick 2-min survey about your usage",
                    "url": "https://example.com/survey",
                    "starts_at": "2026-01-30T00:00:00Z",
                    "expires_at": "2026-03-01T00:00:00Z",
                    "show_once": true
                }
            ]
        }"#;

        let file: NotificationsFile = serde_json::from_str(json).unwrap();
        assert_eq!(file.schema_version, 1);
        assert_eq!(file.notifications.len(), 1);
        assert_eq!(file.notifications[0].id, "survey-2026-01");
        assert!(file.notifications[0].show_once);
    }

    #[test]
    fn test_deserialize_notification_without_optional_fields() {
        let json = r#"{
            "id": "simple-notification",
            "title": "Title",
            "message": "Message",
            "starts_at": "2026-01-01T00:00:00Z",
            "expires_at": "2026-12-31T23:59:59Z"
        }"#;

        let notification: RemoteNotification = serde_json::from_str(json).unwrap();
        assert_eq!(notification.id, "simple-notification");
        assert!(notification.url.is_none());
        assert!(!notification.show_once);
    }
}
