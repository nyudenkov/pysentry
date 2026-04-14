// SPDX-License-Identifier: MIT

use crate::notifications::{NotificationClient, RemoteNotification};
use crate::AuditCache;

/// Fetch remote notifications silently, returning empty vec on any error
pub(crate) async fn fetch_remote_notifications_silent(
    cache: &AuditCache,
) -> Vec<RemoteNotification> {
    let client = NotificationClient::new(cache.clone());
    client.get_displayable_notifications().await
}

/// Display a notification to the user
pub(crate) fn display_notification(notification: &RemoteNotification) {
    println!("\n\u{1f4e2} {}", notification.title);
    println!("   {}", notification.message);
    if let Some(url) = &notification.url {
        println!("   \u{2192} {}", url);
    }
}

/// Mark a notification as shown in the cache
pub(crate) async fn mark_notification_shown(
    cache: &AuditCache,
    notification_id: &str,
) -> anyhow::Result<()> {
    let client = NotificationClient::new(cache.clone());
    client.mark_as_shown(notification_id).await
}
