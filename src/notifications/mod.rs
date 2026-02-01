// SPDX-License-Identifier: MIT

//! Remote notifications support
//!
//! This module provides support for fetching and displaying remote notifications
//! from a GitHub-hosted JSON file. Notifications support time windows and
//! "show once" tracking.

pub mod client;
pub mod types;

pub use client::NotificationClient;
pub use types::{NotificationsFile, RemoteNotification, ShownNotificationsState};
