// SPDX-License-Identifier: MIT

use crate::cli::CheckVersionArgs;
use crate::types::Version;
use anyhow::Result;
use std::str::FromStr;

pub(crate) const CURRENT_VERSION: &str = env!("CARGO_PKG_VERSION");
pub(crate) const GITHUB_REPO: &str = "nyudenkov/pysentry";

pub async fn check_version(args: &CheckVersionArgs) -> Result<()> {
    // Info commands always show output - -q flag is accepted for CLI consistency but ignored
    if args.is_verbose() {
        println!("Checking for updates...");
        println!("Current version: {CURRENT_VERSION}");
        println!("Repository: {GITHUB_REPO}");
    } else {
        println!("Checking for updates...");
    }

    let client = reqwest::Client::new();
    let url = format!("https://api.github.com/repos/{GITHUB_REPO}/releases/latest");

    if args.is_verbose() {
        println!("Fetching: {url}");
    }

    let response = match client
        .get(&url)
        .header("User-Agent", format!("pysentry/{CURRENT_VERSION}"))
        .header("Accept", "application/vnd.github+json")
        .send()
        .await
    {
        Ok(response) => response,
        Err(e) => {
            eprintln!("Failed to check for updates: {e}");
            return Ok(());
        }
    };

    if !response.status().is_success() {
        eprintln!("Failed to check for updates: HTTP {}", response.status());
        return Ok(());
    }

    let release_info: serde_json::Value = match response.json().await {
        Ok(json) => json,
        Err(e) => {
            eprintln!("Failed to parse release information: {e}");
            return Ok(());
        }
    };

    let latest_tag = match release_info["tag_name"].as_str() {
        Some(tag) => tag,
        None => {
            eprintln!("Failed to get latest version information");
            return Ok(());
        }
    };

    let latest_version_str = latest_tag.strip_prefix('v').unwrap_or(latest_tag);

    if args.is_verbose() {
        println!("Latest release tag: {latest_tag}");
    }

    let current_version = match Version::from_str(CURRENT_VERSION) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("Failed to parse current version: {e}");
            return Ok(());
        }
    };

    let latest_version = match Version::from_str(latest_version_str) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("Failed to parse latest version '{latest_version_str}': {e}");
            return Ok(());
        }
    };

    if latest_version > current_version {
        println!("✨ Update available!");
        println!("Current version: {CURRENT_VERSION}");
        println!("Latest version:  {latest_version_str}");
        println!();
        println!("To update:");
        println!("  • Rust CLI: cargo install pysentry");
        println!("  • Python package: pip install --upgrade pysentry-rs");
        if let Some(release_url) = release_info["html_url"].as_str() {
            println!("  • Release notes: {release_url}");
        }
    } else if latest_version < current_version {
        println!("🚀 You're running a development version!");
        println!("Current version: {CURRENT_VERSION}");
        println!("Latest stable:   {latest_version_str}");
    } else {
        println!("✅ You're running the latest version!");
        println!("Current version: {CURRENT_VERSION}");
    }

    Ok(())
}

pub async fn check_for_update_silent() -> Result<Option<String>> {
    let client = reqwest::Client::new();
    let url = format!("https://api.github.com/repos/{GITHUB_REPO}/releases/latest");

    let response = match client
        .get(&url)
        .header("User-Agent", format!("pysentry/{CURRENT_VERSION}"))
        .header("Accept", "application/vnd.github+json")
        .timeout(std::time::Duration::from_secs(5))
        .send()
        .await
    {
        Ok(response) => response,
        Err(_) => {
            return Ok(None);
        }
    };

    if !response.status().is_success() {
        return Ok(None);
    }

    let release_info: serde_json::Value = match response.json().await {
        Ok(json) => json,
        Err(_) => {
            return Ok(None);
        }
    };

    let latest_tag = match release_info["tag_name"].as_str() {
        Some(tag) => tag,
        None => {
            return Ok(None);
        }
    };

    let latest_version_str = latest_tag.strip_prefix('v').unwrap_or(latest_tag);

    let current_version = match Version::from_str(CURRENT_VERSION) {
        Ok(v) => v,
        Err(_) => {
            return Ok(None);
        }
    };

    let latest_version = match Version::from_str(latest_version_str) {
        Ok(v) => v,
        Err(_) => {
            return Ok(None);
        }
    };

    if latest_version > current_version {
        Ok(Some(latest_version_str.to_string()))
    } else {
        Ok(None)
    }
}
