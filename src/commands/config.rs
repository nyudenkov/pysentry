// SPDX-License-Identifier: MIT

use crate::cli::{ConfigInitArgs, ConfigPathArgs, ConfigShowArgs, ConfigValidateArgs};
use crate::{Config, ConfigLoader};
use anyhow::{Context, Result};

pub async fn config_init(args: &ConfigInitArgs) -> Result<()> {
    let output_path = args
        .output
        .clone()
        .unwrap_or_else(|| std::path::PathBuf::from(".pysentry.toml"));

    if output_path.exists() && !args.force {
        anyhow::bail!(
            "Configuration file already exists: {}. Use --force to overwrite.",
            output_path.display()
        );
    }

    let config_content = if args.minimal {
        generate_minimal_config()
    } else {
        Config::generate_default_toml()
    };

    fs_err::write(&output_path, config_content)?;

    println!("Created configuration file: {}", output_path.display());
    println!();
    println!("You can now customize your settings in this file.");
    println!("Configuration reference:");
    println!("- Format: human, json, sarif, markdown");
    println!("- Sources: pypa, pypi, osv");
    println!("- Resolver: uv, pip-tools");
    println!("- HTTP: Configure timeouts, retries, and progress indication");
    println!("- Include withdrawn: true/false");

    Ok(())
}

pub async fn config_validate(args: &ConfigValidateArgs) -> Result<()> {
    let config_loader = if let Some(ref config_path) = args.config {
        ConfigLoader::load_from_file(config_path)?
    } else {
        ConfigLoader::load()?
    };

    let config_path = config_loader.config_path_display();

    if args.is_verbose() {
        println!("Validating configuration file: {config_path}");
    }

    // The configuration is already validated during loading
    // If we get here, validation passed

    if config_loader.config_path.is_some() {
        println!("✅ Configuration is valid: {config_path}");

        if args.is_verbose() {
            println!("Configuration details:");
            println!("  Version: {}", config_loader.config.version);
            println!("  Format: {}", config_loader.config.defaults.format);
            println!(
                "  Sources: {}",
                config_loader.config.sources.enabled.join(", ")
            );
            println!(
                "  Resolver: {}",
                config_loader.config.resolver.resolver_type
            );
            println!("  Cache enabled: {}", config_loader.config.cache.enabled);
        }
    } else {
        println!("No configuration file found. Using built-in defaults.");
    }

    Ok(())
}

pub async fn config_show(args: &ConfigShowArgs) -> Result<()> {
    let config_loader = if let Some(ref config_path) = args.config {
        ConfigLoader::load_from_file(config_path)?
    } else {
        ConfigLoader::load()?
    };

    if args.toml {
        // Show raw TOML format
        let toml_content = toml::to_string_pretty(&config_loader.config)
            .context("Failed to serialize configuration to TOML")?;
        println!("{toml_content}");
    } else {
        // Show human-readable format
        println!(
            "Configuration loaded from: {}",
            config_loader.config_path_display()
        );
        println!();
        println!("Effective configuration:");
        println!("  Version: {}", config_loader.config.version);
        println!("  Format: {}", config_loader.config.defaults.format);
        println!("  Fail on: {}", config_loader.config.defaults.fail_on);
        println!("  Scope: {}", config_loader.config.defaults.scope);
        println!(
            "  Direct only: {}",
            config_loader.config.defaults.direct_only
        );
        println!("  Detailed: {}", config_loader.config.defaults.detailed);
        println!("  Compact: {}", config_loader.config.defaults.compact);
        println!(
            "  Include withdrawn: {}",
            config_loader.config.defaults.include_withdrawn
        );
        println!();
        println!(
            "  Sources: {}",
            config_loader.config.sources.enabled.join(", ")
        );
        println!();
        println!(
            "  Resolver: {}",
            config_loader.config.resolver.resolver_type
        );
        println!();
        println!("  Cache enabled: {}", config_loader.config.cache.enabled);
        if let Some(ref cache_dir) = config_loader.config.cache.directory {
            println!("  Cache directory: {cache_dir}");
        }
        println!(
            "  Resolution cache TTL: {} hours",
            config_loader.config.cache.resolution_ttl
        );
        println!(
            "  Vulnerability cache TTL: {} hours",
            config_loader.config.cache.vulnerability_ttl
        );
        println!();
        if !config_loader.config.ignore.ids.is_empty() {
            println!(
                "  Ignored IDs: {}",
                config_loader.config.ignore.ids.join(", ")
            );
        }
        println!();
        println!("  HTTP timeout: {}s", config_loader.config.http.timeout);
        println!(
            "  HTTP connect timeout: {}s",
            config_loader.config.http.connect_timeout
        );
        println!(
            "  HTTP max retries: {}",
            config_loader.config.http.max_retries
        );
        println!(
            "  HTTP retry backoff: {}-{}s",
            config_loader.config.http.retry_initial_backoff,
            config_loader.config.http.retry_max_backoff
        );
        println!(
            "  HTTP show progress: {}",
            config_loader.config.http.show_progress
        );
    }

    Ok(())
}

pub async fn config_path(args: &ConfigPathArgs) -> Result<()> {
    let config_loader = ConfigLoader::load()?;

    if let Some(config_path) = config_loader.config_path {
        println!("{}", config_path.display());

        if args.is_verbose() {
            println!();
            println!("Configuration file found and loaded successfully.");

            // Show file size and modification time
            if let Ok(metadata) = fs_err::metadata(&config_path) {
                println!("Size: {} bytes", metadata.len());
                if let Ok(modified) = metadata.modified() {
                    println!("Modified: {modified:?}");
                }
            }
        }
    } else if args.is_verbose() {
        println!("No configuration file found.");
        println!("Using built-in defaults.");
        println!();
        println!("To create a configuration file, run:");
        println!("  pysentry config init");
    } else {
        // Exit with code 1 to indicate no config file found
        std::process::exit(1);
    }

    Ok(())
}

fn generate_minimal_config() -> String {
    r#"# PySentry minimal configuration
version = 1

[defaults]
fail_on = "high"

# Uncomment to include dev/optional dependencies
# scope = "all"

# Uncomment to include withdrawn vulnerabilities by default
# include_withdrawn = true

# Uncomment for compact output (summary + one-liner per vuln)
# compact = true

# Display mode for human output: "text" (classic) or "table" (aligned columns, compact mode only)
# display = "table"

[sources]
# All vulnerability sources are enabled by default: PyPA, PyPI, and OSV
# enabled = ["pypa", "pypi", "osv"]

# Uncomment to use specific sources only
# enabled = ["pypa"]

[ignore]
# Add vulnerability IDs to ignore
ids = []

# Add vulnerability IDs to ignore only while they have no fix available
# This is useful for acknowledging unfixable vulnerabilities temporarily
# Once a fix becomes available, the scan will fail again
while_no_fix = []

# Example:
# ids = ["GHSA-1234-5678-90ab", "CVE-2024-12345"]
# while_no_fix = ["CVE-2025-8869"]
"#
    .to_string()
}
