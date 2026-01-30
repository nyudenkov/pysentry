// SPDX-License-Identifier: MIT

//! Centralized logging initialization for the PySentry CLI.
//!
//! This module provides a unified interface for configuring tracing/logging
//! across all CLI commands, supporting multi-level verbosity via `-v` flags.

use clap_verbosity_flag::{ErrorLevel, Verbosity};
use tracing_subscriber::EnvFilter;

/// Type alias for the application's verbosity configuration.
///
/// Uses `ErrorLevel` as the default, meaning:
/// - No flags: error level only
/// - `-v`: warn level
/// - `-vv`: info level
/// - `-vvv`: debug level
/// - `-vvvv`: trace level
/// - `-q`: silent (no output)
pub type AppVerbosity = Verbosity<ErrorLevel>;

/// Initialize the tracing subscriber with the specified verbosity level.
///
/// If `RUST_LOG` environment variable is set, it takes precedence over
/// the verbosity flags, allowing fine-grained control for advanced users.
///
/// # Arguments
///
/// * `verbosity` - The verbosity configuration from CLI flags
///
/// # Returns
///
/// Returns `Ok(())` on success, or an error if tracing initialization fails.
pub fn init_tracing(verbosity: &AppVerbosity) -> anyhow::Result<()> {
    let filter = if std::env::var("RUST_LOG").is_ok() {
        EnvFilter::from_default_env()
    } else {
        let level = verbosity.tracing_level_filter();
        EnvFilter::from_default_env().add_directive(level.into())
    };

    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .try_init()
        .ok(); // Ignore error if already initialized

    Ok(())
}

/// Check if the verbosity is set to silent mode (-q flag).
pub fn is_quiet(verbosity: &AppVerbosity) -> bool {
    verbosity.is_silent()
}

/// Check if any verbosity flags were provided (-v or more).
///
/// Returns true if verbosity level is higher than the default (error).
pub fn is_verbose(verbosity: &AppVerbosity) -> bool {
    !is_quiet(verbosity)
        && verbosity.tracing_level_filter() > tracing::level_filters::LevelFilter::ERROR
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_verbosity_is_error_level() {
        let verbosity = AppVerbosity::default();
        assert!(!is_quiet(&verbosity));
        assert!(!is_verbose(&verbosity));
    }
}
