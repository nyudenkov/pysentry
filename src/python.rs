// SPDX-License-Identifier: MIT

use crate::cli::{config_init, config_path, config_show, config_validate, ConfigCommands};
use crate::logging;
use anyhow::Result;
use pyo3::exceptions::PyRuntimeError;
use pyo3::prelude::*;

async fn handle_config_command(config_command: ConfigCommands) -> Result<()> {
    match config_command {
        ConfigCommands::Init(init_args) => {
            logging::init_tracing(&init_args.verbosity)?;
            config_init(&init_args).await
        }
        ConfigCommands::Validate(validate_args) => {
            logging::init_tracing(&validate_args.verbosity)?;
            config_validate(&validate_args).await
        }
        ConfigCommands::Show(show_args) => {
            logging::init_tracing(&show_args.verbosity)?;
            config_show(&show_args).await
        }
        ConfigCommands::Path(path_args) => {
            logging::init_tracing(&path_args.verbosity)?;
            config_path(&path_args).await
        }
    }
}

#[pyfunction]
fn run_cli(py: Python<'_>, args: Vec<String>) -> PyResult<i32> {
    // Release GIL during Rust execution - allows Python to handle signals
    py.detach(|| {
        let rt = tokio::runtime::Runtime::new()
            .map_err(|e| PyRuntimeError::new_err(format!("Failed to create async runtime: {e}")))?;

        rt.block_on(async {
            use crate::cli::{audit, check_resolvers, check_version, Cli, Commands};
            use clap::Parser;

            let cli_result = Cli::try_parse_from(&args);

            let cli = match cli_result {
                Ok(cli) => cli,
                Err(e) => {
                    eprint!("{e}");
                    return Ok(if e.exit_code() == 0 { 0 } else { 2 });
                }
            };

            match cli.command {
                None => {
                    let (merged_audit_args, config) = match cli.audit_args.load_and_merge_config() {
                        Ok(result) => result,
                        Err(e) => {
                            eprintln!("Configuration error: {e}");
                            return Ok(1);
                        }
                    };

                    let http_config = config.as_ref().map(|c| c.http.clone()).unwrap_or_default();
                    let vulnerability_ttl = config
                        .as_ref()
                        .map(|c| c.cache.vulnerability_ttl)
                        .unwrap_or(48);

                    if let Err(e) = logging::init_tracing(&merged_audit_args.verbosity) {
                        eprintln!("Warning: Failed to initialize tracing: {e}");
                    }

                    let cache_dir = merged_audit_args.cache_dir.clone().unwrap_or_else(|| {
                        dirs::cache_dir()
                            .unwrap_or_else(std::env::temp_dir)
                            .join("pysentry")
                    });

                    match audit(&merged_audit_args, &cache_dir, http_config, vulnerability_ttl).await {
                        Ok(exit_code) => Ok(exit_code),
                        Err(e) => {
                            eprintln!("Error: Audit failed: {e}");
                            Ok(1)
                        }
                    }
                }
                Some(Commands::Resolvers(resolvers_args)) => {
                    if let Err(e) = logging::init_tracing(&resolvers_args.verbosity) {
                        eprintln!("Warning: Failed to initialize tracing: {e}");
                    }

                    match check_resolvers(&resolvers_args).await {
                        Ok(()) => Ok(0),
                        Err(e) => {
                            eprintln!("Error: {e}");
                            Ok(1)
                        }
                    }
                }
                Some(Commands::CheckVersion(check_version_args)) => {
                    if let Err(e) = logging::init_tracing(&check_version_args.verbosity) {
                        eprintln!("Warning: Failed to initialize tracing: {e}");
                    }

                    match check_version(&check_version_args).await {
                        Ok(()) => Ok(0),
                        Err(e) => {
                            eprintln!("Error: {e}");
                            Ok(1)
                        }
                    }
                }
                Some(Commands::Config(config_command)) => {
                    match handle_config_command(config_command).await {
                        Ok(()) => Ok(0),
                        Err(e) => {
                            eprintln!("Error: {e}");
                            Ok(1)
                        }
                    }
                }
            }
        })
    })
}

#[pyfunction]
fn get_version() -> String {
    env!("CARGO_PKG_VERSION").to_string()
}

#[pymodule(gil_used = false)]
fn _internal(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(run_cli, m)?)?;
    m.add_function(wrap_pyfunction!(get_version, m)?)?;
    Ok(())
}
