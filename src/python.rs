/*
 * pysentry - Python security vulnerability scanner
 * Copyright (C) 2025 nyudenkov <nyudenkov@pm.me>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

use crate::cli::{config_init, config_path, config_show, config_validate, ConfigCommands};
use anyhow::Result;
use pyo3::exceptions::PyRuntimeError;
use pyo3::prelude::*;
use std::sync::Once;

static TRACING_INIT: Once = Once::new();

fn ensure_tracing_initialized() {
    TRACING_INIT.call_once(|| {
        use tracing_subscriber::EnvFilter;
        tracing_subscriber::fmt()
            .with_env_filter(EnvFilter::from_default_env())
            .init();
    });
}

async fn handle_config_command(config_command: ConfigCommands) -> Result<()> {
    match config_command {
        ConfigCommands::Init(init_args) => config_init(&init_args).await,
        ConfigCommands::Validate(validate_args) => config_validate(&validate_args).await,
        ConfigCommands::Show(show_args) => config_show(&show_args).await,
        ConfigCommands::Path(path_args) => config_path(&path_args).await,
    }
}

#[pyfunction]
fn run_cli(args: Vec<String>) -> PyResult<i32> {
    ensure_tracing_initialized();

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
                let audit_args = cli.audit_args;

                let cache_dir = audit_args.cache_dir.clone().unwrap_or_else(|| {
                    dirs::cache_dir()
                        .unwrap_or_else(std::env::temp_dir)
                        .join("pysentry")
                });

                match audit(&audit_args, &cache_dir).await {
                    Ok(exit_code) => Ok(exit_code),
                    Err(e) => {
                        eprintln!("Error: Audit failed: {e}");
                        Ok(1)
                    }
                }
            }
            Some(Commands::Resolvers(resolvers_args)) => {
                match check_resolvers(resolvers_args.verbose).await {
                    Ok(()) => Ok(0),
                    Err(e) => {
                        eprintln!("Error: {e}");
                        Ok(1)
                    }
                }
            }
            Some(Commands::CheckVersion(check_version_args)) => {
                match check_version(check_version_args.verbose).await {
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
}

#[pyfunction]
fn get_version() -> String {
    env!("CARGO_PKG_VERSION").to_string()
}

#[pymodule]
fn _internal(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(run_cli, m)?)?;
    m.add_function(wrap_pyfunction!(get_version, m)?)?;
    Ok(())
}
