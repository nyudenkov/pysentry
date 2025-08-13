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

use anyhow::Result;
use clap::Parser;
use tracing_subscriber::EnvFilter;

use pysentry::cli::{
    audit, check_resolvers, check_version, config_init, config_path, config_show, config_validate,
    Cli, Commands, ConfigCommands,
};

#[tokio::main]
async fn main() -> Result<()> {
    let args = Cli::parse();

    match args.command {
        // No subcommand provided - run audit with flattened args
        None => {
            let (merged_audit_args, _config) = match args.audit_args.load_and_merge_config() {
                Ok(result) => result,
                Err(e) => {
                    eprintln!("Configuration error: {e}");
                    std::process::exit(1);
                }
            };

            let log_level = if merged_audit_args.verbose {
                "info"
            } else {
                "error"
            };

            tracing_subscriber::fmt()
                .with_env_filter(EnvFilter::from_default_env().add_directive(log_level.parse()?))
                .init();

            let cache_dir = merged_audit_args.cache_dir.clone().unwrap_or_else(|| {
                dirs::cache_dir()
                    .unwrap_or_else(std::env::temp_dir)
                    .join("pysentry")
            });

            let exit_code = audit(&merged_audit_args, &cache_dir).await?;

            std::process::exit(exit_code);
        }
        Some(Commands::Resolvers(resolvers_args)) => {
            let log_level = if resolvers_args.verbose {
                "debug"
            } else {
                "error"
            };

            tracing_subscriber::fmt()
                .with_env_filter(EnvFilter::from_default_env().add_directive(log_level.parse()?))
                .init();

            check_resolvers(resolvers_args.verbose).await?;
            std::process::exit(0);
        }
        Some(Commands::CheckVersion(check_version_args)) => {
            let log_level = if check_version_args.verbose {
                "debug"
            } else {
                "error"
            };

            tracing_subscriber::fmt()
                .with_env_filter(EnvFilter::from_default_env().add_directive(log_level.parse()?))
                .init();

            check_version(check_version_args.verbose).await?;
            std::process::exit(0);
        }
        Some(Commands::Config(config_command)) => {
            tracing_subscriber::fmt()
                .with_env_filter(EnvFilter::from_default_env().add_directive("error".parse()?))
                .init();

            match config_command {
                ConfigCommands::Init(init_args) => {
                    config_init(&init_args).await?;
                }
                ConfigCommands::Validate(validate_args) => {
                    config_validate(&validate_args).await?;
                }
                ConfigCommands::Show(show_args) => {
                    config_show(&show_args).await?;
                }
                ConfigCommands::Path(path_args) => {
                    config_path(&path_args).await?;
                }
            }
            std::process::exit(0);
        }
    }
}
