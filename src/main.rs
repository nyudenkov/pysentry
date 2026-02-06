// SPDX-License-Identifier: MIT

use anyhow::Result;
use clap::Parser;
use std::process::ExitCode;

use pysentry::cli::{
    audit, check_resolvers, check_version, config_init, config_path, config_show, config_validate,
    Cli, Commands, ConfigCommands,
};
use pysentry::logging;

#[tokio::main]
#[cfg_attr(feature = "hotpath", hotpath::main)]
async fn main() -> ExitCode {
    match run().await {
        Ok(code) => ExitCode::from(code),
        Err(e) => {
            eprintln!("Error: {e}");
            ExitCode::FAILURE
        }
    }
}

async fn run() -> Result<u8> {
    let args = Cli::parse();

    match args.command {
        None => {
            let (merged_audit_args, config) = match args.audit_args.load_and_merge_config() {
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
            let notifications_enabled = config
                .as_ref()
                .map(|c| c.notifications.enabled)
                .unwrap_or(true);

            logging::init_tracing(&merged_audit_args.verbosity)?;

            let cache_dir = merged_audit_args.cache_dir.clone().unwrap_or_else(|| {
                dirs::cache_dir()
                    .unwrap_or_else(std::env::temp_dir)
                    .join("pysentry")
            });

            let exit_code = audit(
                &merged_audit_args,
                &cache_dir,
                http_config,
                vulnerability_ttl,
                notifications_enabled,
            )
            .await?;

            Ok(exit_code as u8)
        }
        Some(Commands::Resolvers(resolvers_args)) => {
            logging::init_tracing(&resolvers_args.verbosity)?;
            check_resolvers(&resolvers_args).await?;
            Ok(0)
        }
        Some(Commands::CheckVersion(check_version_args)) => {
            logging::init_tracing(&check_version_args.verbosity)?;
            check_version(&check_version_args).await?;
            Ok(0)
        }
        Some(Commands::Config(config_command)) => {
            match config_command {
                ConfigCommands::Init(init_args) => {
                    logging::init_tracing(&init_args.verbosity)?;
                    config_init(&init_args).await?;
                }
                ConfigCommands::Validate(validate_args) => {
                    logging::init_tracing(&validate_args.verbosity)?;
                    config_validate(&validate_args).await?;
                }
                ConfigCommands::Show(show_args) => {
                    logging::init_tracing(&show_args.verbosity)?;
                    config_show(&show_args).await?;
                }
                ConfigCommands::Path(path_args) => {
                    logging::init_tracing(&path_args.verbosity)?;
                    config_path(&path_args).await?;
                }
            }
            Ok(0)
        }
    }
}
