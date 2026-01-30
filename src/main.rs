// SPDX-License-Identifier: MIT

use anyhow::Result;
use clap::Parser;

use pysentry::cli::{
    audit, check_resolvers, check_version, config_init, config_path, config_show, config_validate,
    Cli, Commands, ConfigCommands,
};
use pysentry::logging;

#[tokio::main]
async fn main() -> Result<()> {
    let args = Cli::parse();

    match args.command {
        // No subcommand provided - run audit with flattened args
        None => {
            let (merged_audit_args, config) = match args.audit_args.load_and_merge_config() {
                Ok(result) => result,
                Err(e) => {
                    eprintln!("Configuration error: {e}");
                    std::process::exit(1);
                }
            };

            let http_config = config.as_ref().map(|c| c.http.clone()).unwrap_or_default();
            let vulnerability_ttl = config
                .as_ref()
                .map(|c| c.cache.vulnerability_ttl)
                .unwrap_or(48);

            logging::init_tracing(&merged_audit_args.verbosity)?;

            let cache_dir = merged_audit_args.cache_dir.clone().unwrap_or_else(|| {
                dirs::cache_dir()
                    .unwrap_or_else(std::env::temp_dir)
                    .join("pysentry")
            });

            let exit_code =
                audit(&merged_audit_args, &cache_dir, http_config, vulnerability_ttl).await?;

            std::process::exit(exit_code);
        }
        Some(Commands::Resolvers(resolvers_args)) => {
            logging::init_tracing(&resolvers_args.verbosity)?;

            check_resolvers(&resolvers_args).await?;
            std::process::exit(0);
        }
        Some(Commands::CheckVersion(check_version_args)) => {
            logging::init_tracing(&check_version_args.verbosity)?;

            check_version(&check_version_args).await?;
            std::process::exit(0);
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
            std::process::exit(0);
        }
    }
}
