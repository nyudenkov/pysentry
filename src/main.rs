use anyhow::Result;
use clap::Parser;
use tracing_subscriber::EnvFilter;

use pysentry::cli::{audit, check_resolvers, check_version, Cli, Commands};

#[tokio::main]
async fn main() -> Result<()> {
    let args = Cli::parse();

    match args.command {
        // No subcommand provided - run audit with flattened args
        None => {
            let audit_args = args.audit_args;

            let log_level = if audit_args.verbose {
                "debug"
            } else if audit_args.quiet {
                "error"
            } else {
                "info"
            };

            tracing_subscriber::fmt()
                .with_env_filter(EnvFilter::from_default_env().add_directive(log_level.parse()?))
                .init();

            let cache_dir = audit_args.cache_dir.clone().unwrap_or_else(|| {
                dirs::cache_dir()
                    .unwrap_or_else(std::env::temp_dir)
                    .join("pysentry")
            });

            let exit_code = audit(&audit_args, &cache_dir).await?;

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
    }
}
