// SPDX-License-Identifier: MIT

use crate::cli::ResolversArgs;
use crate::dependency::resolvers::ResolverRegistry;
use crate::types::ResolverType;
use anyhow::Result;

pub async fn check_resolvers(args: &ResolversArgs) -> Result<()> {
    // Info commands always show output - -q flag is accepted for CLI consistency but ignored
    if !args.is_verbose() {
        println!("Checking available dependency resolvers...");
        println!();
    }

    let all_resolvers = vec![ResolverType::Uv, ResolverType::PipTools];

    let mut available_resolvers = Vec::new();
    let mut unavailable_resolvers = Vec::new();

    for resolver_type in all_resolvers {
        if args.is_verbose() {
            println!("Checking {resolver_type}...");
        }

        let resolver = ResolverRegistry::create_resolver(resolver_type);
        let is_available = resolver.is_available().await;

        if is_available {
            available_resolvers.push(resolver_type);
        } else {
            unavailable_resolvers.push(resolver_type);
        }
    }

    if !available_resolvers.is_empty() {
        println!("✓ Available resolvers ({}):", available_resolvers.len());
        for resolver in &available_resolvers {
            println!("  {resolver}");
        }
        println!();
    }

    if !unavailable_resolvers.is_empty() {
        println!("✗ Unavailable resolvers ({}):", unavailable_resolvers.len());
        for resolver in &unavailable_resolvers {
            println!("  {resolver} - not installed or not in PATH");
        }
        println!();
    }

    if available_resolvers.is_empty() {
        println!("⚠️  No dependency resolvers are available!");
        println!("Please install at least one resolver:");
        println!("  • UV (recommended): https://docs.astral.sh/uv/");
        println!("  • pip-tools: pip install pip-tools");
        return Ok(());
    }

    match ResolverRegistry::detect_best_resolver().await {
        Ok(best) => {
            println!("🎯 Auto-detected resolver: {best}");
        }
        Err(_) => {
            println!("⚠️  No resolver can be auto-detected");
        }
    }

    Ok(())
}
