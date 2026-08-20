// SPDX-License-Identifier: MIT

use crate::cli::{AuditArgs, AuditFormat, DisplayModeArg, ResolverTypeArg, SeverityLevel};
use crate::parsers::DependencyStats;
use crate::{Config, ConfigLoader};
use anyhow::Result;

impl AuditArgs {
    pub fn load_and_merge_config(&self) -> Result<(Self, Option<Config>)> {
        let config_loader = if let Some(ref config_path) = self.config {
            ConfigLoader::load_from_file(config_path)?
        } else {
            ConfigLoader::load_with_options(self.no_config)?
        };

        let config = config_loader.config.clone();
        let merged_args = self.merge_with_config(&config);

        Ok((merged_args, Some(config)))
    }

    pub fn merge_with_config(&self, config: &Config) -> Self {
        let mut merged = self.clone();

        if self.format == AuditFormat::Human && config.defaults.format != "human" {
            merged.format = match config.defaults.format.as_str() {
                "json" => AuditFormat::Json,
                "sarif" => AuditFormat::Sarif,
                "markdown" => AuditFormat::Markdown,
                _ => AuditFormat::Human, // fallback
            };
        }

        if self.fail_on == SeverityLevel::Medium && config.defaults.fail_on != "medium" {
            merged.fail_on = match config.defaults.fail_on.as_str() {
                "low" => SeverityLevel::Low,
                "high" => SeverityLevel::High,
                "critical" => SeverityLevel::Critical,
                _ => SeverityLevel::Medium, // fallback
            };
        }

        if !self.exclude_extra && config.defaults.scope == "main" {
            merged.exclude_extra = true;
        }

        if !self.direct_only {
            merged.direct_only = config.defaults.direct_only;
        }

        if self.compact {
            // --compact explicitly set on CLI: override any config-level detailed
            merged.detailed = false;
        } else if !self.detailed {
            merged.detailed = config.defaults.detailed;
        }

        if self.detailed {
            // --detailed explicitly set on CLI: override any config-level compact
            merged.compact = false;
        } else if !self.compact {
            merged.compact = config.defaults.compact;
        }

        // CLI Some → always wins; CLI None → config takes precedence; fallback: Table
        if let Some(cli_display) = self.display {
            merged.display = Some(cli_display);
        } else {
            merged.display = Some(match config.defaults.display.as_str() {
                "text" => DisplayModeArg::Text,
                _ => DisplayModeArg::Table,
            });
        }

        if !self.include_withdrawn {
            merged.include_withdrawn = config.defaults.include_withdrawn;
        }

        if self.resolver == ResolverTypeArg::Uv && config.resolver.resolver_type != "uv" {
            merged.resolver = match config.resolver.resolver_type.as_str() {
                "pip-tools" => ResolverTypeArg::PipTools,
                _ => ResolverTypeArg::Uv, // fallback
            };
        }

        if !self.no_resolver && config.resolver.no_resolver {
            merged.no_resolver = true;
        }

        if merged.no_resolver {
            merged.direct_only = true;
        }

        if !self.no_cache && !config.cache.enabled {
            merged.no_cache = true;
        }

        if self.cache_dir.is_none() {
            if let Some(ref cache_dir) = config.cache.directory {
                merged.cache_dir = Some(std::path::PathBuf::from(cache_dir));
            }
        }

        if self.resolution_cache_ttl == 24 {
            merged.resolution_cache_ttl = config.cache.resolution_ttl;
        }

        if self.sources.is_empty() && !config.sources.enabled.is_empty() {
            merged.sources = config.sources.enabled.clone();
        }

        if self.service_url.is_none() {
            merged.service_url = config.sources.service_url.clone();
        }

        if !self.include_scripts && config.defaults.include_scripts {
            merged.include_scripts = true;
        }

        let mut ignore_ids = self.ignore_ids.clone();
        ignore_ids.extend(config.ignore.ids.clone());
        merged.ignore_ids = ignore_ids;

        let mut ignore_while_no_fix = self.ignore_while_no_fix.clone();
        ignore_while_no_fix.extend(config.ignore.while_no_fix.clone());
        merged.ignore_while_no_fix = ignore_while_no_fix;

        let mut ignore_packages = self.ignore_packages.clone();
        ignore_packages.extend(config.ignore.packages.clone());
        merged.ignore_packages = ignore_packages;

        // fail_on_partial defaults to true (fail-closed); the CLI flag and config
        // can only relax it, matching the "flags turn ON" idiom (cf. no_fail_on_unknown).
        if !self.no_fail_on_partial && !config.sources.fail_on_partial {
            merged.no_fail_on_partial = true;
        }

        // Per-group fail thresholds (config-only). Normalize keys to PEP 735 form so
        // they compare against graph attribution's normalized group names. Levels were
        // validated at config load; the fallback keeps this infallible.
        merged.group_fail_on = config
            .groups
            .iter()
            .map(|(name, policy)| {
                // invariant: levels were validated in Config::validate at load, so parse
                // cannot fail here; the fallback keeps this map infallible without a panic.
                let level = policy.fail_on.parse().unwrap_or(SeverityLevel::Medium);
                (
                    crate::parsers::manifest_reader::normalize_group_name(name),
                    level,
                )
            })
            .collect();

        // CLI -v flag overrides config quiet. Only apply config quiet when not explicitly verbose.
        if config.output.quiet && !crate::logging::is_verbose(&self.verbosity) {
            merged.config_quiet = true;
        }

        // Merge maintenance (PEP 792) settings
        if !self.no_maintenance_check && !config.maintenance.enabled {
            merged.no_maintenance_check = true;
        }
        if !self.forbid_archived && config.maintenance.forbid_archived {
            merged.forbid_archived = true;
        }
        if !self.forbid_deprecated && config.maintenance.forbid_deprecated {
            merged.forbid_deprecated = true;
        }
        if !self.forbid_quarantined && config.maintenance.forbid_quarantined {
            merged.forbid_quarantined = true;
        }
        if !self.forbid_unmaintained && config.maintenance.forbid_unmaintained {
            merged.forbid_unmaintained = true;
        }
        if !self.maintenance_direct_only && config.maintenance.check_direct_only {
            merged.maintenance_direct_only = true;
        }
        if self.maintenance_cache_ttl == 1 {
            merged.maintenance_cache_ttl = config.maintenance.cache_ttl;
        }

        if !self.no_ci_detect && config.defaults.no_ci_detect {
            merged.no_ci_detect = true;
        }

        // CLI groups (non-empty) wins; otherwise fall back to config defaults.groups
        if merged.groups.is_empty() && !config.defaults.groups.is_empty() {
            merged.groups = config.defaults.groups.clone();
        }

        merged
    }
}

pub(crate) fn calculate_dependency_stats(
    dependencies: &[crate::dependency::scanner::ScannedDependency],
) -> DependencyStats {
    let parsed_deps: Vec<crate::parsers::ParsedDependency> = dependencies
        .iter()
        .map(|dep| crate::parsers::ParsedDependency {
            name: dep.name.clone(),
            version: dep.version.clone(),
            is_direct: dep.is_direct,
            source: dep.source.clone().into(),
            path: dep.path.clone(),
            source_file: dep.source_file.clone(),
        })
        .collect();

    DependencyStats::from_dependencies(&parsed_deps)
}

#[cfg(test)]
mod tests {
    use crate::cli::{AuditArgs, Cli, VulnerabilitySourceType};
    use crate::DetailLevel;
    use clap::Parser;

    fn parse_audit_args(args: &[&str]) -> AuditArgs {
        let cli = Cli::try_parse_from(std::iter::once("pysentry").chain(args.iter().copied()))
            .expect("valid CLI args");
        cli.audit_args
    }

    #[test]
    fn test_cli_compact_overrides_config_detailed() {
        // Config says detailed, but --compact on CLI must win.
        let args = parse_audit_args(&["--compact", "."]);
        let mut config = crate::config::Config::default();
        config.defaults.detailed = true;
        let merged = args.merge_with_config(&config);
        assert_eq!(merged.detail_level(), DetailLevel::Compact);
        assert!(
            !merged.detailed,
            "detailed must be cleared when --compact is explicit"
        );
    }

    #[test]
    fn test_cli_detailed_overrides_config_compact() {
        // Config says compact, but --detailed on CLI must win.
        let args = parse_audit_args(&["--detailed", "."]);
        let mut config = crate::config::Config::default();
        config.defaults.compact = true;
        let merged = args.merge_with_config(&config);
        assert_eq!(merged.detail_level(), DetailLevel::Detailed);
        assert!(
            !merged.compact,
            "compact must be cleared when --detailed is explicit"
        );
    }

    #[test]
    fn test_config_both_compact_and_detailed_resolves_to_detailed() {
        // clap's conflicts_with only guards CLI flags; a config file can set both bools with
        // no CLI flag to override them. detail_level must still resolve deterministically —
        // detailed wins — never panic or fall back to a dropped Normal level.
        let args = parse_audit_args(&["."]);
        let mut config = crate::config::Config::default();
        config.defaults.compact = true;
        config.defaults.detailed = true;
        let merged = args.merge_with_config(&config);
        assert!(merged.compact && merged.detailed);
        assert_eq!(merged.detail_level(), DetailLevel::Detailed);
    }

    #[test]
    fn test_display_config_overrides_default() {
        let args = parse_audit_args(&["."]);
        let mut config = crate::config::Config::default();
        config.defaults.display = "text".to_string();
        let merged = args.merge_with_config(&config);
        assert_eq!(merged.display_mode(), crate::DisplayMode::Text);
    }

    #[test]
    fn test_display_cli_text_overrides_config_table() {
        let args = parse_audit_args(&["--display", "text", "."]);
        let config = crate::config::Config::default(); // config display = "table"
        let merged = args.merge_with_config(&config);
        assert_eq!(merged.display_mode(), crate::DisplayMode::Text);
    }

    #[test]
    fn test_display_cli_table_overrides_config_text() {
        // Explicit --display table must win even when config says "text"
        let args = parse_audit_args(&["--display", "table", "."]);
        let mut config = crate::config::Config::default();
        config.defaults.display = "text".to_string();
        let merged = args.merge_with_config(&config);
        assert_eq!(merged.display_mode(), crate::DisplayMode::Table);
    }

    #[test]
    fn test_config_quiet_applied_when_no_cli_verbosity() {
        let args = parse_audit_args(&["."]);
        let mut config = crate::config::Config::default();
        config.output.quiet = true;
        let merged = args.merge_with_config(&config);
        assert!(merged.config_quiet);
        assert!(merged.is_quiet());
    }

    #[test]
    fn test_config_quiet_not_applied_by_default() {
        let args = parse_audit_args(&["."]);
        let config = crate::config::Config::default(); // output.quiet = false
        let merged = args.merge_with_config(&config);
        assert!(!merged.config_quiet);
        assert!(!merged.is_quiet());
    }

    #[test]
    fn test_verbose_flag_overrides_config_quiet() {
        let args = parse_audit_args(&["-v", "."]);
        let mut config = crate::config::Config::default();
        config.output.quiet = true;
        let merged = args.merge_with_config(&config);
        assert!(!merged.config_quiet); // config_quiet not applied when -v is present
        assert!(!merged.is_quiet()); // not quiet overall
    }

    #[test]
    fn test_sources_merge_from_config() {
        let args = parse_audit_args(&["."]);
        let mut config = crate::config::Config::default();
        config.sources.enabled = vec!["pypa".to_string()];
        let merged = args.merge_with_config(&config);
        assert_eq!(merged.sources, vec!["pypa".to_string()]);
        let resolved = merged.resolve_sources().unwrap();
        assert_eq!(resolved, vec![VulnerabilitySourceType::Pypa]);
    }

    #[test]
    fn test_sources_cli_overrides_config() {
        let args = parse_audit_args(&["--sources", "osv", "."]);
        let mut config = crate::config::Config::default();
        config.sources.enabled = vec!["pypa".to_string()];
        let merged = args.merge_with_config(&config);
        // CLI --sources takes precedence; config sources are not applied
        assert_eq!(merged.sources, vec!["osv".to_string()]);
        let resolved = merged.resolve_sources().unwrap();
        assert_eq!(resolved, vec![VulnerabilitySourceType::Osv]);
    }

    #[test]
    fn test_service_url_merge_from_config() {
        let args = parse_audit_args(&["."]);
        let mut config = crate::config::Config::default();
        config.sources.service_url = Some("https://osv.internal/v1".to_string());
        let merged = args.merge_with_config(&config);
        assert_eq!(
            merged.service_url,
            Some("https://osv.internal/v1".to_string())
        );
    }

    #[test]
    fn test_service_url_cli_overrides_config() {
        let args = parse_audit_args(&["--service-url", "https://cli.example/v1", "."]);
        let mut config = crate::config::Config::default();
        config.sources.service_url = Some("https://config.example/v1".to_string());
        let merged = args.merge_with_config(&config);
        assert_eq!(
            merged.service_url,
            Some("https://cli.example/v1".to_string())
        );
    }

    #[test]
    fn test_no_resolver_config_merge() {
        let args = parse_audit_args(&["."]);
        let mut config = crate::config::Config::default();
        config.resolver.no_resolver = true;
        let merged = args.merge_with_config(&config);
        assert!(merged.no_resolver);
        assert!(merged.direct_only);
    }

    #[test]
    fn test_no_resolver_cli_overrides_config() {
        let args = parse_audit_args(&["--no-resolver", "."]);
        let config = crate::config::Config::default();
        let merged = args.merge_with_config(&config);
        assert!(merged.no_resolver);
    }

    #[test]
    fn test_merge_groups_cli_overrides_config() {
        let args = parse_audit_args(&["--group", "polars", "."]);
        let mut config = crate::config::Config::default();
        config.defaults.groups = vec!["dev".to_string()];
        let merged = args.merge_with_config(&config);
        assert_eq!(merged.groups, vec!["polars"]);
    }

    #[test]
    fn test_merge_groups_config_fallback() {
        let args = parse_audit_args(&["."]);
        let mut config = crate::config::Config::default();
        config.defaults.groups = vec!["polars".to_string()];
        let merged = args.merge_with_config(&config);
        assert_eq!(merged.groups, vec!["polars"]);
    }

    #[test]
    fn test_merge_groups_both_empty_is_none() {
        let args = parse_audit_args(&["."]);
        let config = crate::config::Config::default();
        let merged = args.merge_with_config(&config);
        assert!(merged.groups.is_empty());
    }

    #[test]
    fn test_group_from_cli_does_not_force_direct_only() {
        let args = parse_audit_args(&["--group", "polars", "."]);
        let config = crate::config::Config::default();
        let merged = args.merge_with_config(&config);
        assert!(!merged.direct_only);
    }

    #[test]
    fn test_group_from_config_does_not_force_direct_only() {
        let args = parse_audit_args(&["."]);
        let mut config = crate::config::Config::default();
        config.defaults.groups = vec!["polars".to_string()];
        let merged = args.merge_with_config(&config);
        assert!(!merged.direct_only);
    }

    #[test]
    fn test_group_plus_explicit_direct_only_idempotent() {
        let args = parse_audit_args(&["--group", "polars", "--direct-only", "."]);
        let config = crate::config::Config::default();
        let merged = args.merge_with_config(&config);
        assert!(merged.direct_only);
    }

    #[test]
    fn test_fail_on_partial_config_relaxes_default() {
        let args = parse_audit_args(&["."]);
        let mut config = crate::config::Config::default();
        config.sources.fail_on_partial = false;
        let merged = args.merge_with_config(&config);
        assert!(merged.no_fail_on_partial);
    }

    #[test]
    fn test_fail_on_partial_strict_by_default() {
        let args = parse_audit_args(&["."]);
        let config = crate::config::Config::default(); // fail_on_partial = true
        let merged = args.merge_with_config(&config);
        assert!(!merged.no_fail_on_partial);
    }

    #[test]
    fn test_cli_no_fail_on_partial_overrides_config_strict() {
        let args = parse_audit_args(&["--no-fail-on-partial", "."]);
        let config = crate::config::Config::default(); // fail_on_partial = true
        let merged = args.merge_with_config(&config);
        assert!(merged.no_fail_on_partial);
    }

    #[test]
    fn test_ignore_packages_merged_from_config() {
        let args = parse_audit_args(&["."]);
        let mut config = crate::config::Config::default();
        config.ignore.packages = vec!["internal-pkg".to_string()];
        let merged = args.merge_with_config(&config);
        assert_eq!(merged.ignore_packages, vec!["internal-pkg"]);
    }

    // compact-XOR-detailed must hold on the merged/effective config (#174/Q16).
    // No guard exists in perform_audit: Config::validate rejects both-true at load,
    // and merge's precedence clears the loser. These cases pin that invariant.
    #[test]
    fn test_compact_detailed_mutually_exclusive_post_merge() {
        // CLI --compact + config detailed.
        let args = parse_audit_args(&["--compact", "."]);
        let mut config = crate::config::Config::default();
        config.defaults.detailed = true;
        let merged = args.merge_with_config(&config);
        assert!(!(merged.compact && merged.detailed));

        // CLI --detailed + config compact.
        let args = parse_audit_args(&["--detailed", "."]);
        let mut config = crate::config::Config::default();
        config.defaults.compact = true;
        let merged = args.merge_with_config(&config);
        assert!(!(merged.compact && merged.detailed));
    }

    #[test]
    fn test_empty_groups_does_not_force_direct_only() {
        let args = parse_audit_args(&["."]);
        let config = crate::config::Config::default();
        let merged = args.merge_with_config(&config);
        assert!(!merged.direct_only);
    }
}
