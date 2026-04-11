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

        let mut ignore_ids = self.ignore_ids.clone();
        ignore_ids.extend(config.ignore.ids.clone());
        merged.ignore_ids = ignore_ids;

        let mut ignore_while_no_fix = self.ignore_while_no_fix.clone();
        ignore_while_no_fix.extend(config.ignore.while_no_fix.clone());
        merged.ignore_while_no_fix = ignore_while_no_fix;

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

        if !self.no_ci_detect && config.defaults.no_ci_detect {
            merged.no_ci_detect = true;
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
}
