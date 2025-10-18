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

//! Configuration file support for PySentry
//!
//! This module provides TOML-based configuration file support for PySentry,
//! allowing users to define default settings, ignore rules, and project-specific
//! configurations in `.pysentry.toml` files.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    #[serde(default = "default_version")]
    pub version: u32,

    #[serde(default)]
    pub defaults: DefaultConfig,

    #[serde(default)]
    pub sources: SourcesConfig,

    #[serde(default)]
    pub resolver: ResolverConfig,

    #[serde(default)]
    pub cache: CacheConfig,

    #[serde(default)]
    pub output: OutputConfig,

    #[serde(default)]
    pub ignore: IgnoreConfig,

    #[serde(default)]
    pub projects: Vec<ProjectConfig>,

    #[serde(default)]
    pub ci: CiConfig,

    #[serde(default)]
    pub http: HttpConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DefaultConfig {
    #[serde(default = "default_format")]
    pub format: String,

    #[serde(default = "default_severity")]
    pub severity: String,

    #[serde(default = "default_fail_on")]
    pub fail_on: String,

    #[serde(default = "default_scope")]
    pub scope: String,

    #[serde(default)]
    pub direct_only: bool,

    #[serde(default)]
    pub detailed: bool,

    #[serde(default)]
    pub include_withdrawn: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SourcesConfig {
    #[serde(default = "default_sources")]
    pub enabled: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResolverConfig {
    #[serde(default = "default_resolver_type", rename = "type")]
    pub resolver_type: String,

    #[serde(default = "default_fallback_resolver")]
    pub fallback: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CacheConfig {
    #[serde(default = "default_cache_enabled")]
    pub enabled: bool,

    pub directory: Option<String>,

    #[serde(default = "default_resolution_ttl")]
    pub resolution_ttl: u64,

    #[serde(default = "default_vulnerability_ttl")]
    pub vulnerability_ttl: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OutputConfig {
    #[serde(default)]
    pub quiet: bool,

    #[serde(default)]
    pub verbose: bool,

    #[serde(default = "default_color")]
    pub color: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct IgnoreConfig {
    #[serde(default)]
    pub ids: Vec<String>,

    #[serde(default)]
    pub while_no_fix: Vec<String>,

    #[serde(default)]
    pub patterns: Vec<String>,

    #[serde(default)]
    pub packages: Vec<PackageIgnoreRule>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PackageIgnoreRule {
    pub name: String,

    pub versions: Option<Vec<String>>,

    #[serde(default)]
    pub ids: Vec<String>,

    pub reason: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProjectConfig {
    pub path: String,

    pub severity: Option<String>,

    pub fail_on: Option<String>,

    pub sources: Option<Vec<String>>,

    #[serde(default)]
    pub ignore_ids: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CiConfig {
    #[serde(default = "default_ci_enabled")]
    pub enabled: String,

    #[serde(default = "default_ci_format")]
    pub format: String,

    #[serde(default = "default_ci_fail_on")]
    pub fail_on: String,

    #[serde(default = "default_ci_annotations")]
    pub annotations: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpConfig {
    #[serde(default = "default_http_timeout")]
    pub timeout: u64,

    #[serde(default = "default_http_connect_timeout")]
    pub connect_timeout: u64,

    #[serde(default = "default_http_max_retries")]
    pub max_retries: u32,

    #[serde(default = "default_http_retry_initial_backoff")]
    pub retry_initial_backoff: u64,

    #[serde(default = "default_http_retry_max_backoff")]
    pub retry_max_backoff: u64,

    #[serde(default = "default_http_show_progress")]
    pub show_progress: bool,
}

pub struct ConfigLoader {
    pub config_path: Option<PathBuf>,

    pub config: Config,
}

impl Default for ConfigLoader {
    fn default() -> Self {
        Self::new()
    }
}

impl ConfigLoader {
    pub fn new() -> Self {
        Self {
            config_path: None,
            config: Config::default(),
        }
    }

    pub fn load() -> Result<Self> {
        Self::load_with_options(false)
    }

    pub fn load_with_options(disable_config: bool) -> Result<Self> {
        let mut loader = Self::new();

        if disable_config || std::env::var("PYSENTRY_NO_CONFIG").is_ok() {
            return Ok(loader);
        }

        if let Ok(env_config_path) = std::env::var("PYSENTRY_CONFIG") {
            let config_path = PathBuf::from(env_config_path);
            if config_path.exists() {
                loader.config = Self::load_config_file(&config_path).with_context(|| {
                    format!(
                        "Failed to load config from environment variable PYSENTRY_CONFIG: {}",
                        config_path.display()
                    )
                })?;
                loader.config_path = Some(config_path);
                return Ok(loader);
            } else {
                anyhow::bail!(
                    "Config file specified in PYSENTRY_CONFIG does not exist: {}",
                    config_path.display()
                );
            }
        }

        if let Some(config_path) = Self::discover_config_file()? {
            loader.config = Self::load_config_file(&config_path)
                .with_context(|| format!("Failed to load config from {}", config_path.display()))?;
            loader.config_path = Some(config_path);
        }

        Ok(loader)
    }

    pub fn load_from_file<P: AsRef<Path>>(path: P) -> Result<Self> {
        let config_path = path.as_ref().to_path_buf();
        let config = Self::load_config_file(&config_path)
            .with_context(|| format!("Failed to load config from {}", config_path.display()))?;

        Ok(Self {
            config_path: Some(config_path),
            config,
        })
    }

    pub fn discover_config_file() -> Result<Option<PathBuf>> {
        let config_names = [".pysentry.toml"];

        if let Ok(current_dir) = std::env::current_dir() {
            let mut dir = current_dir.as_path();

            loop {
                for config_name in &config_names {
                    let config_path = dir.join(config_name);
                    if config_path.exists() {
                        return Ok(Some(config_path));
                    }
                }

                if dir.join(".git").exists() || dir.parent().is_none() {
                    break;
                }

                dir = dir.parent().unwrap();
            }
        }

        if let Some(config_dir) = dirs::config_dir() {
            let user_config = config_dir.join("pysentry").join("config.toml");
            if user_config.exists() {
                return Ok(Some(user_config));
            }
        }

        #[cfg(unix)]
        {
            let system_config = PathBuf::from("/etc/pysentry/config.toml");
            if system_config.exists() {
                return Ok(Some(system_config));
            }
        }

        Ok(None)
    }

    fn load_config_file<P: AsRef<Path>>(path: P) -> Result<Config> {
        let content = fs_err::read_to_string(&path)
            .with_context(|| format!("Failed to read config file: {}", path.as_ref().display()))?;

        let config: Config = toml::from_str(&content).with_context(|| {
            format!(
                "Failed to parse TOML config file: {}",
                path.as_ref().display()
            )
        })?;

        config.validate()?;

        Ok(config)
    }

    pub fn config_path_display(&self) -> String {
        match &self.config_path {
            Some(path) => path.display().to_string(),
            None => "<built-in defaults>".to_string(),
        }
    }
}

impl Config {
    pub fn validate(&self) -> Result<()> {
        if self.version == 0 {
            anyhow::bail!("Configuration version cannot be 0. Please set version = 1.");
        }
        if self.version > 1 {
            anyhow::bail!("Unsupported configuration version: {}. This version of PySentry supports version 1.", self.version);
        }

        match self.defaults.format.as_str() {
            "human" | "json" | "sarif" | "markdown" => {}
            _ => anyhow::bail!(
                "Invalid format '{}'. Valid formats: human, json, sarif, markdown",
                self.defaults.format
            ),
        }

        self.validate_severity(&self.defaults.severity, "defaults.severity")?;
        self.validate_severity(&self.defaults.fail_on, "defaults.fail_on")?;

        match self.defaults.scope.as_str() {
            "main" | "all" => {}
            _ => anyhow::bail!(
                "Invalid scope '{}'. Valid scopes: main, all",
                self.defaults.scope
            ),
        }

        if self.sources.enabled.is_empty() {
            anyhow::bail!(
                "At least one vulnerability source must be enabled. Valid sources: pypa, pypi, osv"
            );
        }

        for source in &self.sources.enabled {
            match source.as_str() {
                "pypa" | "pypi" | "osv" => {}
                _ => anyhow::bail!(
                    "Invalid vulnerability source '{}'. Valid sources: pypa, pypi, osv",
                    source
                ),
            }
        }

        match self.resolver.resolver_type.as_str() {
            "uv" | "pip-tools" => {}
            _ => anyhow::bail!(
                "Invalid resolver type '{}'. Valid types: uv, pip-tools",
                self.resolver.resolver_type
            ),
        }

        match self.resolver.fallback.as_str() {
            "uv" | "pip-tools" => {}
            _ => anyhow::bail!(
                "Invalid fallback resolver '{}'. Valid types: uv, pip-tools",
                self.resolver.fallback
            ),
        }

        if self.cache.resolution_ttl == 0 {
            anyhow::bail!("Resolution cache TTL must be greater than 0 hours");
        }
        if self.cache.vulnerability_ttl == 0 {
            anyhow::bail!("Vulnerability cache TTL must be greater than 0 hours");
        }

        match self.output.color.as_str() {
            "auto" | "always" | "never" => {}
            _ => anyhow::bail!(
                "Invalid color setting '{}'. Valid settings: auto, always, never",
                self.output.color
            ),
        }

        match self.ci.enabled.as_str() {
            "auto" | "enabled" | "disabled" => {}
            _ => anyhow::bail!(
                "Invalid CI enabled setting '{}'. Valid settings: auto, enabled, disabled",
                self.ci.enabled
            ),
        }

        match self.ci.format.as_str() {
            "human" | "json" | "sarif" | "markdown" => {}
            _ => anyhow::bail!(
                "Invalid CI format '{}'. Valid formats: human, json, sarif, markdown",
                self.ci.format
            ),
        }

        self.validate_severity(&self.ci.fail_on, "ci.fail_on")?;

        if self.http.timeout == 0 {
            anyhow::bail!("HTTP timeout must be greater than 0 seconds");
        }
        if self.http.connect_timeout == 0 {
            anyhow::bail!("HTTP connect timeout must be greater than 0 seconds");
        }
        if self.http.retry_initial_backoff == 0 {
            anyhow::bail!("HTTP retry initial backoff must be greater than 0 seconds");
        }
        if self.http.retry_max_backoff < self.http.retry_initial_backoff {
            anyhow::bail!(
                "HTTP retry max backoff ({}) must be greater than or equal to initial backoff ({})",
                self.http.retry_max_backoff,
                self.http.retry_initial_backoff
            );
        }

        for (i, pattern) in self.ignore.patterns.iter().enumerate() {
            if let Err(e) = regex::Regex::new(pattern) {
                anyhow::bail!(
                    "Invalid regex pattern in ignore.patterns[{}]: '{}' - {}",
                    i,
                    pattern,
                    e
                );
            }
        }

        for (i, project) in self.projects.iter().enumerate() {
            if project.path.is_empty() {
                anyhow::bail!("Project path cannot be empty in projects[{}]", i);
            }

            if let Some(ref severity) = project.severity {
                self.validate_severity(severity, &format!("projects[{i}].severity"))?;
            }

            if let Some(ref fail_on) = project.fail_on {
                self.validate_severity(fail_on, &format!("projects[{i}].fail_on"))?;
            }

            if let Some(ref sources) = project.sources {
                if sources.is_empty() {
                    anyhow::bail!("Project sources cannot be empty in projects[{}]. Remove the field or provide at least one source.", i);
                }
                for source in sources {
                    match source.as_str() {
                        "pypa" | "pypi" | "osv" => {},
                        _ => anyhow::bail!("Invalid vulnerability source '{}' in projects[{}].sources. Valid sources: pypa, pypi, osv", source, i),
                    }
                }
            }
        }

        Ok(())
    }

    fn validate_severity(&self, severity: &str, field_name: &str) -> Result<()> {
        match severity {
            "low" | "medium" | "high" | "critical" => Ok(()),
            _ => anyhow::bail!(
                "Invalid severity '{}' in {}. Valid severities: low, medium, high, critical",
                severity,
                field_name
            ),
        }
    }

    pub fn generate_default_toml() -> String {
        let config = Config::default();
        toml::to_string_pretty(&config)
            .unwrap_or_else(|_| "# Failed to generate default configuration".to_string())
    }
}

impl Default for Config {
    fn default() -> Self {
        Self {
            version: default_version(),
            defaults: DefaultConfig::default(),
            sources: SourcesConfig::default(),
            resolver: ResolverConfig::default(),
            cache: CacheConfig::default(),
            output: OutputConfig::default(),
            ignore: IgnoreConfig::default(),
            projects: Vec::new(),
            ci: CiConfig::default(),
            http: HttpConfig::default(),
        }
    }
}

impl Default for DefaultConfig {
    fn default() -> Self {
        Self {
            format: default_format(),
            severity: default_severity(),
            fail_on: default_fail_on(),
            scope: default_scope(),
            direct_only: false,
            detailed: false,
            include_withdrawn: false,
        }
    }
}

impl Default for SourcesConfig {
    fn default() -> Self {
        Self {
            enabled: default_sources(),
        }
    }
}

impl Default for ResolverConfig {
    fn default() -> Self {
        Self {
            resolver_type: default_resolver_type(),
            fallback: default_fallback_resolver(),
        }
    }
}

impl Default for CacheConfig {
    fn default() -> Self {
        Self {
            enabled: default_cache_enabled(),
            directory: None,
            resolution_ttl: default_resolution_ttl(),
            vulnerability_ttl: default_vulnerability_ttl(),
        }
    }
}

impl Default for OutputConfig {
    fn default() -> Self {
        Self {
            quiet: false,
            verbose: false,
            color: default_color(),
        }
    }
}

impl Default for CiConfig {
    fn default() -> Self {
        Self {
            enabled: default_ci_enabled(),
            format: default_ci_format(),
            fail_on: default_ci_fail_on(),
            annotations: default_ci_annotations(),
        }
    }
}

impl Default for HttpConfig {
    fn default() -> Self {
        Self {
            timeout: default_http_timeout(),
            connect_timeout: default_http_connect_timeout(),
            max_retries: default_http_max_retries(),
            retry_initial_backoff: default_http_retry_initial_backoff(),
            retry_max_backoff: default_http_retry_max_backoff(),
            show_progress: default_http_show_progress(),
        }
    }
}

fn default_version() -> u32 {
    1
}
fn default_format() -> String {
    "human".to_string()
}
fn default_severity() -> String {
    "low".to_string()
}
fn default_fail_on() -> String {
    "medium".to_string()
}
fn default_scope() -> String {
    "all".to_string()
}
fn default_sources() -> Vec<String> {
    vec!["pypa".to_string()]
}
fn default_resolver_type() -> String {
    "uv".to_string()
}
fn default_fallback_resolver() -> String {
    "pip-tools".to_string()
}
fn default_cache_enabled() -> bool {
    true
}
fn default_resolution_ttl() -> u64 {
    24
}
fn default_vulnerability_ttl() -> u64 {
    48
}
fn default_color() -> String {
    "auto".to_string()
}
fn default_ci_enabled() -> String {
    "auto".to_string()
}
fn default_ci_format() -> String {
    "sarif".to_string()
}
fn default_ci_fail_on() -> String {
    "high".to_string()
}
fn default_ci_annotations() -> bool {
    true
}
fn default_http_timeout() -> u64 {
    120
}
fn default_http_connect_timeout() -> u64 {
    30
}
fn default_http_max_retries() -> u32 {
    3
}
fn default_http_retry_initial_backoff() -> u64 {
    1
}
fn default_http_retry_max_backoff() -> u64 {
    60
}
fn default_http_show_progress() -> bool {
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    #[test]
    fn test_config_load_from_file() {
        let temp_dir = TempDir::new().unwrap();
        let config_path = temp_dir.path().join(".pysentry.toml");

        let config_content = r#"
version = 1

[defaults]
format = "markdown"
severity = "medium"
fail_on = "low"

[sources]
enabled = ["pypa", "pypi", "osv"]

[cache]
enabled = false
"#;

        fs::write(&config_path, config_content).unwrap();

        let loader = ConfigLoader::load_from_file(&config_path).unwrap();

        assert_eq!(loader.config.defaults.format, "markdown");
        assert_eq!(loader.config.defaults.severity, "medium");
        assert_eq!(loader.config.defaults.fail_on, "low");
        assert_eq!(loader.config.sources.enabled, vec!["pypa", "pypi", "osv"]);
        assert!(!loader.config.cache.enabled);
        assert!(loader.config_path.is_some());
    }

    #[test]
    fn test_config_default_values() {
        let config = Config::default();

        assert_eq!(config.version, 1);
        assert_eq!(config.defaults.format, "human");
        assert_eq!(config.defaults.severity, "low");
        assert_eq!(config.defaults.fail_on, "medium");
        assert_eq!(config.sources.enabled, vec!["pypa"]);
        assert!(config.cache.enabled);
    }

    #[test]
    fn test_config_validation() {
        let mut config = Config::default();

        // Valid config should pass
        assert!(config.validate().is_ok());

        // Invalid format
        config.defaults.format = "invalid".to_string();
        assert!(config.validate().is_err());
        config.defaults.format = "human".to_string();

        // Invalid severity
        config.defaults.severity = "invalid".to_string();
        assert!(config.validate().is_err());
        config.defaults.severity = "low".to_string();

        // Invalid source
        config.sources.enabled = vec!["invalid".to_string()];
        assert!(config.validate().is_err());
        config.sources.enabled = vec!["pypa".to_string()];

        // Empty sources
        config.sources.enabled = vec![];
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_config_loader_with_no_config() {
        // Test that loader works even when no config file exists
        let loader = ConfigLoader::load_with_options(true).unwrap();
        assert!(loader.config_path.is_none());
        assert_eq!(loader.config.defaults.format, "human");
    }
}
