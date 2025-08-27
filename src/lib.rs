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

//! PySentry - Security vulnerability auditing for Python packages
//!
//! This crate provides comprehensive security vulnerability scanning for Python projects
//! using various vulnerability databases (PyPA, PyPI JSON API, OSV.dev).

pub use cache::{AuditCache, Cache, CacheBucket, CacheEntry, DatabaseMetadata, Freshness};
pub use config::{
    CacheConfig, CiConfig, Config, ConfigLoader, DefaultConfig, IgnoreConfig, OutputConfig,
    PackageIgnoreRule, ProjectConfig, ResolverConfig, SourcesConfig,
};
pub use dependency::scanner::{DependencyScanner, DependencyStats};
pub use output::report::{AuditReport, AuditSummary, ReportGenerator};
pub use providers::{VulnerabilityProvider, VulnerabilitySource};
pub use types::{
    AuditFormat, PackageName, ResolutionCacheEntry, ResolvedDependency, ResolverType,
    SeverityLevel, Version, VulnerabilitySourceType,
};
pub use vulnerability::{
    database::{Severity, VersionRange, Vulnerability, VulnerabilityDatabase, VulnerabilityMatch},
    matcher::{DatabaseStats, FixAnalysis, FixSuggestion, MatcherConfig, VulnerabilityMatcher},
};

pub mod cache;
pub mod cli;
pub mod config;
pub mod dependency;
pub mod output;
pub mod parsers;
pub mod providers;
pub mod types;
pub mod vulnerability;

mod error;

pub use error::{AuditError, Result};

#[cfg(feature = "python")]
mod python;

/// Main entry point for performing audits
///
/// This is a high-level API that coordinates the entire audit process:
/// 1. Dependency scanning
/// 2. Vulnerability database fetching
/// 3. Vulnerability matching
/// 4. Report generation
pub struct AuditEngine {
    scanner: DependencyScanner,
    cache: Option<AuditCache>,
}

impl AuditEngine {
    /// Create a new audit engine with default configuration
    pub fn new() -> Self {
        Self {
            scanner: DependencyScanner::default(),
            cache: None,
        }
    }

    /// Create a new audit engine with custom scanner configuration
    pub fn with_scanner(scanner: DependencyScanner) -> Self {
        Self {
            scanner,
            cache: None,
        }
    }

    /// Set cache for the audit engine
    pub fn with_cache(mut self, cache: AuditCache) -> Self {
        self.cache = Some(cache);
        self
    }

    /// Perform a complete audit of a Python project
    pub async fn audit_project<P: AsRef<std::path::Path>>(
        &self,
        project_path: P,
        source_type: VulnerabilitySourceType,
        min_severity: SeverityLevel,
        ignore_ids: &[String],
        direct_only: bool,
        include_withdrawn: bool,
    ) -> Result<AuditReport> {
        let project_path = project_path.as_ref();

        // 1. Scan dependencies
        let (dependencies, skipped_packages, parser_name) =
            self.scanner.scan_project(project_path).await?;
        let dependency_stats = self.scanner.get_stats(&dependencies);
        let warnings =
            self.scanner
                .validate_dependencies(&dependencies, &skipped_packages, &parser_name);

        // 2. Create vulnerability source
        let cache = self.cache.as_ref().cloned().unwrap_or_else(|| {
            let temp_dir = std::env::temp_dir().join("pysentry-cache");
            AuditCache::new(temp_dir)
        });

        let vuln_source = VulnerabilitySource::new(source_type, cache, false);

        // 3. Fetch vulnerabilities
        let packages: Vec<(String, String)> = dependencies
            .iter()
            .map(|dep| (dep.name.to_string(), dep.version.to_string()))
            .collect();

        let database = vuln_source.fetch_vulnerabilities(&packages).await?;

        // 4. Match vulnerabilities
        let matcher_config = MatcherConfig::new(
            min_severity,
            ignore_ids.to_vec(),
            direct_only,
            include_withdrawn,
        );
        let matcher = VulnerabilityMatcher::new(database, matcher_config);

        let matches = matcher.find_vulnerabilities(&dependencies)?;
        let filtered_matches = matcher.filter_matches(matches);

        let database_stats = matcher.get_database_stats();
        let fix_analysis = matcher.analyze_fixes(&filtered_matches);

        // 5. Create report
        let report = AuditReport::new(
            dependency_stats,
            database_stats,
            filtered_matches,
            fix_analysis,
            warnings,
        );

        Ok(report)
    }
}

impl Default for AuditEngine {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_audit_engine_creation() {
        let engine = AuditEngine::new();
        assert!(engine.cache.is_none());
    }

    #[test]
    fn test_audit_engine_with_cache() {
        let cache = AuditCache::new(std::env::temp_dir().join("test-cache"));
        let engine = AuditEngine::new().with_cache(cache);
        assert!(engine.cache.is_some());
    }
}
