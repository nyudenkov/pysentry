// SPDX-License-Identifier: MIT

use async_trait::async_trait;
use std::fmt;

use crate::{Result, VulnerabilityDatabase};

pub(crate) use self::osv::OsvSource;
pub(crate) use self::pypa::PypaSource;
pub(crate) use self::pypi::PypiSource;

pub(crate) mod osv;
mod pypa;
mod pypi;
pub(crate) mod retry;

fn truncate_chars(value: &str, max_chars: usize) -> &str {
    for (count, (idx, _)) in value.char_indices().enumerate() {
        if count == max_chars {
            return &value[..idx];
        }
    }
    value
}

/// Trait for vulnerability data sources
#[async_trait]
pub trait VulnerabilityProvider: Send + Sync {
    /// Name of the vulnerability source
    fn name(&self) -> &'static str;

    /// Fetch vulnerabilities for the given packages
    async fn fetch_vulnerabilities(
        &self,
        packages: &[(String, String)], // (name, version) pairs
    ) -> Result<VulnerabilityDatabase>;
}

/// Enum representing available vulnerability sources
pub enum VulnerabilitySource {
    /// `PyPA` Advisory Database (ZIP download)
    PypaZip(PypaSource),
    /// PyPI JSON API
    Pypi(PypiSource),
    /// OSV.dev batch API
    Osv(OsvSource),
}

impl VulnerabilitySource {
    /// Create a new vulnerability source from the CLI option
    pub fn new(
        source: crate::types::VulnerabilitySource,
        cache: crate::AuditCache,
        no_cache: bool,
        http_config: crate::config::HttpConfig,
        vulnerability_ttl: u64,
    ) -> Self {
        match source {
            crate::types::VulnerabilitySource::Pypa => VulnerabilitySource::PypaZip(
                PypaSource::new(cache, no_cache, http_config, vulnerability_ttl),
            ),
            crate::types::VulnerabilitySource::Pypi => VulnerabilitySource::Pypi(PypiSource::new(
                cache,
                no_cache,
                http_config,
                vulnerability_ttl,
            )),
            crate::types::VulnerabilitySource::Osv => VulnerabilitySource::Osv(OsvSource::new(
                cache,
                no_cache,
                http_config,
                vulnerability_ttl,
            )),
        }
    }

    /// Get the name of the source
    pub fn name(&self) -> &'static str {
        match self {
            VulnerabilitySource::PypaZip(s) => s.name(),
            VulnerabilitySource::Pypi(s) => s.name(),
            VulnerabilitySource::Osv(s) => s.name(),
        }
    }

    /// Fetch vulnerabilities for the given packages
    pub async fn fetch_vulnerabilities(
        &self,
        packages: &[(String, String)],
    ) -> Result<VulnerabilityDatabase> {
        match self {
            VulnerabilitySource::PypaZip(s) => s.fetch_vulnerabilities(packages).await,
            VulnerabilitySource::Pypi(s) => s.fetch_vulnerabilities(packages).await,
            VulnerabilitySource::Osv(s) => s.fetch_vulnerabilities(packages).await,
        }
    }
}

impl fmt::Debug for VulnerabilitySource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "VulnerabilitySource({})", self.name())
    }
}
