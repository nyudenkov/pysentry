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

use async_trait::async_trait;
use std::fmt;

use crate::{Result, VulnerabilityDatabase};

pub(crate) use self::osv::OsvSource;
pub(crate) use self::pypa::PypaSource;
pub(crate) use self::pypi::PypiSource;

pub(crate) mod osv;
mod pypa;
mod pypi;

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
    ) -> Self {
        match source {
            crate::types::VulnerabilitySource::Pypa => {
                // PypaSource is now self-contained with direct PyPA parsing
                VulnerabilitySource::PypaZip(PypaSource::new(cache, no_cache))
            }
            crate::types::VulnerabilitySource::Pypi => {
                // PypiSource queries PyPI JSON API directly
                VulnerabilitySource::Pypi(PypiSource::new(cache, no_cache))
            }
            crate::types::VulnerabilitySource::Osv => {
                // OsvSource directly queries OSV API
                VulnerabilitySource::Osv(OsvSource::new(cache, no_cache))
            }
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
