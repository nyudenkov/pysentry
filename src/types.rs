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

use serde::{Deserialize, Serialize};
use std::fmt;
use std::str::FromStr;

#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct PackageName(String);

impl PackageName {
    pub fn new(name: &str) -> Self {
        let normalized = name.to_lowercase().replace('_', "-");
        Self(normalized)
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for PackageName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<&str> for PackageName {
    fn from(name: &str) -> Self {
        Self::new(name)
    }
}

impl From<String> for PackageName {
    fn from(name: String) -> Self {
        Self::new(&name)
    }
}

impl FromStr for PackageName {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // Validate Python package names according to PEP 508
        // Package names should only contain letters, numbers, periods, hyphens, and underscores
        if s.is_empty() {
            return Err("Package name cannot be empty".to_string());
        }

        let is_valid = s
            .chars()
            .all(|c| c.is_alphanumeric() || c == '.' || c == '-' || c == '_');

        if is_valid {
            Ok(Self::new(s))
        } else {
            Err(format!("Invalid package name: '{s}'. Package names can only contain letters, numbers, periods, hyphens, and underscores."))
        }
    }
}

/// Version type (using pep440_rs::Version as Version)
pub use pep440_rs::Version;

/// Audit output formats
#[derive(Debug, Clone)]
pub enum AuditFormat {
    Human,
    Json,
    Sarif,
    Markdown,
}

/// Severity levels
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum SeverityLevel {
    Low,
    Medium,
    High,
    Critical,
}

/// Vulnerability sources
#[derive(Debug, Clone)]
pub enum VulnerabilitySource {
    Pypa,
    Pypi,
    Osv,
}

/// Vulnerability source types (for CLI compatibility)
pub type VulnerabilitySourceType = VulnerabilitySource;

/// Resolution cache entry containing resolved output and essential metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResolutionCacheEntry {
    /// The resolved output string
    pub output: String,
    /// Type of resolver used (uv, pip-tools)
    pub resolver_type: ResolverType,
    /// Version of the resolver tool
    pub resolver_version: String,
    /// Python version used for resolution
    pub python_version: String,
    /// List of resolved dependencies
    pub dependencies: Vec<ResolvedDependency>,
}

/// Individual resolved dependency
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResolvedDependency {
    /// Package name
    pub name: String,
    /// Resolved version
    pub version: String,
    /// Whether this is a direct dependency (vs transitive)
    pub is_direct: bool,
    /// Source file that contained this dependency
    pub source_file: std::path::PathBuf,
    /// Any extras specified for this dependency
    pub extras: Vec<String>,
    /// Environment markers for this dependency
    pub markers: Option<String>,
}

/// Resolver types for caching and registry
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ResolverType {
    /// UV resolver (Rust-based, fastest)
    Uv,
    /// pip-tools resolver (Python-based, widely used)
    PipTools,
}

impl fmt::Display for ResolverType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ResolverType::Uv => write!(f, "uv"),
            ResolverType::PipTools => write!(f, "pip-tools"),
        }
    }
}

impl From<&str> for ResolverType {
    fn from(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "uv" => ResolverType::Uv,
            "pip-tools" | "pip_tools" | "piptools" => ResolverType::PipTools,
            _ => ResolverType::Uv, // Default fallback
        }
    }
}
