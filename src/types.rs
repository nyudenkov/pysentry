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
