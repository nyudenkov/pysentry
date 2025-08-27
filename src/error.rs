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

use thiserror::Error;

/// Result type for audit operations
pub type Result<T> = std::result::Result<T, AuditError>;

/// Audit error types
#[derive(Debug, Error)]
pub enum AuditError {
    #[error("No dependency information found. Generate a lock file (uv.lock, poetry.lock, Pipfile.lock, pylock.toml) or add pyproject.toml/requirements.txt")]
    NoDependencyInfo,

    #[error("Failed to download vulnerability database: {0}")]
    DatabaseDownload(Box<dyn std::error::Error + Send + Sync>),

    #[error("Failed to read project dependencies: {0}")]
    DependencyRead(Box<dyn std::error::Error + Send + Sync>),

    #[error("Failed to parse lock file: {0}")]
    LockFileParse(#[from] toml::de::Error),

    #[error("Invalid dependency specification: {0}")]
    InvalidDependency(String),

    #[error("Cache operation failed: {0}")]
    Cache(#[from] anyhow::Error),

    #[error("JSON operation failed: {0}")]
    Json(#[from] serde_json::Error),

    #[error("HTTP request failed: {0}")]
    Http(#[from] reqwest::Error),

    #[error("IO operation failed: {0}")]
    Io(#[from] std::io::Error),

    #[error("Version parsing failed: {0}")]
    Version(#[from] pep440_rs::VersionParseError),

    #[error("PyPA advisory parsing failed: {0}")]
    PypaAdvisoryParse(String, #[source] Box<dyn std::error::Error + Send + Sync>),

    // UV resolver specific errors
    #[error("UV dependency resolver not found. Install with: pip install uv")]
    UvNotAvailable,

    #[error("No requirements.txt files found in the project directory")]
    NoRequirementsFound,

    #[error("UV dependency resolution timed out after 5 minutes")]
    UvTimeout,

    #[error("UV execution failed: {0}")]
    UvExecutionFailed(String),

    #[error("UV dependency resolution failed: {0}")]
    UvResolutionFailed(String),

    #[error("UV resolution produced no dependencies")]
    EmptyResolution,

    // pip-tools resolver specific errors
    #[error("pip-tools dependency resolver not found. Install with: pip install pip-tools")]
    PipToolsNotAvailable,

    #[error("pip-tools dependency resolution timed out after 5 minutes")]
    PipToolsTimeout,

    #[error("pip-tools execution failed: {0}")]
    PipToolsExecutionFailed(String),

    #[error("pip-tools dependency resolution failed: {0}")]
    PipToolsResolutionFailed(String),

    #[error("Audit error: {message}")]
    Other { message: String },
}

impl AuditError {
    /// Create a new "other" error with a custom message
    pub fn other<S: Into<String>>(message: S) -> Self {
        Self::Other {
            message: message.into(),
        }
    }
}
