use thiserror::Error;

/// Result type for audit operations
pub type Result<T> = std::result::Result<T, AuditError>;

/// Audit error types
#[derive(Debug, Error)]
pub enum AuditError {
    #[error("No dependency information found. Run 'uv lock' to generate a lock file")]
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
