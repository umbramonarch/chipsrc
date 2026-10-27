use std::path::PathBuf;
use thiserror::Error;

/// Canonical error type for `chipsrc-core`.
#[derive(Debug, Error)]
pub enum ChipsrcError {
    #[error("I/O error at {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("Repository path does not exist or is not a directory: {0}")]
    InvalidRepoPath(PathBuf),

    #[error("No supported source files discovered in repository: {0}")]
    NoSourceFilesFound(PathBuf),

    #[error("Bundle not found at {0}")]
    BundleNotFound(PathBuf),

    #[error("JSON serialization error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("Invalid regular expression '{pattern}': {source}")]
    InvalidRegex {
        pattern: String,
        #[source]
        source: regex::Error,
    },

    #[error("Tree-sitter parser configuration error: {0}")]
    ParserConfig(String),
}

impl ChipsrcError {
    pub fn io(path: impl Into<PathBuf>, source: std::io::Error) -> Self {
        Self::Io {
            path: path.into(),
            source,
        }
    }
}

pub type Result<T> = std::result::Result<T, ChipsrcError>;
