use thiserror::Error;

pub type Result<T> = std::result::Result<T, CharonError>;

#[derive(Debug, Error)]
pub enum CharonError {
    #[error("{0}")]
    Message(String),

    #[error("config error: {0}")]
    Config(String),

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),

    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("vendor '{vendor}' does not support {indicator_type} indicators")]
    UnsupportedIndicator {
        vendor: String,
        indicator_type: String,
    },

    #[error("no API key configured for vendor '{0}'")]
    MissingApiKey(String),

    #[error("rate limited by vendor '{0}'")]
    RateLimited(String),
}

impl CharonError {
    pub fn msg(s: impl Into<String>) -> Self {
        Self::Message(s.into())
    }
}
