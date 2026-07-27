//! Indicator detection and classification.

mod detect;

pub use detect::{classify_line, detect_file, DetectionSummary};

use serde::{Deserialize, Serialize};
use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IndicatorType {
    Email,
    IpAddress,
    Ja4,
    Hash,
    Unknown,
}

impl IndicatorType {
    pub fn label(self) -> &'static str {
        match self {
            Self::Email => "email",
            Self::IpAddress => "ip",
            Self::Ja4 => "ja4",
            Self::Hash => "hash",
            Self::Unknown => "unknown",
        }
    }

    pub fn all_known() -> &'static [IndicatorType] {
        &[Self::Email, Self::IpAddress, Self::Ja4, Self::Hash]
    }
}

impl fmt::Display for IndicatorType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HashKind {
    Md5,
    Sha1,
    Sha256,
    Sha512,
}

impl HashKind {
    pub fn label(self) -> &'static str {
        match self {
            Self::Md5 => "md5",
            Self::Sha1 => "sha1",
            Self::Sha256 => "sha256",
            Self::Sha512 => "sha512",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Indicator {
    pub raw: String,
    pub kind: IndicatorType,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hash_kind: Option<HashKind>,
    pub line_no: usize,
}

impl Indicator {
    pub fn new(raw: impl Into<String>, kind: IndicatorType, line_no: usize) -> Self {
        Self {
            raw: raw.into(),
            kind,
            hash_kind: None,
            line_no,
        }
    }

    pub fn with_hash_kind(mut self, hash_kind: HashKind) -> Self {
        self.hash_kind = Some(hash_kind);
        self
    }
}
