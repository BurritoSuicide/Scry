//! Indicator detection and classification.

mod detect;
mod subnet;

pub use detect::{classify_line, detect_file, DetectionSummary};
pub use subnet::{expand_cidr_to_first_ip, parse_cidr};

use serde::{Deserialize, Serialize};
use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IndicatorType {
    Email,
    IpAddress,
    Domain,
    Ja4,
    Hash,
    Unknown,
}

impl IndicatorType {
    pub fn label(self) -> &'static str {
        match self {
            Self::Email => "email",
            Self::IpAddress => "ip",
            Self::Domain => "domain",
            Self::Ja4 => "ja4",
            Self::Hash => "hash",
            Self::Unknown => "unknown",
        }
    }

    pub fn all_known() -> &'static [IndicatorType] {
        &[
            Self::Email,
            Self::IpAddress,
            Self::Domain,
            Self::Ja4,
            Self::Hash,
        ]
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
    /// Value used for vendor queries (first IP when expanded from a subnet).
    pub raw: String,
    pub kind: IndicatorType,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hash_kind: Option<HashKind>,
    pub line_no: usize,
    /// Original CIDR string when `raw` was expanded from a subnet.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub from_subnet: Option<String>,
}

impl Indicator {
    pub fn new(raw: impl Into<String>, kind: IndicatorType, line_no: usize) -> Self {
        Self {
            raw: raw.into(),
            kind,
            hash_kind: None,
            line_no,
            from_subnet: None,
        }
    }

    pub fn with_hash_kind(mut self, hash_kind: HashKind) -> Self {
        self.hash_kind = Some(hash_kind);
        self
    }

    pub fn with_subnet(mut self, cidr: impl Into<String>) -> Self {
        self.from_subnet = Some(cidr.into());
        self
    }
}

/// How a live result line should be colored in the feed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResultSeverity {
    Malicious,
    Suspicious,
    Clean,
    Error,
    Warning,
}
