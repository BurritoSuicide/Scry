//! VirusTotal vendor integration (API v3).

mod client;

pub use client::VirusTotal;

use crate::indicator::IndicatorType;

pub const VENDOR_ID: &str = "virustotal";
pub const VENDOR_NAME: &str = "VirusTotal";

pub const SUPPORTED: &[IndicatorType] = &[
    IndicatorType::Hash,
    IndicatorType::IpAddress,
    IndicatorType::Domain,
    IndicatorType::Email, // via search / related — limited on public API
];
