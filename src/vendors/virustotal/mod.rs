//! VirusTotal vendor integration (API v3).

mod client;

pub use client::VirusTotal;

use crate::indicator::IndicatorType;
use crate::rate_limit::RateLimitSpec;

pub const VENDOR_ID: &str = "virustotal";
pub const VENDOR_NAME: &str = "VirusTotal";

pub const SUPPORTED: &[IndicatorType] = &[
    IndicatorType::Hash,
    IndicatorType::IpAddress,
    IndicatorType::Email, // via search / related — limited on public API
];

/// Public API defaults. Premium keys still benefit from pacing; we can
/// specialize this later based on key tier stored in config.
pub fn public_rate_limit() -> RateLimitSpec {
    RateLimitSpec::public_vt()
}
