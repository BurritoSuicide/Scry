//! Hybrid Analysis (Falcon Sandbox) public API v2.

mod client;

pub use client::HybridAnalysis;

use crate::indicator::IndicatorType;

pub const VENDOR_ID: &str = "hybrid_analysis";
pub const VENDOR_NAME: &str = "Hybrid Analysis";

pub const SUPPORTED: &[IndicatorType] = &[
    IndicatorType::Hash,
    IndicatorType::Domain,
    IndicatorType::IpAddress,
];
