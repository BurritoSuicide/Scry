//! AlienVault / LevelBlue Open Threat Exchange (OTX) DirectConnect API.

mod client;

pub use client::AlienVaultOtx;

use crate::indicator::IndicatorType;

pub const VENDOR_ID: &str = "alienvault_otx";
pub const VENDOR_NAME: &str = "AlienVault OTX";

pub const SUPPORTED: &[IndicatorType] = &[
    IndicatorType::IpAddress,
    IndicatorType::Domain,
    IndicatorType::Hash,
];
