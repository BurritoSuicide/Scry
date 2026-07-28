//! AbuseIPDB community IP reputation (API v2).

mod client;

pub use client::AbuseIpdb;

use crate::indicator::IndicatorType;

pub const VENDOR_ID: &str = "abuseipdb";
pub const VENDOR_NAME: &str = "AbuseIPDB";

pub const SUPPORTED: &[IndicatorType] = &[IndicatorType::IpAddress];
