//! abuse.ch vendor — MalwareBazaar + URLhaus + ThreatFox behind one Auth-Key.

mod client;

pub use client::AbuseCh;

use crate::indicator::IndicatorType;

pub const VENDOR_ID: &str = "abusech";
pub const VENDOR_NAME: &str = "abuse.ch";

pub const SUPPORTED: &[IndicatorType] = &[
    IndicatorType::Hash,
    IndicatorType::Domain,
    IndicatorType::IpAddress,
];
