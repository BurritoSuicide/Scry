//! GreyNoise Community API (IP context).

mod client;

pub use client::GreyNoise;

use crate::indicator::IndicatorType;

pub const VENDOR_ID: &str = "greynoise";
pub const VENDOR_NAME: &str = "GreyNoise";

pub const SUPPORTED: &[IndicatorType] = &[IndicatorType::IpAddress];
