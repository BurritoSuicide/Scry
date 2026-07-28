use super::{SUPPORTED, VENDOR_ID, VENDOR_NAME};
use crate::error::{ScryError, Result};
use crate::indicator::{Indicator, IndicatorType};
use crate::vendors::{OsintVendor, VendorResult};
use async_trait::async_trait;
use reqwest::StatusCode;
use serde_json::Value;
use std::collections::BTreeMap;

const API_BASE: &str = "https://otx.alienvault.com/api/v1";

#[derive(Debug, Clone, Default)]
pub struct AlienVaultOtx {
    client: reqwest::Client,
}

impl AlienVaultOtx {
    pub fn new() -> Self {
        Self {
            client: reqwest::Client::new(),
        }
    }

    fn indicator_path(indicator: &Indicator) -> Result<String> {
        match indicator.kind {
            IndicatorType::IpAddress => {
                let kind = if indicator.raw.contains(':') {
                    "IPv6"
                } else {
                    "IPv4"
                };
                Ok(format!(
                    "{API_BASE}/indicators/{kind}/{}/general",
                    indicator.raw
                ))
            }
            IndicatorType::Domain => Ok(format!(
                "{API_BASE}/indicators/hostname/{}/general",
                indicator.raw
            )),
            IndicatorType::Hash => Ok(format!(
                "{API_BASE}/indicators/file/{}/general",
                indicator.raw
            )),
            other => Err(ScryError::UnsupportedIndicator {
                vendor: VENDOR_NAME.into(),
                indicator_type: other.to_string(),
            }),
        }
    }

    async fn get_general(&self, url: &str, api_key: &str) -> Result<Value> {
        let response = self
            .client
            .get(url)
            .header("X-OTX-API-KEY", api_key)
            .header("Accept", "application/json")
            .send()
            .await?;

        let status = response.status();
        let body = response.text().await.unwrap_or_default();

        if status == StatusCode::TOO_MANY_REQUESTS {
            return Err(ScryError::RateLimited(VENDOR_ID.into()));
        }
        if status == StatusCode::UNAUTHORIZED || status == StatusCode::FORBIDDEN {
            return Err(ScryError::msg(format!(
                "AlienVault OTX auth failed ({status}): {}",
                truncate(&body, 180)
            )));
        }
        if status == StatusCode::NOT_FOUND {
            return Ok(serde_json::json!({
                "pulse_info": { "count": 0, "pulses": [] },
                "scry_note": "not_found"
            }));
        }
        if !status.is_success() {
            return Err(ScryError::msg(format!(
                "AlienVault OTX HTTP {status}: {}",
                truncate(&body, 200)
            )));
        }

        Ok(serde_json::from_str(&body).unwrap_or_else(|_| {
            serde_json::json!({ "raw_text": body })
        }))
    }

    fn summarize(raw: &Value) -> (String, BTreeMap<String, String>) {
        let mut fields = BTreeMap::new();

        let pulse_count = raw["pulse_info"]["count"]
            .as_u64()
            .or_else(|| {
                raw["pulse_info"]["pulses"]
                    .as_array()
                    .map(|a| a.len() as u64)
            })
            .unwrap_or(0);

        // Pulses are community threat intel — any hit is suspicious; several → malicious.
        let (malicious, suspicious) = if pulse_count >= 3 {
            (1, 0)
        } else if pulse_count > 0 {
            (0, 1)
        } else {
            (0, 0)
        };

        fields.insert("pulse_count".into(), pulse_count.to_string());
        fields.insert("malicious".into(), malicious.to_string());
        fields.insert("suspicious".into(), suspicious.to_string());

        if let Some(rep) = raw["reputation"]
            .as_i64()
            .or_else(|| raw["reputation"].as_u64().map(|u| u as i64))
        {
            fields.insert("reputation".into(), rep.to_string());
        }
        if let Some(cc) = raw
            .pointer("/country_iso_code")
            .and_then(|v| v.as_str())
            .or_else(|| raw["country_code"].as_str())
            .or_else(|| raw.pointer("/geo/country_iso_code").and_then(|v| v.as_str()))
        {
            fields.insert("country".into(), cc.into());
        }
        if let Some(asn) = raw["asn"].as_str().or_else(|| raw["asn"].as_str()) {
            if !asn.is_empty() {
                fields.insert("asn".into(), asn.into());
            }
        }

        // Collect a few pulse names for the summary / CSV fields.
        if let Some(pulses) = raw["pulse_info"]["pulses"].as_array() {
            let names: Vec<&str> = pulses
                .iter()
                .filter_map(|p| p["name"].as_str())
                .take(3)
                .collect();
            if !names.is_empty() {
                fields.insert("pulse_names".into(), names.join("; "));
            }
        }

        let summary = if raw["scry_note"].as_str() == Some("not_found") {
            "not found in OTX".into()
        } else if pulse_count == 0 {
            "0 pulses".into()
        } else {
            let names = fields
                .get("pulse_names")
                .map(|s| format!(" · {s}"))
                .unwrap_or_default();
            format!("{pulse_count} pulse(s){names}")
        };

        (summary, fields)
    }
}

#[async_trait]
impl OsintVendor for AlienVaultOtx {
    fn id(&self) -> &'static str {
        VENDOR_ID
    }

    fn name(&self) -> &'static str {
        VENDOR_NAME
    }

    fn description(&self) -> &'static str {
        "OTX pulses · IP / domain / hash community threat intel"
    }

    fn supported_types(&self) -> &[IndicatorType] {
        SUPPORTED
    }

    async fn lookup(&self, indicator: &Indicator, api_key: &str) -> Result<VendorResult> {
        let url = Self::indicator_path(indicator)?;
        let raw = self.get_general(&url, api_key).await?;
        let (summary, fields) = Self::summarize(&raw);
        Ok(VendorResult::ok(VENDOR_ID, indicator, summary, fields, raw))
    }
}

fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_string()
    } else {
        let t: String = s.chars().take(max).collect();
        format!("{t}…")
    }
}
