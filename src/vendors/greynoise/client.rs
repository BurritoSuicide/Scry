use super::{SUPPORTED, VENDOR_ID, VENDOR_NAME};
use crate::error::{ScryError, Result};
use crate::indicator::{Indicator, IndicatorType};
use crate::vendors::{OsintVendor, VendorResult};
use async_trait::async_trait;
use reqwest::StatusCode;
use serde_json::Value;
use std::collections::BTreeMap;

const API_BASE: &str = "https://api.greynoise.io/v3/community";

#[derive(Debug, Clone, Default)]
pub struct GreyNoise {
    client: reqwest::Client,
}

impl GreyNoise {
    pub fn new() -> Self {
        Self {
            client: reqwest::Client::new(),
        }
    }

    async fn lookup_ip(&self, ip: &str, api_key: &str) -> Result<Value> {
        let response = self
            .client
            .get(format!("{API_BASE}/{ip}"))
            .header("key", api_key)
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
                "GreyNoise auth failed ({status}): {}",
                truncate(&body, 180)
            )));
        }
        // Community API returns 404 when the IP is unknown / not observed.
        if status == StatusCode::NOT_FOUND {
            return Ok(serde_json::json!({
                "ip": ip,
                "noise": false,
                "riot": false,
                "classification": "unknown",
                "message": "IP not observed / not found in GreyNoise community data",
                "scry_note": "not_found"
            }));
        }
        if !status.is_success() {
            return Err(ScryError::msg(format!(
                "GreyNoise HTTP {status}: {}",
                truncate(&body, 200)
            )));
        }

        Ok(serde_json::from_str(&body).unwrap_or_else(|_| {
            serde_json::json!({ "raw_text": body })
        }))
    }

    fn summarize(raw: &Value) -> (String, BTreeMap<String, String>) {
        let mut fields = BTreeMap::new();

        let noise = raw["noise"].as_bool().unwrap_or(false);
        let riot = raw["riot"].as_bool().unwrap_or(false);
        let classification = raw["classification"]
            .as_str()
            .unwrap_or("unknown")
            .to_ascii_lowercase();
        let name = raw["name"].as_str().unwrap_or("").trim();
        let last_seen = raw["last_seen"].as_str().unwrap_or("");
        let link = raw["link"].as_str().unwrap_or("");

        let (malicious, suspicious) = match classification.as_str() {
            "malicious" => (1, 0),
            "suspicious" => (0, 1),
            "benign" => (0, 0),
            _ if noise => (0, 1),
            _ => (0, 0),
        };

        fields.insert("noise".into(), noise.to_string());
        fields.insert("riot".into(), riot.to_string());
        fields.insert("classification".into(), classification.clone());
        fields.insert("malicious".into(), malicious.to_string());
        fields.insert("suspicious".into(), suspicious.to_string());
        if !name.is_empty() {
            fields.insert("name".into(), name.into());
        }
        if !last_seen.is_empty() {
            fields.insert("last_seen".into(), last_seen.into());
        }
        if !link.is_empty() {
            fields.insert("link".into(), link.into());
        }

        let summary = if raw["scry_note"].as_str() == Some("not_found") {
            "not observed in GreyNoise community data".into()
        } else if riot && classification == "benign" {
            format!(
                "RIOT benign · {}{}",
                if name.is_empty() { "known service" } else { name },
                if last_seen.is_empty() {
                    String::new()
                } else {
                    format!(" · seen {last_seen}")
                }
            )
        } else if noise {
            format!(
                "noise · {classification}{}",
                if name.is_empty() {
                    String::new()
                } else {
                    format!(" · {name}")
                }
            )
        } else if !classification.is_empty() && classification != "unknown" {
            format!("classification {classification}")
        } else {
            "no GreyNoise noise / RIOT tags".into()
        };

        (summary, fields)
    }
}

#[async_trait]
impl OsintVendor for GreyNoise {
    fn id(&self) -> &'static str {
        VENDOR_ID
    }

    fn name(&self) -> &'static str {
        VENDOR_NAME
    }

    fn description(&self) -> &'static str {
        "Internet scanner noise vs RIOT · community IP context"
    }

    fn supported_types(&self) -> &[IndicatorType] {
        SUPPORTED
    }

    async fn lookup(&self, indicator: &Indicator, api_key: &str) -> Result<VendorResult> {
        match indicator.kind {
            IndicatorType::IpAddress => {
                let raw = self.lookup_ip(&indicator.raw, api_key).await?;
                let (summary, fields) = Self::summarize(&raw);
                Ok(VendorResult::ok(VENDOR_ID, indicator, summary, fields, raw))
            }
            other => Err(ScryError::UnsupportedIndicator {
                vendor: VENDOR_NAME.into(),
                indicator_type: other.to_string(),
            }),
        }
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
