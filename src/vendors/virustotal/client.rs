use super::{SUPPORTED, VENDOR_ID, VENDOR_NAME};
use crate::error::{ScryError, Result};
use crate::indicator::{Indicator, IndicatorType};
use crate::vendors::{OsintVendor, VendorResult};
use async_trait::async_trait;
use reqwest::StatusCode;
use serde_json::Value;
use std::collections::BTreeMap;

const API_BASE: &str = "https://www.virustotal.com/api/v3";

#[derive(Debug, Clone, Default)]
pub struct VirusTotal {
    client: reqwest::Client,
}

impl VirusTotal {
    pub fn new() -> Self {
        Self {
            client: reqwest::Client::new(),
        }
    }

    fn endpoint_for(indicator: &Indicator) -> Result<String> {
        match indicator.kind {
            IndicatorType::Hash => Ok(format!("{API_BASE}/files/{}", indicator.raw)),
            IndicatorType::IpAddress => Ok(format!("{API_BASE}/ip_addresses/{}", indicator.raw)),
            IndicatorType::Domain => Ok(format!("{API_BASE}/domains/{}", indicator.raw)),
            IndicatorType::Email => {
                // Public API has no first-class email object; use intelligence search.
                let q = urlencoding_minimal(&format!("email:{}", indicator.raw));
                Ok(format!("{API_BASE}/search?query={q}"))
            }
            other => Err(ScryError::UnsupportedIndicator {
                vendor: VENDOR_NAME.into(),
                indicator_type: other.to_string(),
            }),
        }
    }

    async fn get_json(&self, url: &str, api_key: &str) -> Result<Value> {
        let response = self
            .client
            .get(url)
            .header("x-apikey", api_key)
            .header("Accept", "application/json")
            .send()
            .await?;

        let status = response.status();
        let body = response.text().await.unwrap_or_default();

        if status == StatusCode::TOO_MANY_REQUESTS {
            return Err(ScryError::RateLimited(VENDOR_ID.into()));
        }
        if status == StatusCode::NOT_FOUND {
            return Ok(serde_json::json!({
                "data": null,
                "scry_note": "not found in VirusTotal"
            }));
        }
        if !status.is_success() {
            return Err(ScryError::msg(format!(
                "VirusTotal HTTP {status}: {}",
                truncate(&body, 240)
            )));
        }

        let value: Value = serde_json::from_str(&body).unwrap_or_else(|_| {
            serde_json::json!({ "raw_text": body })
        });
        Ok(value)
    }

    fn summarize_file(raw: &Value) -> (String, BTreeMap<String, String>) {
        let mut fields = BTreeMap::new();
        let attrs = &raw["data"]["attributes"];
        let stats = &attrs["last_analysis_stats"];

        let malicious = stats["malicious"].as_u64().unwrap_or(0);
        let suspicious = stats["suspicious"].as_u64().unwrap_or(0);
        let harmless = stats["harmless"].as_u64().unwrap_or(0);
        let undetected = stats["undetected"].as_u64().unwrap_or(0);

        fields.insert("malicious".into(), malicious.to_string());
        fields.insert("suspicious".into(), suspicious.to_string());
        fields.insert("harmless".into(), harmless.to_string());
        fields.insert("undetected".into(), undetected.to_string());
        if let Some(names) = attrs["names"].as_array() {
            let joined = names
                .iter()
                .filter_map(|v| v.as_str())
                .take(5)
                .collect::<Vec<_>>()
                .join(", ");
            if !joined.is_empty() {
                fields.insert("names".into(), joined);
            }
        }
        if let Some(t) = attrs["type_description"].as_str() {
            fields.insert("type".into(), t.to_string());
        }
        if let Some(r) = attrs["reputation"].as_i64() {
            fields.insert("reputation".into(), r.to_string());
        }

        let summary = format!("{malicious} malicious / {suspicious} suspicious engines");
        (summary, fields)
    }

    fn summarize_ip(raw: &Value) -> (String, BTreeMap<String, String>) {
        let mut fields = BTreeMap::new();
        let attrs = &raw["data"]["attributes"];
        let stats = &attrs["last_analysis_stats"];

        let malicious = stats["malicious"].as_u64().unwrap_or(0);
        let suspicious = stats["suspicious"].as_u64().unwrap_or(0);

        fields.insert("malicious".into(), malicious.to_string());
        fields.insert("suspicious".into(), suspicious.to_string());
        if let Some(asn) = attrs["asn"].as_u64() {
            fields.insert("asn".into(), asn.to_string());
        }
        if let Some(as_owner) = attrs["as_owner"].as_str() {
            fields.insert("as_owner".into(), as_owner.to_string());
        }
        if let Some(country) = attrs["country"].as_str() {
            fields.insert("country".into(), country.to_string());
        }
        if let Some(net) = attrs["network"].as_str() {
            fields.insert("network".into(), net.to_string());
        }
        if let Some(r) = attrs["reputation"].as_i64() {
            fields.insert("reputation".into(), r.to_string());
        }

        let summary = format!(
            "IP reputation: {malicious} malicious / {suspicious} suspicious"
        );
        (summary, fields)
    }

    fn summarize_domain(raw: &Value) -> (String, BTreeMap<String, String>) {
        let mut fields = BTreeMap::new();
        let attrs = &raw["data"]["attributes"];
        let stats = &attrs["last_analysis_stats"];

        let malicious = stats["malicious"].as_u64().unwrap_or(0);
        let suspicious = stats["suspicious"].as_u64().unwrap_or(0);

        fields.insert("malicious".into(), malicious.to_string());
        fields.insert("suspicious".into(), suspicious.to_string());
        if let Some(r) = attrs["reputation"].as_i64() {
            fields.insert("reputation".into(), r.to_string());
        }
        if let Some(cats) = attrs["categories"].as_object() {
            let joined = cats
                .values()
                .filter_map(|v| v.as_str())
                .take(4)
                .collect::<Vec<_>>()
                .join(", ");
            if !joined.is_empty() {
                fields.insert("categories".into(), joined);
            }
        }

        let summary = format!(
            "domain reputation: {malicious} malicious / {suspicious} suspicious"
        );
        (summary, fields)
    }

    fn summarize_search(raw: &Value) -> (String, BTreeMap<String, String>) {
        let mut fields = BTreeMap::new();
        let count = raw["data"]
            .as_array()
            .map(|a| a.len())
            .unwrap_or(0);
        fields.insert("result_count".into(), count.to_string());
        let summary = format!("{count} related object(s) from VT search");
        (summary, fields)
    }
}

#[async_trait]
impl OsintVendor for VirusTotal {
    fn id(&self) -> &'static str {
        VENDOR_ID
    }

    fn name(&self) -> &'static str {
        VENDOR_NAME
    }

    fn description(&self) -> &'static str {
        "File / IP / URL reputation and multi-engine malware analysis"
    }

    fn supported_types(&self) -> &[IndicatorType] {
        SUPPORTED
    }

    async fn lookup(&self, indicator: &Indicator, api_key: &str) -> Result<VendorResult> {
        let url = Self::endpoint_for(indicator)?;
        let raw = self.get_json(&url, api_key).await?;

        if raw.get("scry_note").and_then(|v| v.as_str()) == Some("not found in VirusTotal") {
            let mut fields = BTreeMap::new();
            fields.insert("status".into(), "not_found".into());
            return Ok(VendorResult::ok(
                VENDOR_ID,
                indicator,
                "Not found in VirusTotal",
                fields,
                raw,
            ));
        }

        let (summary, fields) = match indicator.kind {
            IndicatorType::Hash => Self::summarize_file(&raw),
            IndicatorType::IpAddress => Self::summarize_ip(&raw),
            IndicatorType::Domain => Self::summarize_domain(&raw),
            IndicatorType::Email => Self::summarize_search(&raw),
            other => {
                return Err(ScryError::UnsupportedIndicator {
                    vendor: VENDOR_NAME.into(),
                    indicator_type: other.to_string(),
                });
            }
        };

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

/// Minimal query escaping so we can avoid an extra dependency for one call site.
fn urlencoding_minimal(s: &str) -> String {
    let mut out = String::with_capacity(s.len() * 2);
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char);
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}
