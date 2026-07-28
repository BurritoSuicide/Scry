use super::{SUPPORTED, VENDOR_ID, VENDOR_NAME};
use crate::error::{ScryError, Result};
use crate::indicator::{Indicator, IndicatorType};
use crate::vendors::{OsintVendor, VendorResult};
use async_trait::async_trait;
use reqwest::StatusCode;
use serde_json::Value;
use std::collections::BTreeMap;

const API_BASE: &str = "https://api.abuseipdb.com/api/v2";
/// How far back to consider reports (API default is 30; 90 is a useful OSINT window).
const MAX_AGE_DAYS: &str = "90";

#[derive(Debug, Clone, Default)]
pub struct AbuseIpdb {
    client: reqwest::Client,
}

impl AbuseIpdb {
    pub fn new() -> Self {
        Self {
            client: reqwest::Client::new(),
        }
    }

    async fn check_ip(&self, ip: &str, api_key: &str) -> Result<Value> {
        let response = self
            .client
            .get(format!("{API_BASE}/check"))
            .header("Key", api_key)
            .header("Accept", "application/json")
            .query(&[
                ("ipAddress", ip),
                ("maxAgeInDays", MAX_AGE_DAYS),
            ])
            .send()
            .await?;

        let status = response.status();
        let body = response.text().await.unwrap_or_default();

        if status == StatusCode::TOO_MANY_REQUESTS {
            return Err(ScryError::RateLimited(VENDOR_ID.into()));
        }
        if status == StatusCode::UNAUTHORIZED || status == StatusCode::FORBIDDEN {
            return Err(ScryError::msg(format!(
                "AbuseIPDB auth failed ({status}): {}",
                truncate(&body, 180)
            )));
        }
        if !status.is_success() {
            return Err(ScryError::msg(format!(
                "AbuseIPDB HTTP {status}: {}",
                truncate(&body, 200)
            )));
        }

        Ok(serde_json::from_str(&body).unwrap_or_else(|_| {
            serde_json::json!({ "raw_text": body })
        }))
    }

    fn summarize(raw: &Value) -> (String, BTreeMap<String, String>) {
        let mut fields = BTreeMap::new();
        let data = &raw["data"];

        let score = data["abuseConfidenceScore"]
            .as_u64()
            .or_else(|| data["abuseConfidenceScore"].as_i64().map(|i| i.max(0) as u64))
            .unwrap_or(0);
        let total_reports = data["totalReports"].as_u64().unwrap_or(0);
        let distinct = data["numDistinctUsers"].as_u64().unwrap_or(0);
        let whitelisted = data["isWhitelisted"].as_bool().unwrap_or(false);
        let is_tor = data["isTor"].as_bool().unwrap_or(false);

        // Map confidence into live-feed severity colors.
        let (malicious, suspicious) = if whitelisted {
            (0, 0)
        } else if score >= 50 || (total_reports > 0 && score >= 25) {
            if score >= 50 {
                (1, 0)
            } else {
                (0, 1)
            }
        } else if total_reports > 0 || score > 0 {
            (0, 1)
        } else {
            (0, 0)
        };

        fields.insert("abuse_confidence".into(), score.to_string());
        fields.insert("total_reports".into(), total_reports.to_string());
        fields.insert("distinct_users".into(), distinct.to_string());
        fields.insert("malicious".into(), malicious.to_string());
        fields.insert("suspicious".into(), suspicious.to_string());
        fields.insert("whitelisted".into(), whitelisted.to_string());
        fields.insert("is_tor".into(), is_tor.to_string());

        if let Some(cc) = data["countryCode"].as_str() {
            fields.insert("country".into(), cc.into());
        }
        if let Some(isp) = data["isp"].as_str().filter(|s| !s.is_empty()) {
            fields.insert("isp".into(), isp.into());
        }
        if let Some(usage) = data["usageType"].as_str().filter(|s| !s.is_empty()) {
            fields.insert("usage_type".into(), usage.into());
        }
        if let Some(domain) = data["domain"].as_str().filter(|s| !s.is_empty()) {
            fields.insert("domain".into(), domain.into());
        }
        if let Some(last) = data["lastReportedAt"].as_str() {
            fields.insert("last_reported".into(), last.into());
        }

        let country = fields
            .get("country")
            .map(|s| s.as_str())
            .unwrap_or("??");

        let summary = if whitelisted {
            format!("whitelisted · confidence {score}% · {country}")
        } else if total_reports == 0 && score == 0 {
            format!("clean · confidence 0% · {country}")
        } else {
            format!(
                "confidence {score}% · {total_reports} report(s) · {distinct} reporter(s) · {country}{}",
                if is_tor { " · Tor" } else { "" }
            )
        };

        (summary, fields)
    }
}

#[async_trait]
impl OsintVendor for AbuseIpdb {
    fn id(&self) -> &'static str {
        VENDOR_ID
    }

    fn name(&self) -> &'static str {
        VENDOR_NAME
    }

    fn description(&self) -> &'static str {
        "Community IP abuse reports · confidence score + ISP / country"
    }

    fn supported_types(&self) -> &[IndicatorType] {
        SUPPORTED
    }

    async fn lookup(&self, indicator: &Indicator, api_key: &str) -> Result<VendorResult> {
        match indicator.kind {
            IndicatorType::IpAddress => {
                let raw = self.check_ip(&indicator.raw, api_key).await?;
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
