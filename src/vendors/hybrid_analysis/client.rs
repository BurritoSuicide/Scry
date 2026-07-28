use super::{SUPPORTED, VENDOR_ID, VENDOR_NAME};
use crate::error::{ScryError, Result};
use crate::indicator::{Indicator, IndicatorType};
use crate::vendors::{OsintVendor, VendorResult};
use async_trait::async_trait;
use reqwest::StatusCode;
use serde_json::{json, Value};
use std::collections::BTreeMap;

const API_BASE: &str = "https://hybrid-analysis.com/api/v2";
/// Hybrid Analysis rejects requests without a User-Agent.
const USER_AGENT: &str = "Scry OSINT TUI";

#[derive(Debug, Clone, Default)]
pub struct HybridAnalysis {
    client: reqwest::Client,
}

impl HybridAnalysis {
    pub fn new() -> Self {
        Self {
            client: reqwest::Client::new(),
        }
    }

    fn headers(api_key: &str) -> reqwest::header::HeaderMap {
        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert(
            "api-key",
            api_key.parse().unwrap_or(reqwest::header::HeaderValue::from_static("")),
        );
        headers.insert(
            reqwest::header::USER_AGENT,
            USER_AGENT.parse().unwrap_or(reqwest::header::HeaderValue::from_static("Scry")),
        );
        headers.insert(
            reqwest::header::ACCEPT,
            "application/json"
                .parse()
                .unwrap_or(reqwest::header::HeaderValue::from_static("application/json")),
        );
        headers
    }

    async fn parse_response(response: reqwest::Response) -> Result<Value> {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        if status == StatusCode::TOO_MANY_REQUESTS {
            return Err(ScryError::RateLimited(VENDOR_ID.into()));
        }
        if status == StatusCode::FORBIDDEN || status == StatusCode::UNAUTHORIZED {
            return Err(ScryError::msg(format!(
                "Hybrid Analysis auth failed ({status}): {}",
                truncate(&body, 180)
            )));
        }
        if !status.is_success() {
            // Some quota errors come back as 400 with validation_errors.
            if body.contains("Exceeded maximum API requests") {
                return Err(ScryError::RateLimited(VENDOR_ID.into()));
            }
            return Err(ScryError::msg(format!(
                "Hybrid Analysis HTTP {status}: {}",
                truncate(&body, 200)
            )));
        }
        if body.trim().is_empty() {
            return Ok(json!([]));
        }
        Ok(serde_json::from_str(&body).unwrap_or_else(|_| json!({ "raw_text": body })))
    }

    async fn search_hash(&self, hash: &str, api_key: &str) -> Result<Value> {
        let response = self
            .client
            .get(format!("{API_BASE}/search/hash"))
            .headers(Self::headers(api_key))
            .query(&[("hash", hash)])
            .send()
            .await?;
        Self::parse_response(response).await
    }

    async fn search_terms(&self, field: &str, value: &str, api_key: &str) -> Result<Value> {
        let response = self
            .client
            .post(format!("{API_BASE}/search/terms"))
            .headers(Self::headers(api_key))
            .header(
                reqwest::header::CONTENT_TYPE,
                "application/x-www-form-urlencoded",
            )
            .form(&[(field, value)])
            .send()
            .await?;
        Self::parse_response(response).await
    }

    fn summarize_hash(raw: &Value) -> (String, BTreeMap<String, String>) {
        let mut fields = BTreeMap::new();
        let reports = if let Some(arr) = raw.as_array() {
            arr.clone()
        } else if let Some(arr) = raw.get("reports").and_then(|v| v.as_array()) {
            arr.clone()
        } else {
            Vec::new()
        };

        fields.insert("report_count".into(), reports.len().to_string());
        if reports.is_empty() {
            fields.insert("malicious".into(), "0".into());
            fields.insert("suspicious".into(), "0".into());
            return ("No Hybrid Analysis reports for hash".into(), fields);
        }

        let mut best_score = 0i64;
        let mut worst_verdict = String::new();
        let mut family = String::new();
        let mut malicious = 0u64;
        let mut suspicious = 0u64;

        for report in &reports {
            let score = report["threat_score"]
                .as_i64()
                .or_else(|| report["threat_score"].as_u64().map(|u| u as i64))
                .unwrap_or(0);
            if score > best_score {
                best_score = score;
            }
            if let Some(v) = report["verdict"].as_str() {
                classify_verdict(v, &mut malicious, &mut suspicious);
                if verdict_rank(v) >= verdict_rank(&worst_verdict) {
                    worst_verdict = v.to_string();
                }
            }
            if family.is_empty() {
                if let Some(f) = report["vx_family"].as_str().filter(|s| !s.is_empty()) {
                    family = f.to_string();
                }
            }
            if let Some(av) = report["av_detect"].as_u64().or_else(|| {
                report["av_detect"]
                    .as_str()
                    .and_then(|s| s.parse().ok())
            }) {
                fields
                    .entry("av_detect".into())
                    .or_insert_with(|| av.to_string());
            }
        }

        fields.insert("threat_score".into(), best_score.to_string());
        fields.insert("malicious".into(), malicious.to_string());
        fields.insert("suspicious".into(), suspicious.to_string());
        if !worst_verdict.is_empty() {
            fields.insert("verdict".into(), worst_verdict.clone());
        }
        if !family.is_empty() {
            fields.insert("vx_family".into(), family.clone());
        }

        let summary = match (malicious > 0, suspicious > 0, family.is_empty()) {
            (true, _, false) => format!(
                "{n} report(s) · verdict malicious · family {family} · score {best_score}",
                n = reports.len()
            ),
            (true, _, true) => {
                format!("{n} report(s) · verdict malicious · score {best_score}", n = reports.len())
            }
            (_, true, _) => format!(
                "{n} report(s) · verdict suspicious · score {best_score}",
                n = reports.len()
            ),
            _ => format!(
                "{n} report(s) · verdict {} · score {best_score}",
                if worst_verdict.is_empty() {
                    "unknown"
                } else {
                    &worst_verdict
                },
                n = reports.len()
            ),
        };
        (summary, fields)
    }

    fn summarize_terms(raw: &Value, kind_label: &str) -> (String, BTreeMap<String, String>) {
        let mut fields = BTreeMap::new();
        let results = raw
            .get("result")
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default();
        let count = raw["count"]
            .as_u64()
            .unwrap_or(results.len() as u64);

        fields.insert("result_count".into(), count.to_string());
        if results.is_empty() {
            fields.insert("malicious".into(), "0".into());
            fields.insert("suspicious".into(), "0".into());
            return (
                format!("No Hybrid Analysis samples contacted this {kind_label}"),
                fields,
            );
        }

        let mut malicious = 0u64;
        let mut suspicious = 0u64;
        let mut best_score = 0i64;
        let mut family = String::new();
        let mut worst_verdict = String::new();

        for item in results.iter().take(25) {
            let score = item["threat_score"]
                .as_i64()
                .or_else(|| item["threat_score"].as_u64().map(|u| u as i64))
                .unwrap_or(0);
            best_score = best_score.max(score);
            if let Some(v) = item["verdict"].as_str() {
                classify_verdict(v, &mut malicious, &mut suspicious);
                if verdict_rank(v) >= verdict_rank(&worst_verdict) {
                    worst_verdict = v.to_string();
                }
            }
            if family.is_empty() {
                if let Some(f) = item["vx_family"].as_str().filter(|s| !s.is_empty()) {
                    family = f.to_string();
                }
            }
        }

        fields.insert("threat_score".into(), best_score.to_string());
        fields.insert("malicious".into(), malicious.to_string());
        fields.insert("suspicious".into(), suspicious.to_string());
        if !worst_verdict.is_empty() {
            fields.insert("verdict".into(), worst_verdict.clone());
        }
        if !family.is_empty() {
            fields.insert("vx_family".into(), family.clone());
        }
        if let Some(sha) = results
            .first()
            .and_then(|r| r["sha256"].as_str())
        {
            fields.insert("example_sha256".into(), sha.into());
        }

        let summary = if malicious > 0 {
            format!(
                "{count} sample(s) · malicious contact · score {best_score}{}",
                if family.is_empty() {
                    String::new()
                } else {
                    format!(" · {family}")
                }
            )
        } else if suspicious > 0 {
            format!("{count} sample(s) · suspicious contact · score {best_score}")
        } else {
            format!(
                "{count} sample(s) related · verdict {}",
                if worst_verdict.is_empty() {
                    "unknown"
                } else {
                    &worst_verdict
                }
            )
        };
        (summary, fields)
    }
}

#[async_trait]
impl OsintVendor for HybridAnalysis {
    fn id(&self) -> &'static str {
        VENDOR_ID
    }

    fn name(&self) -> &'static str {
        VENDOR_NAME
    }

    fn description(&self) -> &'static str {
        "Falcon Sandbox malware reports · hash / host / domain search"
    }

    fn supported_types(&self) -> &[IndicatorType] {
        SUPPORTED
    }

    async fn lookup(&self, indicator: &Indicator, api_key: &str) -> Result<VendorResult> {
        let raw = match indicator.kind {
            IndicatorType::Hash => self.search_hash(&indicator.raw, api_key).await?,
            IndicatorType::IpAddress => {
                self.search_terms("host", &indicator.raw, api_key).await?
            }
            IndicatorType::Domain => {
                self.search_terms("domain", &indicator.raw, api_key).await?
            }
            other => {
                return Err(ScryError::UnsupportedIndicator {
                    vendor: VENDOR_NAME.into(),
                    indicator_type: other.to_string(),
                });
            }
        };

        let (summary, fields) = match indicator.kind {
            IndicatorType::Hash => Self::summarize_hash(&raw),
            IndicatorType::IpAddress => Self::summarize_terms(&raw, "IP"),
            IndicatorType::Domain => Self::summarize_terms(&raw, "domain"),
            _ => unreachable!(),
        };

        Ok(VendorResult::ok(VENDOR_ID, indicator, summary, fields, raw))
    }
}

fn classify_verdict(verdict: &str, malicious: &mut u64, suspicious: &mut u64) {
    let v = verdict.to_ascii_lowercase();
    if v.contains("malicious") {
        *malicious += 1;
    } else if v.contains("suspicious") {
        *suspicious += 1;
    }
}

fn verdict_rank(verdict: &str) -> u8 {
    let v = verdict.to_ascii_lowercase();
    if v.contains("malicious") {
        5
    } else if v.contains("suspicious") {
        4
    } else if v.contains("no specific threat") {
        3
    } else if v.contains("no verdict") {
        2
    } else if v.contains("whitelist") {
        1
    } else if v.is_empty() {
        0
    } else {
        2
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
