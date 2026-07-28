use super::{SUPPORTED, VENDOR_ID, VENDOR_NAME};
use crate::error::{ScryError, Result};
use crate::indicator::{HashKind, Indicator, IndicatorType};
use crate::vendors::{OsintVendor, VendorResult};
use async_trait::async_trait;
use reqwest::StatusCode;
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Mutex;

const MB_API: &str = "https://mb-api.abuse.ch/api/v1/";
const URLHAUS_HOST: &str = "https://urlhaus-api.abuse.ch/v1/host/";
const URLHAUS_PAYLOAD: &str = "https://urlhaus-api.abuse.ch/v1/payload/";
const THREATFOX_API: &str = "https://threatfox-api.abuse.ch/api/v1/";
const FEODO_JSON: &str = "https://feodotracker.abuse.ch/downloads/ipblocklist.json";

/// How long to keep the Feodo IP blocklist in memory between refreshes.
const FEODO_CACHE_TTL: Duration = Duration::from_secs(30 * 60);

#[derive(Debug, Default)]
struct FeodoCache {
    loaded_at: Option<Instant>,
    /// ip → list of matching C2 entries
    by_ip: BTreeMap<String, Vec<Value>>,
}

#[derive(Debug, Clone, Default)]
pub struct AbuseCh {
    client: reqwest::Client,
    feodo: Arc<Mutex<FeodoCache>>,
}

impl AbuseCh {
    pub fn new() -> Self {
        Self {
            client: reqwest::Client::new(),
            feodo: Arc::new(Mutex::new(FeodoCache::default())),
        }
    }

    async fn post_form(
        &self,
        url: &str,
        api_key: &str,
        form: &[(&str, String)],
    ) -> Result<Value> {
        let response = self
            .client
            .post(url)
            .header("Auth-Key", api_key)
            .form(form)
            .send()
            .await?;
        Self::parse_response(response).await
    }

    /// ThreatFox expects a raw JSON body (official clients do not rely on form encoding).
    async fn post_threatfox(&self, api_key: &str, body: Value) -> Result<Value> {
        let response = self
            .client
            .post(THREATFOX_API)
            .header("Auth-Key", api_key)
            .header("Content-Type", "application/json")
            .body(body.to_string())
            .send()
            .await?;
        Self::parse_response(response).await
    }

    async fn parse_response(response: reqwest::Response) -> Result<Value> {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        if status == StatusCode::TOO_MANY_REQUESTS {
            return Err(ScryError::RateLimited(VENDOR_ID.into()));
        }
        if !status.is_success() {
            return Err(ScryError::msg(format!(
                "abuse.ch HTTP {status}: {}",
                truncate(&body, 200)
            )));
        }
        Ok(serde_json::from_str(&body).unwrap_or_else(|_| json!({ "raw_text": body })))
    }

    async fn query_malwarebazaar(&self, indicator: &Indicator, api_key: &str) -> Result<Value> {
        self.post_form(
            MB_API,
            api_key,
            &[
                ("query", "get_info".into()),
                ("hash", indicator.raw.clone()),
            ],
        )
        .await
    }

    async fn query_urlhaus_payload(&self, indicator: &Indicator, api_key: &str) -> Result<Value> {
        let field = match (indicator.hash_kind, indicator.raw.len()) {
            (Some(HashKind::Md5), _) | (None, 32) => "md5_hash",
            (Some(HashKind::Sha256), _) | (None, 64) => "sha256_hash",
            _ => {
                return Ok(json!({
                    "query_status": "skipped",
                    "scry_note": "URLhaus payload lookup supports MD5/SHA256 only"
                }));
            }
        };
        self.post_form(URLHAUS_PAYLOAD, api_key, &[(field, indicator.raw.clone())])
            .await
    }

    async fn query_urlhaus_host(&self, host: &str, api_key: &str) -> Result<Value> {
        self.post_form(URLHAUS_HOST, api_key, &[("host", host.to_string())])
            .await
    }

    /// Search ThreatFox. IPs are often stored as `ip:port`, so use wildcard (non-exact)
    /// matching for IP lookups; domains/hashes can stay exact.
    async fn query_threatfox_ioc(
        &self,
        term: &str,
        api_key: &str,
        exact_match: bool,
    ) -> Result<Value> {
        let mut body = json!({
            "query": "search_ioc",
            "search_term": term,
        });
        // Only send exact_match when true; omitting defaults to wildcard on the API.
        if exact_match {
            body["exact_match"] = json!(true);
        }
        let mut result = self.post_threatfox(api_key, body).await?;

        // For IP searches, keep only IOCs that are this IP or ip:port for this IP.
        if !exact_match {
            if let Some(data) = result.get_mut("data").and_then(|d| d.as_array_mut()) {
                data.retain(|entry| {
                    entry["ioc"]
                        .as_str()
                        .map(|ioc| ioc_matches_ip(ioc, term))
                        .unwrap_or(false)
                });
                if data.is_empty()
                    && result["query_status"].as_str() == Some("ok")
                {
                    result["query_status"] = json!("no_result");
                }
            }
        }

        Ok(result)
    }

    async fn query_threatfox_hash(&self, indicator: &Indicator, api_key: &str) -> Result<Value> {
        let allowed = matches!(
            (indicator.hash_kind, indicator.raw.len()),
            (Some(HashKind::Md5), _)
                | (Some(HashKind::Sha256), _)
                | (None, 32)
                | (None, 64)
        );
        if !allowed {
            return Ok(json!({
                "query_status": "skipped",
                "scry_note": "ThreatFox hash search supports MD5/SHA256 only"
            }));
        }
        self.post_threatfox(
            api_key,
            json!({
                "query": "search_hash",
                "hash": indicator.raw
            }),
        )
        .await
    }

    async fn query_feodo(&self, ip: &str, api_key: &str) -> Result<Value> {
        self.ensure_feodo_cache(api_key).await?;
        let cache = self.feodo.lock().await;
        match cache.by_ip.get(ip) {
            Some(entries) if !entries.is_empty() => Ok(json!({
                "query_status": "ok",
                "data": entries,
            })),
            _ => Ok(json!({
                "query_status": "no_result",
                "data": [],
            })),
        }
    }

    async fn ensure_feodo_cache(&self, api_key: &str) -> Result<()> {
        {
            let cache = self.feodo.lock().await;
            if let Some(loaded) = cache.loaded_at {
                if loaded.elapsed() < FEODO_CACHE_TTL && !cache.by_ip.is_empty() {
                    return Ok(());
                }
            }
        }

        let response = self
            .client
            .get(FEODO_JSON)
            .header("Auth-Key", api_key)
            .send()
            .await?;
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        if !status.is_success() {
            return Err(ScryError::msg(format!(
                "Feodo Tracker HTTP {status}: {}",
                truncate(&body, 200)
            )));
        }

        let parsed: Value = serde_json::from_str(&body).map_err(|e| {
            ScryError::msg(format!("Feodo Tracker JSON parse error: {e}"))
        })?;

        let mut by_ip: BTreeMap<String, Vec<Value>> = BTreeMap::new();
        if let Some(arr) = parsed.as_array() {
            for entry in arr {
                let ip = entry
                    .get("ip_address")
                    .or_else(|| entry.get("ip"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                if ip.is_empty() {
                    continue;
                }
                by_ip.entry(ip.to_string()).or_default().push(entry.clone());
            }
        }

        let mut cache = self.feodo.lock().await;
        cache.by_ip = by_ip;
        cache.loaded_at = Some(Instant::now());
        Ok(())
    }

    fn summarize(
        indicator: &Indicator,
        mb: Option<&Value>,
        urlhaus: Option<&Value>,
        threatfox: Option<&Value>,
        feodo: Option<&Value>,
    ) -> (String, BTreeMap<String, String>, Value) {
        let mut fields = BTreeMap::new();
        let mut hits = Vec::new();
        let mut parts = Vec::new();

        if let Some(v) = mb {
            let status = v["query_status"].as_str().unwrap_or("unknown");
            fields.insert("malwarebazaar".into(), status.into());
            if status == "ok" {
                hits.push("MalwareBazaar");
                if let Some(sig) = v["data"]
                    .as_array()
                    .and_then(|a| a.first())
                    .and_then(|e| e["signature"].as_str())
                {
                    fields.insert("mb_signature".into(), sig.into());
                    parts.push(format!("MB:{sig}"));
                } else {
                    parts.push("MB:hit".into());
                }
                if let Some(tags) = v["data"]
                    .as_array()
                    .and_then(|a| a.first())
                    .and_then(|e| e["tags"].as_array())
                {
                    let joined: Vec<_> = tags.iter().filter_map(|t| t.as_str()).take(6).collect();
                    if !joined.is_empty() {
                        fields.insert("mb_tags".into(), joined.join(", "));
                    }
                }
            } else if status != "hash_not_found" && status != "skipped" {
                parts.push(format!("MB:{status}"));
            }
        }

        if let Some(v) = urlhaus {
            let status = v["query_status"].as_str().unwrap_or("unknown");
            fields.insert("urlhaus".into(), status.into());
            if status == "ok" {
                hits.push("URLhaus");
                if let Some(count) = v["url_count"].as_u64().or_else(|| {
                    v["urls"].as_array().map(|a| a.len() as u64)
                }) {
                    fields.insert("urlhaus_url_count".into(), count.to_string());
                    parts.push(format!("UH:{count} urls"));
                } else if let Some(ft) = v["file_type"].as_str() {
                    fields.insert("urlhaus_file_type".into(), ft.into());
                    parts.push(format!("UH:payload/{ft}"));
                } else {
                    parts.push("UH:hit".into());
                }
                if let Some(first) = v["firstseen"].as_str() {
                    fields.insert("urlhaus_firstseen".into(), first.into());
                }
            } else if !matches!(status, "no_results" | "skipped" | "hash_not_found") {
                parts.push(format!("UH:{status}"));
            }
        }

        if let Some(v) = threatfox {
            let status = v["query_status"].as_str().unwrap_or("unknown");
            fields.insert("threatfox".into(), status.into());
            if status == "ok" {
                hits.push("ThreatFox");
                if let Some(data) = v["data"].as_array() {
                    fields.insert("threatfox_hits".into(), data.len().to_string());
                    if let Some(first) = data.first() {
                        if let Some(ioc) = first["ioc"].as_str() {
                            fields.insert("tf_ioc".into(), ioc.into());
                        }
                        if let Some(t) = first["threat_type"].as_str() {
                            fields.insert("tf_threat_type".into(), t.into());
                        }
                        if let Some(m) = first["malware_printable"]
                            .as_str()
                            .or_else(|| first["malware"].as_str())
                        {
                            fields.insert("tf_malware".into(), m.into());
                            parts.push(format!("TF:{m}"));
                        } else {
                            parts.push(format!("TF:{} hits", data.len()));
                        }
                        if let Some(ioc_type) = first["ioc_type"].as_str() {
                            fields.insert("tf_ioc_type".into(), ioc_type.into());
                        }
                    }
                } else {
                    parts.push("TF:hit".into());
                }
            } else if !matches!(status, "no_result" | "no_results" | "skipped") {
                parts.push(format!("TF:{status}"));
            }
        }

        if let Some(v) = feodo {
            let status = v["query_status"].as_str().unwrap_or("unknown");
            fields.insert("feodo".into(), status.into());
            if status == "ok" {
                hits.push("Feodo");
                if let Some(data) = v["data"].as_array() {
                    fields.insert("feodo_hits".into(), data.len().to_string());
                    if let Some(first) = data.first() {
                        if let Some(m) = first["malware"].as_str() {
                            fields.insert("feodo_malware".into(), m.into());
                            parts.push(format!("Feodo:{m}"));
                        }
                        if let Some(s) = first["status"].as_str() {
                            fields.insert("feodo_status".into(), s.into());
                        }
                        if let Some(p) = first["port"].as_u64().or_else(|| {
                            first["port"].as_str().and_then(|s| s.parse().ok())
                        }) {
                            fields.insert("feodo_port".into(), p.to_string());
                        }
                        if let Some(c) = first["country"].as_str() {
                            fields.insert("feodo_country".into(), c.into());
                        }
                        if let Some(asn) = first["as_number"].as_u64().or_else(|| {
                            first["as_number"].as_str().and_then(|s| s.parse().ok())
                        }) {
                            fields.insert("feodo_asn".into(), asn.to_string());
                        }
                    }
                }
            }
        }

        let malicious = if hits.is_empty() { 0 } else { 1 };
        fields.insert("malicious".into(), malicious.to_string());
        fields.insert("suspicious".into(), "0".into());
        fields.insert(
            "services_hit".into(),
            if hits.is_empty() {
                "none".into()
            } else {
                hits.join("+")
            },
        );

        let summary = if hits.is_empty() {
            format!(
                "No abuse.ch hits for {} ({})",
                indicator.raw,
                indicator.kind.label()
            )
        } else {
            format!(
                "Listed on {} — {}",
                hits.join("+"),
                if parts.is_empty() {
                    "known threat".into()
                } else {
                    parts.join(" · ")
                }
            )
        };

        let raw = json!({
            "malwarebazaar": mb,
            "urlhaus": urlhaus,
            "threatfox": threatfox,
            "feodo": feodo,
        });

        (summary, fields, raw)
    }
}

#[async_trait]
impl OsintVendor for AbuseCh {
    fn id(&self) -> &'static str {
        VENDOR_ID
    }

    fn name(&self) -> &'static str {
        VENDOR_NAME
    }

    fn description(&self) -> &'static str {
        "MalwareBazaar · URLhaus · ThreatFox · Feodo (one Auth-Key)"
    }

    fn supported_types(&self) -> &[IndicatorType] {
        SUPPORTED
    }

    async fn lookup(&self, indicator: &Indicator, api_key: &str) -> Result<VendorResult> {
        let (mb, urlhaus, threatfox, feodo) = match indicator.kind {
            IndicatorType::Hash => {
                let mb = Some(self.query_malwarebazaar(indicator, api_key).await?);
                let uh = Some(self.query_urlhaus_payload(indicator, api_key).await?);
                let tf = Some(self.query_threatfox_hash(indicator, api_key).await?);
                (mb, uh, tf, None)
            }
            IndicatorType::Domain => {
                let uh = Some(self.query_urlhaus_host(&indicator.raw, api_key).await?);
                // Domains can be exact; still allow substring matches if exact fails later.
                let tf = Some(
                    self.query_threatfox_ioc(&indicator.raw, api_key, true)
                        .await?,
                );
                (None, uh, tf, None)
            }
            IndicatorType::IpAddress => {
                // ThreatFox stores many IPs as ip:port — wildcard search is required.
                let uh = Some(self.query_urlhaus_host(&indicator.raw, api_key).await?);
                let tf = Some(
                    self.query_threatfox_ioc(&indicator.raw, api_key, false)
                        .await?,
                );
                let feodo = Some(self.query_feodo(&indicator.raw, api_key).await?);
                (None, uh, tf, feodo)
            }
            other => {
                return Err(ScryError::UnsupportedIndicator {
                    vendor: VENDOR_NAME.into(),
                    indicator_type: other.to_string(),
                });
            }
        };

        // If domain exact match missed, retry ThreatFox with wildcard once.
        let threatfox = match (indicator.kind, threatfox) {
            (IndicatorType::Domain, Some(tf))
                if matches!(
                    tf["query_status"].as_str(),
                    Some("no_result" | "no_results")
                ) =>
            {
                Some(
                    self.query_threatfox_ioc(&indicator.raw, api_key, false)
                        .await?,
                )
            }
            (_, other) => other,
        };

        let (summary, fields, raw) = Self::summarize(
            indicator,
            mb.as_ref(),
            urlhaus.as_ref(),
            threatfox.as_ref(),
            feodo.as_ref(),
        );
        Ok(VendorResult::ok(VENDOR_ID, indicator, summary, fields, raw))
    }
}

fn ioc_matches_ip(ioc: &str, ip: &str) -> bool {
    if ioc == ip {
        return true;
    }
    // ip:port form used heavily by ThreatFox
    if let Some((host, port)) = ioc.split_once(':') {
        if host == ip && !port.is_empty() && port.chars().all(|c| c.is_ascii_digit()) {
            return true;
        }
    }
    // Rare URL-ish forms that embed the IP
    ioc.starts_with(&(ip.to_string() + ":")) || ioc.contains(&(ip.to_string() + "/"))
}

fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_string()
    } else {
        let t: String = s.chars().take(max).collect();
        format!("{t}…")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_ip_port_iocs() {
        assert!(ioc_matches_ip("27.133.154.218:443", "27.133.154.218"));
        assert!(ioc_matches_ip("27.133.154.218", "27.133.154.218"));
        assert!(!ioc_matches_ip("27.133.154.219:443", "27.133.154.218"));
        assert!(!ioc_matches_ip("evil.com", "27.133.154.218"));
    }
}
