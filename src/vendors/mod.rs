//! Pluggable OSINT vendor registry.
//!
//! To add a vendor:
//! 1. Create `src/vendors/<id>/` implementing [`OsintVendor`].
//! 2. Add it to [`all_vendors`].
//! 3. That's it — menus, key cache, and the runner pick it up automatically.

pub mod abusech;
pub mod abuseipdb;
pub mod alienvault_otx;
pub mod greynoise;
pub mod hybrid_analysis;
pub mod virustotal;

use crate::error::Result;
use crate::indicator::{Indicator, IndicatorType};
use crate::rate_limit::{RateLimitSpec, UsageProfile};
use async_trait::async_trait;
use serde_json::Value;
use std::collections::BTreeMap;
use std::sync::Arc;

/// Normalized lookup outcome from any vendor.
#[derive(Debug, Clone)]
pub struct VendorResult {
    pub vendor_id: String,
    pub indicator: String,
    pub indicator_type: IndicatorType,
    pub summary: String,
    pub fields: BTreeMap<String, String>,
    pub raw: Value,
    pub success: bool,
    pub error: Option<String>,
}

impl VendorResult {
    pub fn ok(
        vendor_id: impl Into<String>,
        indicator: &Indicator,
        summary: impl Into<String>,
        fields: BTreeMap<String, String>,
        raw: Value,
    ) -> Self {
        Self {
            vendor_id: vendor_id.into(),
            indicator: indicator.raw.clone(),
            indicator_type: indicator.kind,
            summary: summary.into(),
            fields,
            raw,
            success: true,
            error: None,
        }
    }

    pub fn err(
        vendor_id: impl Into<String>,
        indicator: &Indicator,
        error: impl Into<String>,
    ) -> Self {
        Self {
            vendor_id: vendor_id.into(),
            indicator: indicator.raw.clone(),
            indicator_type: indicator.kind,
            summary: String::new(),
            fields: BTreeMap::new(),
            raw: Value::Null,
            success: false,
            error: Some(error.into()),
        }
    }

    /// Threat coloring for the live results feed.
    pub fn severity(&self) -> crate::indicator::ResultSeverity {
        use crate::indicator::ResultSeverity;
        if !self.success {
            return ResultSeverity::Error;
        }
        let malicious = field_u64(&self.fields, "malicious");
        let suspicious = field_u64(&self.fields, "suspicious");
        if malicious > 0 {
            ResultSeverity::Malicious
        } else if suspicious > 0 {
            ResultSeverity::Suspicious
        } else {
            ResultSeverity::Clean
        }
    }
}

fn field_u64(fields: &BTreeMap<String, String>, key: &str) -> u64 {
    fields
        .get(key)
        .and_then(|v| v.parse().ok())
        .unwrap_or(0)
}

/// Capability / suitability hint shown when the input mix is a poor fit.
#[derive(Debug, Clone)]
pub struct VendorFit {
    pub vendor_id: String,
    pub vendor_name: String,
    pub supported: bool,
    pub note: String,
}

#[async_trait]
pub trait OsintVendor: Send + Sync {
    fn id(&self) -> &'static str;
    fn name(&self) -> &'static str;
    fn description(&self) -> &'static str;

    /// Indicator types this vendor can usefully query.
    fn supported_types(&self) -> &[IndicatorType];

    /// Rate limit for a usage profile (personal vs enterprise).
    fn rate_limit_for(&self, profile: UsageProfile) -> RateLimitSpec {
        RateLimitSpec::for_vendor(self.id(), profile)
            .unwrap_or_else(|| RateLimitSpec::per_minute(30))
    }

    /// Personal-tier shortcut (menus / defaults).
    fn rate_limit(&self) -> RateLimitSpec {
        self.rate_limit_for(UsageProfile::Personal)
    }

    fn supports(&self, kind: IndicatorType) -> bool {
        self.supported_types().contains(&kind)
    }

    /// Evaluate fit against a detected mix of indicator types.
    fn fit_for(&self, present: &[IndicatorType]) -> VendorFit {
        let supported_present: Vec<_> = present
            .iter()
            .copied()
            .filter(|t| self.supports(*t))
            .collect();
        let unsupported_present: Vec<_> = present
            .iter()
            .copied()
            .filter(|t| !self.supports(*t))
            .collect();

        if supported_present.is_empty() {
            return VendorFit {
                vendor_id: self.id().into(),
                vendor_name: self.name().into(),
                supported: false,
                note: format!(
                    "{} does not support the detected types ({})",
                    self.name(),
                    present
                        .iter()
                        .map(|t| t.label())
                        .collect::<Vec<_>>()
                        .join(", ")
                ),
            };
        }

        if !unsupported_present.is_empty() {
            return VendorFit {
                vendor_id: self.id().into(),
                vendor_name: self.name().into(),
                supported: true,
                note: format!(
                    "Will query {} only; skipping {}",
                    supported_present
                        .iter()
                        .map(|t| t.label())
                        .collect::<Vec<_>>()
                        .join("/"),
                    unsupported_present
                        .iter()
                        .map(|t| t.label())
                        .collect::<Vec<_>>()
                        .join("/")
                ),
            };
        }

        VendorFit {
            vendor_id: self.id().into(),
            vendor_name: self.name().into(),
            supported: true,
            note: "Good fit for detected indicator types".into(),
        }
    }

    async fn lookup(&self, indicator: &Indicator, api_key: &str) -> Result<VendorResult>;
}

pub type VendorHandle = Arc<dyn OsintVendor>;

/// Canonical list of built-in vendors. Append new vendors here.
pub fn all_vendors() -> Vec<VendorHandle> {
    vec![
        Arc::new(virustotal::VirusTotal::default()),
        Arc::new(abusech::AbuseCh::default()),
        Arc::new(hybrid_analysis::HybridAnalysis::default()),
        Arc::new(abuseipdb::AbuseIpdb::default()),
        Arc::new(greynoise::GreyNoise::default()),
        Arc::new(alienvault_otx::AlienVaultOtx::default()),
    ]
}

pub fn vendor_by_id(id: &str) -> Option<VendorHandle> {
    all_vendors().into_iter().find(|v| v.id() == id)
}

pub fn selected_vendors(ids: &std::collections::BTreeSet<String>) -> Vec<VendorHandle> {
    all_vendors()
        .into_iter()
        .filter(|v| ids.contains(v.id()))
        .collect()
}

/// Vendors that can query the given indicator type.
pub fn vendors_for_type(kind: IndicatorType) -> Vec<VendorHandle> {
    all_vendors()
        .into_iter()
        .filter(|v| v.supports(kind))
        .collect()
}
