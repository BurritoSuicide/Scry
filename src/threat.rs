//! Threat tallies and tag harvesting for the live investigation panels.

use crate::indicator::ResultSeverity;
use crate::vendors::VendorResult;
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Clone, Default)]
pub struct ThreatCounts {
    pub malicious: u64,
    pub suspicious: u64,
    pub benign: u64,
    pub errors: u64,
}

impl ThreatCounts {
    pub fn record(&mut self, severity: ResultSeverity) {
        match severity {
            ResultSeverity::Malicious => self.malicious += 1,
            ResultSeverity::Suspicious => self.suspicious += 1,
            ResultSeverity::Clean => self.benign += 1,
            ResultSeverity::Error => self.errors += 1,
            ResultSeverity::Warning => {}
        }
    }

    pub fn total_classified(&self) -> u64 {
        self.malicious + self.suspicious + self.benign
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TagKind {
    Malware,
    Family,
    Actor,
    Category,
    Pulse,
    Other,
}

impl TagKind {
    pub fn label(self) -> &'static str {
        match self {
            Self::Malware => "malware",
            Self::Family => "family",
            Self::Actor => "actor",
            Self::Category => "category",
            Self::Pulse => "pulse",
            Self::Other => "tag",
        }
    }
}

#[derive(Debug, Clone)]
pub struct TagHit {
    pub tag: String,
    pub kind: TagKind,
    pub count: u64,
    pub sources: BTreeSet<String>,
    pub sample_indicator: String,
}

#[derive(Debug, Clone, Default)]
pub struct ThreatBoard {
    pub counts: ThreatCounts,
    /// Lowercase tag → aggregate hit.
    pub tags: BTreeMap<String, TagHit>,
}

impl ThreatBoard {
    pub fn clear(&mut self) {
        *self = Self::default();
    }

    pub fn ingest(&mut self, result: &VendorResult) {
        self.counts.record(result.severity());
        for (kind, raw) in extract_tags(result) {
            let display = raw.trim();
            if display.is_empty() {
                continue;
            }
            let key = display.to_ascii_lowercase();
            let entry = self.tags.entry(key).or_insert_with(|| TagHit {
                tag: display.to_string(),
                kind,
                count: 0,
                sources: BTreeSet::new(),
                sample_indicator: result.indicator.clone(),
            });
            entry.count += 1;
            entry.sources.insert(result.vendor_id.clone());
            if entry.sample_indicator.is_empty() {
                entry.sample_indicator = result.indicator.clone();
            }
        }
    }

    /// Highest-count tags first (cap for the TUI).
    pub fn top_tags(&self, limit: usize) -> Vec<&TagHit> {
        let mut items: Vec<&TagHit> = self.tags.values().collect();
        items.sort_by(|a, b| {
            b.count
                .cmp(&a.count)
                .then_with(|| a.tag.to_ascii_lowercase().cmp(&b.tag.to_ascii_lowercase()))
        });
        items.into_iter().take(limit).collect()
    }
}

/// Pull malware / actor / category labels out of normalized vendor fields.
pub fn extract_tags(result: &VendorResult) -> Vec<(TagKind, String)> {
    let f = &result.fields;
    let mut out = Vec::new();

    push_split(&mut out, TagKind::Other, f.get("mb_tags"), &[',', ';']);
    push_one(&mut out, TagKind::Malware, f.get("mb_signature"));
    push_one(&mut out, TagKind::Malware, f.get("tf_malware"));
    push_one(&mut out, TagKind::Malware, f.get("feodo_malware"));
    push_one(&mut out, TagKind::Family, f.get("vx_family"));
    push_one(&mut out, TagKind::Category, f.get("tf_threat_type"));
    push_split(&mut out, TagKind::Category, f.get("categories"), &[',', ';', '|']);
    push_split(&mut out, TagKind::Pulse, f.get("pulse_names"), &[';']);

    // GreyNoise actor / service name — only when classified or noisy.
    if let Some(name) = f.get("name") {
        let class = f
            .get("classification")
            .map(|s| s.to_ascii_lowercase())
            .unwrap_or_default();
        let noise = f.get("noise").map(|s| s == "true").unwrap_or(false);
        if !name.is_empty()
            && (noise
                || class.contains("malicious")
                || class.contains("suspicious")
                || class.contains("benign"))
        {
            out.push((TagKind::Actor, name.clone()));
        }
    }

    // Generic fallbacks some vendors may populate later.
    push_split(&mut out, TagKind::Other, f.get("tags"), &[',', ';']);
    push_one(&mut out, TagKind::Family, f.get("malware_family"));
    push_one(&mut out, TagKind::Actor, f.get("threat_actor"));

    out.retain(|(_, t)| {
        let s = t.trim().to_ascii_lowercase();
        !s.is_empty() && s != "unknown" && s != "none" && s != "n/a" && s != "-"
    });
    out
}

fn push_one(out: &mut Vec<(TagKind, String)>, kind: TagKind, value: Option<&String>) {
    if let Some(v) = value {
        let t = v.trim();
        if !t.is_empty() {
            out.push((kind, t.to_string()));
        }
    }
}

fn push_split(
    out: &mut Vec<(TagKind, String)>,
    kind: TagKind,
    value: Option<&String>,
    seps: &[char],
) {
    if let Some(v) = value {
        for part in v.split(|c| seps.contains(&c)) {
            let t = part.trim();
            if !t.is_empty() {
                out.push((kind, t.to_string()));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::indicator::{Indicator, IndicatorType};
    use crate::vendors::VendorResult;
    use serde_json::json;
    use std::collections::BTreeMap;

    #[test]
    fn harvests_malware_and_actor_tags() {
        let mut fields = BTreeMap::new();
        fields.insert("malicious".into(), "1".into());
        fields.insert("mb_tags".into(), "apt29, cobaltstrike".into());
        fields.insert("tf_malware".into(), "RedLine".into());
        fields.insert("name".into(), "FancyBear".into());
        fields.insert("classification".into(), "malicious".into());
        let ind = Indicator::new("1.2.3.4", IndicatorType::IpAddress, 1);
        let result = VendorResult::ok("abusech", &ind, "hit", fields, json!({}));
        let tags = extract_tags(&result);
        assert!(tags.iter().any(|(_, t)| t == "apt29"));
        assert!(tags.iter().any(|(_, t)| t == "RedLine"));
        assert!(tags
            .iter()
            .any(|(k, t)| *k == TagKind::Actor && t == "FancyBear"));

        let mut board = ThreatBoard::default();
        board.ingest(&result);
        assert_eq!(board.counts.malicious, 1);
        assert!(board.tags.contains_key("redline"));
    }
}
