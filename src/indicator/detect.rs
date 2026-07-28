use super::{expand_cidr_to_first_ip, parse_cidr, HashKind, Indicator, IndicatorType};
use crate::error::{ScryError, Result};
use regex::Regex;
use std::collections::BTreeMap;
use std::fs;
use std::path::Path;
use std::sync::OnceLock;

fn email_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"(?i)^[a-z0-9._%+\-]+@[a-z0-9.\-]+\.[a-z]{2,}$").expect("email regex")
    })
}

fn ipv4_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r"^(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)$",
        )
        .expect("ipv4 regex")
    })
}

fn ipv6_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"(?i)^(?:[0-9a-f]{1,4}:){2,7}[0-9a-f]{1,4}$|^::(?:[0-9a-f]{1,4}:){0,6}[0-9a-f]{1,4}$|^(?:[0-9a-f]{1,4}:){1,7}:$").expect("ipv6 regex")
    })
}

fn cidr_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    // IPv4 or IPv6 address followed by /prefix
    RE.get_or_init(|| {
        Regex::new(
            r"(?i)^(?:(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)|[0-9a-f:]+)/([0-9]{1,3})$",
        )
        .expect("cidr regex")
    })
}

fn ja4_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"(?i)^[tq][0-9]{2}[a-z0-9]+_[0-9a-f]+(?:_[0-9a-f]+)+$").expect("ja4 regex")
    })
}

fn hex_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"(?i)^[0-9a-f]+$").expect("hex regex"))
}

fn domain_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r"(?i)^(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$",
        )
        .expect("domain regex")
    })
}

/// Classify a single trimmed line into an indicator type.
/// CIDR subnets become an IP indicator querying the first address in range.
pub fn classify_line(line: &str, line_no: usize) -> Indicator {
    let raw = line.trim();
    if raw.is_empty() {
        return Indicator::new(raw, IndicatorType::Unknown, line_no);
    }

    if email_re().is_match(raw) {
        return Indicator::new(raw, IndicatorType::Email, line_no);
    }

    // Subnets before bare IPs so "1.2.3.0/24" isn't partially matched.
    if cidr_re().is_match(raw) {
        if let Some((first_ip, cidr)) = parse_cidr(raw) {
            return Indicator::new(first_ip, IndicatorType::IpAddress, line_no).with_subnet(cidr);
        }
        // Host route like /32 — treat as plain IP if the address part is valid.
        if let Some((addr, prefix)) = raw.split_once('/') {
            if let Some(first) = expand_cidr_to_first_ip(addr, prefix.parse().unwrap_or(255)) {
                return Indicator::new(first, IndicatorType::IpAddress, line_no);
            }
        }
    }

    if ipv4_re().is_match(raw) || ipv6_re().is_match(raw) {
        return Indicator::new(raw, IndicatorType::IpAddress, line_no);
    }

    if ja4_re().is_match(raw) {
        return Indicator::new(raw, IndicatorType::Ja4, line_no);
    }

    if hex_re().is_match(raw) {
        let kind = match raw.len() {
            32 => Some(HashKind::Md5),
            40 => Some(HashKind::Sha1),
            64 => Some(HashKind::Sha256),
            128 => Some(HashKind::Sha512),
            _ => None,
        };
        if let Some(hash_kind) = kind {
            return Indicator::new(raw, IndicatorType::Hash, line_no).with_hash_kind(hash_kind);
        }
    }

    if domain_re().is_match(raw) {
        return Indicator::new(raw.to_ascii_lowercase(), IndicatorType::Domain, line_no);
    }

    Indicator::new(raw, IndicatorType::Unknown, line_no)
}

#[derive(Debug, Clone, Default)]
pub struct DetectionSummary {
    pub indicators: Vec<Indicator>,
    pub counts: BTreeMap<IndicatorType, usize>,
    pub unknowns: usize,
    /// `(original_cidr, first_ip)` for each expanded subnet.
    pub subnet_expansions: Vec<(String, String)>,
}

impl DetectionSummary {
    pub fn total(&self) -> usize {
        self.indicators.len()
    }

    pub fn known_types(&self) -> Vec<IndicatorType> {
        IndicatorType::all_known()
            .iter()
            .copied()
            .filter(|t| self.counts.get(t).copied().unwrap_or(0) > 0)
            .collect()
    }

    pub fn is_predominantly(&self, kind: IndicatorType) -> bool {
        let n = self.counts.get(&kind).copied().unwrap_or(0);
        n > 0 && n * 2 >= self.total().saturating_sub(self.unknowns).max(1)
    }
}

/// Load a newline-separated indicator file and auto-detect types.
pub fn detect_file(path: &Path) -> Result<DetectionSummary> {
    let contents = fs::read_to_string(path).map_err(|e| {
        ScryError::msg(format!("failed to read {}: {e}", path.display()))
    })?;

    let mut summary = DetectionSummary::default();
    for (idx, line) in contents.lines().enumerate() {
        let line_no = idx + 1;
        if line.trim().is_empty() {
            continue;
        }
        let indicator = classify_line(line, line_no);
        if let Some(cidr) = indicator.from_subnet.clone() {
            summary
                .subnet_expansions
                .push((cidr, indicator.raw.clone()));
        }
        *summary.counts.entry(indicator.kind).or_insert(0) += 1;
        if indicator.kind == IndicatorType::Unknown {
            summary.unknowns += 1;
        }
        summary.indicators.push(indicator);
    }

    if summary.indicators.is_empty() {
        return Err(ScryError::msg("input file contained no indicators"));
    }

    Ok(summary)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_common_shapes() {
        assert_eq!(
            classify_line("alice@example.com", 1).kind,
            IndicatorType::Email
        );
        assert_eq!(
            classify_line("8.8.8.8", 1).kind,
            IndicatorType::IpAddress
        );
        assert_eq!(
            classify_line("t13d1516h2_8daaf6152771_b186095e22b6", 1).kind,
            IndicatorType::Ja4
        );
        let h = classify_line("d41d8cd98f00b204e9800998ecf8427e", 1);
        assert_eq!(h.kind, IndicatorType::Hash);
        assert_eq!(h.hash_kind, Some(HashKind::Md5));
    }

    #[test]
    fn detects_subnet_and_expands() {
        let ind = classify_line("192.168.1.0/24", 1);
        assert_eq!(ind.kind, IndicatorType::IpAddress);
        assert_eq!(ind.raw, "192.168.1.0");
        assert_eq!(ind.from_subnet.as_deref(), Some("192.168.1.0/24"));
    }
}
