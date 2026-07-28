//! Normalize and deduplicate indicator lines (defang, strip URLs, etc.).

use super::{classify_line, DetectionSummary, Indicator, IndicatorType};
use crate::error::{ScryError, Result};
use std::collections::BTreeSet;
use std::fs;
use std::path::Path;

/// Options for loading an indicator file.
#[derive(Debug, Clone, Copy)]
pub struct DetectOptions {
    pub normalize: bool,
    pub dedup: bool,
}

impl Default for DetectOptions {
    fn default() -> Self {
        Self {
            normalize: false,
            dedup: false,
        }
    }
}

impl DetectOptions {
    pub fn from_flags(normalize_and_dedup: bool) -> Self {
        Self {
            normalize: normalize_and_dedup,
            dedup: normalize_and_dedup,
        }
    }
}

/// Refang / clean a single raw indicator line (no classification).
pub fn normalize_line(raw: &str) -> String {
    let mut s = raw.trim().to_string();
    if s.is_empty() {
        return s;
    }

    // Strip surrounding quotes.
    if (s.starts_with('"') && s.ends_with('"')) || (s.starts_with('\'') && s.ends_with('\'')) {
        s = s[1..s.len() - 1].trim().to_string();
    }

    // Common defanging.
    s = s.replace("[.]", ".");
    s = s.replace("(.)", ".");
    s = s.replace("{.}", ".");
    s = s.replace("[://]", "://");
    s = s.replace("[:]", ":");
    // hxxp / hXXp variants
    if let Some(rest) = strip_prefix_ci(&s, "hxxps://") {
        s = format!("https://{rest}");
    } else if let Some(rest) = strip_prefix_ci(&s, "hxxp://") {
        s = format!("http://{rest}");
    }

    // Strip URL scheme and path → host/IP (or keep path-less token).
    if let Some(rest) = strip_prefix_ci(&s, "https://") {
        s = host_from_url_rest(rest);
    } else if let Some(rest) = strip_prefix_ci(&s, "http://") {
        s = host_from_url_rest(rest);
    }

    // Trailing punctuation / commas often pasted from reports.
    while s.ends_with([',', ';', '.', ')', ']', '}']) {
        // Don't strip trailing dots from domains like "co.uk." wait — co.uk shouldn't end with .
        // Only strip if it's clearly punctuation after a TLD-ish token; be conservative:
        if s.ends_with([',', ';', ')', ']', '}']) {
            s.pop();
            s = s.trim_end().to_string();
        } else if s.ends_with('.') && s.matches('.').count() >= 2 {
            // "example.com." → "example.com"
            s.pop();
            break;
        } else {
            break;
        }
    }

    s.trim().to_string()
}

fn strip_prefix_ci<'a>(s: &'a str, prefix: &str) -> Option<&'a str> {
    if s.len() >= prefix.len() && s[..prefix.len()].eq_ignore_ascii_case(prefix) {
        Some(&s[prefix.len()..])
    } else {
        None
    }
}

fn host_from_url_rest(rest: &str) -> String {
    let rest = rest.trim();
    // Drop userinfo@ if present.
    let after_at = rest.rsplit_once('@').map(|(_, h)| h).unwrap_or(rest);
    // Host[:port][/path][?query]
    let host_port = after_at
        .split(['/', '?', '#'])
        .next()
        .unwrap_or(after_at)
        .trim();
    // Strip brackets for IPv6 literals [::1]:443
    if host_port.starts_with('[') {
        if let Some(end) = host_port.find(']') {
            return host_port[1..end].to_string();
        }
    }
    // Strip :port for IPv4/hostname
    if let Some((host, port)) = host_port.rsplit_once(':') {
        if port.chars().all(|c| c.is_ascii_digit()) && !host.contains(':') {
            return host.to_string();
        }
    }
    host_port.to_string()
}

/// Normalize then classify; returns Unknown for empty lines.
pub fn classify_normalized(line: &str, line_no: usize) -> Indicator {
    let cleaned = normalize_line(line);
    if cleaned.is_empty() {
        return Indicator::new("", IndicatorType::Unknown, line_no);
    }
    classify_line(&cleaned, line_no)
}

/// Apply normalize + optional dedup to an in-memory list of lines.
/// Returns `(new_lines, removed_duplicates)`.
pub fn normalize_and_dedup_lines(lines: &[String]) -> (Vec<String>, usize) {
    let mut out = Vec::new();
    let mut seen = BTreeSet::new();
    let mut dupes = 0usize;

    for line in lines {
        if line.trim().is_empty() {
            continue;
        }
        let cleaned = normalize_line(line);
        if cleaned.is_empty() {
            continue;
        }
        let key = dedup_key(&cleaned);
        if !seen.insert(key) {
            dupes += 1;
            continue;
        }
        out.push(cleaned);
    }
    (out, dupes)
}

fn dedup_key(normalized: &str) -> String {
    let ind = classify_line(normalized, 0);
    match ind.kind {
        IndicatorType::Domain | IndicatorType::Email => ind.raw.to_ascii_lowercase(),
        IndicatorType::Hash | IndicatorType::Ja4 => ind.raw.to_ascii_lowercase(),
        IndicatorType::IpAddress => ind.raw,
        IndicatorType::Unknown => normalized.to_ascii_lowercase(),
    }
}

/// Load indicators with optional normalize/dedup.
pub fn detect_file_with(path: &Path, opts: DetectOptions) -> Result<DetectionSummary> {
    let contents = fs::read_to_string(path).map_err(|e| {
        ScryError::msg(format!("failed to read {}: {e}", path.display()))
    })?;

    let mut summary = DetectionSummary::default();
    let mut seen = BTreeSet::new();
    let mut line_no = 0usize;

    for line in contents.lines() {
        line_no += 1;
        if line.trim().is_empty() {
            continue;
        }
        let indicator = if opts.normalize {
            classify_normalized(line, line_no)
        } else {
            classify_line(line, line_no)
        };
        if indicator.raw.is_empty() {
            continue;
        }
        if opts.dedup {
            let key = dedup_key(&indicator.raw);
            if !seen.insert(key) {
                continue;
            }
        }
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
    fn refangs_and_strips_url() {
        assert_eq!(normalize_line("hxxp://evil[.]com/path"), "evil.com");
        assert_eq!(normalize_line("https://1.2.3.4:8080/x"), "1.2.3.4");
        assert_eq!(normalize_line("\"example.com.\""), "example.com");
    }

    #[test]
    fn dedups_domains_case_insensitive() {
        let (out, dupes) = normalize_and_dedup_lines(&[
            "Example.COM".into(),
            "https://example.com/a".into(),
            "8.8.8.8".into(),
            "8.8.8.8".into(),
        ]);
        assert_eq!(dupes, 2);
        assert_eq!(out.len(), 2);
        assert!(out.iter().any(|s| s.eq_ignore_ascii_case("example.com")));
        assert!(out.iter().any(|s| s == "8.8.8.8"));
    }
}
