//! Extract unique IP addresses from Scry input or output files.

use crate::config::LastInvestigation;
use crate::indicator::{classify_line, detect_file, IndicatorType};
use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

/// Prefer last input path; otherwise first existing output path.
pub fn resolve_last_investigation_path(last: &LastInvestigation) -> Option<PathBuf> {
    if let Some(input) = &last.input_path {
        if input.is_file() {
            return Some(input.clone());
        }
    }
    last.output_paths
        .iter()
        .find(|p| p.is_file())
        .cloned()
}

/// Collect unique IP strings from an input indicator file or an investigation output.
pub fn extract_ips_from_path(path: &Path) -> Result<Vec<String>, String> {
    if !path.is_file() {
        return Err(format!("file not found: {}", path.display()));
    }
    let name = path
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();

    if name.ends_with(".csv") {
        extract_ips_from_csv(path)
    } else if name.ends_with("_raw.txt") || name.contains("_raw.") {
        extract_ips_from_raw(path)
    } else {
        // Prefer input-style detection; if that fails with no indicators, try raw scan.
        match extract_ips_from_input(path) {
            Ok(ips) if !ips.is_empty() => Ok(ips),
            Ok(_) => Err("no IP addresses found in file".into()),
            Err(e) => {
                // Maybe it's a misnamed output — try line scan for IPs.
                match extract_ips_from_raw(path) {
                    Ok(ips) if !ips.is_empty() => Ok(ips),
                    _ => Err(e),
                }
            }
        }
    }
}

fn extract_ips_from_input(path: &Path) -> Result<Vec<String>, String> {
    let summary = detect_file(path).map_err(|e| e.to_string())?;
    let mut set = BTreeSet::new();
    for ind in summary.indicators {
        if ind.kind == IndicatorType::IpAddress {
            set.insert(ind.raw);
        }
    }
    if set.is_empty() {
        return Err("no IP addresses found in input file".into());
    }
    Ok(set.into_iter().collect())
}

fn extract_ips_from_csv(path: &Path) -> Result<Vec<String>, String> {
    let mut reader = csv::Reader::from_path(path).map_err(|e| format!("read CSV: {e}"))?;
    let headers = reader
        .headers()
        .map_err(|e| format!("CSV headers: {e}"))?
        .clone();

    let indicator_idx = headers
        .iter()
        .position(|h| {
            let h = h.to_ascii_lowercase();
            h == "indicator" || h == "ip" || h == "ip_address"
        })
        .ok_or_else(|| "CSV missing indicator column".to_string())?;

    let type_idx = headers.iter().position(|h| {
        let h = h.to_ascii_lowercase();
        h == "type" || h == "indicator_type"
    });

    let mut set = BTreeSet::new();
    for record in reader.records() {
        let record = record.map_err(|e| format!("CSV row: {e}"))?;
        let indicator = record.get(indicator_idx).unwrap_or("").trim();
        if indicator.is_empty() {
            continue;
        }
        if let Some(ti) = type_idx {
            let ty = record.get(ti).unwrap_or("").trim().to_ascii_lowercase();
            if !ty.is_empty() && ty != "ip" && ty != "ip_address" && ty != "ipaddress" {
                continue;
            }
        }
        let classified = classify_line(indicator, 0);
        if classified.kind == IndicatorType::IpAddress {
            set.insert(classified.raw);
        }
    }

    if set.is_empty() {
        return Err("no IP addresses found in CSV".into());
    }
    Ok(set.into_iter().collect())
}

fn extract_ips_from_raw(path: &Path) -> Result<Vec<String>, String> {
    let contents =
        fs::read_to_string(path).map_err(|e| format!("read {}: {e}", path.display()))?;
    let mut set = BTreeSet::new();
    for (idx, line) in contents.lines().enumerate() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        // Raw dumps look like `indicator: 1.2.3.4` or bare IPs.
        let candidate = if let Some(rest) = trimmed.strip_prefix("indicator:") {
            rest.trim()
        } else if let Some(rest) = trimmed.strip_prefix("Indicator:") {
            rest.trim()
        } else {
            trimmed
        };
        // Take first whitespace-separated token.
        let token = candidate.split_whitespace().next().unwrap_or("");
        let classified = classify_line(token, idx + 1);
        if classified.kind == IndicatorType::IpAddress {
            set.insert(classified.raw);
        }
    }
    if set.is_empty() {
        return Err("no IP addresses found in file".into());
    }
    Ok(set.into_iter().collect())
}
