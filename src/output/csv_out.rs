use crate::config::Verbosity;
use crate::error::{CharonError, Result};
use crate::vendors::VendorResult;
use std::fs::File;
use std::path::{Path, PathBuf};

pub fn write_csv(path: &Path, results: &[VendorResult], verbosity: Verbosity) -> Result<PathBuf> {
    let file = File::create(path)?;
    let mut wtr = csv::Writer::from_writer(file);

    match verbosity {
        Verbosity::Quiet => {
            wtr.write_record(["vendor", "indicator", "type", "success", "summary"])
                .map_err(|e| CharonError::msg(e.to_string()))?;
            for r in results {
                wtr.write_record([
                    r.vendor_id.as_str(),
                    r.indicator.as_str(),
                    r.indicator_type.label(),
                    if r.success { "true" } else { "false" },
                    if r.success {
                        r.summary.as_str()
                    } else {
                        r.error.as_deref().unwrap_or("error")
                    },
                ])
                .map_err(|e| CharonError::msg(e.to_string()))?;
            }
        }
        Verbosity::Normal | Verbosity::Verbose => {
            // Flatten known fields into columns; unknown keys still land in `extra`.
            let mut field_keys: Vec<String> = results
                .iter()
                .flat_map(|r| r.fields.keys().cloned())
                .collect();
            field_keys.sort();
            field_keys.dedup();

            let mut header = vec![
                "vendor".into(),
                "indicator".into(),
                "type".into(),
                "success".into(),
                "summary".into(),
                "error".into(),
            ];
            header.extend(field_keys.iter().cloned());
            if matches!(verbosity, Verbosity::Verbose) {
                header.push("raw_json".into());
            }
            wtr.write_record(&header)
                .map_err(|e| CharonError::msg(e.to_string()))?;

            for r in results {
                let mut row: Vec<String> = vec![
                    r.vendor_id.clone(),
                    r.indicator.clone(),
                    r.indicator_type.label().to_string(),
                    r.success.to_string(),
                    r.summary.clone(),
                    r.error.clone().unwrap_or_default(),
                ];
                for key in &field_keys {
                    row.push(r.fields.get(key).cloned().unwrap_or_default());
                }
                if matches!(verbosity, Verbosity::Verbose) {
                    row.push(r.raw.to_string());
                }
                wtr.write_record(&row)
                    .map_err(|e| CharonError::msg(e.to_string()))?;
            }
        }
    }

    wtr.flush().map_err(|e| CharonError::msg(e.to_string()))?;
    Ok(path.to_path_buf())
}
