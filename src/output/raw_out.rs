use crate::config::Verbosity;
use crate::error::Result;
use crate::vendors::VendorResult;
use std::fs::File;
use std::io::Write;
use std::path::{Path, PathBuf};

pub fn write_raw(path: &Path, results: &[VendorResult], verbosity: Verbosity) -> Result<PathBuf> {
    let mut file = File::create(path)?;

    for (idx, r) in results.iter().enumerate() {
        writeln!(file, "========== Result {} ==========", idx + 1)?;
        writeln!(file, "vendor:    {}", r.vendor_id)?;
        writeln!(file, "indicator: {}", r.indicator)?;
        writeln!(file, "type:      {}", r.indicator_type)?;
        writeln!(file, "success:   {}", r.success)?;
        if r.success {
            writeln!(file, "summary:   {}", r.summary)?;
            if !r.fields.is_empty() && !matches!(verbosity, Verbosity::Quiet) {
                writeln!(file, "fields:")?;
                for (k, v) in &r.fields {
                    writeln!(file, "  {k}: {v}")?;
                }
            }
            if matches!(verbosity, Verbosity::Verbose) {
                writeln!(file, "raw:")?;
                writeln!(
                    file,
                    "{}",
                    serde_json::to_string_pretty(&r.raw).unwrap_or_else(|_| r.raw.to_string())
                )?;
            }
        } else {
            writeln!(
                file,
                "error:     {}",
                r.error.as_deref().unwrap_or("unknown")
            )?;
        }
        writeln!(file)?;
    }

    Ok(path.to_path_buf())
}
