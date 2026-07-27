//! Result exporters.

mod csv_out;
mod raw_out;

use crate::config::{OutputFormat, Verbosity};
use crate::error::Result;
use crate::vendors::VendorResult;
use std::path::{Path, PathBuf};

pub fn write_results(
    output_dir: &Path,
    basename: &str,
    results: &[VendorResult],
    format: OutputFormat,
    verbosity: Verbosity,
) -> Result<Vec<PathBuf>> {
    let mut paths = Vec::new();
    match format {
        OutputFormat::Csv => {
            paths.push(csv_out::write_csv(
                &output_dir.join(format!("{basename}.csv")),
                results,
                verbosity,
            )?);
        }
        OutputFormat::RawTxt => {
            paths.push(raw_out::write_raw(
                &output_dir.join(format!("{basename}_raw.txt")),
                results,
                verbosity,
            )?);
        }
        OutputFormat::Both => {
            paths.push(csv_out::write_csv(
                &output_dir.join(format!("{basename}.csv")),
                results,
                verbosity,
            )?);
            paths.push(raw_out::write_raw(
                &output_dir.join(format!("{basename}_raw.txt")),
                results,
                verbosity,
            )?);
        }
    }
    Ok(paths)
}
