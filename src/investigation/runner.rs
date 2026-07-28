use crate::config::{Config, OutputFormat, Verbosity};
use crate::error::{ScryError, Result};
use crate::indicator::{detect_file, DetectionSummary, Indicator};
use crate::output;
use crate::rate_limit::RateLimiter;
use crate::vendors::{selected_vendors, VendorFit, VendorHandle, VendorResult};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{mpsc, Mutex};

#[derive(Debug, Clone)]
pub struct InvestigationRequest {
    pub input_path: PathBuf,
    pub output_dir: PathBuf,
    pub format: OutputFormat,
    pub verbosity: Verbosity,
}

#[derive(Debug, Clone)]
pub enum InvestigationStatus {
    Idle,
    Preparing,
    Running,
    WaitingRateLimit { vendor: String, wait: Duration },
    Completed,
    Failed(String),
}

#[derive(Debug, Clone)]
pub struct ProgressSnapshot {
    pub status: InvestigationStatus,
    pub total_queries: usize,
    pub completed_queries: usize,
    pub started_at: Option<Instant>,
    pub eta: Option<Duration>,
    pub current_indicator: Option<String>,
    pub current_vendor: Option<String>,
    pub recent_results: Vec<String>,
    pub warnings: Vec<String>,
}

impl Default for ProgressSnapshot {
    fn default() -> Self {
        Self {
            status: InvestigationStatus::Idle,
            total_queries: 0,
            completed_queries: 0,
            started_at: None,
            eta: None,
            current_indicator: None,
            current_vendor: None,
            recent_results: Vec::new(),
            warnings: Vec::new(),
        }
    }
}

impl ProgressSnapshot {
    pub fn fraction(&self) -> f64 {
        if self.total_queries == 0 {
            0.0
        } else {
            self.completed_queries as f64 / self.total_queries as f64
        }
    }

    pub fn is_active(&self) -> bool {
        matches!(
            self.status,
            InvestigationStatus::Preparing
                | InvestigationStatus::Running
                | InvestigationStatus::WaitingRateLimit { .. }
        )
    }
}

#[derive(Debug, Clone)]
pub enum LiveEvent {
    Warning(String),
    Progress(ProgressSnapshot),
    /// Formatted feed line plus the raw vendor result for threat/tag panels.
    ResultHit {
        line: String,
        result: VendorResult,
    },
    Finished {
        output_paths: Vec<PathBuf>,
        results: usize,
    },
    Failed(String),
}

pub type InvestigationProgress = Arc<Mutex<ProgressSnapshot>>;

pub async fn run_investigation(
    config: Config,
    request: InvestigationRequest,
    tx: mpsc::UnboundedSender<LiveEvent>,
) {
    match run_inner(config, request, &tx).await {
        Ok(()) => {}
        Err(e) => {
            let _ = tx.send(LiveEvent::Failed(e.to_string()));
        }
    }
}

async fn run_inner(
    config: Config,
    request: InvestigationRequest,
    tx: &mpsc::UnboundedSender<LiveEvent>,
) -> Result<()> {
    let mut snap = ProgressSnapshot {
        status: InvestigationStatus::Preparing,
        ..Default::default()
    };
    let _ = tx.send(LiveEvent::Progress(snap.clone()));

    let summary = detect_file(&request.input_path)?;
    let vendors = selected_vendors(&config.selected_vendors);
    if vendors.is_empty() {
        return Err(ScryError::msg(
            "no vendors selected — enable at least one in List / Select Vendors",
        ));
    }

    let present = summary.known_types();
    let mut plan: Vec<(VendorHandle, Indicator)> = Vec::new();
    let mut warnings = Vec::new();

    for vendor in &vendors {
        if config.api_key(vendor.id()).is_none() {
            warnings.push(format!(
                "Skipping {}: no API key cached",
                vendor.name()
            ));
            let _ = tx.send(LiveEvent::Warning(warnings.last().unwrap().clone()));
            continue;
        }

        let fit: VendorFit = vendor.fit_for(&present);
        if !fit.supported {
            warnings.push(format!("⚠ {}", fit.note));
            let _ = tx.send(LiveEvent::Warning(fit.note.clone()));
            continue;
        }
        if fit.note.contains("skipping") || fit.note.contains("Will query") {
            warnings.push(fit.note.clone());
            let _ = tx.send(LiveEvent::Warning(fit.note.clone()));
        }

        for indicator in &summary.indicators {
            if vendor.supports(indicator.kind) {
                plan.push((Arc::clone(vendor), indicator.clone()));
            }
        }
    }

    if plan.is_empty() {
        return Err(ScryError::msg(
            "nothing to query — check vendor selection, API keys, and indicator types",
        ));
    }

    // Extra heuristic: malware hash DBs vs pure IP lists.
    emit_mix_warnings(&summary, &vendors, tx);

    snap.total_queries = plan.len();
    snap.warnings = warnings;
    snap.status = InvestigationStatus::Running;
    snap.started_at = Some(Instant::now());
    let _ = tx.send(LiveEvent::Progress(snap.clone()));

    let mut limiters: HashMap<String, RateLimiter> = HashMap::new();
    for vendor in &vendors {
        let spec = config.effective_rate_limit(vendor.id());
        limiters.insert(vendor.id().to_string(), RateLimiter::new(spec));
    }

    let mut results: Vec<VendorResult> = Vec::with_capacity(plan.len());

    for (vendor, indicator) in plan {
        let key = config
            .api_key(vendor.id())
            .ok_or_else(|| ScryError::MissingApiKey(vendor.id().into()))?
            .to_string();

        let limiter = limiters
            .get_mut(vendor.id())
            .expect("limiter registered for vendor");

        let wait = limiter.time_until_ready();
        if !wait.is_zero() {
            snap.status = InvestigationStatus::WaitingRateLimit {
                vendor: vendor.name().to_string(),
                wait,
            };
            let _ = tx.send(LiveEvent::Progress(snap.clone()));
        }
        limiter.acquire().await;

        snap.status = InvestigationStatus::Running;
        snap.current_vendor = Some(vendor.name().to_string());
        snap.current_indicator = Some(indicator.raw.clone());
        let _ = tx.send(LiveEvent::Progress(snap.clone()));

        let result = match vendor.lookup(&indicator, &key).await {
            Ok(r) => r,
            Err(ScryError::RateLimited(_)) => {
                // Back off a full minute and retry once.
                snap.status = InvestigationStatus::WaitingRateLimit {
                    vendor: vendor.name().to_string(),
                    wait: Duration::from_secs(60),
                };
                let _ = tx.send(LiveEvent::Progress(snap.clone()));
                tokio::time::sleep(Duration::from_secs(60)).await;
                match vendor.lookup(&indicator, &key).await {
                    Ok(r) => r,
                    Err(e) => VendorResult::err(vendor.id(), &indicator, e.to_string()),
                }
            }
            Err(e) => VendorResult::err(vendor.id(), &indicator, e.to_string()),
        };

        let line = match result.severity() {
            crate::indicator::ResultSeverity::Malicious => format!(
                "● {} · {} → {}",
                result.vendor_id, result.indicator, result.summary
            ),
            crate::indicator::ResultSeverity::Suspicious => format!(
                "◐ {} · {} → {}",
                result.vendor_id, result.indicator, result.summary
            ),
            crate::indicator::ResultSeverity::Clean => format!(
                "○ {} · {} → {}",
                result.vendor_id, result.indicator, result.summary
            ),
            crate::indicator::ResultSeverity::Error => format!(
                "✗ {} · {} → {}",
                result.vendor_id,
                result.indicator,
                result.error.clone().unwrap_or_default()
            ),
            crate::indicator::ResultSeverity::Warning => format!(
                "⚠ {} · {} → {}",
                result.vendor_id, result.indicator, result.summary
            ),
        };

        snap.recent_results.push(line.clone());
        if snap.recent_results.len() > 50 {
            snap.recent_results.remove(0);
        }
        snap.completed_queries += 1;
        snap.eta = estimate_eta(&snap, &limiters);
        let _ = tx.send(LiveEvent::ResultHit {
            line,
            result: result.clone(),
        });
        let _ = tx.send(LiveEvent::Progress(snap.clone()));

        results.push(result);
    }

    std::fs::create_dir_all(&request.output_dir)?;
    let stamp = chrono::Local::now().format("%Y%m%d_%H%M%S");
    let base = request
        .input_path
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("investigation");
    let output_paths = output::write_results(
        &request.output_dir,
        &format!("{base}_{stamp}"),
        &results,
        request.format,
        request.verbosity,
    )?;

    snap.status = InvestigationStatus::Completed;
    snap.current_indicator = None;
    snap.current_vendor = None;
    let _ = tx.send(LiveEvent::Progress(snap));
    let _ = tx.send(LiveEvent::Finished {
        output_paths,
        results: results.len(),
    });

    Ok(())
}

fn emit_mix_warnings(
    summary: &DetectionSummary,
    vendors: &[VendorHandle],
    tx: &mpsc::UnboundedSender<LiveEvent>,
) {
    let only_ips = summary.counts.len() == 1
        && summary
            .counts
            .contains_key(&crate::indicator::IndicatorType::IpAddress);
    let mostly_hashes = summary.is_predominantly(crate::indicator::IndicatorType::Hash);

    for vendor in vendors {
        let supports_hash = vendor.supports(crate::indicator::IndicatorType::Hash);
        let supports_ip = vendor.supports(crate::indicator::IndicatorType::IpAddress);

        if only_ips && supports_hash && !supports_ip {
            let msg = format!(
                "Input is IP-only; {} (malware hash focus) may return little of value",
                vendor.name()
            );
            let _ = tx.send(LiveEvent::Warning(msg));
        }
        if mostly_hashes && supports_ip && !supports_hash {
            let msg = format!(
                "Input is mostly hashes; {} (IP/network focus) may not be recommended",
                vendor.name()
            );
            let _ = tx.send(LiveEvent::Warning(msg));
        }
    }

    if summary.unknowns > 0 {
        let _ = tx.send(LiveEvent::Warning(format!(
            "{} line(s) could not be auto-detected and will be skipped",
            summary.unknowns
        )));
    }
}

fn estimate_eta(
    snap: &ProgressSnapshot,
    limiters: &HashMap<String, RateLimiter>,
) -> Option<Duration> {
    let remaining = snap.total_queries.saturating_sub(snap.completed_queries);
    if remaining == 0 {
        return Some(Duration::ZERO);
    }
    // Conservative: assume the slowest vendor pacing dominates.
    let min_rpm = limiters
        .values()
        .map(|l| {
            let s = l.spec();
            if s.unthrottled {
                10_000
            } else {
                s.requests_per_minute.max(1)
            }
        })
        .min()
        .unwrap_or(4);
    let secs = (remaining as u64).saturating_mul(60) / min_rpm as u64;
    Some(Duration::from_secs(secs))
}

/// Preview detection + vendor fit without running queries (for the TUI wizard).
pub fn preview_fit(config: &Config, path: &Path) -> Result<(DetectionSummary, Vec<VendorFit>)> {
    let summary = detect_file(path)?;
    let present = summary.known_types();
    let fits = selected_vendors(&config.selected_vendors)
        .into_iter()
        .map(|v| v.fit_for(&present))
        .collect();
    Ok((summary, fits))
}
