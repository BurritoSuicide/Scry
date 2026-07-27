//! Investigation orchestration: rate-limited multi-vendor queries.

mod runner;

pub use runner::{
    preview_fit, run_investigation, InvestigationProgress, InvestigationRequest,
    InvestigationStatus, LiveEvent, ProgressSnapshot,
};
