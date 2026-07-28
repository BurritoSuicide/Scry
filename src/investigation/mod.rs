//! Investigation orchestration: rate-limited multi-vendor queries.

mod runner;

pub use runner::{
    preview_fit, InvestigationProgress, InvestigationRequest, InvestigationStatus, LiveEvent,
    ProgressSnapshot, run_investigation,
};
