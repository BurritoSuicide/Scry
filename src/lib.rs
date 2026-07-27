//! Charon — modular OSINT investigation TUI.

pub mod app;
pub mod browser;
pub mod config;
pub mod error;
pub mod indicator;
pub mod investigation;
pub mod output;
pub mod rate_limit;
pub mod theme;
pub mod tui;
pub mod vendors;

pub use app::{App, Screen};
pub use error::{CharonError, Result};
