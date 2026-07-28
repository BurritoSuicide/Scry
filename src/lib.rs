//! Scry — modular OSINT investigation TUI.

pub mod app;
pub mod browser;
pub mod clipboard;
pub mod cli;
pub mod config;
pub mod editor;
pub mod error;
pub mod indicator;
pub mod investigation;
pub mod map;
pub mod output;
pub mod rate_limit;
pub mod theme;
pub mod threat;
pub mod tui;
pub mod vendors;
pub mod viewer;

pub use app::{App, Screen};
pub use error::{Result, ScryError};
