//! Persistent configuration: API keys, selected vendors, defaults.

use crate::error::{CharonError, Result};
use crate::theme::ColorScheme;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    /// Vendor id → API key (cached for future sessions).
    #[serde(default)]
    pub api_keys: BTreeMap<String, String>,

    /// Vendor ids currently enabled for investigations.
    #[serde(default)]
    pub selected_vendors: BTreeSet<String>,

    /// Default output preferences (overridable per-run in the TUI).
    #[serde(default)]
    pub defaults: OutputDefaults,

    /// Active TUI color scheme.
    #[serde(default)]
    pub color_scheme: ColorScheme,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OutputDefaults {
    #[serde(default = "default_format")]
    pub format: OutputFormat,
    #[serde(default = "default_verbosity")]
    pub verbosity: Verbosity,
}

fn default_format() -> OutputFormat {
    OutputFormat::Csv
}

fn default_verbosity() -> Verbosity {
    Verbosity::Normal
}

impl Default for OutputDefaults {
    fn default() -> Self {
        Self {
            format: OutputFormat::Csv,
            verbosity: Verbosity::Normal,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OutputFormat {
    Csv,
    RawTxt,
    Both,
}

impl OutputFormat {
    pub fn label(self) -> &'static str {
        match self {
            Self::Csv => "CSV (per-vendor fields)",
            Self::RawTxt => "Raw TXT (full JSON dumps)",
            Self::Both => "Both CSV + Raw TXT",
        }
    }

    pub fn all() -> &'static [OutputFormat] {
        &[Self::Csv, Self::RawTxt, Self::Both]
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Verbosity {
    Quiet,
    Normal,
    Verbose,
}

impl Verbosity {
    pub fn label(self) -> &'static str {
        match self {
            Self::Quiet => "Quiet — key fields only",
            Self::Normal => "Normal — useful summary fields",
            Self::Verbose => "Verbose — full vendor payload",
        }
    }

    pub fn all() -> &'static [Verbosity] {
        &[Self::Quiet, Self::Normal, Self::Verbose]
    }
}

impl Default for Config {
    fn default() -> Self {
        Self {
            api_keys: BTreeMap::new(),
            // VirusTotal selected by default so first-run flow is obvious.
            selected_vendors: BTreeSet::from(["virustotal".to_string()]),
            defaults: OutputDefaults::default(),
            color_scheme: ColorScheme::default(),
        }
    }
}

impl Config {
    pub fn config_dir() -> Result<PathBuf> {
        let base = dirs::config_dir().ok_or_else(|| {
            CharonError::Config("could not resolve user config directory".into())
        })?;
        Ok(base.join("charon"))
    }

    pub fn config_path() -> Result<PathBuf> {
        Ok(Self::config_dir()?.join("config.toml"))
    }

    pub fn load() -> Result<Self> {
        let path = Self::config_path()?;
        if !path.exists() {
            let cfg = Self::default();
            cfg.save()?;
            return Ok(cfg);
        }
        let raw = fs::read_to_string(&path)?;
        let cfg: Config = toml::from_str(&raw)
            .map_err(|e| CharonError::Config(format!("parse {}: {e}", path.display())))?;
        Ok(cfg)
    }

    pub fn save(&self) -> Result<()> {
        let dir = Self::config_dir()?;
        fs::create_dir_all(&dir)?;
        let path = dir.join("config.toml");
        let raw = toml::to_string_pretty(self)
            .map_err(|e| CharonError::Config(format!("serialize config: {e}")))?;
        fs::write(path, raw)?;
        Ok(())
    }

    pub fn api_key(&self, vendor_id: &str) -> Option<&str> {
        self.api_keys
            .get(vendor_id)
            .map(String::as_str)
            .filter(|k| !k.is_empty())
    }

    pub fn set_api_key(&mut self, vendor_id: impl Into<String>, key: impl Into<String>) {
        let key = key.into().trim().to_string();
        let id = vendor_id.into();
        if key.is_empty() {
            self.api_keys.remove(&id);
        } else {
            self.api_keys.insert(id, key);
        }
    }

    pub fn clear_api_key(&mut self, vendor_id: &str) {
        self.api_keys.remove(vendor_id);
    }

    pub fn is_vendor_selected(&self, vendor_id: &str) -> bool {
        self.selected_vendors.contains(vendor_id)
    }

    pub fn toggle_vendor(&mut self, vendor_id: &str) -> bool {
        if self.selected_vendors.contains(vendor_id) {
            self.selected_vendors.remove(vendor_id);
            false
        } else {
            self.selected_vendors.insert(vendor_id.to_string());
            true
        }
    }

    pub fn selected_count(&self) -> usize {
        self.selected_vendors.len()
    }
}
