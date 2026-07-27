//! Application state machine driving Charon's screens.

use crate::config::{Config, OutputFormat, Verbosity};
use crate::indicator::DetectionSummary;
use crate::investigation::{
    preview_fit, InvestigationRequest, InvestigationStatus, LiveEvent, ProgressSnapshot,
};
use crate::theme::ColorScheme;
use crate::vendors::{all_vendors, VendorFit};
use std::path::PathBuf;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Screen {
    MainMenu,
    Investigation,
    ApiKeys,
    Vendors,
    ColorScheme,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InvestigateStep {
    InputPath,
    ReviewDetection,
    OutputFormat,
    Verbosity,
    Running,
    Done,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApiKeyMode {
    List,
    EnterKey,
    ConfirmClear,
}

pub struct App {
    pub config: Config,
    pub screen: Screen,
    pub should_quit: bool,
    pub status_message: String,

    // Main menu
    pub menu_index: usize,

    // Investigation wizard
    pub investigate_step: InvestigateStep,
    pub input_path: String,
    pub output_dir: String,
    pub detection: Option<DetectionSummary>,
    pub vendor_fits: Vec<VendorFit>,
    pub format_index: usize,
    pub verbosity_index: usize,
    pub progress: ProgressSnapshot,
    pub live_lines: Vec<String>,
    pub output_paths: Vec<PathBuf>,
    pub investigate_cursor: usize, // for review lists etc.
    investigation_tx: Option<mpsc::UnboundedReceiver<LiveEvent>>,
    investigation_handle: Option<JoinHandle<()>>,

    // API keys
    pub api_key_mode: ApiKeyMode,
    pub api_key_index: usize,
    pub api_key_input: String,

    // Vendors
    pub vendor_index: usize,
    /// When enabling a vendor without a key, jump into key entry.
    pub pending_key_for_vendor: Option<String>,

    // Color scheme picker
    pub color_scheme_index: usize,
    color_scheme_backup: ColorScheme,
}

impl App {
    pub fn new(config: Config) -> Self {
        let format_index = OutputFormat::all()
            .iter()
            .position(|f| *f == config.defaults.format)
            .unwrap_or(0);
        let verbosity_index = Verbosity::all()
            .iter()
            .position(|v| *v == config.defaults.verbosity)
            .unwrap_or(1);

        let color_scheme_index = ColorScheme::all()
            .iter()
            .position(|s| *s == config.color_scheme)
            .unwrap_or(0);
        let color_scheme_backup = config.color_scheme;

        Self {
            config,
            screen: Screen::MainMenu,
            should_quit: false,
            status_message: "↑↓ navigate · Enter select · q quit".into(),
            menu_index: 0,
            investigate_step: InvestigateStep::InputPath,
            input_path: String::new(),
            output_dir: default_output_dir(),
            detection: None,
            vendor_fits: Vec::new(),
            format_index,
            verbosity_index,
            progress: ProgressSnapshot::default(),
            live_lines: Vec::new(),
            output_paths: Vec::new(),
            investigate_cursor: 0,
            investigation_tx: None,
            investigation_handle: None,
            api_key_mode: ApiKeyMode::List,
            api_key_index: 0,
            api_key_input: String::new(),
            vendor_index: 0,
            pending_key_for_vendor: None,
            color_scheme_index,
            color_scheme_backup,
        }
    }

    pub fn menu_items() -> &'static [&'static str] {
        &[
            "Run OSINT Investigation",
            "Add / Remove / Change API Key",
            "List / Select Vendors",
            "Color Scheme",
            "Quit",
        ]
    }

    pub fn palette(&self) -> crate::theme::Palette {
        self.config.color_scheme.palette()
    }

    pub fn selected_format(&self) -> OutputFormat {
        OutputFormat::all()[self.format_index]
    }

    pub fn selected_verbosity(&self) -> Verbosity {
        Verbosity::all()[self.verbosity_index]
    }

    pub fn open_main_menu(&mut self) {
        self.screen = Screen::MainMenu;
        self.status_message =
            "↑↓ navigate · Enter select · q quit".into();
    }

    pub fn open_investigation(&mut self) {
        self.screen = Screen::Investigation;
        self.investigate_step = InvestigateStep::InputPath;
        self.input_path.clear();
        self.detection = None;
        self.vendor_fits.clear();
        self.live_lines.clear();
        self.output_paths.clear();
        self.progress = ProgressSnapshot::default();
        self.status_message =
            "Enter path to newline-separated indicator file · Esc back".into();
    }

    pub fn open_api_keys(&mut self) {
        self.screen = Screen::ApiKeys;
        self.api_key_mode = ApiKeyMode::List;
        self.api_key_index = 0;
        self.api_key_input.clear();
        self.status_message =
            "↑↓ select vendor · Enter set key · d delete · Esc back".into();
    }

    pub fn open_vendors(&mut self) {
        self.screen = Screen::Vendors;
        self.vendor_index = 0;
        self.status_message =
            "↑↓ move · Space/Enter toggle · Esc back".into();
    }

    pub fn open_color_scheme(&mut self) {
        self.screen = Screen::ColorScheme;
        self.color_scheme_backup = self.config.color_scheme;
        self.color_scheme_index = ColorScheme::all()
            .iter()
            .position(|s| *s == self.config.color_scheme)
            .unwrap_or(0);
        self.status_message =
            "↑↓ preview · Enter apply & save · Esc cancel".into();
    }

    pub fn cancel_color_scheme(&mut self) {
        self.config.color_scheme = self.color_scheme_backup;
        self.open_main_menu();
    }

    pub fn activate_menu_item(&mut self) {
        match self.menu_index {
            0 => self.open_investigation(),
            1 => self.open_api_keys(),
            2 => self.open_vendors(),
            3 => self.open_color_scheme(),
            4 => self.should_quit = true,
            _ => {}
        }
    }

    pub fn apply_color_scheme_at_cursor(&mut self) {
        if let Some(scheme) = ColorScheme::all().get(self.color_scheme_index).copied() {
            self.config.color_scheme = scheme;
            let _ = self.config.save();
            self.status_message = format!("Color scheme set to {}", scheme.label());
            self.open_main_menu();
        }
    }

    pub fn preview_color_scheme_at_cursor(&mut self) {
        if let Some(scheme) = ColorScheme::all().get(self.color_scheme_index).copied() {
            self.config.color_scheme = scheme;
        }
    }

    pub fn submit_input_path(&mut self) {
        let path = PathBuf::from(self.input_path.trim());
        match preview_fit(&self.config, &path) {
            Ok((summary, fits)) => {
                self.detection = Some(summary);
                self.vendor_fits = fits;
                self.investigate_step = InvestigateStep::ReviewDetection;
                self.investigate_cursor = 0;
                self.status_message =
                    "Review detection & vendor fit · Enter continue · Esc back".into();
            }
            Err(e) => {
                self.status_message = format!("⚠ {e}");
            }
        }
    }

    pub fn start_investigation(&mut self) {
        let input = PathBuf::from(self.input_path.trim());
        let output_dir = PathBuf::from(self.output_dir.trim());
        let request = InvestigationRequest {
            input_path: input,
            output_dir,
            format: self.selected_format(),
            verbosity: self.selected_verbosity(),
        };

        let (tx, rx) = mpsc::unbounded_channel();
        self.investigation_tx = Some(rx);
        self.investigate_step = InvestigateStep::Running;
        self.progress.status = InvestigationStatus::Preparing;
        self.live_lines.clear();
        self.status_message = "Investigation running… · Esc cancels view (task continues)".into();

        // Persist chosen defaults for next time.
        self.config.defaults.format = self.selected_format();
        self.config.defaults.verbosity = self.selected_verbosity();
        let _ = self.config.save();

        let config = self.config.clone();
        self.investigation_handle = Some(tokio::spawn(async move {
            crate::investigation::run_investigation(config, request, tx).await;
        }));
    }

    pub fn poll_investigation(&mut self) {
        let mut finished = false;
        if let Some(rx) = self.investigation_tx.as_mut() {
            while let Ok(event) = rx.try_recv() {
                match event {
                    LiveEvent::Warning(w) => {
                        self.live_lines.push(format!("⚠ {w}"));
                    }
                    LiveEvent::Progress(p) => {
                        self.progress = p;
                    }
                    LiveEvent::ResultLine(line) => {
                        self.live_lines.push(line);
                        if self.live_lines.len() > 200 {
                            self.live_lines.remove(0);
                        }
                    }
                    LiveEvent::Finished {
                        output_paths,
                        results,
                    } => {
                        self.output_paths = output_paths;
                        self.investigate_step = InvestigateStep::Done;
                        self.status_message =
                            format!("Complete — {results} result(s). Enter returns to menu.");
                        finished = true;
                    }
                    LiveEvent::Failed(err) => {
                        self.progress.status = InvestigationStatus::Failed(err.clone());
                        self.investigate_step = InvestigateStep::Done;
                        self.status_message = format!("Failed: {err}");
                        finished = true;
                    }
                }
            }
        }
        if finished {
            self.investigation_tx = None;
        }
    }

    pub fn vendor_ids(&self) -> Vec<&'static str> {
        all_vendors().iter().map(|v| v.id()).collect()
    }

    pub fn begin_enter_api_key(&mut self, vendor_id: &str) {
        self.pending_key_for_vendor = Some(vendor_id.to_string());
        self.api_key_input.clear();
        self.api_key_mode = ApiKeyMode::EnterKey;
        self.screen = Screen::ApiKeys;
        self.status_message = format!("Paste API key for {vendor_id} · Enter save · Esc cancel");
    }

    pub fn save_api_key_input(&mut self) {
        if let Some(vendor_id) = self.pending_key_for_vendor.take() {
            let key = self.api_key_input.trim().to_string();
            if key.is_empty() {
                self.status_message = "API key was empty — not saved".into();
            } else {
                self.config.set_api_key(&vendor_id, key);
                let _ = self.config.save();
                self.config.selected_vendors.insert(vendor_id.clone());
                let _ = self.config.save();
                self.status_message = format!("API key saved for {vendor_id}");
            }
        } else {
            // From API key list screen
            let vendors = all_vendors();
            if let Some(v) = vendors.get(self.api_key_index) {
                let key = self.api_key_input.trim().to_string();
                self.config.set_api_key(v.id(), key);
                let _ = self.config.save();
                self.status_message = format!("API key updated for {}", v.name());
            }
        }
        self.api_key_input.clear();
        self.api_key_mode = ApiKeyMode::List;
    }

    pub fn toggle_vendor_at_cursor(&mut self) {
        let vendors = all_vendors();
        if let Some(v) = vendors.get(self.vendor_index) {
            let id = v.id().to_string();
            let now_selected = self.config.toggle_vendor(&id);
            let _ = self.config.save();
            if now_selected && self.config.api_key(&id).is_none() {
                self.begin_enter_api_key(&id);
            } else if now_selected {
                self.status_message = format!("{} enabled", v.name());
            } else {
                self.status_message = format!("{} disabled", v.name());
            }
        }
    }
}

fn default_output_dir() -> String {
    dirs::home_dir()
        .map(|h| h.join("charon-output").display().to_string())
        .unwrap_or_else(|| "./charon-output".into())
}
