//! Application state machine driving Scry's screens.

use crate::browser::FileBrowser;
use crate::config::{Config, OutputFormat, Verbosity};
use crate::editor::TextEditor;
use crate::indicator::{DetectionSummary, IndicatorType};
use crate::investigation::{
    preview_fit, InvestigationRequest, InvestigationStatus, LiveEvent, ProgressSnapshot,
};
use crate::rate_limit::{RateLimitOverride, RateLimitSpec, UsageProfile};
use crate::theme::ColorScheme;
use crate::threat::ThreatBoard;
use crate::tui::fx::FxEngine;
use crate::vendors::{all_vendors, vendors_for_type, VendorFit};
use crate::viewer::FileViewer;
use std::path::PathBuf;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Screen {
    MainMenu,
    Investigation,
    ApiKeys,
    Vendors,
    Profiles,
    Options,
    ColorScheme,
    ViewOutputBrowse,
    ViewOutput,
    EditInputBrowse,
    EditInput,
    /// Prompt for a new input filename.
    EditInputNewName,
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VendorMode {
    List,
    BulkByType,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OptionsMode {
    List,
    /// Confirm warning before editing rate limits.
    RateWarning,
    /// Pick a vendor to override.
    RateVendorList,
    /// Edit fields for one vendor override.
    RateEdit,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RateEditField {
    PerMinute,
    PerHour,
    PerDay,
    Unthrottled,
    ClearOverride,
    Save,
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
    pub file_browser: FileBrowser,
    pub input_path: String,
    pub output_dir: String,
    pub detection: Option<DetectionSummary>,
    pub vendor_fits: Vec<VendorFit>,
    pub format_index: usize,
    pub verbosity_index: usize,
    pub progress: ProgressSnapshot,
    pub live_lines: Vec<String>,
    /// Live malicious / suspicious / benign tallies + harvested tags.
    pub threat_board: ThreatBoard,
    pub output_paths: Vec<PathBuf>,
    pub investigate_cursor: usize,
    /// TachyonFX transitions + ambient panel / progress animations.
    pub fx: FxEngine,
    investigation_tx: Option<mpsc::UnboundedReceiver<LiveEvent>>,
    investigation_handle: Option<JoinHandle<()>>,

    // API keys
    pub api_key_mode: ApiKeyMode,
    pub api_key_index: usize,
    pub api_key_input: String,

    // Vendors
    pub vendor_index: usize,
    pub vendor_mode: VendorMode,
    pub bulk_type_index: usize,
    pub pending_key_for_vendor: Option<String>,

    // Profiles
    pub profile_index: usize,

    // Options / rate overrides
    pub options_mode: OptionsMode,
    pub options_index: usize,
    pub rate_vendor_index: usize,
    pub rate_edit_field: usize,
    pub rate_edit_vendor: Option<String>,
    pub rate_draft: RateLimitOverride,
    pub rate_edit_input: String,
    pub rate_typing: bool,

    // Color scheme picker
    pub color_scheme_index: usize,
    color_scheme_backup: ColorScheme,

    // View output / edit input
    pub output_browser: FileBrowser,
    pub input_browser: FileBrowser,
    pub file_viewer: Option<FileViewer>,
    pub text_editor: Option<TextEditor>,
    pub new_file_name: String,
    /// Visible rows hint updated by the draw pass for scroll math.
    pub view_visible_rows: usize,
    /// Second Esc discards unsaved editor changes.
    pub editor_discard_armed: bool,
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
        let profile_index = UsageProfile::all()
            .iter()
            .position(|p| *p == config.usage_profile)
            .unwrap_or(0);

        Self {
            config,
            screen: Screen::MainMenu,
            should_quit: false,
            status_message: "↑↓ navigate · Enter select · q quit".into(),
            menu_index: 0,
            investigate_step: InvestigateStep::InputPath,
            file_browser: FileBrowser::from_cwd(),
            input_path: String::new(),
            output_dir: default_output_dir(),
            detection: None,
            vendor_fits: Vec::new(),
            format_index,
            verbosity_index,
            progress: ProgressSnapshot::default(),
            live_lines: Vec::new(),
            threat_board: ThreatBoard::default(),
            output_paths: Vec::new(),
            investigate_cursor: 0,
            fx: FxEngine::new(),
            investigation_tx: None,
            investigation_handle: None,
            api_key_mode: ApiKeyMode::List,
            api_key_index: 0,
            api_key_input: String::new(),
            vendor_index: 0,
            vendor_mode: VendorMode::List,
            bulk_type_index: 0,
            pending_key_for_vendor: None,
            profile_index,
            options_mode: OptionsMode::List,
            options_index: 0,
            rate_vendor_index: 0,
            rate_edit_field: 0,
            rate_edit_vendor: None,
            rate_draft: RateLimitOverride::from_spec(RateLimitSpec::per_minute(30)),
            rate_edit_input: String::new(),
            rate_typing: false,
            color_scheme_index,
            color_scheme_backup,
            output_browser: FileBrowser::new(PathBuf::from(default_output_dir())),
            input_browser: FileBrowser::from_cwd(),
            file_viewer: None,
            text_editor: None,
            new_file_name: String::new(),
            view_visible_rows: 20,
            editor_discard_armed: false,
        }
    }

    pub fn menu_items() -> &'static [&'static str] {
        &[
            "Run OSINT Investigation",
            "View Output",
            "Add / Edit Input",
            "Add / Remove / Change API Key",
            "List / Select Vendors",
            "Usage Profile",
            "Options",
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
        self.status_message = "↑↓ navigate · Enter select · q quit".into();
    }

    pub fn open_investigation(&mut self) {
        self.screen = Screen::Investigation;
        self.investigate_step = InvestigateStep::InputPath;
        self.input_path.clear();
        self.detection = None;
        self.vendor_fits.clear();
        self.live_lines.clear();
        self.threat_board.clear();
        self.output_paths.clear();
        self.progress = ProgressSnapshot::default();
        self.file_browser = FileBrowser::from_cwd();
        self.file_browser.select_best_indicator_file();
        let found = self.file_browser.indicator_file_count();
        self.status_message = if found > 0 {
            format!(
                "Found {found} indicator file(s) · ↑↓ move · →/Enter open · ← back · Esc menu"
            )
        } else {
            "↑↓ move · →/Enter open dir or select file · ← parent · Esc menu".into()
        };
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
        self.vendor_mode = VendorMode::List;
        self.vendor_index = 0;
        self.status_message =
            "↑↓ move · Space/Enter toggle · b bulk-by-type · Esc back".into();
    }

    pub fn open_profiles(&mut self) {
        self.screen = Screen::Profiles;
        self.profile_index = UsageProfile::all()
            .iter()
            .position(|p| *p == self.config.usage_profile)
            .unwrap_or(0);
        self.status_message = "↑↓ choose profile · Enter apply · Esc back".into();
    }

    pub fn open_options(&mut self) {
        self.screen = Screen::Options;
        self.options_mode = OptionsMode::List;
        self.options_index = 0;
        self.status_message = "↑↓ · Enter · Esc back".into();
    }

    pub fn open_color_scheme(&mut self) {
        self.screen = Screen::ColorScheme;
        self.color_scheme_backup = self.config.color_scheme;
        self.color_scheme_index = ColorScheme::all()
            .iter()
            .position(|s| *s == self.config.color_scheme)
            .unwrap_or(0);
        self.status_message = "↑↓ preview · Enter apply & save · Esc cancel".into();
    }

    pub fn cancel_color_scheme(&mut self) {
        self.config.color_scheme = self.color_scheme_backup;
        self.open_main_menu();
    }

    pub fn activate_menu_item(&mut self) {
        match self.menu_index {
            0 => self.open_investigation(),
            1 => self.open_view_output(),
            2 => self.open_edit_input(),
            3 => self.open_api_keys(),
            4 => self.open_vendors(),
            5 => self.open_profiles(),
            6 => self.open_options(),
            7 => self.open_color_scheme(),
            8 => self.should_quit = true,
            _ => {}
        }
    }

    pub fn open_view_output(&mut self) {
        let dir = PathBuf::from(self.output_dir.trim());
        let _ = std::fs::create_dir_all(&dir);
        self.output_browser = FileBrowser::new(dir);
        self.file_viewer = None;
        self.screen = Screen::ViewOutputBrowse;
        self.status_message =
            "Browse investigation output · ↑↓ · Enter open · Esc menu".into();
    }

    pub fn open_edit_input(&mut self) {
        self.input_browser = FileBrowser::from_cwd();
        self.input_browser.select_best_indicator_file();
        self.text_editor = None;
        self.screen = Screen::EditInputBrowse;
        self.status_message =
            "↑↓ · Enter edit · n new file · Esc menu".into();
    }

    pub fn open_selected_output_file(&mut self) {
        let Some(entry) = self.output_browser.selected_entry().cloned() else {
            self.status_message = "No entry selected".into();
            return;
        };
        if entry.is_dir {
            self.output_browser.enter();
            return;
        }
        match FileViewer::open(&entry.path) {
            Ok(viewer) => {
                self.status_message = viewer.status.clone();
                self.file_viewer = Some(viewer);
                self.screen = Screen::ViewOutput;
            }
            Err(e) => {
                self.status_message = format!("Open failed: {e}");
            }
        }
    }

    pub fn open_selected_input_file(&mut self) {
        let Some(entry) = self.input_browser.selected_entry().cloned() else {
            self.status_message = "No entry selected".into();
            return;
        };
        if entry.is_dir {
            self.input_browser.enter();
            self.input_browser.select_best_indicator_file();
            return;
        }
        match TextEditor::open(&entry.path) {
            Ok(editor) => {
                self.status_message = editor.status.clone();
                self.text_editor = Some(editor);
                self.screen = Screen::EditInput;
            }
            Err(e) => {
                self.status_message = format!("Open failed: {e}");
            }
        }
    }

    pub fn begin_new_input_file(&mut self) {
        self.new_file_name = "indicators.txt".into();
        self.screen = Screen::EditInputNewName;
        self.status_message = "Enter filename · Enter create · Esc cancel".into();
    }

    pub fn confirm_new_input_file(&mut self) {
        let name = self.new_file_name.trim();
        if name.is_empty() {
            self.status_message = "Filename was empty".into();
            return;
        }
        let path = self.input_browser.cwd.join(name);
        let editor = TextEditor::create_new(path);
        self.status_message = editor.status.clone();
        self.text_editor = Some(editor);
        self.screen = Screen::EditInput;
    }

    pub fn close_viewer(&mut self) {
        self.file_viewer = None;
        self.screen = Screen::ViewOutputBrowse;
        self.status_message =
            "Browse investigation output · ↑↓ · Enter open · Esc menu".into();
    }

    pub fn close_editor(&mut self, force: bool) {
        if !force {
            if let Some(ed) = &self.text_editor {
                if ed.dirty {
                    if !self.editor_discard_armed {
                        self.editor_discard_armed = true;
                        self.status_message =
                            "Unsaved changes · Ctrl+S save · Esc again to discard".into();
                        return;
                    }
                }
            }
        }
        self.editor_discard_armed = false;
        self.text_editor = None;
        self.screen = Screen::EditInputBrowse;
        self.status_message = "↑↓ · Enter edit · n new file · Esc menu".into();
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

    /// Ranger: enter dir, or select file.
    pub fn browser_confirm(&mut self) {
        let Some(entry) = self.file_browser.selected_entry().cloned() else {
            self.status_message = "No entry selected".into();
            return;
        };
        if entry.is_dir {
            self.file_browser.enter();
            self.file_browser.select_best_indicator_file();
            self.update_browser_status();
            return;
        }
        self.input_path = entry.path.display().to_string();
        self.submit_input_path();
    }

    pub fn browser_enter_dir(&mut self) {
        let Some(entry) = self.file_browser.selected_entry() else {
            return;
        };
        if entry.is_dir {
            self.file_browser.enter();
            self.file_browser.select_best_indicator_file();
            self.update_browser_status();
        }
    }

    pub fn browser_leave_dir(&mut self) {
        if self.file_browser.leave() {
            self.update_browser_status();
        }
    }

    pub fn update_browser_status(&mut self) {
        let found = self.file_browser.indicator_file_count();
        let cwd = self.file_browser.cwd.display();
        self.status_message = if found > 0 {
            format!("{cwd}  ·  {found} indicator file(s) detected · ← → ↑ ↓ · Enter")
        } else {
            format!("{cwd}  ·  ← → ↑ ↓ · Enter select · Esc back")
        };
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
        self.threat_board.clear();
        self.status_message = "Investigation running… · Esc cancels view (task continues)".into();

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
                    LiveEvent::ResultHit { line, result } => {
                        self.threat_board.ingest(&result);
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

    pub fn enter_bulk_select_mode(&mut self) {
        self.vendor_mode = VendorMode::BulkByType;
        self.bulk_type_index = 0;
        self.status_message =
            "Bulk-select · ↑↓ type · Enter enable all matching vendors · Esc cancel".into();
    }

    pub fn bulk_select_type_at_cursor(&mut self) {
        let types = IndicatorType::all_known();
        let Some(kind) = types.get(self.bulk_type_index).copied() else {
            return;
        };
        let matching = vendors_for_type(kind);
        if matching.is_empty() {
            self.status_message = format!("No vendors support {}", kind.label());
            self.vendor_mode = VendorMode::List;
            return;
        }
        let mut missing_key: Option<String> = None;
        let mut enabled = 0usize;
        for v in &matching {
            if !self.config.is_vendor_selected(v.id()) {
                self.config.select_vendor(v.id());
                enabled += 1;
            }
            if self.config.api_key(v.id()).is_none() && missing_key.is_none() {
                missing_key = Some(v.id().to_string());
            }
        }
        let _ = self.config.save();
        self.vendor_mode = VendorMode::List;
        self.status_message = format!(
            "Enabled {} vendor(s) for {} indicators",
            matching.len(),
            kind.label()
        );
        if enabled == 0 {
            self.status_message = format!(
                "All {}-capable vendors were already selected",
                kind.label()
            );
        }
        if let Some(id) = missing_key {
            self.begin_enter_api_key(&id);
        }
    }

    pub fn apply_profile_at_cursor(&mut self) {
        if let Some(profile) = UsageProfile::all().get(self.profile_index).copied() {
            self.config.usage_profile = profile;
            let _ = self.config.save();
            self.status_message = format!("Usage profile set to {}", profile.short());
            self.open_main_menu();
        }
    }

    pub fn options_items() -> &'static [&'static str] {
        &["Manual rate limits…", "Clear all rate overrides"]
    }

    pub fn begin_rate_limit_warning(&mut self) {
        self.options_mode = OptionsMode::RateWarning;
        self.status_message =
            "⚠ Read the warning · Enter continue · Esc cancel".into();
    }

    pub fn open_rate_vendor_list(&mut self) {
        self.options_mode = OptionsMode::RateVendorList;
        self.rate_vendor_index = 0;
        self.status_message =
            "↑↓ vendor · Enter edit · d clear override · Esc back".into();
    }

    pub fn begin_rate_edit_at_cursor(&mut self) {
        let vendors = all_vendors();
        let Some(v) = vendors.get(self.rate_vendor_index) else {
            return;
        };
        let id = v.id().to_string();
        let draft = self
            .config
            .rate_overrides
            .get(&id)
            .cloned()
            .unwrap_or_else(|| {
                RateLimitOverride::from_spec(self.config.effective_rate_limit(&id))
            });
        self.rate_edit_vendor = Some(id);
        self.rate_draft = draft;
        self.rate_edit_field = 0;
        self.rate_edit_input.clear();
        self.options_mode = OptionsMode::RateEdit;
        self.status_message =
            "↑↓ field · Enter edit/save · Esc cancel · numbers when editing".into();
    }

    pub fn rate_edit_fields() -> &'static [RateEditField] {
        &[
            RateEditField::PerMinute,
            RateEditField::PerHour,
            RateEditField::PerDay,
            RateEditField::Unthrottled,
            RateEditField::ClearOverride,
            RateEditField::Save,
        ]
    }

    pub fn activate_rate_edit_field(&mut self) {
        let fields = Self::rate_edit_fields();
        let Some(field) = fields.get(self.rate_edit_field).copied() else {
            return;
        };
        match field {
            RateEditField::Unthrottled => {
                self.rate_draft.unthrottled = !self.rate_draft.unthrottled;
            }
            RateEditField::ClearOverride => {
                if let Some(id) = self.rate_edit_vendor.take() {
                    self.config.clear_rate_override(&id);
                    let _ = self.config.save();
                    self.status_message = format!("Cleared override for {id}");
                }
                self.open_rate_vendor_list();
            }
            RateEditField::Save => {
                if let Some(id) = self.rate_edit_vendor.take() {
                    if self.rate_draft.unthrottled {
                        self.rate_draft.requests_per_minute =
                            self.rate_draft.requests_per_minute.max(1);
                    }
                    self.config.set_rate_override(&id, self.rate_draft.clone());
                    let _ = self.config.save();
                    self.status_message = format!(
                        "Saved rate override for {id} ({})",
                        self.rate_draft.to_spec().display()
                    );
                }
                self.open_rate_vendor_list();
            }
            RateEditField::PerMinute | RateEditField::PerHour | RateEditField::PerDay => {
                self.rate_edit_input.clear();
                self.rate_typing = true;
                self.status_message = match field {
                    RateEditField::PerMinute => "Type requests/minute · Enter apply".into(),
                    RateEditField::PerHour => {
                        "Type requests/hour (empty = none) · Enter apply".into()
                    }
                    RateEditField::PerDay => {
                        "Type requests/day (empty = none) · Enter apply".into()
                    }
                    _ => unreachable!(),
                };
            }
        }
    }

    pub fn apply_rate_edit_input(&mut self) {
        let fields = Self::rate_edit_fields();
        let Some(field) = fields.get(self.rate_edit_field).copied() else {
            return;
        };
        let raw = self.rate_edit_input.trim();
        match field {
            RateEditField::PerMinute => {
                if let Ok(n) = raw.parse::<u32>() {
                    if n > 0 {
                        self.rate_draft.requests_per_minute = n;
                        self.rate_draft.unthrottled = false;
                    }
                }
            }
            RateEditField::PerHour => {
                self.rate_draft.requests_per_hour = if raw.is_empty() {
                    None
                } else {
                    raw.parse::<u32>().ok().filter(|n| *n > 0)
                };
                self.rate_draft.unthrottled = false;
            }
            RateEditField::PerDay => {
                self.rate_draft.requests_per_day = if raw.is_empty() {
                    None
                } else {
                    raw.parse::<u32>().ok().filter(|n| *n > 0)
                };
                self.rate_draft.unthrottled = false;
            }
            _ => {}
        }
        self.rate_edit_input.clear();
        self.rate_typing = false;
        self.status_message = "Value updated · ↑↓ fields · Save to persist".into();
    }

    pub fn clear_all_rate_overrides(&mut self) {
        self.config.rate_overrides.clear();
        let _ = self.config.save();
        self.status_message = "Cleared all manual rate overrides".into();
        self.options_mode = OptionsMode::List;
    }
}

fn default_output_dir() -> String {
    let home = dirs::home_dir();
    let scry = home
        .as_ref()
        .map(|h| h.join("scry-output"))
        .unwrap_or_else(|| PathBuf::from("./scry-output"));
    // Prefer the new dir; fall back to leftover Imbas output if present.
    let imbas = home.as_ref().map(|h| h.join("imbas-output"));
    if scry.is_dir() {
        return scry.display().to_string();
    }
    if let Some(legacy) = imbas {
        if legacy.is_dir() {
            return legacy.display().to_string();
        }
    }
    scry.display().to_string()
}
