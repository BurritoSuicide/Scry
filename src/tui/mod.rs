pub mod event;
pub mod fx;
pub mod theme;
pub mod ui;
pub mod widgets;

use crate::app::{
    ApiKeyMode, App, InvestigateStep, OptionsMode, Screen, VendorMode,
};
use crate::config::{OutputFormat, Verbosity};
use crate::indicator::IndicatorType;
use crate::rate_limit::UsageProfile;
use crate::theme::ColorScheme;
use crate::vendors::all_vendors;
use crate::viewer::copy_to_clipboard;
use anyhow::Result;
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use event::{AppEvent, EventSource};
use ratatui::Terminal;
use ui::draw;

pub async fn run<B: ratatui::backend::Backend>(
    terminal: &mut Terminal<B>,
    app: &mut App,
    events: &EventSource,
) -> Result<()> {
    loop {
        app.poll_investigation();
        terminal.draw(|frame| draw(frame, app))?;

        match events.next()? {
            AppEvent::Tick => {
                // Redraw so tachyonfx ambient animations keep advancing.
            }
            AppEvent::Key(key) => {
                if handle_key(app, key) {
                    break;
                }
            }
            AppEvent::Paste(text) => handle_paste(app, &text),
        }

        if app.should_quit {
            break;
        }
    }
    Ok(())
}

fn handle_key(app: &mut App, key: KeyEvent) -> bool {
    if key.code == KeyCode::Char('q')
        && !is_text_entry(app)
        && key.modifiers == KeyModifiers::NONE
    {
        app.should_quit = true;
        return true;
    }
    // Global Ctrl+C quit — except Ctrl+C is also common cancel; keep quit.
    // Ctrl+S / Ctrl+V handled in editor.
    if key.code == KeyCode::Char('c')
        && key.modifiers.contains(KeyModifiers::CONTROL)
        && app.screen != Screen::EditInput
        && app.screen != Screen::ViewOutput
    {
        app.should_quit = true;
        return true;
    }

    match app.screen {
        Screen::MainMenu => handle_main_menu(app, key),
        Screen::Investigation => handle_investigation(app, key),
        Screen::ApiKeys => handle_api_keys(app, key),
        Screen::Vendors => handle_vendors(app, key),
        Screen::Profiles => handle_profiles(app, key),
        Screen::Options => handle_options(app, key),
        Screen::ColorScheme => handle_color_scheme(app, key),
        Screen::ViewOutputBrowse => handle_view_output_browse(app, key),
        Screen::ViewOutput => handle_view_output(app, key),
        Screen::EditInputBrowse => handle_edit_input_browse(app, key),
        Screen::EditInput => handle_edit_input(app, key),
        Screen::EditInputNewName => handle_edit_input_new_name(app, key),
    }
    false
}

fn is_text_entry(app: &App) -> bool {
    matches!(
        (app.screen, app.api_key_mode),
        (Screen::ApiKeys, ApiKeyMode::EnterKey)
    ) || (app.screen == Screen::Options && app.rate_typing)
        || matches!(
            app.screen,
            Screen::EditInput | Screen::EditInputNewName | Screen::ViewOutput
        )
}

fn handle_paste(app: &mut App, text: &str) {
    match app.screen {
        Screen::EditInput => {
            if let Some(ed) = app.text_editor.as_mut() {
                ed.paste(text);
                app.editor_discard_armed = false;
                app.status_message = ed.status.clone();
            }
        }
        Screen::ApiKeys if app.api_key_mode == ApiKeyMode::EnterKey => {
            paste_into_api_key(app, text);
        }
        Screen::EditInputNewName => {
            let cleaned: String = text
                .chars()
                .filter(|c| *c != '\n' && *c != '\r')
                .collect();
            app.new_file_name.push_str(&cleaned);
        }
        _ => {}
    }
}

/// API keys are single-line secrets; take the first non-empty line and trim.
fn sanitize_api_key_paste(text: &str) -> String {
    text.lines()
        .map(str::trim)
        .find(|line| !line.is_empty())
        .unwrap_or("")
        .to_string()
}

fn paste_into_api_key(app: &mut App, text: &str) {
    let cleaned = sanitize_api_key_paste(text);
    if cleaned.is_empty() {
        app.status_message = "Clipboard/paste was empty".into();
        return;
    }
    app.api_key_input.push_str(&cleaned);
    app.status_message = format!(
        "Pasted {} char(s) · Enter save · Esc cancel",
        cleaned.chars().count()
    );
}

fn handle_main_menu(app: &mut App, key: KeyEvent) {
    let len = App::menu_items().len();
    match key.code {
        KeyCode::Up | KeyCode::Char('k') => {
            app.menu_index = app.menu_index.checked_sub(1).unwrap_or(len - 1);
        }
        KeyCode::Down | KeyCode::Char('j') => {
            app.menu_index = (app.menu_index + 1) % len;
        }
        KeyCode::Enter => app.activate_menu_item(),
        _ => {}
    }
}

fn handle_color_scheme(app: &mut App, key: KeyEvent) {
    let n = ColorScheme::all().len();
    match key.code {
        KeyCode::Esc => app.cancel_color_scheme(),
        KeyCode::Up | KeyCode::Char('k') => {
            app.color_scheme_index = app.color_scheme_index.checked_sub(1).unwrap_or(n - 1);
            app.preview_color_scheme_at_cursor();
        }
        KeyCode::Down | KeyCode::Char('j') => {
            app.color_scheme_index = (app.color_scheme_index + 1) % n;
            app.preview_color_scheme_at_cursor();
        }
        KeyCode::Enter => app.apply_color_scheme_at_cursor(),
        _ => {}
    }
}

fn handle_investigation(app: &mut App, key: KeyEvent) {
    match app.investigate_step {
        InvestigateStep::InputPath => match key.code {
            KeyCode::Esc => app.open_main_menu(),
            KeyCode::Up | KeyCode::Char('k') => app.file_browser.move_up(),
            KeyCode::Down | KeyCode::Char('j') => app.file_browser.move_down(),
            KeyCode::Right | KeyCode::Char('l') => app.browser_enter_dir(),
            KeyCode::Left | KeyCode::Char('h') | KeyCode::Backspace => {
                app.browser_leave_dir();
            }
            KeyCode::Enter => app.browser_confirm(),
            _ => {}
        },
        InvestigateStep::ReviewDetection => match key.code {
            KeyCode::Esc => {
                app.investigate_step = InvestigateStep::InputPath;
                app.update_browser_status();
            }
            KeyCode::Enter => {
                app.investigate_step = InvestigateStep::OutputFormat;
                app.status_message = "Choose output format · ↑↓ · Enter".into();
            }
            _ => {}
        },
        InvestigateStep::OutputFormat => match key.code {
            KeyCode::Esc => app.investigate_step = InvestigateStep::ReviewDetection,
            KeyCode::Up | KeyCode::Char('k') => {
                let n = OutputFormat::all().len();
                app.format_index = app.format_index.checked_sub(1).unwrap_or(n - 1);
            }
            KeyCode::Down | KeyCode::Char('j') => {
                app.format_index = (app.format_index + 1) % OutputFormat::all().len();
            }
            KeyCode::Enter => {
                app.investigate_step = InvestigateStep::Verbosity;
                app.status_message = "Choose verbosity · ↑↓ · Enter to launch".into();
            }
            _ => {}
        },
        InvestigateStep::Verbosity => match key.code {
            KeyCode::Esc => app.investigate_step = InvestigateStep::OutputFormat,
            KeyCode::Up | KeyCode::Char('k') => {
                let n = Verbosity::all().len();
                app.verbosity_index = app.verbosity_index.checked_sub(1).unwrap_or(n - 1);
            }
            KeyCode::Down | KeyCode::Char('j') => {
                app.verbosity_index = (app.verbosity_index + 1) % Verbosity::all().len();
            }
            KeyCode::Enter => app.start_investigation(),
            _ => {}
        },
        InvestigateStep::Running => {
            if key.code == KeyCode::Esc {
                app.open_main_menu();
            }
        }
        InvestigateStep::Done => match key.code {
            KeyCode::Enter | KeyCode::Esc => app.open_main_menu(),
            _ => {}
        },
    }
}

fn handle_api_keys(app: &mut App, key: KeyEvent) {
    match app.api_key_mode {
        ApiKeyMode::List => {
            let n = all_vendors().len().max(1);
            match key.code {
                KeyCode::Esc => app.open_main_menu(),
                KeyCode::Up | KeyCode::Char('k') => {
                    app.api_key_index = app.api_key_index.checked_sub(1).unwrap_or(n - 1);
                }
                KeyCode::Down | KeyCode::Char('j') => {
                    app.api_key_index = (app.api_key_index + 1) % n;
                }
                KeyCode::Enter => {
                    let vendors = all_vendors();
                    if let Some(v) = vendors.get(app.api_key_index) {
                        app.pending_key_for_vendor = Some(v.id().to_string());
                        app.api_key_input.clear();
                        app.api_key_mode = ApiKeyMode::EnterKey;
                        app.status_message = format!(
                            "Enter API key for {} · Ctrl+V / paste · Enter save · Esc cancel",
                            v.name()
                        );
                    }
                }
                KeyCode::Char('d') => {
                    let vendors = all_vendors();
                    if let Some(v) = vendors.get(app.api_key_index) {
                        app.config.clear_api_key(v.id());
                        let _ = app.config.save();
                        app.status_message = format!("Cleared API key for {}", v.name());
                    }
                }
                _ => {}
            }
        }
        ApiKeyMode::EnterKey => {
            if key.code == KeyCode::Char('v') && key.modifiers.contains(KeyModifiers::CONTROL) {
                match crate::clipboard::paste_text() {
                    Ok(text) => paste_into_api_key(app, &text),
                    Err(e) => app.status_message = e.to_string(),
                }
                return;
            }
            match key.code {
                KeyCode::Esc => {
                    app.api_key_mode = ApiKeyMode::List;
                    app.api_key_input.clear();
                    app.pending_key_for_vendor = None;
                    app.status_message = "Cancelled key entry".into();
                }
                KeyCode::Enter => app.save_api_key_input(),
                KeyCode::Backspace => {
                    app.api_key_input.pop();
                }
                KeyCode::Char(c)
                    if !key
                        .modifiers
                        .intersects(KeyModifiers::CONTROL | KeyModifiers::ALT | KeyModifiers::SUPER)
                =>
                {
                    app.api_key_input.push(c);
                }
                _ => {}
            }
        }
        ApiKeyMode::ConfirmClear => {
            if key.code == KeyCode::Esc {
                app.api_key_mode = ApiKeyMode::List;
            }
        }
    }
}

fn handle_vendors(app: &mut App, key: KeyEvent) {
    match app.vendor_mode {
        VendorMode::List => {
            let n = all_vendors().len().max(1);
            match key.code {
                KeyCode::Esc => app.open_main_menu(),
                KeyCode::Up | KeyCode::Char('k') => {
                    app.vendor_index = app.vendor_index.checked_sub(1).unwrap_or(n - 1);
                }
                KeyCode::Down | KeyCode::Char('j') => {
                    app.vendor_index = (app.vendor_index + 1) % n;
                }
                KeyCode::Enter | KeyCode::Char(' ') => app.toggle_vendor_at_cursor(),
                KeyCode::Char('b') => app.enter_bulk_select_mode(),
                _ => {}
            }
        }
        VendorMode::BulkByType => {
            let n = IndicatorType::all_known().len().max(1);
            match key.code {
                KeyCode::Esc => {
                    app.vendor_mode = VendorMode::List;
                    app.status_message =
                        "↑↓ move · Space/Enter toggle · b bulk-by-type · Esc back".into();
                }
                KeyCode::Up | KeyCode::Char('k') => {
                    app.bulk_type_index = app.bulk_type_index.checked_sub(1).unwrap_or(n - 1);
                }
                KeyCode::Down | KeyCode::Char('j') => {
                    app.bulk_type_index = (app.bulk_type_index + 1) % n;
                }
                KeyCode::Enter => app.bulk_select_type_at_cursor(),
                _ => {}
            }
        }
    }
}

fn handle_profiles(app: &mut App, key: KeyEvent) {
    let n = UsageProfile::all().len();
    match key.code {
        KeyCode::Esc => app.open_main_menu(),
        KeyCode::Up | KeyCode::Char('k') => {
            app.profile_index = app.profile_index.checked_sub(1).unwrap_or(n - 1);
        }
        KeyCode::Down | KeyCode::Char('j') => {
            app.profile_index = (app.profile_index + 1) % n;
        }
        KeyCode::Enter => app.apply_profile_at_cursor(),
        _ => {}
    }
}

fn handle_options(app: &mut App, key: KeyEvent) {
    match app.options_mode {
        OptionsMode::List => {
            let n = App::options_items().len().max(1);
            match key.code {
                KeyCode::Esc => app.open_main_menu(),
                KeyCode::Up | KeyCode::Char('k') => {
                    app.options_index = app.options_index.checked_sub(1).unwrap_or(n - 1);
                }
                KeyCode::Down | KeyCode::Char('j') => {
                    app.options_index = (app.options_index + 1) % n;
                }
                KeyCode::Enter => match app.options_index {
                    0 => app.begin_rate_limit_warning(),
                    1 => app.clear_all_rate_overrides(),
                    _ => {}
                },
                _ => {}
            }
        }
        OptionsMode::RateWarning => match key.code {
            KeyCode::Esc => {
                app.options_mode = OptionsMode::List;
                app.status_message = "↑↓ · Enter · Esc back".into();
            }
            KeyCode::Enter => app.open_rate_vendor_list(),
            _ => {}
        },
        OptionsMode::RateVendorList => {
            let n = all_vendors().len().max(1);
            match key.code {
                KeyCode::Esc => {
                    app.options_mode = OptionsMode::List;
                    app.status_message = "↑↓ · Enter · Esc back".into();
                }
                KeyCode::Up | KeyCode::Char('k') => {
                    app.rate_vendor_index =
                        app.rate_vendor_index.checked_sub(1).unwrap_or(n - 1);
                }
                KeyCode::Down | KeyCode::Char('j') => {
                    app.rate_vendor_index = (app.rate_vendor_index + 1) % n;
                }
                KeyCode::Enter => app.begin_rate_edit_at_cursor(),
                KeyCode::Char('d') => {
                    if let Some(v) = all_vendors().get(app.rate_vendor_index) {
                        app.config.clear_rate_override(v.id());
                        let _ = app.config.save();
                        app.status_message = format!("Cleared override for {}", v.name());
                    }
                }
                _ => {}
            }
        }
        OptionsMode::RateEdit => {
            if app.rate_typing {
                match key.code {
                    KeyCode::Esc => {
                        app.rate_typing = false;
                        app.rate_edit_input.clear();
                        app.status_message = "Cancelled edit".into();
                    }
                    KeyCode::Enter => app.apply_rate_edit_input(),
                    KeyCode::Backspace => {
                        app.rate_edit_input.pop();
                    }
                    KeyCode::Char(c) if c.is_ascii_digit() => {
                        app.rate_edit_input.push(c);
                    }
                    _ => {}
                }
                return;
            }
            let n = App::rate_edit_fields().len();
            match key.code {
                KeyCode::Esc => {
                    app.rate_edit_vendor = None;
                    app.open_rate_vendor_list();
                }
                KeyCode::Up | KeyCode::Char('k') => {
                    app.rate_edit_field = app.rate_edit_field.checked_sub(1).unwrap_or(n - 1);
                }
                KeyCode::Down | KeyCode::Char('j') => {
                    app.rate_edit_field = (app.rate_edit_field + 1) % n;
                }
                KeyCode::Enter | KeyCode::Char(' ') => app.activate_rate_edit_field(),
                _ => {}
            }
        }
    }
}

fn handle_view_output_browse(app: &mut App, key: KeyEvent) {
    match key.code {
        KeyCode::Esc => app.open_main_menu(),
        KeyCode::Up | KeyCode::Char('k') => app.output_browser.move_up(),
        KeyCode::Down | KeyCode::Char('j') => app.output_browser.move_down(),
        KeyCode::Right | KeyCode::Char('l') => {
            if app
                .output_browser
                .selected_entry()
                .is_some_and(|e| e.is_dir)
            {
                app.output_browser.enter();
            }
        }
        KeyCode::Left | KeyCode::Char('h') | KeyCode::Backspace => {
            let _ = app.output_browser.leave();
        }
        KeyCode::Enter => app.open_selected_output_file(),
        _ => {}
    }
}

fn handle_view_output(app: &mut App, key: KeyEvent) {
    let visible = app.view_visible_rows.max(1);
    match key.code {
        KeyCode::Esc => app.close_viewer(),
        KeyCode::Up | KeyCode::Char('k') => {
            if let Some(v) = app.file_viewer.as_mut() {
                v.move_up();
                app.status_message = v.status.clone();
            }
        }
        KeyCode::Down | KeyCode::Char('j') => {
            if let Some(v) = app.file_viewer.as_mut() {
                v.move_down(visible);
                app.status_message = v.status.clone();
            }
        }
        KeyCode::PageUp => {
            if let Some(v) = app.file_viewer.as_mut() {
                v.page_up(visible);
            }
        }
        KeyCode::PageDown => {
            if let Some(v) = app.file_viewer.as_mut() {
                v.page_down(visible);
            }
        }
        KeyCode::Left | KeyCode::Char('h') => {
            if let Some(v) = app.file_viewer.as_mut() {
                v.move_left();
            }
        }
        KeyCode::Right | KeyCode::Char('l') => {
            if let Some(v) = app.file_viewer.as_mut() {
                v.move_right();
            }
        }
        KeyCode::Char('c') if !key.modifiers.contains(KeyModifiers::CONTROL) => {
            if let Some(v) = app.file_viewer.as_mut() {
                let payload = v.copy_all_text();
                let chars = payload.chars().count();
                match copy_to_clipboard(&payload) {
                    Ok(()) => {
                        v.set_copied_status(&format!("csv/text ({chars} chars)"));
                        app.status_message = v.status.clone();
                    }
                    Err(e) => app.status_message = e.to_string(),
                }
            }
        }
        KeyCode::Char('m') => {
            if let Some(v) = app.file_viewer.as_mut() {
                let payload = v.copy_all_markdown();
                let chars = payload.chars().count();
                match copy_to_clipboard(&payload) {
                    Ok(()) => {
                        v.set_copied_status(&format!("markdown table ({chars} chars)"));
                        app.status_message = v.status.clone();
                    }
                    Err(e) => app.status_message = e.to_string(),
                }
            }
        }
        KeyCode::Char('y') => {
            if let Some(v) = app.file_viewer.as_mut() {
                let payload = v.copy_selection_text();
                let chars = payload.chars().count();
                match copy_to_clipboard(&payload) {
                    Ok(()) => {
                        v.set_copied_status(&format!("selection ({chars} chars)"));
                        app.status_message = v.status.clone();
                    }
                    Err(e) => app.status_message = e.to_string(),
                }
            }
        }
        KeyCode::Char('Y') => {
            if let Some(v) = app.file_viewer.as_mut() {
                let payload = v.copy_selection_markdown();
                let chars = payload.chars().count();
                match copy_to_clipboard(&payload) {
                    Ok(()) => {
                        v.set_copied_status(&format!("row as markdown ({chars} chars)"));
                        app.status_message = v.status.clone();
                    }
                    Err(e) => app.status_message = e.to_string(),
                }
            }
        }
        _ => {}
    }
}

fn handle_edit_input_browse(app: &mut App, key: KeyEvent) {
    match key.code {
        KeyCode::Esc => app.open_main_menu(),
        KeyCode::Up | KeyCode::Char('k') => app.input_browser.move_up(),
        KeyCode::Down | KeyCode::Char('j') => app.input_browser.move_down(),
        KeyCode::Right | KeyCode::Char('l') => {
            if app
                .input_browser
                .selected_entry()
                .is_some_and(|e| e.is_dir)
            {
                app.input_browser.enter();
                app.input_browser.select_best_indicator_file();
            }
        }
        KeyCode::Left | KeyCode::Char('h') | KeyCode::Backspace => {
            if app.input_browser.leave() {
                app.input_browser.select_best_indicator_file();
            }
        }
        KeyCode::Enter => app.open_selected_input_file(),
        KeyCode::Char('n') => app.begin_new_input_file(),
        _ => {}
    }
}

fn handle_edit_input_new_name(app: &mut App, key: KeyEvent) {
    match key.code {
        KeyCode::Esc => {
            app.screen = Screen::EditInputBrowse;
            app.status_message = "↑↓ · Enter edit · n new file · Esc menu".into();
        }
        KeyCode::Enter => app.confirm_new_input_file(),
        KeyCode::Backspace => {
            app.new_file_name.pop();
        }
        KeyCode::Char(c) if !c.is_control() => {
            app.new_file_name.push(c);
        }
        _ => {}
    }
}

fn handle_edit_input(app: &mut App, key: KeyEvent) {
    let visible = app.view_visible_rows.max(1);
    // Ctrl+S save
    if key.code == KeyCode::Char('s') && key.modifiers.contains(KeyModifiers::CONTROL) {
        if let Some(ed) = app.text_editor.as_mut() {
            match ed.save() {
                Ok(()) => {
                    app.editor_discard_armed = false;
                    app.status_message = ed.status.clone();
                }
                Err(e) => app.status_message = format!("Save failed: {e}"),
            }
        }
        return;
    }
    // Ctrl+V paste from clipboard
    if key.code == KeyCode::Char('v') && key.modifiers.contains(KeyModifiers::CONTROL) {
        if let Some(ed) = app.text_editor.as_mut() {
            match ed.paste_from_clipboard() {
                Ok(()) => {
                    app.editor_discard_armed = false;
                    app.status_message = ed.status.clone();
                }
                Err(e) => app.status_message = e.to_string(),
            }
        }
        return;
    }

    match key.code {
        KeyCode::Esc => app.close_editor(false),
        KeyCode::Up => {
            if let Some(ed) = app.text_editor.as_mut() {
                ed.move_up();
                ed.ensure_visible(visible);
            }
        }
        KeyCode::Down => {
            if let Some(ed) = app.text_editor.as_mut() {
                ed.move_down();
                ed.ensure_visible(visible);
            }
        }
        KeyCode::Left => {
            if let Some(ed) = app.text_editor.as_mut() {
                ed.move_left();
            }
        }
        KeyCode::Right => {
            if let Some(ed) = app.text_editor.as_mut() {
                ed.move_right();
            }
        }
        KeyCode::Enter => {
            if let Some(ed) = app.text_editor.as_mut() {
                ed.insert_newline();
                ed.ensure_visible(visible);
                app.editor_discard_armed = false;
            }
        }
        KeyCode::Backspace => {
            if let Some(ed) = app.text_editor.as_mut() {
                ed.backspace();
                app.editor_discard_armed = false;
            }
        }
        KeyCode::Delete => {
            if let Some(ed) = app.text_editor.as_mut() {
                ed.delete_forward();
                app.editor_discard_armed = false;
            }
        }
        KeyCode::Char('d') if key.modifiers.contains(KeyModifiers::CONTROL) => {
            if let Some(ed) = app.text_editor.as_mut() {
                ed.delete_line();
                app.editor_discard_armed = false;
                app.status_message = ed.status.clone();
            }
        }
        KeyCode::Char(c)
            if key.modifiers == KeyModifiers::NONE
                || key.modifiers == KeyModifiers::SHIFT =>
        {
            if let Some(ed) = app.text_editor.as_mut() {
                ed.insert_char(c);
                ed.ensure_visible(visible);
                app.editor_discard_armed = false;
            }
        }
        _ => {}
    }
}
