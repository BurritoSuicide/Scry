pub mod event;
pub mod theme;
pub mod ui;
pub mod widgets;

use crate::app::{
    ApiKeyMode, App, InvestigateStep, Screen,
};
use crate::config::{OutputFormat, Verbosity};
use crate::theme::ColorScheme;
use crate::vendors::all_vendors;
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
            AppEvent::Tick => {}
            AppEvent::Key(key) => {
                if handle_key(app, key) {
                    break;
                }
            }
        }

        if app.should_quit {
            break;
        }
    }
    Ok(())
}

fn handle_key(app: &mut App, key: KeyEvent) -> bool {
    // Global quit
    if key.code == KeyCode::Char('q')
        && !is_text_entry(app)
        && key.modifiers == KeyModifiers::NONE
    {
        app.should_quit = true;
        return true;
    }
    if key.code == KeyCode::Char('c') && key.modifiers.contains(KeyModifiers::CONTROL) {
        app.should_quit = true;
        return true;
    }

    match app.screen {
        Screen::MainMenu => handle_main_menu(app, key),
        Screen::Investigation => handle_investigation(app, key),
        Screen::ApiKeys => handle_api_keys(app, key),
        Screen::Vendors => handle_vendors(app, key),
        Screen::ColorScheme => handle_color_scheme(app, key),
    }
    false
}

fn is_text_entry(app: &App) -> bool {
    matches!(
        (app.screen, app.api_key_mode),
        (Screen::ApiKeys, ApiKeyMode::EnterKey)
    )
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
                        app.status_message =
                            format!("Enter API key for {} · Enter save · Esc cancel", v.name());
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
        ApiKeyMode::EnterKey => match key.code {
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
            KeyCode::Char(c) => app.api_key_input.push(c),
            _ => {}
        },
        ApiKeyMode::ConfirmClear => {
            if key.code == KeyCode::Esc {
                app.api_key_mode = ApiKeyMode::List;
            }
        }
    }
}

fn handle_vendors(app: &mut App, key: KeyEvent) {
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
        _ => {}
    }
}
