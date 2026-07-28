use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, BorderType, Borders, Clear, List, ListItem, Paragraph, Wrap};
use ratatui::Frame;

use super::fx::{focus_area_for, FxAreas};
use super::widgets::{draw_animated_progress, panel_block, progress_label};
use crate::app::{ApiKeyMode, App, InvestigateStep, OptionsMode, RateEditField, Screen, VendorMode};
use crate::config::{OutputFormat, Verbosity};
use crate::indicator::IndicatorType;
use crate::investigation::InvestigationStatus;
use crate::rate_limit::UsageProfile;
use crate::theme::{ColorScheme, Palette};
use crate::threat::TagKind;
use crate::vendors::{all_vendors, vendors_for_type};
use crate::viewer::ViewKind;
use ratatui::widgets::{Cell, Row, Table};

pub fn draw(frame: &mut Frame<'_>, app: &mut App) {
    let theme = app.palette();
    let area = frame.area();
    frame.render_widget(Clear, area);
    frame.render_widget(
        Block::default().style(Style::default().bg(theme.bg).fg(theme.text)),
        area,
    );

    let root = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3), // title bar
            Constraint::Length(3), // progress under title
            Constraint::Min(10),   // body
            Constraint::Length(2), // status
        ])
        .split(area);

    let full_width_body = matches!(
        app.screen,
        Screen::ViewOutput
            | Screen::ViewOutputBrowse
            | Screen::EditInput
            | Screen::EditInputBrowse
            | Screen::EditInputNewName
    );

    let mut areas = FxAreas {
        header: root[0],
        progress: root[1],
        body: root[2],
        full_width_body,
        ..FxAreas::default()
    };

    if full_width_body {
        areas.center = root[2];
    } else {
        let cols = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([
                Constraint::Percentage(24),
                Constraint::Percentage(52),
                Constraint::Percentage(24),
            ])
            .split(root[2]);
        areas.left = cols[0];
        areas.center = cols[1];
        areas.right = cols[2];
        // Keep in sync with draw_left_panel so focus wraps the menu, not the chart.
        let left_rows = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Min(12), Constraint::Length(12)])
            .split(cols[0]);
        areas.menu = left_rows[0];
    }
    areas.focus = focus_area_for(app.screen, &areas);

    draw_header(frame, root[0], app, theme);
    draw_progress_bar(frame, root[1], app, theme);
    draw_body(frame, root[2], app, theme);
    draw_status(frame, root[3], app, theme);

    let screen = app.screen;
    let scheme = app.config.color_scheme;
    let progress_active = app.progress.is_active();
    app.fx
        .process(frame, areas, screen, scheme, theme, progress_active);
}

fn draw_header(frame: &mut Frame<'_>, area: Rect, app: &App, theme: Palette) {
    let selected = app.config.selected_count();
    let vendors_total = all_vendors().len();
    let left = Line::from(vec![
        Span::styled(" SCRY ", theme.title_style()),
        Span::styled("│", Style::default().fg(theme.border)),
        Span::styled(
            format!(" vendors {selected}/{vendors_total} selected "),
            theme.accent_style(),
        ),
        Span::styled("│", Style::default().fg(theme.border)),
        Span::styled(
            format!(" profile {} ", app.config.usage_profile.short()),
            theme.accent_style(),
        ),
    ]);

    let status = match &app.progress.status {
        InvestigationStatus::Idle => "idle",
        InvestigationStatus::Preparing => "preparing",
        InvestigationStatus::Running => "running",
        InvestigationStatus::WaitingRateLimit { .. } => "rate-limit",
        InvestigationStatus::Completed => "done",
        InvestigationStatus::Failed(_) => "failed",
    };
    let mut right_text = progress_label(
        app.progress.completed_queries,
        app.progress.total_queries,
        app.progress.eta,
        status,
    );
    if let InvestigationStatus::WaitingRateLimit { vendor, wait } = &app.progress.status {
        right_text = format!(
            "{right_text} · wait {vendor} {:.0}s",
            wait.as_secs_f64()
        );
    }

    let block = Block::default()
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(theme.panel_border(true))
        .style(Style::default().bg(theme.panel));
    let inner = block.inner(area);
    frame.render_widget(block, area);

    let cols = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Min(20), Constraint::Length(
            right_text.chars().count().clamp(18, 48) as u16
        )])
        .split(inner);

    frame.render_widget(Paragraph::new(left), cols[0]);
    frame.render_widget(
        Paragraph::new(Line::from(Span::styled(right_text, theme.muted_style())))
            .alignment(ratatui::layout::Alignment::Right),
        cols[1],
    );
}

fn draw_progress_bar(frame: &mut Frame<'_>, area: Rect, app: &App, theme: Palette) {
    let focused = matches!(app.investigate_step, InvestigateStep::Running)
        || app.progress.is_active();
    let block = panel_block(" progress ", focused, theme);
    let inner = block.inner(area);
    frame.render_widget(block, area);

    // Full-width bar only — stats live in the title bar; tachyonfx shimmers the fill.
    draw_animated_progress(
        frame,
        inner,
        app.progress.fraction(),
        app.progress.is_active(),
        theme,
    );
}

fn draw_status(frame: &mut Frame<'_>, area: Rect, app: &App, theme: Palette) {
    let msg = Paragraph::new(Line::from(vec![
        Span::styled(" ▸ ", theme.accent_style()),
        Span::styled(app.status_message.clone(), theme.muted_style()),
    ]))
    .style(Style::default().bg(theme.bg));
    frame.render_widget(msg, area);
}

fn draw_body(frame: &mut Frame<'_>, area: Rect, app: &mut App, theme: Palette) {
    // Full-width workspace for viewers / editors.
    if matches!(
        app.screen,
        Screen::ViewOutput
            | Screen::ViewOutputBrowse
            | Screen::EditInput
            | Screen::EditInputBrowse
            | Screen::EditInputNewName
    ) {
        draw_center_panel(frame, area, app, theme);
        return;
    }

    let cols = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage(24),
            Constraint::Percentage(52),
            Constraint::Percentage(24),
        ])
        .split(area);

    draw_left_panel(frame, cols[0], app, theme);
    draw_center_panel(frame, cols[1], app, theme);
    draw_right_panel(frame, cols[2], app, theme);
}

fn draw_left_panel(frame: &mut Frame<'_>, area: Rect, app: &App, theme: Palette) {
    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(12), Constraint::Length(12)])
        .split(area);

    draw_menu_panel(frame, rows[0], app, theme);
    draw_threat_chart(frame, rows[1], app, theme);
}

fn draw_menu_panel(frame: &mut Frame<'_>, area: Rect, app: &App, theme: Palette) {
    let focused = app.screen == Screen::MainMenu;
    let block = panel_block(" main menu ", focused, theme);
    let inner = block.inner(area);
    frame.render_widget(block, area);

    let items: Vec<ListItem> = App::menu_items()
        .iter()
        .enumerate()
        .map(|(i, label)| {
            let selected = focused && i == app.menu_index;
            let prefix = if selected { "◆ " } else { "  " };
            let style = if selected {
                theme.selected()
            } else if i == app.menu_index {
                Style::default()
                    .fg(theme.accent)
                    .add_modifier(Modifier::BOLD)
            } else {
                theme.text_style()
            };
            ListItem::new(Line::from(Span::styled(
                format!("{prefix}{label}"),
                style,
            )))
        })
        .collect();

    frame.render_widget(List::new(items), inner);
}

/// Vertical bars for malicious / suspicious / benign tallies.
fn draw_threat_chart(frame: &mut Frame<'_>, area: Rect, app: &App, theme: Palette) {
    let counts = &app.threat_board.counts;
    let title = if counts.total_classified() + counts.errors == 0 {
        " threat mix "
    } else {
        " threat mix "
    };
    let block = panel_block(title, false, theme);
    let inner = block.inner(area);
    frame.render_widget(block, area);

    if inner.width < 9 || inner.height < 4 {
        return;
    }

    let series = [
        ("MAL", counts.malicious, theme.danger),
        ("SUS", counts.suspicious, theme.warn),
        ("BEN", counts.benign, theme.ok),
    ];
    let max = series.iter().map(|(_, v, _)| *v).max().unwrap_or(0).max(1);
    let label_rows = 2u16;
    let bar_h = inner.height.saturating_sub(label_rows).max(1);
    let gap = 1u16;
    let bar_w = ((inner.width.saturating_sub(gap * 2)) / 3).clamp(2, 5);

    let buf = frame.buffer_mut();
    for (i, (label, value, color)) in series.iter().enumerate() {
        let filled = ((*value as f64 / max as f64) * bar_h as f64).round() as u16;
        let filled = filled.min(bar_h);
        let x = inner.x + i as u16 * (bar_w + gap);
        for row in 0..bar_h {
            let y = inner.y + (bar_h - 1 - row);
            let ch = if row < filled { '█' } else { '░' };
            let style = if row < filled {
                Style::default().fg(*color)
            } else {
                Style::default().fg(theme.progress_bg)
            };
            for dx in 0..bar_w {
                if let Some(cell) = buf.cell_mut((x + dx, y)) {
                    cell.set_symbol(&ch.to_string());
                    cell.set_style(style);
                }
            }
        }
        let label_y = inner.y + bar_h;
        let value_y = label_y.saturating_add(1).min(inner.y + inner.height.saturating_sub(1));
        let label_style = Style::default().fg(*color).add_modifier(Modifier::BOLD);
        for (dx, ch) in label.chars().enumerate() {
            if let Some(cell) = buf.cell_mut((x + dx as u16, label_y)) {
                cell.set_symbol(&ch.to_string());
                cell.set_style(label_style);
            }
        }
        let val = value.to_string();
        for (dx, ch) in val.chars().enumerate() {
            if (x as usize + dx) < (inner.x + inner.width) as usize {
                if let Some(cell) = buf.cell_mut((x + dx as u16, value_y)) {
                    cell.set_symbol(&ch.to_string());
                    cell.set_style(theme.muted_style());
                }
            }
        }
    }
}

fn draw_center_panel(frame: &mut Frame<'_>, area: Rect, app: &mut App, theme: Palette) {
    // Workspace on top, live results underneath with more vertical room.
    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Percentage(48), Constraint::Percentage(52)])
        .split(area);

    draw_workspace(frame, rows[0], app, theme);
    draw_results_panel(frame, rows[1], app, theme);
}

fn draw_workspace(frame: &mut Frame<'_>, area: Rect, app: &mut App, theme: Palette) {
    let title = match app.screen {
        Screen::MainMenu => " workspace ",
        Screen::Investigation => " investigation ",
        Screen::ApiKeys => " api keys ",
        Screen::Vendors => " vendors ",
        Screen::Profiles => " usage profile ",
        Screen::Options => " options ",
        Screen::ColorScheme => " color scheme ",
        Screen::ViewOutputBrowse => " view output ",
        Screen::ViewOutput => " view output ",
        Screen::EditInputBrowse => " add / edit input ",
        Screen::EditInput | Screen::EditInputNewName => " add / edit input ",
    };
    let focused = app.screen != Screen::MainMenu;
    let block = panel_block(title, focused, theme);
    let inner = block.inner(area);
    frame.render_widget(block, area);

    match app.screen {
        Screen::MainMenu => draw_workspace_home(frame, inner, app, theme),
        Screen::Investigation => draw_investigation(frame, inner, app, theme),
        Screen::ApiKeys => draw_api_keys(frame, inner, app, theme),
        Screen::Vendors => draw_vendors(frame, inner, app, theme),
        Screen::Profiles => draw_profiles(frame, inner, app, theme),
        Screen::Options => draw_options(frame, inner, app, theme),
        Screen::ColorScheme => draw_color_scheme(frame, inner, app, theme),
        Screen::ViewOutputBrowse => draw_file_browser(
            frame,
            inner,
            &app.output_browser,
            "Investigation output files",
            theme,
        ),
        Screen::ViewOutput => draw_file_viewer(frame, inner, app, theme),
        Screen::EditInputBrowse => draw_file_browser(
            frame,
            inner,
            &app.input_browser,
            "Indicator input files · n = new",
            theme,
        ),
        Screen::EditInput => draw_text_editor(frame, inner, app, theme),
        Screen::EditInputNewName => draw_new_file_prompt(frame, inner, app, theme),
    }
}

fn draw_workspace_home(frame: &mut Frame<'_>, area: Rect, app: &App, theme: Palette) {
    let lines = vec![
        Line::from(Span::styled(
            "OSINT investigations for emails · IPs · domains · JA4 · hashes",
            theme.text_style(),
        )),
        Line::from(""),
        Line::from(vec![
            Span::styled("Selected vendors: ", theme.muted_style()),
            Span::styled(
                app.config.selected_count().to_string(),
                theme.accent_style(),
            ),
        ]),
        Line::from(vec![
            Span::styled("Color scheme:     ", theme.muted_style()),
            Span::styled(app.config.color_scheme.label(), theme.accent_style()),
        ]),
        Line::from(vec![
            Span::styled("Usage profile:    ", theme.muted_style()),
            Span::styled(app.config.usage_profile.label(), theme.accent_style()),
        ]),
        Line::from(""),
        Line::from(Span::styled(
            "View Output · Add/Edit Input · Run Investigation from the menu.",
            theme.muted_style(),
        )),
    ];
    frame.render_widget(Paragraph::new(lines), area);
}

fn draw_color_scheme(frame: &mut Frame<'_>, area: Rect, app: &App, theme: Palette) {
    let items: Vec<ListItem> = ColorScheme::all()
        .iter()
        .enumerate()
        .map(|(i, scheme)| {
            let selected = i == app.color_scheme_index;
            let active = *scheme == app.config.color_scheme;
            let prefix = if selected { "◆ " } else { "  " };
            let mark = if active { "●" } else { "○" };
            let style = if selected {
                theme.selected()
            } else {
                theme.text_style()
            };
            ListItem::new(Span::styled(
                format!("{prefix}{mark}  {}", scheme.label()),
                style,
            ))
        })
        .collect();
    frame.render_widget(List::new(items), area);
}

fn draw_investigation(frame: &mut Frame<'_>, area: Rect, app: &App, theme: Palette) {
    match app.investigate_step {
        InvestigateStep::InputPath => {
            let mut lines = vec![
                Line::from(Span::styled(
                    format!("Browse · {}", app.file_browser.cwd.display()),
                    theme.title_style(),
                )),
                Line::from(Span::styled(
                    "↑↓ move · →/Enter open · ← parent · Esc menu",
                    theme.muted_style(),
                )),
                Line::from(""),
            ];
            for (i, entry) in app.file_browser.entries.iter().enumerate() {
                let selected = i == app.file_browser.selected;
                let prefix = if selected { "◆ " } else { "  " };
                let style = if selected {
                    theme.selected()
                } else if entry.looks_like_indicators() {
                    theme.ok_style()
                } else {
                    theme.text_style()
                };
                lines.push(Line::from(Span::styled(
                    format!("{prefix}{}", entry.label()),
                    style,
                )));
            }
            if app.file_browser.entries.is_empty() {
                lines.push(Line::from(Span::styled(
                    "(empty directory)",
                    theme.muted_style(),
                )));
            }
            frame.render_widget(Paragraph::new(lines).wrap(Wrap { trim: true }), area);
        }
        InvestigateStep::ReviewDetection => {
            let mut lines = vec![Line::from(Span::styled(
                "Detection preview & vendor fit",
                theme.title_style(),
            ))];
            if let Some(det) = &app.detection {
                lines.push(Line::from(format!(
                    "indicators: {}  ·  unknown: {}",
                    det.total(),
                    det.unknowns
                )));
                for (kind, count) in &det.counts {
                    lines.push(Line::from(format!("  {:>8}  {}", kind.label(), count)));
                }
            }
            lines.push(Line::from(""));
            lines.push(Line::from(Span::styled(
                "Vendor suitability",
                theme.accent_style(),
            )));
            for fit in &app.vendor_fits {
                let mark = if fit.supported { "✓" } else { "✗" };
                let style = if fit.supported {
                    theme.ok_style()
                } else {
                    theme.warn_style()
                };
                lines.push(Line::from(Span::styled(
                    format!(" {mark} {} — {}", fit.vendor_name, fit.note),
                    style,
                )));
            }
            lines.push(Line::from(""));
            lines.push(Line::from(Span::styled(
                "Enter to choose output format",
                theme.muted_style(),
            )));
            frame.render_widget(Paragraph::new(lines).wrap(Wrap { trim: true }), area);
        }
        InvestigateStep::OutputFormat => {
            let items: Vec<ListItem> = OutputFormat::all()
                .iter()
                .enumerate()
                .map(|(i, f)| {
                    let selected = i == app.format_index;
                    let prefix = if selected { "◆ " } else { "  " };
                    let style = if selected {
                        theme.selected()
                    } else {
                        theme.text_style()
                    };
                    ListItem::new(Span::styled(format!("{prefix}{}", f.label()), style))
                })
                .collect();
            frame.render_widget(List::new(items), area);
        }
        InvestigateStep::Verbosity => {
            let items: Vec<ListItem> = Verbosity::all()
                .iter()
                .enumerate()
                .map(|(i, v)| {
                    let selected = i == app.verbosity_index;
                    let prefix = if selected { "◆ " } else { "  " };
                    let style = if selected {
                        theme.selected()
                    } else {
                        theme.text_style()
                    };
                    ListItem::new(Span::styled(format!("{prefix}{}", v.label()), style))
                })
                .collect();
            frame.render_widget(List::new(items), area);
        }
        InvestigateStep::Running | InvestigateStep::Done => {
            let mut lines = vec![Line::from(Span::styled(
                match app.investigate_step {
                    InvestigateStep::Running => "Investigation in progress…",
                    _ => "Investigation complete",
                },
                theme.title_style(),
            ))];
            if let Some(v) = &app.progress.current_vendor {
                lines.push(Line::from(format!("vendor     {v}")));
            }
            if let Some(i) = &app.progress.current_indicator {
                lines.push(Line::from(format!("indicator  {}", short(i, 48))));
            }
            match &app.progress.status {
                InvestigationStatus::WaitingRateLimit { vendor, wait } => {
                    lines.push(Line::from(Span::styled(
                        format!(
                            "rate-limit pacing {vendor} — {:.0}s",
                            wait.as_secs_f64()
                        ),
                        theme.warn_style(),
                    )));
                }
                InvestigationStatus::Failed(e) => {
                    lines.push(Line::from(Span::styled(e.clone(), theme.danger_style())));
                }
                _ => {}
            }
            if !app.output_paths.is_empty() {
                lines.push(Line::from(""));
                lines.push(Line::from(Span::styled("Wrote:", theme.ok_style())));
                for p in &app.output_paths {
                    lines.push(Line::from(format!("  {}", p.display())));
                }
            }
            frame.render_widget(Paragraph::new(lines).wrap(Wrap { trim: true }), area);
        }
    }
}

fn draw_api_keys(frame: &mut Frame<'_>, area: Rect, app: &App, theme: Palette) {
    match app.api_key_mode {
        ApiKeyMode::EnterKey => {
            let vendor = app
                .pending_key_for_vendor
                .clone()
                .unwrap_or_else(|| "vendor".into());
            let masked: String = app.api_key_input.chars().map(|_| '•').collect();
            let lines = vec![
                Line::from(Span::styled(
                    format!("API key for {vendor}"),
                    theme.title_style(),
                )),
                Line::from(""),
                Line::from(vec![
                    Span::styled(" key ▸ ", theme.accent_style()),
                    Span::raw(format!("{masked}█")),
                ]),
                Line::from(""),
                Line::from(Span::styled(
                    "Stored in ~/.config/scry/config.toml",
                    theme.muted_style(),
                )),
            ];
            frame.render_widget(Paragraph::new(lines), area);
        }
        _ => {
            let vendors = all_vendors();
            let items: Vec<ListItem> = vendors
                .iter()
                .enumerate()
                .map(|(i, v)| {
                    let has = app.config.api_key(v.id()).is_some();
                    let mark = if has { "●" } else { "○" };
                    let selected = i == app.api_key_index;
                    let style = if selected {
                        theme.selected()
                    } else if has {
                        theme.ok_style()
                    } else {
                        theme.text_style()
                    };
                    let label = format!(
                        "{} {}  {}{}",
                        if selected { "◆" } else { " " },
                        mark,
                        v.name(),
                        if has { "  (cached)" } else { "  (missing)" }
                    );
                    ListItem::new(Span::styled(label, style))
                })
                .collect();
            frame.render_widget(List::new(items), area);
        }
    }
}

fn draw_vendors(frame: &mut Frame<'_>, area: Rect, app: &App, theme: Palette) {
    if app.vendor_mode == VendorMode::BulkByType {
        draw_vendor_bulk(frame, area, app, theme);
        return;
    }

    let vendors = all_vendors();
    let items: Vec<ListItem> = vendors
        .iter()
        .enumerate()
        .map(|(i, v)| {
            let checked = app.config.is_vendor_selected(v.id());
            let boxc = if checked { "[x]" } else { "[ ]" };
            let selected = i == app.vendor_index;
            let style = if selected {
                theme.selected()
            } else {
                theme.text_style()
            };
            let rl = app.config.effective_rate_limit(v.id());
            let mut rate = rl.display();
            if app.config.rate_overrides.contains_key(v.id()) {
                rate.push_str(" · override");
            }
            let types = v
                .supported_types()
                .iter()
                .map(|t| t.label())
                .collect::<Vec<_>>()
                .join(", ");
            ListItem::new(vec![
                Line::from(Span::styled(
                    format!(
                        "{} {} {}  — {}",
                        if selected { "◆" } else { " " },
                        boxc,
                        v.name(),
                        v.description()
                    ),
                    style,
                )),
                Line::from(Span::styled(
                    format!("      types: {types}  ·  rate: {rate}"),
                    if selected {
                        Style::default().fg(theme.bg).bg(theme.accent)
                    } else {
                        theme.muted_style()
                    },
                )),
            ])
        })
        .collect();
    frame.render_widget(List::new(items), area);
}

fn draw_vendor_bulk(frame: &mut Frame<'_>, area: Rect, app: &App, theme: Palette) {
    let mut lines = vec![
        Line::from(Span::styled(
            "Bulk-select vendors by indicator type",
            theme.title_style(),
        )),
        Line::from(Span::styled(
            "Enter enables every vendor that supports the highlighted type.",
            theme.muted_style(),
        )),
        Line::from(""),
    ];
    for (i, kind) in IndicatorType::all_known().iter().enumerate() {
        let selected = i == app.bulk_type_index;
        let n = vendors_for_type(*kind).len();
        let prefix = if selected { "◆ " } else { "  " };
        let style = if selected {
            theme.selected()
        } else {
            theme.text_style()
        };
        lines.push(Line::from(Span::styled(
            format!("{prefix}{:<8}  →  {n} vendor(s)", kind.label()),
            style,
        )));
    }
    frame.render_widget(Paragraph::new(lines), area);
}

fn draw_profiles(frame: &mut Frame<'_>, area: Rect, app: &App, theme: Palette) {
    let mut lines = vec![
        Line::from(Span::styled(
            "Usage profile controls client-side API pacing",
            theme.title_style(),
        )),
        Line::from(Span::styled(
            "Personal = published free tiers · Enterprise = paid / SLA quotas",
            theme.muted_style(),
        )),
        Line::from(""),
    ];
    for (i, profile) in UsageProfile::all().iter().enumerate() {
        let selected = i == app.profile_index;
        let active = *profile == app.config.usage_profile;
        let mark = if active { "●" } else { "○" };
        let prefix = if selected { "◆ " } else { "  " };
        let style = if selected {
            theme.selected()
        } else {
            theme.text_style()
        };
        lines.push(Line::from(Span::styled(
            format!("{prefix}{mark}  {}", profile.label()),
            style,
        )));
        lines.push(Line::from(Span::styled(
            format!("      {}", profile.description()),
            if selected {
                Style::default().fg(theme.bg).bg(theme.accent)
            } else {
                theme.muted_style()
            },
        )));
    }
    frame.render_widget(Paragraph::new(lines).wrap(Wrap { trim: true }), area);
}

fn draw_options(frame: &mut Frame<'_>, area: Rect, app: &App, theme: Palette) {
    match app.options_mode {
        OptionsMode::List => {
            let header = Paragraph::new(vec![
                Line::from(Span::styled("Options", theme.title_style())),
                Line::from(Span::styled(
                    format!(
                        "Active profile: {} · {} override(s)",
                        app.config.usage_profile.short(),
                        app.config.rate_overrides.len()
                    ),
                    theme.muted_style(),
                )),
                Line::from(""),
            ]);
            let chunks = Layout::default()
                .direction(Direction::Vertical)
                .constraints([Constraint::Length(3), Constraint::Min(3)])
                .split(area);
            frame.render_widget(header, chunks[0]);
            let items: Vec<ListItem> = App::options_items()
                .iter()
                .enumerate()
                .map(|(i, label)| {
                    let selected = i == app.options_index;
                    let prefix = if selected { "◆ " } else { "  " };
                    let style = if selected {
                        theme.selected()
                    } else {
                        theme.text_style()
                    };
                    ListItem::new(Span::styled(format!("{prefix}{label}"), style))
                })
                .collect();
            frame.render_widget(List::new(items), chunks[1]);
        }
        OptionsMode::RateWarning => {
            let lines = vec![
                Line::from(Span::styled(
                    "⚠ WARNING — manual rate limits",
                    theme.warn_style().add_modifier(Modifier::BOLD),
                )),
                Line::from(""),
                Line::from(Span::styled(
                    "Raising limits above your vendor tier can cause:",
                    theme.text_style(),
                )),
                Line::from(Span::styled(
                    "  • HTTP 429 / temporary bans",
                    theme.danger_style(),
                )),
                Line::from(Span::styled(
                    "  • burned daily/weekly quotas",
                    theme.danger_style(),
                )),
                Line::from(Span::styled(
                    "  • ToS violations on free/public APIs",
                    theme.danger_style(),
                )),
                Line::from(""),
                Line::from(Span::styled(
                    "Prefer Usage Profile (Personal / Enterprise) when possible.",
                    theme.muted_style(),
                )),
                Line::from(Span::styled(
                    "Unthrottled only skips Scry client pacing — vendors may still reject you.",
                    theme.muted_style(),
                )),
                Line::from(""),
                Line::from(Span::styled(
                    "Enter = I understand, continue · Esc = cancel",
                    theme.accent_style(),
                )),
            ];
            frame.render_widget(Paragraph::new(lines).wrap(Wrap { trim: true }), area);
        }
        OptionsMode::RateVendorList => {
            let items: Vec<ListItem> = all_vendors()
                .into_iter()
                .enumerate()
                .map(|(i, v)| {
                    let selected = i == app.rate_vendor_index;
                    let effective = app.config.effective_rate_limit(v.id());
                    let overridden = app.config.rate_overrides.contains_key(v.id());
                    let tag = if overridden { " [override]" } else { "" };
                    let style = if selected {
                        theme.selected()
                    } else {
                        theme.text_style()
                    };
                    ListItem::new(vec![
                        Line::from(Span::styled(
                            format!(
                                "{} {}{}",
                                if selected { "◆" } else { " " },
                                v.name(),
                                tag
                            ),
                            style,
                        )),
                        Line::from(Span::styled(
                            format!("      {}", effective.display()),
                            if selected {
                                Style::default().fg(theme.bg).bg(theme.accent)
                            } else {
                                theme.muted_style()
                            },
                        )),
                    ])
                })
                .collect();
            frame.render_widget(List::new(items), area);
        }
        OptionsMode::RateEdit => {
            let vendor = app
                .rate_edit_vendor
                .as_deref()
                .unwrap_or("?");
            let mut lines = vec![
                Line::from(Span::styled(
                    format!("Edit rate limit · {vendor}"),
                    theme.title_style(),
                )),
                Line::from(Span::styled(
                    "⚠ Changes override the active usage profile for this vendor.",
                    theme.warn_style(),
                )),
                Line::from(""),
            ];
            for (i, field) in App::rate_edit_fields().iter().enumerate() {
                let selected = i == app.rate_edit_field;
                let prefix = if selected { "◆ " } else { "  " };
                let style = if selected {
                    theme.selected()
                } else {
                    theme.text_style()
                };
                let label = match field {
                    RateEditField::PerMinute => format!(
                        "requests / minute   = {}",
                        app.rate_draft.requests_per_minute
                    ),
                    RateEditField::PerHour => format!(
                        "requests / hour     = {}",
                        app.rate_draft
                            .requests_per_hour
                            .map(|n| n.to_string())
                            .unwrap_or_else(|| "none".into())
                    ),
                    RateEditField::PerDay => format!(
                        "requests / day      = {}",
                        app.rate_draft
                            .requests_per_day
                            .map(|n| n.to_string())
                            .unwrap_or_else(|| "none".into())
                    ),
                    RateEditField::Unthrottled => format!(
                        "unthrottled (client) = {}",
                        if app.rate_draft.unthrottled {
                            "yes"
                        } else {
                            "no"
                        }
                    ),
                    RateEditField::ClearOverride => "clear override & use profile".into(),
                    RateEditField::Save => "save override".into(),
                };
                lines.push(Line::from(Span::styled(format!("{prefix}{label}"), style)));
            }
            if app.rate_typing {
                lines.push(Line::from(""));
                lines.push(Line::from(Span::styled(
                    format!("typing ▸ {}█", app.rate_edit_input),
                    theme.accent_style(),
                )));
            }
            frame.render_widget(Paragraph::new(lines), area);
        }
    }
}


fn draw_right_panel(frame: &mut Frame<'_>, area: Rect, app: &App, theme: Palette) {
    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage(28),
            Constraint::Percentage(28),
            Constraint::Percentage(44),
        ])
        .split(area);

    draw_session_panel(frame, rows[0], app, theme);
    draw_queries_panel(frame, rows[1], app, theme);
    draw_tags_panel(frame, rows[2], app, theme);
}

fn draw_tags_panel(frame: &mut Frame<'_>, area: Rect, app: &App, theme: Palette) {
    let n = app.threat_board.tags.len();
    let title = if n == 0 {
        " tags / intel ".to_string()
    } else {
        format!(" tags / intel ({n}) ")
    };
    let block = panel_block(&title, false, theme);
    let inner = block.inner(area);
    frame.render_widget(block, area);

    let limit = inner.height.max(1) as usize;
    let top = app.threat_board.top_tags(limit);
    if top.is_empty() {
        frame.render_widget(
            Paragraph::new(vec![
                Line::from(Span::styled(
                    "Malware families, actors, and",
                    theme.muted_style(),
                )),
                Line::from(Span::styled(
                    "pulse tags appear here as",
                    theme.muted_style(),
                )),
                Line::from(Span::styled(
                    "vendors report hits.",
                    theme.muted_style(),
                )),
            ]),
            inner,
        );
        return;
    }

    let items: Vec<ListItem> = top
        .into_iter()
        .map(|hit| {
            let kind_style = match hit.kind {
                TagKind::Malware | TagKind::Family => theme.danger_style(),
                TagKind::Actor => theme.warn_style(),
                TagKind::Pulse | TagKind::Category => theme.accent_style(),
                TagKind::Other => theme.muted_style(),
            };
            let sources = hit
                .sources
                .iter()
                .take(2)
                .cloned()
                .collect::<Vec<_>>()
                .join(",");
            let width = inner.width as usize;
            let tag = short(&hit.tag, width.saturating_sub(18).max(8));
            ListItem::new(Line::from(vec![
                Span::styled(format!("{:>3} ", hit.count), theme.muted_style()),
                Span::styled(format!("[{}] ", hit.kind.label()), kind_style),
                Span::styled(tag, theme.text_style()),
                Span::styled(format!(" · {sources}"), theme.muted_style()),
            ]))
        })
        .collect();
    frame.render_widget(List::new(items), inner);
}

fn draw_session_panel(frame: &mut Frame<'_>, area: Rect, app: &App, theme: Palette) {
    let block = panel_block(" session ", false, theme);
    let inner = block.inner(area);
    frame.render_widget(block, area);

    let keys_cached = app.config.api_keys.len();
    let fmt = app.config.defaults.format.label();
    let verb = app.config.defaults.verbosity.label();

    let lines = vec![
        Line::from(vec![
            Span::styled("keys cached  ", theme.muted_style()),
            Span::styled(keys_cached.to_string(), theme.accent_style()),
        ]),
        Line::from(vec![
            Span::styled("out format   ", theme.muted_style()),
            Span::raw(short(fmt, 22)),
        ]),
        Line::from(vec![
            Span::styled("verbosity    ", theme.muted_style()),
            Span::raw(short(verb, 22)),
        ]),
        Line::from(vec![
            Span::styled("theme        ", theme.muted_style()),
            Span::styled(
                short(app.config.color_scheme.label(), 22),
                theme.accent_style(),
            ),
        ]),
        Line::from(vec![
            Span::styled("profile      ", theme.muted_style()),
            Span::styled(app.config.usage_profile.short(), theme.accent_style()),
        ]),
        Line::from(vec![
            Span::styled("output dir   ", theme.muted_style()),
            Span::raw(short(&app.output_dir, 22)),
        ]),
    ];
    frame.render_widget(Paragraph::new(lines).wrap(Wrap { trim: true }), inner);
}

fn draw_queries_panel(frame: &mut Frame<'_>, area: Rect, app: &App, theme: Palette) {
    let block = panel_block(" current query ", false, theme);
    let inner = block.inner(area);
    frame.render_widget(block, area);

    let mut lines = Vec::new();
    if let Some(v) = &app.progress.current_vendor {
        lines.push(Line::from(vec![
            Span::styled("vendor  ", theme.muted_style()),
            Span::styled(v.clone(), theme.accent_style()),
        ]));
    } else {
        lines.push(Line::from(Span::styled(
            "no active query",
            theme.muted_style(),
        )));
    }
    if let Some(i) = &app.progress.current_indicator {
        lines.push(Line::from(vec![
            Span::styled("target  ", theme.muted_style()),
            Span::raw(short(i, 28)),
        ]));
    }
    lines.push(Line::from(""));
    lines.push(Line::from(vec![
        Span::styled("done    ", theme.muted_style()),
        Span::raw(format!(
            "{}/{}",
            app.progress.completed_queries, app.progress.total_queries
        )),
    ]));
    if let Some(eta) = app.progress.eta {
        lines.push(Line::from(vec![
            Span::styled("eta     ", theme.muted_style()),
            Span::raw(format!("{:.0}s", eta.as_secs_f64())),
        ]));
    }
    for w in app.progress.warnings.iter().take(3) {
        lines.push(Line::from(Span::styled(
            format!("⚠ {}", short(w, 32)),
            theme.warn_style(),
        )));
    }
    frame.render_widget(Paragraph::new(lines).wrap(Wrap { trim: true }), inner);
}

fn draw_results_panel(frame: &mut Frame<'_>, area: Rect, app: &App, theme: Palette) {
    let block = panel_block(" live results ", false, theme);
    let inner = block.inner(area);
    frame.render_widget(block, area);

    let start = app.live_lines.len().saturating_sub(inner.height as usize);
    let items: Vec<ListItem> = app.live_lines[start..]
        .iter()
        .map(|line| {
            let style = if line.starts_with('●') {
                theme.danger_style()
            } else if line.starts_with('◐') {
                theme.warn_style()
            } else if line.starts_with('○') || line.starts_with('✓') {
                theme.ok_style()
            } else if line.starts_with('✗') {
                theme.danger_style()
            } else if line.starts_with('⚠') {
                theme.warn_style()
            } else {
                theme.text_style()
            };
            ListItem::new(Span::styled(short(line, inner.width as usize), style))
        })
        .collect();

    if items.is_empty() {
        frame.render_widget(
            Paragraph::new(Span::styled(
                "Results stream here while queries run.",
                theme.muted_style(),
            )),
            inner,
        );
    } else {
        frame.render_widget(List::new(items), inner);
    }
}

fn short(s: &str, max: usize) -> String {
    let count = s.chars().count();
    if count <= max {
        s.to_string()
    } else if max <= 1 {
        "…".into()
    } else {
        let t: String = s.chars().take(max - 1).collect();
        format!("{t}…")
    }
}

fn draw_file_browser(
    frame: &mut Frame<'_>,
    area: Rect,
    browser: &crate::browser::FileBrowser,
    heading: &str,
    theme: Palette,
) {
    let mut lines = vec![
        Line::from(Span::styled(heading, theme.title_style())),
        Line::from(Span::styled(
            format!("{}", browser.cwd.display()),
            theme.muted_style(),
        )),
        Line::from(""),
    ];
    for (i, entry) in browser.entries.iter().enumerate() {
        let selected = i == browser.selected;
        let prefix = if selected { "◆ " } else { "  " };
        let style = if selected {
            theme.selected()
        } else if entry.looks_like_indicators()
            || entry
                .name
                .ends_with(".csv")
            || entry.name.ends_with(".txt")
        {
            theme.ok_style()
        } else {
            theme.text_style()
        };
        lines.push(Line::from(Span::styled(
            format!("{prefix}{}", entry.label()),
            style,
        )));
    }
    if browser.entries.is_empty() {
        lines.push(Line::from(Span::styled(
            "(empty directory)",
            theme.muted_style(),
        )));
    }
    frame.render_widget(Paragraph::new(lines).wrap(Wrap { trim: true }), area);
}

fn draw_file_viewer(frame: &mut Frame<'_>, area: Rect, app: &mut App, theme: Palette) {
    let Some(viewer) = app.file_viewer.as_ref() else {
        frame.render_widget(
            Paragraph::new(Span::styled("No file loaded", theme.muted_style())),
            area,
        );
        return;
    };

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(1), Constraint::Min(3), Constraint::Length(1)])
        .split(area);

    frame.render_widget(
        Paragraph::new(Span::styled(viewer.path.display().to_string(), theme.muted_style())),
        chunks[0],
    );

    let body = chunks[1];
    match viewer.kind {
        ViewKind::Text => {
            app.view_visible_rows = body.height as usize;
            let start = viewer.scroll;
            let end = (start + body.height as usize).min(viewer.lines.len());
            let items: Vec<ListItem> = viewer.lines[start..end]
                .iter()
                .enumerate()
                .map(|(i, line)| {
                    let abs = start + i;
                    let selected = abs == viewer.cursor;
                    let style = if selected {
                        theme.selected()
                    } else {
                        theme.text_style()
                    };
                    let prefix = if selected { "▸ " } else { "  " };
                    ListItem::new(Span::styled(
                        format!("{prefix}{}", short(line, body.width.saturating_sub(2) as usize)),
                        style,
                    ))
                })
                .collect();
            if items.is_empty() {
                frame.render_widget(
                    Paragraph::new(Span::styled("(empty file)", theme.muted_style())),
                    body,
                );
            } else {
                frame.render_widget(List::new(items), body);
            }
        }
        ViewKind::Csv => {
            // Header + rows; reserve one line for header in scroll math.
            app.view_visible_rows = body.height.saturating_sub(1) as usize;
            draw_csv_table(frame, body, viewer, theme);
        }
    }

    frame.render_widget(
        Paragraph::new(Span::styled(viewer.status.clone(), theme.muted_style())),
        chunks[2],
    );
}

fn draw_csv_table(
    frame: &mut Frame<'_>,
    area: Rect,
    viewer: &crate::viewer::FileViewer,
    theme: Palette,
) {
    let col_scroll = viewer.col_scroll;
    let widths: Vec<Constraint> = viewer
        .col_widths
        .iter()
        .skip(col_scroll)
        .map(|w| Constraint::Length((*w as u16).saturating_add(2)))
        .collect();

    if widths.is_empty() {
        frame.render_widget(
            Paragraph::new(Span::styled("(empty csv)", theme.muted_style())),
            area,
        );
        return;
    }

    let header_cells = viewer
        .headers
        .iter()
        .skip(col_scroll)
        .map(|h| Cell::from(h.as_str()).style(theme.title_style()));
    let header = Row::new(header_cells).height(1);

    let visible = area.height.saturating_sub(1) as usize;
    let start = viewer.scroll;
    let end = (start + visible).min(viewer.rows.len());

    let rows = viewer.rows[start..end].iter().enumerate().map(|(i, row)| {
        let abs = start + i;
        let selected = abs == viewer.cursor;
        let cells = (col_scroll..viewer.col_widths.len()).map(|ci| {
            let text = row.get(ci).map(String::as_str).unwrap_or("");
            let clipped = short(text, viewer.col_widths[ci]);
            Cell::from(clipped)
        });
        let style = if selected {
            theme.selected()
        } else {
            theme.text_style()
        };
        Row::new(cells).style(style).height(1)
    });

    let table = Table::new(rows, widths)
        .header(header)
        .column_spacing(1)
        .block(Block::default());
    frame.render_widget(table, area);
}

fn draw_text_editor(frame: &mut Frame<'_>, area: Rect, app: &mut App, theme: Palette) {
    let Some(editor) = app.text_editor.as_ref() else {
        frame.render_widget(
            Paragraph::new(Span::styled("No editor open", theme.muted_style())),
            area,
        );
        return;
    };

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(1), Constraint::Min(3), Constraint::Length(1)])
        .split(area);

    let dirty = if editor.dirty { " ● unsaved" } else { "" };
    frame.render_widget(
        Paragraph::new(Span::styled(
            format!("{}{dirty}", editor.path.display()),
            theme.muted_style(),
        )),
        chunks[0],
    );

    let body = chunks[1];
    app.view_visible_rows = body.height as usize;
    let start = editor.scroll;
    let end = (start + body.height as usize).min(editor.lines.len());

    let items: Vec<ListItem> = editor.lines[start..end]
        .iter()
        .enumerate()
        .map(|(i, line)| {
            let abs = start + i;
            let selected = abs == editor.cursor_row;
            let gutter = format!("{:>4} ", abs + 1);
            let mut display = line.clone();
            if selected {
                let col = editor.cursor_col.min(display.chars().count());
                let mut out = String::new();
                for (ci, ch) in display.chars().enumerate() {
                    if ci == col {
                        out.push('▌');
                    }
                    out.push(ch);
                }
                if col >= display.chars().count() {
                    out.push('▌');
                }
                display = out;
            }
            let style = if selected {
                theme.selected()
            } else {
                theme.text_style()
            };
            ListItem::new(Line::from(vec![
                Span::styled(gutter, theme.muted_style()),
                Span::styled(display, style),
            ]))
        })
        .collect();

    frame.render_widget(List::new(items), body);
    frame.render_widget(
        Paragraph::new(Span::styled(editor.status.clone(), theme.muted_style())),
        chunks[2],
    );
}

fn draw_new_file_prompt(frame: &mut Frame<'_>, area: Rect, app: &App, theme: Palette) {
    let lines = vec![
        Line::from(Span::styled("Create new indicator file", theme.title_style())),
        Line::from(Span::styled(
            format!("Directory: {}", app.input_browser.cwd.display()),
            theme.muted_style(),
        )),
        Line::from(""),
        Line::from(vec![
            Span::styled(" filename ▸ ", theme.accent_style()),
            Span::styled(format!("{}█", app.new_file_name), theme.text_style()),
        ]),
        Line::from(""),
        Line::from(Span::styled(
            "Enter create · Esc cancel",
            theme.muted_style(),
        )),
    ];
    frame.render_widget(Paragraph::new(lines), area);
}
