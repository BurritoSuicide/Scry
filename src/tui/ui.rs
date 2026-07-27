use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Clear, Gauge, List, ListItem, Paragraph, Wrap};
use ratatui::Frame;

use super::widgets::{panel_block, progress_label};
use crate::app::{ApiKeyMode, App, InvestigateStep, Screen};
use crate::config::{OutputFormat, Verbosity};
use crate::investigation::InvestigationStatus;
use crate::theme::{ColorScheme, Palette};
use crate::vendors::all_vendors;

pub fn draw(frame: &mut Frame<'_>, app: &App) {
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

    draw_header(frame, root[0], app, theme);
    draw_progress_bar(frame, root[1], app, theme);
    draw_body(frame, root[2], app, theme);
    draw_status(frame, root[3], app, theme);
}

fn draw_header(frame: &mut Frame<'_>, area: Rect, app: &App, theme: Palette) {
    let selected = app.config.selected_count();
    let vendors_total = all_vendors().len();
    let title = Line::from(vec![
        Span::styled(" CHARON ", theme.title_style()),
        Span::styled("│", Style::default().fg(theme.border)),
        Span::styled(
            format!(" vendors {selected}/{vendors_total} selected "),
            theme.accent_style(),
        ),
        Span::styled("│", Style::default().fg(theme.border)),
        Span::styled(
            format!(" {}", app.config.color_scheme.label()),
            theme.muted_style(),
        ),
    ]);

    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(theme.panel_border(true))
        .style(Style::default().bg(theme.panel));
    let inner = block.inner(area);
    frame.render_widget(block, area);
    frame.render_widget(Paragraph::new(title), inner);
}

fn draw_progress_bar(frame: &mut Frame<'_>, area: Rect, app: &App, theme: Palette) {
    let focused = matches!(app.investigate_step, InvestigateStep::Running);
    let block = panel_block(" progress ", focused, theme);
    let inner = block.inner(area);
    frame.render_widget(block, area);

    let frac = app.progress.fraction();
    let status = match &app.progress.status {
        InvestigationStatus::Idle => "idle",
        InvestigationStatus::Preparing => "preparing",
        InvestigationStatus::Running => "running",
        InvestigationStatus::WaitingRateLimit { .. } => "rate-limited",
        InvestigationStatus::Completed => "completed",
        InvestigationStatus::Failed(_) => "failed",
    };
    let label = progress_label(
        app.progress.completed_queries,
        app.progress.total_queries,
        app.progress.eta,
        status,
    );

    // Single full-width gauge — filled and empty share the same palette
    // (progress / progress_bg). Avoid a second accent-colored meter on the side.
    let gauge = Gauge::default()
        .gauge_style(
            Style::default()
                .fg(theme.progress)
                .bg(theme.progress_bg),
        )
        .ratio(frac.clamp(0.0, 1.0))
        .label(label);
    frame.render_widget(gauge, inner);
}

fn draw_status(frame: &mut Frame<'_>, area: Rect, app: &App, theme: Palette) {
    let msg = Paragraph::new(Line::from(vec![
        Span::styled(" ▸ ", theme.accent_style()),
        Span::styled(app.status_message.clone(), theme.muted_style()),
    ]))
    .style(Style::default().bg(theme.bg));
    frame.render_widget(msg, area);
}

fn draw_body(frame: &mut Frame<'_>, area: Rect, app: &App, theme: Palette) {
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
    draw_menu_panel(frame, area, app, theme);
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

fn draw_center_panel(frame: &mut Frame<'_>, area: Rect, app: &App, theme: Palette) {
    // Workspace on top, live results underneath with more vertical room.
    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Percentage(48), Constraint::Percentage(52)])
        .split(area);

    draw_workspace(frame, rows[0], app, theme);
    draw_results_panel(frame, rows[1], app, theme);
}

fn draw_workspace(frame: &mut Frame<'_>, area: Rect, app: &App, theme: Palette) {
    let title = match app.screen {
        Screen::MainMenu => " workspace ",
        Screen::Investigation => " investigation ",
        Screen::ApiKeys => " api keys ",
        Screen::Vendors => " vendors ",
        Screen::ColorScheme => " color scheme ",
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
        Screen::ColorScheme => draw_color_scheme(frame, inner, app, theme),
    }
}

fn draw_workspace_home(frame: &mut Frame<'_>, area: Rect, app: &App, theme: Palette) {
    let lines = vec![
        Line::from(Span::styled(
            "OSINT investigations for emails · IPs · JA4 · hashes",
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
        Line::from(""),
        Line::from(Span::styled(
            "Use the main menu to start an investigation.",
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

fn draw_file_browser(frame: &mut Frame<'_>, area: Rect, app: &App, theme: Palette) {
    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(2), Constraint::Min(3)])
        .split(area);

    let found = app.file_browser.indicator_file_count();
    let header = vec![
        Line::from(vec![
            Span::styled("cwd ", theme.muted_style()),
            Span::styled(
                app.file_browser.cwd.display().to_string(),
                theme.accent_style(),
            ),
        ]),
        Line::from(Span::styled(
            if found > 0 {
                format!(
                    "{found} file(s) look like indicator lists (highlighted) · ← → navigate"
                )
            } else {
                "← parent · → enter dir · Enter select file · auto-scans .txt/.csv/.list"
                    .into()
            },
            theme.muted_style(),
        )),
    ];
    frame.render_widget(Paragraph::new(header), rows[0]);

    let height = rows[1].height as usize;
    let selected = app.file_browser.selected;
    let start = selected.saturating_sub(height.saturating_sub(1) / 2);
    let end = (start + height).min(app.file_browser.entries.len());
    let start = end.saturating_sub(height).min(start);

    let items: Vec<ListItem> = app.file_browser.entries[start..end]
        .iter()
        .enumerate()
        .map(|(offset, entry)| {
            let i = start + offset;
            let selected = i == app.file_browser.selected;
            let marker = if entry.name == ".." {
                "↑"
            } else if entry.is_dir {
                "▸"
            } else if entry.looks_like_indicators() {
                "●"
            } else {
                " "
            };
            let prefix = if selected { "◆" } else { " " };
            let style = if selected {
                theme.selected()
            } else if entry.looks_like_indicators() {
                theme.ok_style()
            } else if entry.is_dir {
                theme.accent_style()
            } else {
                theme.text_style()
            };
            ListItem::new(Span::styled(
                format!("{prefix} {marker} {}", entry.label()),
                style,
            ))
        })
        .collect();

    if items.is_empty() {
        frame.render_widget(
            Paragraph::new(Span::styled(
                "No text files or directories here.",
                theme.muted_style(),
            )),
            rows[1],
        );
    } else {
        frame.render_widget(List::new(items), rows[1]);
    }
}

fn draw_investigation(frame: &mut Frame<'_>, area: Rect, app: &App, theme: Palette) {
    match app.investigate_step {
        InvestigateStep::InputPath => {
            draw_file_browser(frame, area, app, theme);
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
                    "Stored in ~/.config/charon/config.toml",
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
            let rl = v.rate_limit();
            let rate = match rl.requests_per_day {
                Some(d) => format!("{} /min · {} /day", rl.requests_per_minute, d),
                None => format!("{} /min", rl.requests_per_minute),
            };
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

fn draw_right_panel(frame: &mut Frame<'_>, area: Rect, app: &App, theme: Palette) {
    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Percentage(48), Constraint::Percentage(52)])
        .split(area);

    draw_session_panel(frame, rows[0], app, theme);
    draw_queries_panel(frame, rows[1], app, theme);
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
            let style = if line.starts_with('✓') {
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
