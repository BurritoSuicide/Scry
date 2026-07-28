use super::theme::Palette;
use ratatui::style::Style;
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, BorderType, Borders, Paragraph};
use ratatui::Frame;
use std::time::Duration;

/// Panel chrome: rounded idle borders, thick active borders, highlighted fill when focused.
pub fn panel_block(title: &str, focused: bool, theme: Palette) -> Block<'static> {
    let title_line = if focused {
        Line::from(vec![
            Span::styled("◆ ", theme.accent_style()),
            Span::styled(title.trim().to_string(), theme.focused_title_style()),
            Span::raw(" "),
        ])
    } else {
        Line::from(vec![
            Span::styled("· ", theme.muted_style()),
            Span::styled(title.trim().to_string(), theme.title_style()),
            Span::raw(" "),
        ])
    };

    Block::default()
        .title(title_line)
        .borders(Borders::ALL)
        .border_type(if focused {
            BorderType::Thick
        } else {
            BorderType::Rounded
        })
        .border_style(theme.panel_border(focused))
        .style(Style::default().bg(theme.panel_fill(focused)))
}

pub fn progress_label(
    done: usize,
    total: usize,
    eta: Option<Duration>,
    status: &str,
) -> String {
    let pct = if total == 0 {
        0
    } else {
        (done * 100) / total
    };
    match eta {
        Some(eta) if total > 0 && done < total => {
            format!(
                "{done}/{total}  {pct}%  ·  {status}  ·  eta {:.0}s",
                eta.as_secs_f64()
            )
        }
        _ => format!("{done}/{total}  {pct}%  ·  {status}"),
    }
}

/// Progress meter drawn as themed cells; tachyonfx adds the live shimmer.
pub fn draw_animated_progress(
    frame: &mut Frame<'_>,
    area: ratatui::layout::Rect,
    fraction: f64,
    active: bool,
    theme: Palette,
) {
    let width = area.width as usize;
    if width == 0 {
        return;
    }

    let frac = fraction.clamp(0.0, 1.0);
    let filled = ((frac * width as f64).round() as usize).min(width);

    let mut spans: Vec<Span> = Vec::with_capacity(width);
    for i in 0..width {
        let (ch, style) = if i < filled {
            let tip = active && i + 1 == filled && filled < width;
            let ch = if tip { '▓' } else { '█' };
            let fg = if tip { theme.accent } else { theme.progress };
            (ch, Style::default().fg(fg).bg(theme.progress_bg))
        } else if active && i == filled && filled < width {
            (
                '░',
                Style::default().fg(theme.accent).bg(theme.panel),
            )
        } else {
            (
                '░',
                Style::default().fg(theme.progress_bg).bg(theme.panel),
            )
        };
        spans.push(Span::styled(ch.to_string(), style));
    }

    frame.render_widget(Paragraph::new(Line::from(spans)), area);
}
