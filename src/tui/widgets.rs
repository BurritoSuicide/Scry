use super::theme::Palette;
use ratatui::widgets::{Block, Borders};
use std::time::Duration;

pub fn panel_block(title: &str, focused: bool, theme: Palette) -> Block<'static> {
    Block::default()
        .title(title.to_string())
        .borders(Borders::ALL)
        .border_style(theme.panel_border(focused))
        .style(ratatui::style::Style::default().bg(theme.panel))
}

pub fn progress_label(done: usize, total: usize, eta: Option<Duration>) -> String {
    let pct = if total == 0 {
        0
    } else {
        (done * 100) / total
    };
    match eta {
        Some(eta) if total > 0 && done < total => {
            format!(" {done}/{total}  {pct}%  eta {:.0}s ", eta.as_secs_f64())
        }
        _ => format!(" {done}/{total}  {pct}% "),
    }
}

/// Decorative dual-tone bar reminiscent of btop meters.
pub fn sparkline_bar(fraction: f64, width: usize) -> String {
    if width == 0 {
        return String::new();
    }
    let filled = ((fraction.clamp(0.0, 1.0)) * width as f64).round() as usize;
    let mut s = String::with_capacity(width);
    for i in 0..width {
        if i < filled {
            s.push('█');
        } else {
            s.push('░');
        }
    }
    s
}
