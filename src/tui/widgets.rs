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
                " {done}/{total}  {pct}%  ·  {status}  ·  eta {:.0}s ",
                eta.as_secs_f64()
            )
        }
        _ => format!(" {done}/{total}  {pct}%  ·  {status} "),
    }
}
