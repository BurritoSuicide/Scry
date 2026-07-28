//! Output file viewers — plain text scroll + CSV table (csvlens-inspired).

use crate::error::{ScryError, Result};
use std::fs;
use std::path::{Path, PathBuf};
use unicode_width::UnicodeWidthStr;

const MAX_COL_WIDTH: usize = 36;
const MIN_COL_WIDTH: usize = 4;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ViewKind {
    Text,
    Csv,
}

#[derive(Debug, Clone)]
pub struct FileViewer {
    pub path: PathBuf,
    pub kind: ViewKind,
    pub lines: Vec<String>,
    pub headers: Vec<String>,
    pub rows: Vec<Vec<String>>,
    pub col_widths: Vec<usize>,
    /// Vertical scroll offset (first visible content row / line).
    pub scroll: usize,
    /// Horizontal column scroll for CSV.
    pub col_scroll: usize,
    /// Highlighted row / line (absolute index into content).
    pub cursor: usize,
    pub status: String,
}

impl FileViewer {
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref().to_path_buf();
        if !path.is_file() {
            return Err(ScryError::msg(format!(
                "not a file: {}",
                path.display()
            )));
        }

        let name = path
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("")
            .to_ascii_lowercase();

        if name.ends_with(".csv") {
            Self::open_csv(path)
        } else {
            Self::open_text(path)
        }
    }

    fn open_text(path: PathBuf) -> Result<Self> {
        let raw = fs::read_to_string(&path)?;
        let lines: Vec<String> = if raw.is_empty() {
            Vec::new()
        } else {
            raw.lines().map(str::to_string).collect()
        };
        let cursor = 0;
        Ok(Self {
            path,
            kind: ViewKind::Text,
            lines,
            headers: Vec::new(),
            rows: Vec::new(),
            col_widths: Vec::new(),
            scroll: 0,
            col_scroll: 0,
            cursor,
            status: "↑↓ scroll · c copy all · y copy line · Esc back".into(),
        })
    }

    fn open_csv(path: PathBuf) -> Result<Self> {
        let mut reader = csv::ReaderBuilder::new()
            .flexible(true)
            .from_path(&path)
            .map_err(|e| ScryError::msg(format!("csv read {}: {e}", path.display())))?;

        let headers: Vec<String> = reader
            .headers()
            .map_err(|e| ScryError::msg(format!("csv headers: {e}")))?
            .iter()
            .map(str::to_string)
            .collect();

        let mut rows: Vec<Vec<String>> = Vec::new();
        for record in reader.records() {
            let record = record.map_err(|e| ScryError::msg(format!("csv row: {e}")))?;
            rows.push(record.iter().map(str::to_string).collect());
        }

        let ncols = headers
            .len()
            .max(rows.iter().map(|r| r.len()).max().unwrap_or(0));
        let mut col_widths = vec![MIN_COL_WIDTH; ncols];
        for (i, h) in headers.iter().enumerate() {
            col_widths[i] = col_widths[i].max(h.width().min(MAX_COL_WIDTH));
        }
        for row in &rows {
            for (i, cell) in row.iter().enumerate() {
                if i < col_widths.len() {
                    col_widths[i] = col_widths[i].max(cell.width().min(MAX_COL_WIDTH));
                }
            }
        }

        Ok(Self {
            path,
            kind: ViewKind::Csv,
            lines: Vec::new(),
            headers,
            rows,
            col_widths,
            scroll: 0,
            col_scroll: 0,
            cursor: 0,
            status: "↑↓ rows · ←→ cols · c csv · m markdown · y/Y row (csv/md) · Esc back"
                .into(),
        })
    }

    pub fn title(&self) -> String {
        let name = self
            .path
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("output");
        match self.kind {
            ViewKind::Text => format!(" text · {name} "),
            ViewKind::Csv => format!(" csv · {name} "),
        }
    }

    pub fn content_len(&self) -> usize {
        match self.kind {
            ViewKind::Text => self.lines.len(),
            ViewKind::Csv => self.rows.len(),
        }
    }

    pub fn move_up(&mut self) {
        if self.content_len() == 0 {
            return;
        }
        self.cursor = self.cursor.saturating_sub(1);
        if self.cursor < self.scroll {
            self.scroll = self.cursor;
        }
    }

    pub fn move_down(&mut self, visible: usize) {
        let n = self.content_len();
        if n == 0 {
            return;
        }
        self.cursor = (self.cursor + 1).min(n - 1);
        let bottom = self.scroll.saturating_add(visible.saturating_sub(1));
        if self.cursor > bottom {
            self.scroll = self.cursor.saturating_sub(visible.saturating_sub(1));
        }
    }

    pub fn page_up(&mut self, visible: usize) {
        let step = visible.max(1);
        self.cursor = self.cursor.saturating_sub(step);
        self.scroll = self.scroll.saturating_sub(step);
        if self.cursor < self.scroll {
            self.scroll = self.cursor;
        }
    }

    pub fn page_down(&mut self, visible: usize) {
        let n = self.content_len();
        if n == 0 {
            return;
        }
        let step = visible.max(1);
        self.cursor = (self.cursor + step).min(n - 1);
        let bottom = self.scroll.saturating_add(visible.saturating_sub(1));
        if self.cursor > bottom {
            self.scroll = self.cursor.saturating_sub(visible.saturating_sub(1));
        }
    }

    pub fn move_left(&mut self) {
        self.col_scroll = self.col_scroll.saturating_sub(1);
    }

    pub fn move_right(&mut self) {
        let max = self.col_widths.len().saturating_sub(1);
        if self.col_scroll < max {
            self.col_scroll += 1;
        }
    }

    pub fn ensure_visible(&mut self, visible: usize) {
        if visible == 0 || self.content_len() == 0 {
            return;
        }
        if self.cursor < self.scroll {
            self.scroll = self.cursor;
        }
        let bottom = self.scroll.saturating_add(visible.saturating_sub(1));
        if self.cursor > bottom {
            self.scroll = self.cursor.saturating_sub(visible.saturating_sub(1));
        }
    }

    /// Full document text suitable for clipboard.
    pub fn copy_all_text(&self) -> String {
        match self.kind {
            ViewKind::Text => self.lines.join("\n"),
            ViewKind::Csv => {
                let mut out = String::new();
                if !self.headers.is_empty() {
                    out.push_str(&self.headers.join(","));
                    out.push('\n');
                }
                for row in &self.rows {
                    out.push_str(&csv_escape_row(row));
                    out.push('\n');
                }
                out
            }
        }
    }

    /// Current line / row for clipboard.
    pub fn copy_selection_text(&self) -> String {
        match self.kind {
            ViewKind::Text => self
                .lines
                .get(self.cursor)
                .cloned()
                .unwrap_or_default(),
            ViewKind::Csv => {
                if let Some(row) = self.rows.get(self.cursor) {
                    csv_escape_row(row)
                } else {
                    String::new()
                }
            }
        }
    }

    /// Full CSV rendered as a GitHub-flavored markdown table.
    pub fn copy_all_markdown(&self) -> String {
        match self.kind {
            ViewKind::Text => self.lines.join("\n"),
            ViewKind::Csv => rows_to_markdown(&self.headers, &self.rows),
        }
    }

    /// Header + current CSV row as a tiny markdown table (or current text line).
    pub fn copy_selection_markdown(&self) -> String {
        match self.kind {
            ViewKind::Text => self.copy_selection_text(),
            ViewKind::Csv => {
                let row = self
                    .rows
                    .get(self.cursor)
                    .cloned()
                    .unwrap_or_default();
                rows_to_markdown(&self.headers, &[row])
            }
        }
    }

    pub fn set_copied_status(&mut self, what: &str) {
        self.status = format!("Copied {what} to clipboard · Esc back");
    }
}

fn csv_escape_row(row: &[String]) -> String {
    row.iter()
        .map(|cell| {
            if cell.contains(',') || cell.contains('"') || cell.contains('\n') {
                format!("\"{}\"", cell.replace('"', "\"\""))
            } else {
                cell.clone()
            }
        })
        .collect::<Vec<_>>()
        .join(",")
}

fn md_escape_cell(cell: &str) -> String {
    cell.replace('|', "\\|")
        .replace('\n', "<br>")
        .replace('\r', "")
}

fn markdown_row(cells: &[String], ncols: usize) -> String {
    let mut parts = Vec::with_capacity(ncols);
    for i in 0..ncols {
        let raw = cells.get(i).map(String::as_str).unwrap_or("");
        parts.push(md_escape_cell(raw));
    }
    format!("| {} |", parts.join(" | "))
}

fn rows_to_markdown(headers: &[String], rows: &[Vec<String>]) -> String {
    let ncols = headers
        .len()
        .max(rows.iter().map(|r| r.len()).max().unwrap_or(0))
        .max(1);

    let header_cells: Vec<String> = if headers.is_empty() {
        (0..ncols).map(|i| format!("col{}", i + 1)).collect()
    } else {
        let mut h = headers.to_vec();
        while h.len() < ncols {
            h.push(format!("col{}", h.len() + 1));
        }
        h
    };

    let mut out = String::new();
    out.push_str(&markdown_row(&header_cells, ncols));
    out.push('\n');
    out.push('|');
    for _ in 0..ncols {
        out.push_str(" --- |");
    }
    out.push('\n');
    for row in rows {
        out.push_str(&markdown_row(row, ncols));
        out.push('\n');
    }
    out
}

/// Copy text to the system clipboard.
pub fn copy_to_clipboard(text: &str) -> Result<()> {
    crate::clipboard::copy_text(text)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn markdown_table_escapes_pipes_and_pads() {
        let headers = vec!["a".into(), "b|c".into()];
        let rows = vec![vec!["1".into(), "x\ny".into()], vec!["2".into()]];
        let md = rows_to_markdown(&headers, &rows);
        assert!(md.contains("| a | b\\|c |"));
        assert!(md.contains("| --- | --- |"));
        assert!(md.contains("| 1 | x<br>y |"));
        assert!(md.contains("| 2 |  |"));
    }
}
