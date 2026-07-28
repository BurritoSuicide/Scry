//! Simple multiline text editor for indicator input files.

use crate::error::Result;
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone)]
pub struct TextEditor {
    pub path: PathBuf,
    pub lines: Vec<String>,
    pub cursor_row: usize,
    pub cursor_col: usize,
    pub scroll: usize,
    pub dirty: bool,
    pub is_new: bool,
    pub status: String,
}

impl TextEditor {
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref().to_path_buf();
        let raw = fs::read_to_string(&path).unwrap_or_default();
        let mut lines: Vec<String> = raw.lines().map(str::to_string).collect();
        if lines.is_empty() {
            lines.push(String::new());
        }
        Ok(Self {
            path,
            lines,
            cursor_row: 0,
            cursor_col: 0,
            scroll: 0,
            dirty: false,
            is_new: false,
            status: "type · Enter newline · Ctrl+V paste · Ctrl+D delete line · Ctrl+S save · Esc back"
                .into(),
        })
    }

    pub fn create_new(path: impl AsRef<Path>) -> Self {
        let path = path.as_ref().to_path_buf();
        Self {
            path,
            lines: vec![String::new()],
            cursor_row: 0,
            cursor_col: 0,
            scroll: 0,
            dirty: true,
            is_new: true,
            status: "new file · type · Ctrl+S save · Esc back (asks to save if dirty)".into(),
        }
    }

    pub fn title(&self) -> String {
        let name = self
            .path
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("input");
        let dirty = if self.dirty { " ●" } else { "" };
        format!(" edit{dirty} · {name} ")
    }

    pub fn current_line(&self) -> &str {
        self.lines
            .get(self.cursor_row)
            .map(String::as_str)
            .unwrap_or("")
    }

    fn clamp_col(&mut self) {
        let len = self.current_line().chars().count();
        if self.cursor_col > len {
            self.cursor_col = len;
        }
    }

    pub fn ensure_visible(&mut self, visible: usize) {
        if visible == 0 {
            return;
        }
        if self.cursor_row < self.scroll {
            self.scroll = self.cursor_row;
        }
        let bottom = self.scroll.saturating_add(visible.saturating_sub(1));
        if self.cursor_row > bottom {
            self.scroll = self.cursor_row.saturating_sub(visible.saturating_sub(1));
        }
    }

    pub fn move_up(&mut self) {
        if self.cursor_row > 0 {
            self.cursor_row -= 1;
            self.clamp_col();
        }
    }

    pub fn move_down(&mut self) {
        if self.cursor_row + 1 < self.lines.len() {
            self.cursor_row += 1;
            self.clamp_col();
        }
    }

    pub fn move_left(&mut self) {
        if self.cursor_col > 0 {
            self.cursor_col -= 1;
        } else if self.cursor_row > 0 {
            self.cursor_row -= 1;
            self.cursor_col = self.current_line().chars().count();
        }
    }

    pub fn move_right(&mut self) {
        let len = self.current_line().chars().count();
        if self.cursor_col < len {
            self.cursor_col += 1;
        } else if self.cursor_row + 1 < self.lines.len() {
            self.cursor_row += 1;
            self.cursor_col = 0;
        }
    }

    pub fn insert_char(&mut self, c: char) {
        if c == '\n' || c == '\r' {
            self.insert_newline();
            return;
        }
        if c.is_control() {
            return;
        }
        let line = &mut self.lines[self.cursor_row];
        let byte_idx = line
            .char_indices()
            .nth(self.cursor_col)
            .map(|(i, _)| i)
            .unwrap_or(line.len());
        line.insert(byte_idx, c);
        self.cursor_col += 1;
        self.dirty = true;
    }

    pub fn insert_newline(&mut self) {
        let line = self.lines[self.cursor_row].clone();
        let byte_idx = line
            .char_indices()
            .nth(self.cursor_col)
            .map(|(i, _)| i)
            .unwrap_or(line.len());
        let (left, right) = line.split_at(byte_idx);
        self.lines[self.cursor_row] = left.to_string();
        self.lines.insert(self.cursor_row + 1, right.to_string());
        self.cursor_row += 1;
        self.cursor_col = 0;
        self.dirty = true;
    }

    pub fn backspace(&mut self) {
        if self.cursor_col > 0 {
            let line = &mut self.lines[self.cursor_row];
            let (byte_idx, _) = line
                .char_indices()
                .nth(self.cursor_col - 1)
                .unwrap_or((line.len(), '\0'));
            line.remove(byte_idx);
            self.cursor_col -= 1;
            self.dirty = true;
        } else if self.cursor_row > 0 {
            let current = self.lines.remove(self.cursor_row);
            self.cursor_row -= 1;
            self.cursor_col = self.lines[self.cursor_row].chars().count();
            self.lines[self.cursor_row].push_str(&current);
            self.dirty = true;
        }
    }

    pub fn delete_forward(&mut self) {
        let len = self.current_line().chars().count();
        if self.cursor_col < len {
            let line = &mut self.lines[self.cursor_row];
            let (byte_idx, _) = line
                .char_indices()
                .nth(self.cursor_col)
                .unwrap_or((line.len(), '\0'));
            line.remove(byte_idx);
            self.dirty = true;
        } else if self.cursor_row + 1 < self.lines.len() {
            let next = self.lines.remove(self.cursor_row + 1);
            self.lines[self.cursor_row].push_str(&next);
            self.dirty = true;
        }
    }

    /// Delete the entire current line (`d` when not typing mid-line preference — always ok).
    pub fn delete_line(&mut self) {
        if self.lines.len() == 1 {
            self.lines[0].clear();
            self.cursor_col = 0;
        } else {
            self.lines.remove(self.cursor_row);
            if self.cursor_row >= self.lines.len() {
                self.cursor_row = self.lines.len() - 1;
            }
            self.clamp_col();
        }
        self.dirty = true;
        self.status = "Deleted line · Ctrl+S save · Esc back".into();
    }

    pub fn paste(&mut self, text: &str) {
        if text.is_empty() {
            return;
        }
        let normalized = text.replace("\r\n", "\n").replace('\r', "\n");
        let parts: Vec<&str> = normalized.split('\n').collect();
        if parts.is_empty() {
            return;
        }

        let line = self.lines[self.cursor_row].clone();
        let byte_idx = line
            .char_indices()
            .nth(self.cursor_col)
            .map(|(i, _)| i)
            .unwrap_or(line.len());
        let (left, right) = line.split_at(byte_idx);

        if parts.len() == 1 {
            let mut merged = String::new();
            merged.push_str(left);
            merged.push_str(parts[0]);
            merged.push_str(right);
            self.cursor_col = left.chars().count() + parts[0].chars().count();
            self.lines[self.cursor_row] = merged;
        } else {
            self.lines[self.cursor_row] = format!("{}{}", left, parts[0]);
            for (i, part) in parts.iter().enumerate().skip(1) {
                if i + 1 == parts.len() {
                    let last = format!("{}{}", part, right);
                    self.lines.insert(self.cursor_row + i, last);
                    self.cursor_row += i;
                    self.cursor_col = part.chars().count();
                } else {
                    self.lines.insert(self.cursor_row + i, (*part).to_string());
                }
            }
        }
        self.dirty = true;
        self.status = format!("Pasted {} char(s) · Ctrl+S save · Esc back", text.chars().count());
    }

    pub fn paste_from_clipboard(&mut self) -> Result<()> {
        let text = crate::clipboard::paste_text()?;
        self.paste(&text);
        Ok(())
    }

    pub fn save(&mut self) -> Result<()> {
        if let Some(parent) = self.path.parent() {
            fs::create_dir_all(parent)?;
        }
        let mut body = self.lines.join("\n");
        if !body.ends_with('\n') {
            body.push('\n');
        }
        fs::write(&self.path, body)?;
        self.dirty = false;
        self.is_new = false;
        self.status = format!("Saved {}", self.path.display());
        Ok(())
    }
}
