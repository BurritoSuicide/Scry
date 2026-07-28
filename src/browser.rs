//! Ranger-style directory browser with indicator-file auto-detection.

use crate::indicator::{classify_line, IndicatorType};
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone)]
pub struct BrowserEntry {
    pub name: String,
    pub path: PathBuf,
    pub is_dir: bool,
    /// How many sample lines looked like known OSINT indicators (None = not scanned / N/A).
    pub indicator_hits: Option<usize>,
    pub sample_lines: usize,
}

impl BrowserEntry {
    pub fn looks_like_indicators(&self) -> bool {
        self.indicator_hits.unwrap_or(0) > 0
    }

    pub fn label(&self) -> String {
        if self.is_dir {
            format!("{}/", self.name)
        } else if let Some(hits) = self.indicator_hits {
            if hits > 0 {
                format!("{}  ·  {} indicators", self.name, hits)
            } else {
                self.name.clone()
            }
        } else {
            self.name.clone()
        }
    }
}

#[derive(Debug, Clone)]
pub struct FileBrowser {
    pub cwd: PathBuf,
    pub entries: Vec<BrowserEntry>,
    pub selected: usize,
}

impl FileBrowser {
    pub fn new(start: impl Into<PathBuf>) -> Self {
        let cwd = start.into();
        let mut browser = Self {
            cwd,
            entries: Vec::new(),
            selected: 0,
        };
        browser.refresh();
        browser
    }

    pub fn from_cwd() -> Self {
        let start = std::env::current_dir().unwrap_or_else(|_| {
            dirs::home_dir().unwrap_or_else(|| PathBuf::from("/"))
        });
        Self::new(start)
    }

    pub fn refresh(&mut self) {
        let previous = self
            .entries
            .get(self.selected)
            .map(|e| e.name.clone());

        self.entries = list_entries(&self.cwd);
        self.selected = previous
            .and_then(|name| self.entries.iter().position(|e| e.name == name))
            .unwrap_or(0)
            .min(self.entries.len().saturating_sub(1));
    }

    pub fn selected_entry(&self) -> Option<&BrowserEntry> {
        self.entries.get(self.selected)
    }

    pub fn move_up(&mut self) {
        if self.entries.is_empty() {
            return;
        }
        self.selected = self
            .selected
            .checked_sub(1)
            .unwrap_or(self.entries.len() - 1);
    }

    pub fn move_down(&mut self) {
        if self.entries.is_empty() {
            return;
        }
        self.selected = (self.selected + 1) % self.entries.len();
    }

    /// Enter directory (ranger: Right / Enter on dir).
    pub fn enter(&mut self) -> bool {
        let Some(entry) = self.selected_entry() else {
            return false;
        };
        if !entry.is_dir {
            return false;
        }
        self.cwd = entry.path.clone();
        self.selected = 0;
        self.refresh();
        true
    }

    /// Parent directory (ranger: Left).
    pub fn leave(&mut self) -> bool {
        if let Some(parent) = self.cwd.parent() {
            if parent.as_os_str().is_empty() {
                return false;
            }
            let came_from = self
                .cwd
                .file_name()
                .and_then(|s| s.to_str())
                .map(str::to_string);
            self.cwd = parent.to_path_buf();
            self.refresh();
            if let Some(name) = came_from {
                if let Some(idx) = self.entries.iter().position(|e| e.name == name) {
                    self.selected = idx;
                }
            }
            true
        } else {
            false
        }
    }

    /// Auto-jump to the first file that looks like an indicator list.
    pub fn select_best_indicator_file(&mut self) {
        if let Some(idx) = self
            .entries
            .iter()
            .position(|e| !e.is_dir && e.looks_like_indicators())
        {
            self.selected = idx;
        }
    }

    pub fn indicator_file_count(&self) -> usize {
        self.entries
            .iter()
            .filter(|e| !e.is_dir && e.looks_like_indicators())
            .count()
    }
}

fn list_entries(dir: &Path) -> Vec<BrowserEntry> {
    let mut entries = Vec::new();

    // Virtual parent entry when not at filesystem root.
    if dir.parent().is_some_and(|p| !p.as_os_str().is_empty())
        || dir.parent().is_some()
    {
        if let Some(parent) = dir.parent() {
            entries.push(BrowserEntry {
                name: "..".into(),
                path: parent.to_path_buf(),
                is_dir: true,
                indicator_hits: None,
                sample_lines: 0,
            });
        }
    }

    let Ok(read) = fs::read_dir(dir) else {
        return entries;
    };

    let mut dirs = Vec::new();
    let mut indicator_files = Vec::new();
    let mut other_files = Vec::new();

    for item in read.flatten() {
        let path = item.path();
        let name = item.file_name().to_string_lossy().to_string();
        if name.starts_with('.') {
            continue;
        }
        let is_dir = path.is_dir();
        if is_dir {
            dirs.push(BrowserEntry {
                name,
                path,
                is_dir: true,
                indicator_hits: None,
                sample_lines: 0,
            });
        } else if is_candidate_text(&path) {
            let (hits, samples) = scan_for_indicators(&path);
            let entry = BrowserEntry {
                name,
                path,
                is_dir: false,
                indicator_hits: Some(hits),
                sample_lines: samples,
            };
            if hits > 0 {
                indicator_files.push(entry);
            } else {
                other_files.push(entry);
            }
        }
    }

    dirs.sort_by(|a, b| a.name.to_lowercase().cmp(&b.name.to_lowercase()));
    indicator_files.sort_by(|a, b| {
        b.indicator_hits
            .cmp(&a.indicator_hits)
            .then_with(|| a.name.to_lowercase().cmp(&b.name.to_lowercase()))
    });
    other_files.sort_by(|a, b| a.name.to_lowercase().cmp(&b.name.to_lowercase()));

    // Indicator files float above other files; dirs stay on top after "..".
    entries.extend(dirs);
    entries.extend(indicator_files);
    entries.extend(other_files);
    entries
}

fn is_candidate_text(path: &Path) -> bool {
    let Some(name) = path.file_name().and_then(|s| s.to_str()) else {
        return false;
    };
    let lower = name.to_lowercase();
    if lower.ends_with(".txt")
        || lower.ends_with(".csv")
        || lower.ends_with(".list")
        || lower.ends_with(".ioc")
        || lower.ends_with(".indicators")
    {
        return true;
    }
    // Extensionless small-ish files are worth a peek.
    path.extension().is_none()
}

fn scan_for_indicators(path: &Path) -> (usize, usize) {
    let Ok(mut file) = fs::File::open(path) else {
        return (0, 0);
    };
    // Cap read so browsing stays snappy.
    let mut buf = vec![0u8; 64 * 1024];
    let Ok(n) = file.read(&mut buf) else {
        return (0, 0);
    };
    let Ok(text) = std::str::from_utf8(&buf[..n]) else {
        return (0, 0);
    };

    let mut hits = 0usize;
    let mut samples = 0usize;
    for (i, line) in text.lines().enumerate() {
        if i >= 200 {
            break;
        }
        if line.trim().is_empty() {
            continue;
        }
        samples += 1;
        let kind = classify_line(line, i + 1).kind;
        if !matches!(kind, IndicatorType::Unknown) {
            hits += 1;
        }
    }
    (hits, samples)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn scores_indicator_file() {
        let dir = tempfile_dir();
        let path = dir.join("iocs.txt");
        let mut f = fs::File::create(&path).unwrap();
        writeln!(f, "8.8.8.8").unwrap();
        writeln!(f, "alice@example.com").unwrap();
        let (hits, samples) = scan_for_indicators(&path);
        assert_eq!(samples, 2);
        assert_eq!(hits, 2);
        let _ = fs::remove_dir_all(dir);
    }

    fn tempfile_dir() -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "scry-browser-test-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }
}
