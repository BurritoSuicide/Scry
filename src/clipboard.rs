//! Session-long system clipboard helper.
//!
//! On Linux (X11/Wayland), clipboard data is owned by the process that set it.
//! Dropping `arboard::Clipboard` immediately after `set_text` often makes the
//! copy vanish before anything can paste it. Keep one instance for the app life.

use crate::error::{ScryError, Result};
use std::sync::{Mutex, OnceLock};

fn clipboard_slot() -> &'static Mutex<Option<arboard::Clipboard>> {
    static SLOT: OnceLock<Mutex<Option<arboard::Clipboard>>> = OnceLock::new();
    SLOT.get_or_init(|| Mutex::new(None))
}

fn with_clipboard<F, T>(f: F) -> Result<T>
where
    F: FnOnce(&mut arboard::Clipboard) -> Result<T>,
{
    let slot = clipboard_slot();
    let mut guard = slot
        .lock()
        .map_err(|_| ScryError::msg("clipboard lock poisoned"))?;
    if guard.is_none() {
        let cb = arboard::Clipboard::new()
            .map_err(|e| ScryError::msg(format!("clipboard unavailable: {e}")))?;
        *guard = Some(cb);
    }
    let cb = guard
        .as_mut()
        .ok_or_else(|| ScryError::msg("clipboard not initialized"))?;
    f(cb)
}

/// Copy text to the system clipboard (and primary selection on Linux).
pub fn copy_text(text: &str) -> Result<()> {
    with_clipboard(|cb| {
        #[cfg(target_os = "linux")]
        {
            use arboard::{LinuxClipboardKind, SetExtLinux};
            cb.set()
                .clipboard(LinuxClipboardKind::Clipboard)
                .text(text.to_string())
                .map_err(|e| ScryError::msg(format!("clipboard write failed: {e}")))?;
            // Best-effort primary (middle-click) selection.
            let _ = cb
                .set()
                .clipboard(LinuxClipboardKind::Primary)
                .text(text.to_string());
        }
        #[cfg(not(target_os = "linux"))]
        {
            cb.set_text(text.to_string())
                .map_err(|e| ScryError::msg(format!("clipboard write failed: {e}")))?;
        }
        Ok(())
    })
}

/// Read text from the system clipboard.
pub fn paste_text() -> Result<String> {
    with_clipboard(|cb| {
        cb.get_text()
            .map_err(|e| ScryError::msg(format!("clipboard read failed: {e}")))
    })
}
