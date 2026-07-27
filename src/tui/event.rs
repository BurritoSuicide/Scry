use crossterm::event::{self, Event as CEvent, KeyEvent};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

pub enum AppEvent {
    Tick,
    Key(KeyEvent),
}

pub struct EventSource {
    rx: mpsc::Receiver<AppEvent>,
}

impl EventSource {
    pub fn new(tick_rate: Duration) -> Self {
        let (tx, rx) = mpsc::channel();
        let tx_keys = tx.clone();

        thread::spawn(move || loop {
            if event::poll(Duration::from_millis(50)).unwrap_or(false) {
                if let Ok(CEvent::Key(key)) = event::read() {
                    if key.kind == event::KeyEventKind::Press {
                        let _ = tx_keys.send(AppEvent::Key(key));
                    }
                }
            }
        });

        thread::spawn(move || {
            let mut last = Instant::now();
            loop {
                let timeout = tick_rate.saturating_sub(last.elapsed());
                thread::sleep(timeout.max(Duration::from_millis(10)));
                if last.elapsed() >= tick_rate {
                    let _ = tx.send(AppEvent::Tick);
                    last = Instant::now();
                }
            }
        });

        Self { rx }
    }

    pub fn next(&self) -> anyhow::Result<AppEvent> {
        Ok(self.rx.recv()?)
    }
}
