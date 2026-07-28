//! World map visualization: rotating 3D ASCII globe and static 2D equirectangular map.
//!
//! Earth bitmap and orthographic projection adapted from
//! [SecKC-MHN-Globe](https://github.com/n0xa/SecKC-MHN-Globe) (BSD-2-Clause).

mod earth;
mod extract;
mod flat;
mod geocode;
mod globe;

pub use earth::{sample_earth_at, EARTH_HEIGHT, EARTH_WIDTH};
pub use extract::{extract_ips_from_path, resolve_last_investigation_path};
pub use flat::render_flat;
pub use geocode::{geocode_ips, GeoPoint, GeocodeEvent, DEFAULT_GEOCODE_BASE};
pub use globe::render_globe;

use std::path::PathBuf;
use std::time::Instant;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

/// Display mode for the world map workspace.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum MapMode {
    #[default]
    Globe,
    Flat,
}

impl MapMode {
    pub fn label(self) -> &'static str {
        match self {
            Self::Globe => "3D globe",
            Self::Flat => "2D map",
        }
    }

    pub fn toggle(self) -> Self {
        match self {
            Self::Globe => Self::Flat,
            Self::Flat => Self::Globe,
        }
    }
}

/// Where the map should load IPs from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MapSource {
    LastInvestigation,
    InputFile,
    OutputFile,
}

impl MapSource {
    pub fn label(self) -> &'static str {
        match self {
            Self::LastInvestigation => "Last investigation",
            Self::InputFile => "From input file",
            Self::OutputFile => "From output file",
        }
    }

    pub fn all() -> &'static [MapSource] {
        &[
            Self::LastInvestigation,
            Self::InputFile,
            Self::OutputFile,
        ]
    }
}

/// Kind of cell in a rendered map frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MapCell {
    Empty,
    Ocean,
    Land,
    Coast,
    Marker,
}

/// Active world-map session state.
pub struct MapSession {
    pub mode: MapMode,
    pub source_label: String,
    pub path: Option<PathBuf>,
    pub points: Vec<GeoPoint>,
    pub total_ips: usize,
    pub located: usize,
    pub failed: usize,
    pub list_scroll: usize,
    pub started: Instant,
    pub rotation_period_secs: f64,
    pub aspect_ratio: f64,
    pub loading: bool,
    pub error: Option<String>,
    pub(crate) geocode_rx: Option<mpsc::UnboundedReceiver<GeocodeEvent>>,
    pub(crate) geocode_handle: Option<JoinHandle<()>>,
}

impl Default for MapSession {
    fn default() -> Self {
        Self {
            mode: MapMode::Globe,
            source_label: String::new(),
            path: None,
            points: Vec::new(),
            total_ips: 0,
            located: 0,
            failed: 0,
            list_scroll: 0,
            started: Instant::now(),
            rotation_period_secs: 30.0,
            aspect_ratio: 2.0,
            loading: false,
            error: None,
            geocode_rx: None,
            geocode_handle: None,
        }
    }
}

impl MapSession {
    pub fn rotation_radians(&self) -> f64 {
        let elapsed = self.started.elapsed().as_secs_f64();
        (elapsed / self.rotation_period_secs) * std::f64::consts::TAU
    }

    pub fn located_points(&self) -> Vec<&GeoPoint> {
        self.points.iter().filter(|p| p.valid).collect()
    }

    pub fn progress_label(&self) -> String {
        if self.total_ips == 0 {
            return "no IPs".into();
        }
        format!(
            "{}/{} located · {} failed",
            self.located, self.total_ips, self.failed
        )
    }

    pub fn poll_geocode(&mut self) {
        let mut done = false;
        if let Some(rx) = self.geocode_rx.as_mut() {
            while let Ok(event) = rx.try_recv() {
                match event {
                    GeocodeEvent::Point(point) => {
                        if point.valid {
                            self.located += 1;
                        } else {
                            self.failed += 1;
                        }
                        if let Some(existing) =
                            self.points.iter_mut().find(|p| p.ip == point.ip)
                        {
                            *existing = point;
                        } else {
                            self.points.push(point);
                        }
                    }
                    GeocodeEvent::Finished => {
                        self.loading = false;
                        done = true;
                    }
                    GeocodeEvent::Failed(err) => {
                        self.loading = false;
                        self.error = Some(err);
                        done = true;
                    }
                }
            }
        }
        if done {
            self.geocode_rx = None;
        }
    }

    pub fn abort_geocode(&mut self) {
        if let Some(handle) = self.geocode_handle.take() {
            handle.abort();
        }
        self.geocode_rx = None;
        self.loading = false;
    }
}
