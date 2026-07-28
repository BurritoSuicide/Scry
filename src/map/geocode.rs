//! IP geolocation via the public SecKC MHN geocode API (same as SecKC-MHN-Globe).

use serde::Deserialize;
use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use tokio::sync::{mpsc, Mutex};

pub const DEFAULT_GEOCODE_BASE: &str = "https://mhn.h-i-r.net/seckcapi";

const CACHE_CAP: usize = 512;
const CONCURRENCY: usize = 4;

#[derive(Debug, Clone)]
pub struct GeoPoint {
    pub ip: String,
    pub latitude: f64,
    pub longitude: f64,
    pub city: String,
    pub country: String,
    pub valid: bool,
}

impl GeoPoint {
    pub fn pending(ip: impl Into<String>) -> Self {
        Self {
            ip: ip.into(),
            latitude: 0.0,
            longitude: 0.0,
            city: String::new(),
            country: String::new(),
            valid: false,
        }
    }

    pub fn label(&self) -> String {
        if !self.valid {
            return format!("{}  ·  …", self.ip);
        }
        let place = match (self.city.is_empty(), self.country.is_empty()) {
            (false, false) => format!("{}, {}", self.city, self.country),
            (true, false) => self.country.clone(),
            (false, true) => self.city.clone(),
            (true, true) => "unknown".into(),
        };
        format!("{}  ·  {}", self.ip, place)
    }
}

#[derive(Debug)]
pub enum GeocodeEvent {
    Point(GeoPoint),
    Finished,
    Failed(String),
}

#[derive(Debug, Deserialize)]
struct GeocodeResponse {
    city: Option<NamedLocale>,
    country: Option<CountryLocale>,
    location: Option<LocationCoords>,
}

#[derive(Debug, Deserialize)]
struct NamedLocale {
    names: Option<HashMap<String, String>>,
}

#[derive(Debug, Deserialize)]
struct CountryLocale {
    #[serde(default)]
    iso_code: String,
    names: Option<HashMap<String, String>>,
}

#[derive(Debug, Deserialize)]
struct LocationCoords {
    latitude: Option<f64>,
    longitude: Option<f64>,
}

struct GeoCache {
    order: VecDeque<String>,
    map: HashMap<String, GeoPoint>,
}

impl GeoCache {
    fn new() -> Self {
        Self {
            order: VecDeque::new(),
            map: HashMap::new(),
        }
    }

    fn get(&mut self, ip: &str) -> Option<GeoPoint> {
        if let Some(p) = self.map.get(ip).cloned() {
            if let Some(pos) = self.order.iter().position(|x| x == ip) {
                self.order.remove(pos);
            }
            self.order.push_front(ip.to_string());
            Some(p)
        } else {
            None
        }
    }

    fn insert(&mut self, point: GeoPoint) {
        let ip = point.ip.clone();
        if self.map.contains_key(&ip) {
            if let Some(pos) = self.order.iter().position(|x| x == &ip) {
                self.order.remove(pos);
            }
        } else if self.order.len() >= CACHE_CAP {
            if let Some(old) = self.order.pop_back() {
                self.map.remove(&old);
            }
        }
        self.order.push_front(ip.clone());
        self.map.insert(ip, point);
    }
}

/// Lookup each IP concurrently and stream results on `tx`.
pub fn geocode_ips(
    ips: Vec<String>,
    base_url: String,
    tx: mpsc::UnboundedSender<GeocodeEvent>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        if ips.is_empty() {
            let _ = tx.send(GeocodeEvent::Finished);
            return;
        }

        let client = match reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(15))
            .build()
        {
            Ok(c) => c,
            Err(e) => {
                let _ = tx.send(GeocodeEvent::Failed(format!("HTTP client: {e}")));
                return;
            }
        };

        let cache = Arc::new(Mutex::new(GeoCache::new()));
        let base = base_url.trim_end_matches('/').to_string();
        let sem = Arc::new(tokio::sync::Semaphore::new(CONCURRENCY));
        let mut handles = Vec::with_capacity(ips.len());

        for ip in ips {
            let client = client.clone();
            let base = base.clone();
            let tx = tx.clone();
            let cache = cache.clone();
            let sem = sem.clone();
            handles.push(tokio::spawn(async move {
                let _permit = match sem.acquire().await {
                    Ok(p) => p,
                    Err(_) => return,
                };
                {
                    let mut guard = cache.lock().await;
                    if let Some(cached) = guard.get(&ip) {
                        let _ = tx.send(GeocodeEvent::Point(cached));
                        return;
                    }
                }
                let point = lookup_one(&client, &base, &ip).await;
                {
                    let mut guard = cache.lock().await;
                    guard.insert(point.clone());
                }
                let _ = tx.send(GeocodeEvent::Point(point));
            }));
        }

        for h in handles {
            let _ = h.await;
        }
        let _ = tx.send(GeocodeEvent::Finished);
    })
}

async fn lookup_one(client: &reqwest::Client, base: &str, ip: &str) -> GeoPoint {
    let url = format!("{base}/geocode/{ip}");
    let resp = match client.get(&url).send().await {
        Ok(r) => r,
        Err(_) => return GeoPoint::pending(ip),
    };
    if !resp.status().is_success() {
        return GeoPoint::pending(ip);
    }
    let body: GeocodeResponse = match resp.json().await {
        Ok(b) => b,
        Err(_) => return GeoPoint::pending(ip),
    };
    let lat = body.location.as_ref().and_then(|l| l.latitude);
    let lon = body.location.as_ref().and_then(|l| l.longitude);
    let (Some(latitude), Some(longitude)) = (lat, lon) else {
        return GeoPoint::pending(ip);
    };
    let city = body
        .city
        .and_then(|c| c.names)
        .and_then(|n| n.get("en").cloned())
        .unwrap_or_default();
    let country = body
        .country
        .map(|c| {
            c.names
                .and_then(|n| n.get("en").cloned())
                .filter(|s| !s.is_empty())
                .unwrap_or(c.iso_code)
        })
        .unwrap_or_default();

    GeoPoint {
        ip: ip.to_string(),
        latitude,
        longitude,
        city,
        country,
        valid: true,
    }
}
