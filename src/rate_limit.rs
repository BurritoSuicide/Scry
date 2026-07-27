//! Token-bucket style rate limiting for vendor APIs.

use std::collections::VecDeque;
use std::time::{Duration, Instant};

#[derive(Debug, Clone, Copy)]
pub struct RateLimitSpec {
    /// Maximum requests allowed in `per_minute` window.
    pub requests_per_minute: u32,
    /// Soft daily ceiling (informational + enforced when set).
    pub requests_per_day: Option<u32>,
}

impl RateLimitSpec {
    pub const fn per_minute(requests_per_minute: u32) -> Self {
        Self {
            requests_per_minute,
            requests_per_day: None,
        }
    }

    pub const fn public_vt() -> Self {
        // VirusTotal public API: 4 req/min, 500 req/day.
        Self {
            requests_per_minute: 4,
            requests_per_day: Some(500),
        }
    }
}

/// Sliding-window limiter that also tracks daily usage for soft quotas.
#[derive(Debug)]
pub struct RateLimiter {
    spec: RateLimitSpec,
    minute_hits: VecDeque<Instant>,
    day_hits: VecDeque<Instant>,
}

impl RateLimiter {
    pub fn new(spec: RateLimitSpec) -> Self {
        Self {
            spec,
            minute_hits: VecDeque::new(),
            day_hits: VecDeque::new(),
        }
    }

    pub fn spec(&self) -> RateLimitSpec {
        self.spec
    }

    fn prune(&mut self, now: Instant) {
        let minute_ago = now - Duration::from_secs(60);
        while self
            .minute_hits
            .front()
            .is_some_and(|t| *t < minute_ago)
        {
            self.minute_hits.pop_front();
        }

        let day_ago = now - Duration::from_secs(24 * 60 * 60);
        while self.day_hits.front().is_some_and(|t| *t < day_ago) {
            self.day_hits.pop_front();
        }
    }

    /// How long to wait before the next request is allowed (zero if ready).
    pub fn time_until_ready(&mut self) -> Duration {
        let now = Instant::now();
        self.prune(now);

        if let Some(day_cap) = self.spec.requests_per_day {
            if self.day_hits.len() as u32 >= day_cap {
                if let Some(oldest) = self.day_hits.front() {
                    let reset = *oldest + Duration::from_secs(24 * 60 * 60);
                    return reset.saturating_duration_since(now);
                }
            }
        }

        if self.minute_hits.len() as u32 >= self.spec.requests_per_minute {
            if let Some(oldest) = self.minute_hits.front() {
                let reset = *oldest + Duration::from_secs(60);
                return reset.saturating_duration_since(now);
            }
        }

        Duration::ZERO
    }

    /// Block (async) until a request slot is available, then record the hit.
    pub async fn acquire(&mut self) {
        loop {
            let wait = self.time_until_ready();
            if wait.is_zero() {
                let now = Instant::now();
                self.minute_hits.push_back(now);
                self.day_hits.push_back(now);
                return;
            }
            tokio::time::sleep(wait).await;
        }
    }

    pub fn requests_in_last_minute(&mut self) -> usize {
        self.prune(Instant::now());
        self.minute_hits.len()
    }

    pub fn requests_in_last_day(&mut self) -> usize {
        self.prune(Instant::now());
        self.day_hits.len()
    }
}
