//! Token-bucket rate limiting plus personal / enterprise tier presets.

use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use std::time::{Duration, Instant};

/// Which published API quota tier Scry should pace against.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum UsageProfile {
    /// Free / community / self-signed keys (safe defaults).
    #[default]
    Personal,
    /// Paid / premium / enterprise contract quotas.
    Enterprise,
}

impl UsageProfile {
    pub fn label(self) -> &'static str {
        match self {
            Self::Personal => "Personal (free / community)",
            Self::Enterprise => "Enterprise (paid / premium)",
        }
    }

    pub fn short(self) -> &'static str {
        match self {
            Self::Personal => "personal",
            Self::Enterprise => "enterprise",
        }
    }

    pub fn description(self) -> &'static str {
        match self {
            Self::Personal => {
                "Pace to published free-tier limits so you do not burn daily/weekly quotas."
            }
            Self::Enterprise => {
                "Use paid-tier pacing (or effectively unthrottled when the vendor publishes no cap)."
            }
        }
    }

    pub fn all() -> &'static [UsageProfile] {
        &[Self::Personal, Self::Enterprise]
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RateLimitSpec {
    /// Maximum requests allowed in a 60-second window.
    pub requests_per_minute: u32,
    /// Optional ceiling for a rolling 1-hour window.
    pub requests_per_hour: Option<u32>,
    /// Soft daily ceiling (informational + enforced when set).
    pub requests_per_day: Option<u32>,
    /// When true, client-side limiting is skipped (still respects HTTP 429 retries).
    pub unthrottled: bool,
}

impl RateLimitSpec {
    pub const fn per_minute(requests_per_minute: u32) -> Self {
        Self {
            requests_per_minute,
            requests_per_hour: None,
            requests_per_day: None,
            unthrottled: false,
        }
    }

    pub const fn unthrottled() -> Self {
        Self {
            requests_per_minute: 10_000,
            requests_per_hour: None,
            requests_per_day: None,
            unthrottled: true,
        }
    }

    pub fn display(&self) -> String {
        if self.unthrottled {
            return "unthrottled (client)".into();
        }
        let mut s = format!("{} /min", self.requests_per_minute);
        if let Some(h) = self.requests_per_hour {
            s.push_str(&format!(" · {h} /hour"));
        }
        if let Some(d) = self.requests_per_day {
            s.push_str(&format!(" · {d} /day"));
        }
        s
    }

    // --- VirusTotal ---
    // Personal/public: 4/min, 500/day. Premium/Enterprise: contract SLA (no public cap).
    pub const fn virustotal(profile: UsageProfile) -> Self {
        match profile {
            UsageProfile::Personal => Self {
                requests_per_minute: 4,
                requests_per_hour: None,
                requests_per_day: Some(500),
                unthrottled: false,
            },
            UsageProfile::Enterprise => Self::unthrottled(),
        }
    }

    // --- abuse.ch ---
    // Community Auth-Key: fair-use (no hard published numbers). Commercial API exists for orgs.
    pub const fn abusech(profile: UsageProfile) -> Self {
        match profile {
            UsageProfile::Personal => Self {
                requests_per_minute: 30,
                requests_per_hour: None,
                requests_per_day: None,
                unthrottled: false,
            },
            UsageProfile::Enterprise => Self {
                requests_per_minute: 120,
                requests_per_hour: None,
                requests_per_day: None,
                unthrottled: false,
            },
        }
    }

    // --- Hybrid Analysis ---
    // Restricted self-signed: 5/min, 200/hour. Full/enterprise keys: higher (no public fixed cap).
    pub const fn hybrid_analysis(profile: UsageProfile) -> Self {
        match profile {
            UsageProfile::Personal => Self {
                requests_per_minute: 5,
                requests_per_hour: Some(200),
                requests_per_day: None,
                unthrottled: false,
            },
            UsageProfile::Enterprise => Self {
                requests_per_minute: 60,
                requests_per_hour: Some(2_000),
                requests_per_day: None,
                unthrottled: false,
            },
        }
    }

    // --- AbuseIPDB ---
    // Standard/free check: 1,000/day. Premium subscription check: 50,000/day.
    pub const fn abuseipdb(profile: UsageProfile) -> Self {
        match profile {
            UsageProfile::Personal => Self {
                requests_per_minute: 45,
                requests_per_hour: None,
                requests_per_day: Some(1_000),
                unthrottled: false,
            },
            UsageProfile::Enterprise => Self {
                requests_per_minute: 120,
                requests_per_hour: None,
                requests_per_day: Some(50_000),
                unthrottled: false,
            },
        }
    }

    // --- GreyNoise ---
    // Community: ~50/week (≈7/day share). Paid plans: generally no search metering (2025 packaging).
    pub const fn greynoise(profile: UsageProfile) -> Self {
        match profile {
            UsageProfile::Personal => Self {
                requests_per_minute: 10,
                requests_per_hour: None,
                requests_per_day: Some(7),
                unthrottled: false,
            },
            UsageProfile::Enterprise => Self::unthrottled(),
        }
    }

    // --- AlienVault OTX ---
    // Authenticated: ~10,000/hour. Higher volume with advance notice to LevelBlue.
    pub const fn alienvault_otx(profile: UsageProfile) -> Self {
        match profile {
            UsageProfile::Personal => Self {
                requests_per_minute: 30,
                requests_per_hour: Some(10_000),
                requests_per_day: None,
                unthrottled: false,
            },
            UsageProfile::Enterprise => Self {
                requests_per_minute: 300,
                requests_per_hour: None,
                requests_per_day: None,
                unthrottled: false,
            },
        }
    }

    /// Look up built-in tier limits by vendor id.
    pub fn for_vendor(vendor_id: &str, profile: UsageProfile) -> Option<Self> {
        Some(match vendor_id {
            "virustotal" => Self::virustotal(profile),
            "abusech" => Self::abusech(profile),
            "hybrid_analysis" => Self::hybrid_analysis(profile),
            "abuseipdb" => Self::abuseipdb(profile),
            "greynoise" => Self::greynoise(profile),
            "alienvault_otx" => Self::alienvault_otx(profile),
            _ => return None,
        })
    }
}

/// Manual override stored in config (Options menu). Replaces the profile default when set.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RateLimitOverride {
    pub requests_per_minute: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub requests_per_hour: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub requests_per_day: Option<u32>,
    #[serde(default)]
    pub unthrottled: bool,
}

impl RateLimitOverride {
    pub fn from_spec(spec: RateLimitSpec) -> Self {
        Self {
            requests_per_minute: spec.requests_per_minute,
            requests_per_hour: spec.requests_per_hour,
            requests_per_day: spec.requests_per_day,
            unthrottled: spec.unthrottled,
        }
    }

    pub fn to_spec(&self) -> RateLimitSpec {
        RateLimitSpec {
            requests_per_minute: self.requests_per_minute.max(1),
            requests_per_hour: self.requests_per_hour,
            requests_per_day: self.requests_per_day,
            unthrottled: self.unthrottled,
        }
    }
}

/// Resolve the effective limit for a vendor given profile + optional override.
pub fn effective_rate_limit(
    vendor_id: &str,
    profile: UsageProfile,
    override_: Option<&RateLimitOverride>,
) -> RateLimitSpec {
    if let Some(o) = override_ {
        return o.to_spec();
    }
    RateLimitSpec::for_vendor(vendor_id, profile).unwrap_or_else(|| RateLimitSpec::per_minute(30))
}

/// Sliding-window limiter that also tracks hourly/daily usage for soft quotas.
#[derive(Debug)]
pub struct RateLimiter {
    spec: RateLimitSpec,
    minute_hits: VecDeque<Instant>,
    hour_hits: VecDeque<Instant>,
    day_hits: VecDeque<Instant>,
}

impl RateLimiter {
    pub fn new(spec: RateLimitSpec) -> Self {
        Self {
            spec,
            minute_hits: VecDeque::new(),
            hour_hits: VecDeque::new(),
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

        let hour_ago = now - Duration::from_secs(60 * 60);
        while self.hour_hits.front().is_some_and(|t| *t < hour_ago) {
            self.hour_hits.pop_front();
        }

        let day_ago = now - Duration::from_secs(24 * 60 * 60);
        while self.day_hits.front().is_some_and(|t| *t < day_ago) {
            self.day_hits.pop_front();
        }
    }

    /// How long to wait before the next request is allowed (zero if ready).
    pub fn time_until_ready(&mut self) -> Duration {
        if self.spec.unthrottled {
            return Duration::ZERO;
        }

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

        if let Some(hour_cap) = self.spec.requests_per_hour {
            if self.hour_hits.len() as u32 >= hour_cap {
                if let Some(oldest) = self.hour_hits.front() {
                    let reset = *oldest + Duration::from_secs(60 * 60);
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
        if self.spec.unthrottled {
            return;
        }
        loop {
            let wait = self.time_until_ready();
            if wait.is_zero() {
                let now = Instant::now();
                self.minute_hits.push_back(now);
                self.hour_hits.push_back(now);
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
