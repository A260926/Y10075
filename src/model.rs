//! Domain value objects shared by storage, workers and HTTP layers.

use serde::{Deserialize, Serialize};

/// Injectable clock. Production uses wall-clock millis; tests drive a
/// `FakeClock` so backoff, lease expiry and key validity windows are fully
/// deterministic.
pub trait Clock: Send + Sync {
    fn now_ms(&self) -> i64;
}

pub struct SystemClock;

impl Clock for SystemClock {
    fn now_ms(&self) -> i64 {
        use std::time::{SystemTime, UNIX_EPOCH};
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as i64)
            .unwrap_or(0)
    }
}

/// Mutable virtual clock used in tests.
pub struct FakeClock {
    inner: std::sync::Mutex<i64>,
}

impl FakeClock {
    pub fn new(start_ms: i64) -> Self {
        Self {
            inner: std::sync::Mutex::new(start_ms),
        }
    }
    pub fn advance(&self, ms: i64) {
        *self.inner.lock().unwrap() += ms;
    }
    pub fn set(&self, ms: i64) {
        *self.inner.lock().unwrap() = ms;
    }
}

impl Clock for FakeClock {
    fn now_ms(&self) -> i64 {
        *self.inner.lock().unwrap()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReceiverMode {
    /// Every request returns 200.
    Success,
    /// Accept the connection, never answer (client times out).
    Timeout,
    /// First two requests get 503, subsequent requests get 200.
    FailTwice,
    /// Always return a fixed status (409 by default).
    FixedStatus,
    /// Always return 429 with a Retry-After delay in seconds.
    RateLimited,
}

impl ReceiverMode {
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "success" => Some(Self::Success),
            "timeout" => Some(Self::Timeout),
            "fail_twice" => Some(Self::FailTwice),
            "fixed_status" => Some(Self::FixedStatus),
            "rate_limited" => Some(Self::RateLimited),
            _ => None,
        }
    }
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Success => "success",
            Self::Timeout => "timeout",
            Self::FailTwice => "fail_twice",
            Self::FixedStatus => "fixed_status",
            Self::RateLimited => "rate_limited",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RetryPolicy {
    /// Maximum number of attempts (1 = no retries).
    pub max_attempts: i64,
    /// Base backoff in milliseconds.
    pub base_delay_ms: i64,
    /// Maximum backoff in milliseconds.
    pub max_delay_ms: i64,
    /// Multiplier applied between attempts.
    pub multiplier: f64,
}

impl Default for RetryPolicy {
    fn default() -> Self {
        Self {
            max_attempts: 5,
            base_delay_ms: 500,
            max_delay_ms: 30_000,
            multiplier: 2.0,
        }
    }
}

impl RetryPolicy {
    /// Delay before attempt number `attempt_no` (1-based: first attempt is
    /// immediate).
    pub fn delay_for_attempt(&self, attempt_no: i64) -> i64 {
        if attempt_no <= 1 {
            return 0;
        }
        let steps = (attempt_no - 1) as i32;
        let raw = (self.base_delay_ms as f64 * self.multiplier.powi(steps - 1)) as i64;
        raw.clamp(0, self.max_delay_ms)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeliveryStatus {
    Queued,
    Sending,
    Succeeded,
    Failed,
}

impl DeliveryStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Queued => "queued",
            Self::Sending => "sending",
            Self::Succeeded => "succeeded",
            Self::Failed => "failed",
        }
    }
    pub fn parse(s: &str) -> Self {
        match s {
            "sending" => Self::Sending,
            "succeeded" => Self::Succeeded,
            "failed" => Self::Failed,
            _ => Self::Queued,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttemptState {
    /// Claimed by a worker (lease held), request in flight or process died
    /// before any receipt was recorded.
    Leased,
    /// Response received and receipt persisted; delivery-level state not yet
    /// finalized (crash window).
    Responded,
    /// Delivery-level outcome was written and this attempt is fully settled.
    Done,
}

impl AttemptState {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Leased => "leased",
            Self::Responded => "responded",
            Self::Done => "done",
        }
    }
}

/// Outcome recorded on an attempt receipt / final row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AttemptOutcome {
    /// 2xx; carries the actual status code.
    Success,
    HttpStatus(u16),
    Timeout,
    Error(String),
    /// Lease expired while the request was in flight; result is unknown.
    LeaseLost,
}

impl AttemptOutcome {
    pub fn kind(&self) -> &'static str {
        match self {
            Self::Success => "success",
            Self::HttpStatus(_) => "http_status",
            Self::Timeout => "timeout",
            Self::Error(_) => "error",
            Self::LeaseLost => "lease_lost",
        }
    }
    pub fn http_status(&self) -> Option<i64> {
        match self {
            Self::HttpStatus(s) => Some(*s as i64),
            _ => None,
        }
    }
    pub fn detail(&self) -> String {
        match self {
            Self::Success => "2xx".to_string(),
            Self::HttpStatus(s) => s.to_string(),
            Self::Timeout => "client timeout".to_string(),
            Self::Error(e) => e.clone(),
            Self::LeaseLost => "lease expired before response was recorded".to_string(),
        }
    }
}

/// Whether a response / transport result warrants another attempt.
pub fn is_retryable(outcome: &AttemptOutcome) -> bool {
    match outcome {
        AttemptOutcome::Success => false,
        AttemptOutcome::HttpStatus(s) => {
            // Retry on 429 and 5xx; anything else (4xx) is terminal.
            *s == 429 || (500..600).contains(s)
        }
        AttemptOutcome::Timeout | AttemptOutcome::Error(_) | AttemptOutcome::LeaseLost => true,
    }
}
