use std::collections::HashMap;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use parking_lot::Mutex;

pub trait RateLimiter: Send + Sync {
    fn try_acquire(&self, scope: &str, rpm: u32, concurrent: u32) -> Option<RateLimitPermit>;
}

pub trait RateLimitRelease: Send + Sync {
    fn release(&self, scope: &str);
}

pub struct RateLimitPermit {
    scope: String,
    limiter: Arc<dyn RateLimitRelease>,
    release_concurrent: bool,
}

impl RateLimitPermit {
    pub(crate) fn new(
        scope: String,
        limiter: Arc<dyn RateLimitRelease>,
        release_concurrent: bool,
    ) -> Self {
        Self {
            scope,
            limiter,
            release_concurrent,
        }
    }
}

impl Drop for RateLimitPermit {
    fn drop(&mut self) {
        if self.release_concurrent {
            self.limiter.release(&self.scope);
        }
    }
}

#[derive(Clone)]
pub struct InMemoryRateLimiter {
    state: Arc<Mutex<HashMap<String, RateState>>>,
    window_ms: i64,
}

#[derive(Clone, Debug)]
struct RateState {
    window_start: i64,
    count: u32,
    concurrent: u32,
}

impl InMemoryRateLimiter {
    pub fn new(window_seconds: u64) -> Self {
        Self {
            state: Arc::new(Mutex::new(HashMap::new())),
            window_ms: (window_seconds.max(1) as i64) * 1000,
        }
    }

    pub fn shared(window_seconds: u64) -> Arc<Self> {
        Arc::new(Self::new(window_seconds))
    }

    fn now_ms() -> i64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as i64
    }

    fn release(&self, scope: &str) {
        let mut state = self.state.lock();
        if let Some(entry) = state.get_mut(scope) {
            if entry.concurrent > 0 {
                entry.concurrent -= 1;
            }
        }
    }
}

impl RateLimitRelease for InMemoryRateLimiter {
    fn release(&self, scope: &str) {
        self.release(scope);
    }
}

impl RateLimiter for InMemoryRateLimiter {
    fn try_acquire(&self, scope: &str, rpm: u32, concurrent: u32) -> Option<RateLimitPermit> {
        let now = Self::now_ms();
        let mut state = self.state.lock();
        let entry = state.entry(scope.to_string()).or_insert_with(|| RateState {
            window_start: now,
            count: 0,
            concurrent: 0,
        });

        if now - entry.window_start >= self.window_ms {
            entry.window_start = now;
            entry.count = 0;
        }

        if rpm > 0 && entry.count >= rpm {
            return None;
        }
        if concurrent > 0 && entry.concurrent >= concurrent {
            return None;
        }

        if rpm > 0 {
            entry.count += 1;
        }
        if concurrent > 0 {
            entry.concurrent += 1;
        }

        Some(RateLimitPermit::new(
            scope.to_string(),
            Arc::new(self.clone()),
            concurrent > 0,
        ))
    }
}
