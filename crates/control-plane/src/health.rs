use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use parking_lot::Mutex;

#[derive(Clone, Debug)]
pub struct CircuitBreakerConfig {
    pub enabled: bool,
    pub failure_threshold: u32,
    pub open_duration_ms: u64,
    pub half_open_success_threshold: u32,
}

impl Default for CircuitBreakerConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            failure_threshold: 3,
            open_duration_ms: 30_000,
            half_open_success_threshold: 2,
        }
    }
}

#[derive(Clone, Debug)]
struct CircuitState {
    failures: u32,
    open_until: Option<Instant>,
    half_open_success: u32,
    half_open: bool,
}

impl CircuitState {
    fn new() -> Self {
        Self {
            failures: 0,
            open_until: None,
            half_open_success: 0,
            half_open: false,
        }
    }
}

pub trait HealthStore: Send + Sync {
    fn is_available(&self, id: &str) -> bool;
    fn record_success(&self, id: &str);
    fn record_failure(&self, id: &str);
}

#[derive(Clone)]
pub struct InMemoryHealthStore {
    config: CircuitBreakerConfig,
    states: Arc<Mutex<HashMap<String, CircuitState>>>,
}

impl InMemoryHealthStore {
    pub fn new(config: CircuitBreakerConfig) -> Self {
        Self {
            config,
            states: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub fn shared(config: CircuitBreakerConfig) -> Arc<Self> {
        Arc::new(Self::new(config))
    }
}

impl HealthStore for InMemoryHealthStore {
    fn is_available(&self, id: &str) -> bool {
        if !self.config.enabled {
            return true;
        }
        let mut states = self.states.lock();
        let state = states.entry(id.to_string()).or_insert_with(CircuitState::new);
        if let Some(until) = state.open_until {
            if Instant::now() < until {
                return false;
            }
            state.open_until = None;
            state.half_open = true;
            state.half_open_success = 0;
        }
        true
    }

    fn record_success(&self, id: &str) {
        if !self.config.enabled {
            return;
        }
        let mut states = self.states.lock();
        let state = states.entry(id.to_string()).or_insert_with(CircuitState::new);
        if state.half_open {
            state.half_open_success += 1;
            if state.half_open_success >= self.config.half_open_success_threshold {
                state.failures = 0;
                state.half_open = false;
                state.half_open_success = 0;
            }
            return;
        }
        state.failures = 0;
        state.open_until = None;
    }

    fn record_failure(&self, id: &str) {
        if !self.config.enabled {
            return;
        }
        let mut states = self.states.lock();
        let state = states.entry(id.to_string()).or_insert_with(CircuitState::new);
        if state.half_open {
            state.half_open = false;
            state.half_open_success = 0;
            state.open_until = Some(Instant::now() + Duration::from_millis(self.config.open_duration_ms));
            state.failures = 0;
            return;
        }
        state.failures += 1;
        if state.failures >= self.config.failure_threshold {
            state.open_until = Some(Instant::now() + Duration::from_millis(self.config.open_duration_ms));
            state.failures = 0;
        }
    }
}
