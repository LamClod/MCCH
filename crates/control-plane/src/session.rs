use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use parking_lot::Mutex;

pub trait SessionStore: Send + Sync {
    fn get_binding(&self, session_id: &str) -> Option<String>;
    fn bind_on_success(&self, session_id: &str, provider_id: &str);
    fn acquire_concurrency(&self, provider_id: &str, session_id: &str, limit: u32) -> bool;
    fn release_concurrency(&self, provider_id: &str, session_id: &str);
    fn next_sequence(&self, session_id: &str) -> u64;
}

pub struct InMemorySessionStore {
    bindings: Mutex<HashMap<String, String>>,
    provider_sessions: Mutex<HashMap<String, HashSet<String>>>,
    sequences: Mutex<HashMap<String, u64>>,
}

impl InMemorySessionStore {
    pub fn new() -> Self {
        Self {
            bindings: Mutex::new(HashMap::new()),
            provider_sessions: Mutex::new(HashMap::new()),
            sequences: Mutex::new(HashMap::new()),
        }
    }

    pub fn shared() -> Arc<Self> {
        Arc::new(Self::new())
    }
}

impl SessionStore for InMemorySessionStore {
    fn get_binding(&self, session_id: &str) -> Option<String> {
        self.bindings.lock().get(session_id).cloned()
    }

    fn bind_on_success(&self, session_id: &str, provider_id: &str) {
        self.bindings
            .lock()
            .entry(session_id.to_string())
            .or_insert_with(|| provider_id.to_string());
    }

    fn acquire_concurrency(&self, provider_id: &str, session_id: &str, limit: u32) -> bool {
        if limit == 0 {
            return true;
        }
        let mut map = self.provider_sessions.lock();
        let entry = map.entry(provider_id.to_string()).or_default();
        if entry.contains(session_id) {
            return true;
        }
        if entry.len() as u32 >= limit {
            return false;
        }
        entry.insert(session_id.to_string());
        true
    }

    fn release_concurrency(&self, provider_id: &str, session_id: &str) {
        let mut map = self.provider_sessions.lock();
        if let Some(entry) = map.get_mut(provider_id) {
            entry.remove(session_id);
        }
    }

    fn next_sequence(&self, session_id: &str) -> u64 {
        let mut seq = self.sequences.lock();
        let entry = seq.entry(session_id.to_string()).or_insert(0);
        *entry += 1;
        *entry
    }
}
