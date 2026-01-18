use std::collections::HashMap;
use std::sync::Arc;

use parking_lot::RwLock;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ContextMessage {
    pub role: String,
    pub content: String,
}

pub trait ContextStore: Send + Sync {
    fn load(&self, session_id: &str) -> Vec<ContextMessage>;
    fn append(&self, session_id: &str, messages: &[ContextMessage]);
    fn truncate(&self, session_id: &str, max_messages: usize);
}

#[derive(Clone)]
pub struct InMemoryContextStore {
    store: Arc<RwLock<HashMap<String, Vec<ContextMessage>>>>,
}

impl InMemoryContextStore {
    pub fn new() -> Self {
        Self {
            store: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub fn shared() -> Arc<Self> {
        Arc::new(Self::new())
    }
}

impl ContextStore for InMemoryContextStore {
    fn load(&self, session_id: &str) -> Vec<ContextMessage> {
        self.store
            .read()
            .get(session_id)
            .cloned()
            .unwrap_or_default()
    }

    fn append(&self, session_id: &str, messages: &[ContextMessage]) {
        let mut store = self.store.write();
        let entry = store.entry(session_id.to_string()).or_default();
        entry.extend_from_slice(messages);
    }

    fn truncate(&self, session_id: &str, max_messages: usize) {
        let mut store = self.store.write();
        if let Some(entry) = store.get_mut(session_id) {
            if entry.len() > max_messages {
                let start = entry.len().saturating_sub(max_messages);
                *entry = entry[start..].to_vec();
            }
        }
    }
}
