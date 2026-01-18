use std::sync::Arc;

use parking_lot::Mutex;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AuditEvent {
    pub request_id: String,
    pub stage: String,
    pub detail: String,
}

pub trait AuditSink: Send + Sync {
    fn record(&self, event: AuditEvent);
    fn list(&self) -> Vec<AuditEvent>;
}

#[derive(Clone)]
pub struct InMemoryAuditSink {
    events: Arc<Mutex<Vec<AuditEvent>>>,
}

impl InMemoryAuditSink {
    pub fn new() -> Self {
        Self {
            events: Arc::new(Mutex::new(Vec::new())),
        }
    }

    pub fn shared() -> Arc<Self> {
        Arc::new(Self::new())
    }
}

impl AuditSink for InMemoryAuditSink {
    fn record(&self, event: AuditEvent) {
        self.events.lock().push(event);
    }

    fn list(&self) -> Vec<AuditEvent> {
        self.events.lock().clone()
    }
}
