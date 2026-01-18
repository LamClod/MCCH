use std::collections::HashMap;
use std::sync::Arc;

use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::policy::{
    ClientPolicy, ContextPolicy, GuardConfig, ProbePolicy, RateLimitProfile, RequestFilterRule,
    ToolPolicy, VersionPolicy, WarmupPolicy,
};
use crate::provider::ProviderSnapshot;
use crate::security::TokenRecord;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BusinessSnapshot {
    pub providers: ProviderSnapshot,
    pub guard_config: GuardConfig,
    pub sensitive_words: Vec<String>,
    pub tool_policies: HashMap<String, ToolPolicy>,
    pub request_filters: Vec<RequestFilterRule>,
    pub client_policy: ClientPolicy,
    pub version_policy: VersionPolicy,
    pub warmup_policy: WarmupPolicy,
    pub probe_policy: ProbePolicy,
    pub context_policy: ContextPolicy,
    pub provider_groups: HashMap<String, String>,
    pub rate_limit_profiles: HashMap<String, RateLimitProfile>,
    pub tokens: Vec<TokenRecord>,
}

impl Default for BusinessSnapshot {
    fn default() -> Self {
        Self {
            providers: ProviderSnapshot::new(Vec::new(), Vec::new(), Vec::new(), Vec::new()),
            guard_config: GuardConfig::empty(),
            sensitive_words: Vec::new(),
            tool_policies: HashMap::new(),
            request_filters: Vec::new(),
            client_policy: ClientPolicy::allow_all(),
            version_policy: VersionPolicy::allow_all(),
            warmup_policy: WarmupPolicy::default(),
            probe_policy: ProbePolicy::default(),
            context_policy: ContextPolicy::default(),
            provider_groups: HashMap::new(),
            rate_limit_profiles: HashMap::new(),
            tokens: Vec::new(),
        }
    }
}

#[derive(Debug, Error)]
pub enum RepositoryError {
    #[error("repository error: {0}")]
    Store(String),
    #[error("serialization error: {0}")]
    Serialization(String),
}

pub trait BusinessRepository: Send + Sync {
    fn load_snapshot(&self) -> Result<BusinessSnapshot, RepositoryError>;
    fn save_snapshot(&self, snapshot: &BusinessSnapshot) -> Result<(), RepositoryError>;
    fn is_seeded(&self) -> Result<bool, RepositoryError>;
}

#[derive(Clone)]
pub struct InMemoryBusinessRepository {
    snapshot: Arc<RwLock<BusinessSnapshot>>,
    seeded: Arc<RwLock<bool>>,
}

impl InMemoryBusinessRepository {
    pub fn new(snapshot: BusinessSnapshot) -> Self {
        Self {
            snapshot: Arc::new(RwLock::new(snapshot)),
            seeded: Arc::new(RwLock::new(false)),
        }
    }

    pub fn shared(snapshot: BusinessSnapshot) -> Arc<Self> {
        Arc::new(Self::new(snapshot))
    }
}

impl BusinessRepository for InMemoryBusinessRepository {
    fn load_snapshot(&self) -> Result<BusinessSnapshot, RepositoryError> {
        Ok(self.snapshot.read().clone())
    }

    fn save_snapshot(&self, snapshot: &BusinessSnapshot) -> Result<(), RepositoryError> {
        *self.snapshot.write() = snapshot.clone();
        *self.seeded.write() = true;
        Ok(())
    }

    fn is_seeded(&self) -> Result<bool, RepositoryError> {
        Ok(*self.seeded.read())
    }
}

#[derive(Clone)]
pub struct SledBusinessRepository {
    db: sled::Db,
}

impl SledBusinessRepository {
    pub fn open(path: &str) -> Result<Self, RepositoryError> {
        let db = sled::open(path).map_err(|err| RepositoryError::Store(err.to_string()))?;
        Ok(Self { db })
    }
}

impl BusinessRepository for SledBusinessRepository {
    fn load_snapshot(&self) -> Result<BusinessSnapshot, RepositoryError> {
        let Some(value) = self
            .db
            .get(b"business_snapshot")
            .map_err(|err| RepositoryError::Store(err.to_string()))?
        else {
            return Ok(BusinessSnapshot::default());
        };
        serde_json::from_slice(&value).map_err(|err| RepositoryError::Serialization(err.to_string()))
    }

    fn save_snapshot(&self, snapshot: &BusinessSnapshot) -> Result<(), RepositoryError> {
        let payload =
            serde_json::to_vec(snapshot).map_err(|err| RepositoryError::Serialization(err.to_string()))?;
        self.db
            .insert(b"business_snapshot", payload)
            .map_err(|err| RepositoryError::Store(err.to_string()))?;
        self.db
            .flush()
            .map_err(|err| RepositoryError::Store(err.to_string()))?;
        Ok(())
    }

    fn is_seeded(&self) -> Result<bool, RepositoryError> {
        let value = self
            .db
            .get(b"business_snapshot")
            .map_err(|err| RepositoryError::Store(err.to_string()))?;
        Ok(value.is_some())
    }
}

pub fn seed_if_empty(
    repo: &dyn BusinessRepository,
    seed: &BusinessSnapshot,
) -> Result<bool, RepositoryError> {
    if !repo.is_seeded()? {
        repo.save_snapshot(seed)?;
        return Ok(true);
    }
    Ok(false)
}
