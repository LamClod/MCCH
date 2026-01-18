use std::collections::HashMap;
use std::sync::Arc;

use parking_lot::RwLock;
use serde::{Deserialize, Serialize};

use crate::security::SecurityDescriptor;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub enum ProviderType {
    OpenAiCompatible,
    Anthropic,
    Codex,
    Gemini,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub enum Context1mPreference {
    Disabled,
    Inherit,
    ForceEnable,
}

impl Default for Context1mPreference {
    fn default() -> Self {
        Self::Inherit
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProviderSpec {
    pub id: String,
    pub name: String,
    pub provider_type: ProviderType,
    pub priority: i32,
    pub weight: i32,
    pub enabled: bool,
    pub group_tag: Option<String>,
    pub allowed_models: Vec<String>,
    pub model_redirects: HashMap<String, String>,
    pub join_claude_pool: bool,
    pub limit_concurrent_sessions: u32,
    pub limit_rpm: u32,
    pub limit_concurrent: u32,
    pub context_1m_preference: Context1mPreference,
    pub security_descriptor: SecurityDescriptor,
    pub base_url: String,
    #[serde(default)]
    pub auth_header: Option<String>,
    #[serde(default)]
    pub auth_prefix: Option<String>,
    #[serde(default)]
    pub auth_query_param: Option<String>,
    #[serde(default)]
    pub default_headers: HashMap<String, String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct KeySpec {
    pub id: String,
    pub provider_id: String,
    pub name: String,
    pub secret: String,
    pub enabled: bool,
    pub priority: i32,
    pub weight: i32,
    pub allowed_models: Vec<String>,
    pub limit_rpm: u32,
    pub limit_concurrent: u32,
    pub security_descriptor: SecurityDescriptor,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AddressSpec {
    pub id: String,
    pub provider_id: String,
    pub name: String,
    pub base_url: String,
    pub enabled: bool,
    pub priority: i32,
    pub weight: i32,
    pub limit_rpm: u32,
    pub limit_concurrent: u32,
    pub security_descriptor: SecurityDescriptor,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct KeyAddressLink {
    pub provider_id: String,
    pub key_id: String,
    pub address_id: String,
    pub priority: i32,
    pub weight: i32,
    pub enabled: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProviderSnapshot {
    pub providers: Vec<ProviderSpec>,
    pub keys: Vec<KeySpec>,
    pub addresses: Vec<AddressSpec>,
    pub links: Vec<KeyAddressLink>,
    pub keys_by_provider: HashMap<String, Vec<KeySpec>>,
    pub links_by_key: HashMap<String, Vec<KeyAddressLink>>,
    pub addresses_by_id: HashMap<String, AddressSpec>,
}

impl ProviderSnapshot {
    pub fn new(
        providers: Vec<ProviderSpec>,
        keys: Vec<KeySpec>,
        addresses: Vec<AddressSpec>,
        links: Vec<KeyAddressLink>,
    ) -> Self {
        let mut keys_by_provider: HashMap<String, Vec<KeySpec>> = HashMap::new();
        let mut links_by_key: HashMap<String, Vec<KeyAddressLink>> = HashMap::new();
        let mut addresses_by_id: HashMap<String, AddressSpec> = HashMap::new();

        for key in &keys {
            keys_by_provider
                .entry(key.provider_id.clone())
                .or_default()
                .push(key.clone());
        }

        for link in &links {
            links_by_key
                .entry(link.key_id.clone())
                .or_default()
                .push(link.clone());
        }

        for address in &addresses {
            addresses_by_id.insert(address.id.clone(), address.clone());
        }

        Self {
            providers,
            keys,
            addresses,
            links,
            keys_by_provider,
            links_by_key,
            addresses_by_id,
        }
    }
}

pub trait ProviderRegistry: Send + Sync {
    fn snapshot(&self) -> ProviderSnapshot;
}

pub struct InMemoryProviderRegistry {
    snapshot: RwLock<ProviderSnapshot>,
}

impl InMemoryProviderRegistry {
    pub fn new(snapshot: ProviderSnapshot) -> Self {
        Self {
            snapshot: RwLock::new(snapshot),
        }
    }

    pub fn shared(snapshot: ProviderSnapshot) -> Arc<Self> {
        Arc::new(Self::new(snapshot))
    }

    pub fn set_snapshot(&self, snapshot: ProviderSnapshot) {
        *self.snapshot.write() = snapshot;
    }
}

impl ProviderRegistry for InMemoryProviderRegistry {
    fn snapshot(&self) -> ProviderSnapshot {
        self.snapshot.read().clone()
    }
}
