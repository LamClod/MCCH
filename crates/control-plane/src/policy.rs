use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use parking_lot::RwLock;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GuardConfig {
    pub steps: Vec<String>,
    pub count_tokens_steps: Vec<String>,
}

impl GuardConfig {
    pub fn empty() -> Self {
        Self {
            steps: Vec::new(),
            count_tokens_steps: Vec::new(),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ToolPolicy {
    pub allow_all: bool,
    pub allow: HashSet<String>,
    pub deny: HashSet<String>,
}

impl ToolPolicy {
    pub fn allow_all() -> Self {
        Self {
            allow_all: true,
            allow: HashSet::new(),
            deny: HashSet::new(),
        }
    }

    pub fn denies(&self, name: &str) -> bool {
        self.deny.contains(name)
    }

    pub fn allows(&self, name: &str) -> bool {
        if self.allow_all {
            return !self.denies(name);
        }
        self.allow.contains(name) && !self.denies(name)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ClientPolicy {
    pub allow_all: bool,
    pub allow: HashSet<String>,
    pub deny: HashSet<String>,
}

impl ClientPolicy {
    pub fn allow_all() -> Self {
        Self {
            allow_all: true,
            allow: HashSet::new(),
            deny: HashSet::new(),
        }
    }

    pub fn allows(&self, client_id: &str) -> bool {
        if self.allow_all {
            return !self.deny.contains(client_id);
        }
        self.allow.contains(client_id) && !self.deny.contains(client_id)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VersionPolicy {
    pub allow_all: bool,
    pub allow: HashSet<String>,
    pub deny: HashSet<String>,
}

impl VersionPolicy {
    pub fn allow_all() -> Self {
        Self {
            allow_all: true,
            allow: HashSet::new(),
            deny: HashSet::new(),
        }
    }

    pub fn allows(&self, version: &str) -> bool {
        if self.allow_all {
            return !self.deny.contains(version);
        }
        self.allow.contains(version) && !self.deny.contains(version)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum FilterAction {
    Block,
    Redact { replacement: String },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RequestFilterRule {
    pub pattern: String,
    pub action: FilterAction,
    pub case_sensitive: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WarmupPolicy {
    pub enabled: bool,
    pub response_body: String,
    pub status: u16,
}

impl Default for WarmupPolicy {
    fn default() -> Self {
        Self {
            enabled: true,
            response_body: "{\"status\":\"warmup\"}".to_string(),
            status: 200,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProbePolicy {
    pub enabled: bool,
    pub response_body: String,
    pub status: u16,
}

impl Default for ProbePolicy {
    fn default() -> Self {
        Self {
            enabled: true,
            response_body: "{\"input_tokens\":0}".to_string(),
            status: 200,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ContextPolicy {
    pub enabled: bool,
    pub max_messages: usize,
}

impl Default for ContextPolicy {
    fn default() -> Self {
        Self {
            enabled: true,
            max_messages: 64,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RateLimitProfile {
    pub rpm: u32,
    pub concurrent: u32,
}

impl Default for RateLimitProfile {
    fn default() -> Self {
        Self {
            rpm: 0,
            concurrent: 0,
        }
    }
}

pub trait PolicyService: Send + Sync {
    fn guard_config(&self) -> GuardConfig;
    fn sensitive_words(&self) -> Vec<String>;
    fn tool_policy_for_token(&self, token_id: &str) -> ToolPolicy;
    fn client_policy(&self) -> ClientPolicy;
    fn version_policy(&self) -> VersionPolicy;
    fn request_filters(&self) -> Vec<RequestFilterRule>;
    fn warmup_policy(&self) -> WarmupPolicy;
    fn probe_policy(&self) -> ProbePolicy;
    fn context_policy(&self) -> ContextPolicy;
    fn provider_group_for_token(&self, token_id: &str) -> Option<String>;
    fn rate_limit_profile(&self, token_id: &str) -> RateLimitProfile;
}

pub struct InMemoryPolicyService {
    guard: RwLock<GuardConfig>,
    words: RwLock<Vec<String>>,
    tool_policies: RwLock<HashMap<String, ToolPolicy>>,
    client_policy: RwLock<ClientPolicy>,
    version_policy: RwLock<VersionPolicy>,
    request_filters: RwLock<Vec<RequestFilterRule>>,
    warmup_policy: RwLock<WarmupPolicy>,
    probe_policy: RwLock<ProbePolicy>,
    context_policy: RwLock<ContextPolicy>,
    provider_groups: RwLock<HashMap<String, String>>,
    rate_limits: RwLock<HashMap<String, RateLimitProfile>>,
}

impl InMemoryPolicyService {
    pub fn new() -> Self {
        Self {
            guard: RwLock::new(GuardConfig::empty()),
            words: RwLock::new(Vec::new()),
            tool_policies: RwLock::new(HashMap::new()),
            client_policy: RwLock::new(ClientPolicy::allow_all()),
            version_policy: RwLock::new(VersionPolicy::allow_all()),
            request_filters: RwLock::new(Vec::new()),
            warmup_policy: RwLock::new(WarmupPolicy::default()),
            probe_policy: RwLock::new(ProbePolicy::default()),
            context_policy: RwLock::new(ContextPolicy::default()),
            provider_groups: RwLock::new(HashMap::new()),
            rate_limits: RwLock::new(HashMap::new()),
        }
    }

    pub fn shared() -> Arc<Self> {
        Arc::new(Self::new())
    }

    pub fn set_guard_config(&self, config: GuardConfig) {
        *self.guard.write() = config;
    }

    pub fn set_sensitive_words(&self, words: Vec<String>) {
        *self.words.write() = words;
    }

    pub fn set_tool_policy(&self, token_id: &str, policy: ToolPolicy) {
        self.tool_policies
            .write()
            .insert(token_id.to_string(), policy);
    }

    pub fn set_client_policy(&self, policy: ClientPolicy) {
        *self.client_policy.write() = policy;
    }

    pub fn set_version_policy(&self, policy: VersionPolicy) {
        *self.version_policy.write() = policy;
    }

    pub fn set_request_filters(&self, rules: Vec<RequestFilterRule>) {
        *self.request_filters.write() = rules;
    }

    pub fn set_warmup_policy(&self, policy: WarmupPolicy) {
        *self.warmup_policy.write() = policy;
    }

    pub fn set_probe_policy(&self, policy: ProbePolicy) {
        *self.probe_policy.write() = policy;
    }

    pub fn set_context_policy(&self, policy: ContextPolicy) {
        *self.context_policy.write() = policy;
    }

    pub fn set_provider_group(&self, token_id: &str, group: String) {
        self.provider_groups
            .write()
            .insert(token_id.to_string(), group);
    }

    pub fn set_rate_limit_profile(&self, token_id: &str, profile: RateLimitProfile) {
        self.rate_limits
            .write()
            .insert(token_id.to_string(), profile);
    }
}

impl PolicyService for InMemoryPolicyService {
    fn guard_config(&self) -> GuardConfig {
        self.guard.read().clone()
    }

    fn sensitive_words(&self) -> Vec<String> {
        self.words.read().clone()
    }

    fn tool_policy_for_token(&self, token_id: &str) -> ToolPolicy {
        self.tool_policies
            .read()
            .get(token_id)
            .cloned()
            .unwrap_or_else(ToolPolicy::allow_all)
    }

    fn client_policy(&self) -> ClientPolicy {
        self.client_policy.read().clone()
    }

    fn version_policy(&self) -> VersionPolicy {
        self.version_policy.read().clone()
    }

    fn request_filters(&self) -> Vec<RequestFilterRule> {
        self.request_filters.read().clone()
    }

    fn warmup_policy(&self) -> WarmupPolicy {
        self.warmup_policy.read().clone()
    }

    fn probe_policy(&self) -> ProbePolicy {
        self.probe_policy.read().clone()
    }

    fn context_policy(&self) -> ContextPolicy {
        self.context_policy.read().clone()
    }

    fn provider_group_for_token(&self, token_id: &str) -> Option<String> {
        self.provider_groups.read().get(token_id).cloned()
    }

    fn rate_limit_profile(&self, token_id: &str) -> RateLimitProfile {
        self.rate_limits
            .read()
            .get(token_id)
            .cloned()
            .unwrap_or_default()
    }
}
