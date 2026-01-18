use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use control_plane::bootstrap::from_snapshot_with_stores;
use control_plane::{
    seed_if_empty, AccessCheckConfig, AccessCheckEngine, AccessChecker, AuditSink,
    BusinessRepository, BusinessSnapshot, CircuitBreakerConfig, ContextStore, ControlPlaneBundle,
    ControlPlaneStores, InMemoryAuditSink, InMemoryContextStore, InMemoryHealthStore,
    InMemoryRateLimiter, InMemorySessionStore, PgBusinessRepository, RateLimiter, RedisAuditSink,
    RedisContextStore, RedisRateLimiter, RedisSessionStore, RedisStoreConfig, SessionStore,
    SqliteBusinessRepository, SqliteTsdbSink, SystemConfig, SystemConfigLoader,
    TcpLineProtocolSink, TsdbSink,
};
use kernel::{Forwarder, HttpForwarder, HttpForwarderConfig, Kernel, KernelConfig};
use kernel_space::KernelSpaceBundle;
use redis::Client as RedisClient;
use tokio::sync::{Mutex, RwLock};

use crate::error::AppError;

pub struct AppState {
    pub config_path: PathBuf,
    pub config_raw: RwLock<String>,
    pub config: RwLock<SystemConfig>,
    pub admin_token: RwLock<String>,
    pub kernel_manager: KernelManager,
    pub snapshot_lock: Mutex<()>,
}

impl AppState {
    pub fn new(
        config_path: PathBuf,
        config_raw: String,
        config: SystemConfig,
        kernel_manager: KernelManager,
    ) -> Self {
        let admin_token = config.get_string("security.kernel_token");
        Self {
            config_path,
            config_raw: RwLock::new(config_raw),
            config: RwLock::new(config),
            admin_token: RwLock::new(admin_token),
            kernel_manager,
            snapshot_lock: Mutex::new(()),
        }
    }
}

#[derive(Clone)]
pub struct StoreHandles {
    pub sessions: Arc<dyn SessionStore>,
    pub rate_limiter: Arc<dyn RateLimiter>,
    pub health: Arc<dyn control_plane::HealthStore>,
    pub audit: Arc<dyn AuditSink>,
    pub context_store: Arc<dyn ContextStore>,
    pub metrics: Arc<dyn TsdbSink>,
}

impl StoreHandles {
    pub fn to_control_plane_stores(&self) -> ControlPlaneStores {
        ControlPlaneStores {
            sessions: self.sessions.clone(),
            rate_limiter: self.rate_limiter.clone(),
            health: self.health.clone(),
            audit: self.audit.clone(),
            context_store: self.context_store.clone(),
            metrics: self.metrics.clone(),
        }
    }
}

pub struct KernelManager {
    pub repo: Arc<dyn BusinessRepository>,
    pub stores: StoreHandles,
    pub access: Arc<dyn AccessCheckEngine>,
    pub forwarder: Arc<dyn Forwarder>,
    pub kernel_space: KernelSpaceBundle,
    pub bundle: RwLock<ControlPlaneBundle>,
    pub kernel: RwLock<Arc<Kernel>>,
}

impl KernelManager {
    pub fn from_config(config: &SystemConfig) -> Result<Self, AppError> {
        let repo = build_repository(config)?;
        let repo: Arc<dyn BusinessRepository> = Arc::from(repo);
        let stores = build_store_handles(config)?;
        let access = Arc::new(AccessChecker::new(AccessCheckConfig::default()));
        let forwarder = Arc::new(HttpForwarder::new(HttpForwarderConfig::default()));
        let kernel_space = KernelSpaceBundle::with_defaults();

        let bundle = build_bundle(config, repo.as_ref(), &stores)?;
        let kernel = build_kernel(&bundle, access.clone(), forwarder.clone(), &kernel_space);

        Ok(Self {
            repo,
            stores,
            access,
            forwarder,
            kernel_space,
            bundle: RwLock::new(bundle),
            kernel: RwLock::new(Arc::new(kernel)),
        })
    }

    pub fn build_bundle_from_snapshot(&self, snapshot: &BusinessSnapshot) -> ControlPlaneBundle {
        from_snapshot_with_stores(snapshot, self.stores.to_control_plane_stores())
    }

    pub async fn reload(&self, snapshot: &BusinessSnapshot) {
        let bundle = self.build_bundle_from_snapshot(snapshot);
        let kernel = build_kernel(&bundle, self.access.clone(), self.forwarder.clone(), &self.kernel_space);
        *self.bundle.write().await = bundle;
        *self.kernel.write().await = Arc::new(kernel);
    }
}

pub fn load_config(path: &Path) -> Result<(String, SystemConfig), AppError> {
    let raw = std::fs::read_to_string(path)?;
    let config = SystemConfigLoader::from_str(&raw)?;
    Ok((raw, config))
}

pub fn create_default_config(path: &Path) -> Result<String, AppError> {
    let content = default_config_template();
    std::fs::write(path, content.as_bytes())?;
    Ok(content)
}

pub fn default_config_template() -> String {
    let mut lines = Vec::new();
    lines.push("storage = { dsn = \"\", sqlite_path = \"mcch.sqlite\" }");
    lines.push("cache = { redis_url = \"\" }");
    lines.push("tsdb = { endpoint = \"\", sqlite_path = \"mcch_tsdb.sqlite\", timeout_ms = 1000 }");
    lines.push("security = { kernel_token = \"change-me\", master_key = \"\" }");
    lines.push("runtime = { thread_pool = 8, cache_ttl_seconds = 30 }");
    lines.push("bootstrap = { seed_on_start = true }");
    format!("{}\n", lines.join("\n"))
}

fn build_repository(config: &SystemConfig) -> Result<Box<dyn BusinessRepository>, AppError> {
    let dsn = config.get_string("storage.dsn");
    if dsn.trim().is_empty() {
        let path = config.get_string("storage.sqlite_path");
        let repo = SqliteBusinessRepository::open(&path)?;
        repo.ensure_schema()?;
        return Ok(Box::new(repo));
    }
    if is_sqlite_dsn(&dsn) {
        let path = sqlite_path_from_dsn(&dsn);
        let repo = SqliteBusinessRepository::open(path)?;
        repo.ensure_schema()?;
        return Ok(Box::new(repo));
    }
    let repo = PgBusinessRepository::connect(&dsn)?;
    repo.ensure_schema()?;
    Ok(Box::new(repo))
}

fn build_store_handles(config: &SystemConfig) -> Result<StoreHandles, AppError> {
    let redis_url = config.get_string("cache.redis_url");
    let metrics = resolve_tsdb(config)?;

    if redis_url.trim().is_empty() {
        Ok(StoreHandles {
            sessions: InMemorySessionStore::shared(),
            rate_limiter: InMemoryRateLimiter::shared(60),
            health: InMemoryHealthStore::shared(CircuitBreakerConfig::default()),
            audit: InMemoryAuditSink::shared(),
            context_store: InMemoryContextStore::shared(),
            metrics,
        })
    } else {
        let client = RedisClient::open(redis_url)
            .map_err(|err| AppError::internal(err.to_string()))?;
        let store_config = RedisStoreConfig::default();
        Ok(StoreHandles {
            sessions: Arc::new(RedisSessionStore::new(client.clone(), store_config.clone())),
            rate_limiter: Arc::new(RedisRateLimiter::new(client.clone(), store_config.clone())),
            health: InMemoryHealthStore::shared(CircuitBreakerConfig::default()),
            audit: Arc::new(RedisAuditSink::new(client.clone(), store_config.clone())),
            context_store: Arc::new(RedisContextStore::new(client, store_config)),
            metrics,
        })
    }
}

fn resolve_tsdb(config: &SystemConfig) -> Result<Arc<dyn TsdbSink>, AppError> {
    let endpoint = config.get_string("tsdb.endpoint");
    if endpoint.trim().is_empty() {
        let path = config.get_string("tsdb.sqlite_path");
        let sqlite = SqliteTsdbSink::open(&path)
            .map_err(|err| AppError::internal(err.to_string()))?;
        return Ok(Arc::new(sqlite));
    }
    let timeout_ms = config.get_number("tsdb.timeout_ms");
    let timeout_ms = if timeout_ms <= 0 { 1000 } else { timeout_ms };
    let sink = TcpLineProtocolSink::connect(&endpoint, timeout_ms as u64)
        .map_err(|err| AppError::internal(err.to_string()))?;
    Ok(Arc::new(sink))
}

fn build_bundle(
    config: &SystemConfig,
    repo: &dyn BusinessRepository,
    stores: &StoreHandles,
) -> Result<ControlPlaneBundle, AppError> {
    let seed_on_start = config.get_bool("bootstrap.seed_on_start");
    if seed_on_start {
        let seed = BusinessSnapshot::default();
        seed_if_empty(repo, &seed)?;
    }
    let snapshot = repo.load_snapshot()?;
    Ok(from_snapshot_with_stores(
        &snapshot,
        stores.to_control_plane_stores(),
    ))
}

fn build_kernel(
    bundle: &ControlPlaneBundle,
    access: Arc<dyn AccessCheckEngine>,
    forwarder: Arc<dyn Forwarder>,
    kernel_space: &KernelSpaceBundle,
) -> Kernel {
    let mut kernel = Kernel::new(
        KernelConfig::default(),
        bundle.security.clone(),
        access,
        bundle.policy.clone(),
        bundle.providers.clone(),
        bundle.sessions.clone(),
        bundle.rate_limiter.clone(),
        bundle.health.clone(),
        bundle.audit.clone(),
        bundle.metrics.clone(),
        bundle.context_store.clone(),
        forwarder,
    );

    for plugin in &kernel_space.protocols {
        kernel.register_protocol_plugin(plugin.clone());
    }
    for plugin in &kernel_space.providers {
        kernel.register_provider_plugin(plugin.clone());
    }
    for plugin in &kernel_space.guard_plugins {
        kernel.register_guard_plugin(plugin.clone());
    }

    kernel
}

fn is_sqlite_dsn(dsn: &str) -> bool {
    let trimmed = dsn.trim().to_lowercase();
    trimmed.starts_with("sqlite://") || trimmed.starts_with("sqlite:")
}

fn sqlite_path_from_dsn(dsn: &str) -> &str {
    dsn.trim()
        .strip_prefix("sqlite://")
        .or_else(|| dsn.trim().strip_prefix("sqlite:"))
        .unwrap_or(dsn)
}

pub async fn update_config_file(
    state: &AppState,
    content: String,
) -> Result<SystemConfig, AppError> {
    let parsed = SystemConfigLoader::from_str(&content)?;
    std::fs::write(&state.config_path, content.as_bytes())?;
    *state.config_raw.write().await = content;
    *state.config.write().await = parsed.clone();
    *state.admin_token.write().await = parsed.get_string("security.kernel_token");
    Ok(parsed)
}

pub fn build_policy_payload(snapshot: &BusinessSnapshot) -> PolicyPayload {
    PolicyPayload {
        guard_config: snapshot.guard_config.clone(),
        sensitive_words: snapshot.sensitive_words.clone(),
        tool_policies: snapshot.tool_policies.clone(),
        request_filters: snapshot.request_filters.clone(),
        client_policy: snapshot.client_policy.clone(),
        version_policy: snapshot.version_policy.clone(),
        warmup_policy: snapshot.warmup_policy.clone(),
        probe_policy: snapshot.probe_policy.clone(),
        context_policy: snapshot.context_policy.clone(),
        provider_groups: snapshot.provider_groups.clone(),
        rate_limit_profiles: snapshot.rate_limit_profiles.clone(),
    }
}

pub fn apply_policy_payload(snapshot: &mut BusinessSnapshot, payload: PolicyPayload) {
    snapshot.guard_config = payload.guard_config;
    snapshot.sensitive_words = payload.sensitive_words;
    snapshot.tool_policies = payload.tool_policies;
    snapshot.request_filters = payload.request_filters;
    snapshot.client_policy = payload.client_policy;
    snapshot.version_policy = payload.version_policy;
    snapshot.warmup_policy = payload.warmup_policy;
    snapshot.probe_policy = payload.probe_policy;
    snapshot.context_policy = payload.context_policy;
    snapshot.provider_groups = payload.provider_groups;
    snapshot.rate_limit_profiles = payload.rate_limit_profiles;
}

#[derive(serde::Serialize, serde::Deserialize, Clone)]
pub struct PolicyPayload {
    pub guard_config: control_plane::GuardConfig,
    pub sensitive_words: Vec<String>,
    pub tool_policies: HashMap<String, control_plane::ToolPolicy>,
    pub request_filters: Vec<control_plane::RequestFilterRule>,
    pub client_policy: control_plane::ClientPolicy,
    pub version_policy: control_plane::VersionPolicy,
    pub warmup_policy: control_plane::WarmupPolicy,
    pub probe_policy: control_plane::ProbePolicy,
    pub context_policy: control_plane::ContextPolicy,
    pub provider_groups: HashMap<String, String>,
    pub rate_limit_profiles: HashMap<String, control_plane::RateLimitProfile>,
}

