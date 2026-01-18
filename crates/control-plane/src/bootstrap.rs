use std::collections::HashMap;
use std::sync::Arc;

use crate::config::SystemConfig;
use crate::pg_repository::PgBusinessRepository;
use crate::policy::PolicyService;
use crate::provider::ProviderRegistry;
use crate::redis_store::{
    RedisAuditSink, RedisContextStore, RedisRateLimiter, RedisSessionStore, RedisStoreConfig,
};
use crate::security::SecurityAuthority;
use crate::sqlite_repository::SqliteBusinessRepository;
use crate::tsdb::{InMemoryTsdbSink, SqliteTsdbSink, TcpLineProtocolSink, TsdbSink};
use crate::{
    AuditSink, CircuitBreakerConfig, ContextStore, HealthStore, InMemoryAuditSink,
    InMemoryContextStore, InMemoryHealthStore, InMemoryPolicyService, InMemoryProviderRegistry,
    InMemoryRateLimiter, InMemorySessionStore, RateLimiter, SessionStore, StaticSecurityAuthority,
    TokenRecord,
};

use crate::repository::{seed_if_empty, BusinessRepository, BusinessSnapshot, RepositoryError};

pub struct ControlPlaneBundle {
    pub providers: Arc<dyn ProviderRegistry>,
    pub policy: Arc<dyn PolicyService>,
    pub security: Arc<dyn SecurityAuthority>,
    pub sessions: Arc<dyn SessionStore>,
    pub rate_limiter: Arc<dyn RateLimiter>,
    pub health: Arc<dyn HealthStore>,
    pub audit: Arc<dyn AuditSink>,
    pub context_store: Arc<dyn ContextStore>,
    pub metrics: Arc<dyn TsdbSink>,
}

pub struct ControlPlaneStores {
    pub sessions: Arc<dyn SessionStore>,
    pub rate_limiter: Arc<dyn RateLimiter>,
    pub health: Arc<dyn HealthStore>,
    pub audit: Arc<dyn AuditSink>,
    pub context_store: Arc<dyn ContextStore>,
    pub metrics: Arc<dyn TsdbSink>,
}

impl ControlPlaneStores {
    pub fn in_memory() -> Self {
        Self {
            sessions: InMemorySessionStore::shared(),
            rate_limiter: InMemoryRateLimiter::shared(60),
            health: InMemoryHealthStore::shared(CircuitBreakerConfig::default()),
            audit: InMemoryAuditSink::shared(),
            context_store: InMemoryContextStore::shared(),
            metrics: InMemoryTsdbSink::shared(),
        }
    }
}

impl Default for ControlPlaneStores {
    fn default() -> Self {
        Self::in_memory()
    }
}

pub fn from_snapshot(snapshot: &BusinessSnapshot) -> ControlPlaneBundle {
    from_snapshot_with_stores(snapshot, ControlPlaneStores::default())
}

pub fn from_snapshot_with_stores(
    snapshot: &BusinessSnapshot,
    stores: ControlPlaneStores,
) -> ControlPlaneBundle {
    let providers = InMemoryProviderRegistry::shared(snapshot.providers.clone());
    let policy = InMemoryPolicyService::shared();
    policy.set_guard_config(snapshot.guard_config.clone());
    policy.set_sensitive_words(snapshot.sensitive_words.clone());
    policy.set_request_filters(snapshot.request_filters.clone());
    policy.set_client_policy(snapshot.client_policy.clone());
    policy.set_version_policy(snapshot.version_policy.clone());
    policy.set_warmup_policy(snapshot.warmup_policy.clone());
    policy.set_probe_policy(snapshot.probe_policy.clone());
    policy.set_context_policy(snapshot.context_policy.clone());

    for (token_id, policy_value) in snapshot.tool_policies.clone() {
        policy.set_tool_policy(&token_id, policy_value);
    }
    for (token_id, group) in snapshot.provider_groups.clone() {
        policy.set_provider_group(&token_id, group);
    }
    for (token_id, profile) in snapshot.rate_limit_profiles.clone() {
        policy.set_rate_limit_profile(&token_id, profile);
    }

    let tokens = token_records_to_map(&snapshot.tokens);
    let security = StaticSecurityAuthority::shared(tokens);

    ControlPlaneBundle {
        providers,
        policy,
        security,
        sessions: stores.sessions,
        rate_limiter: stores.rate_limiter,
        health: stores.health,
        audit: stores.audit,
        context_store: stores.context_store,
        metrics: stores.metrics,
    }
}

pub fn load_from_repository(
    repo: &dyn BusinessRepository,
    seed: Option<&BusinessSnapshot>,
    seed_on_start: bool,
) -> Result<ControlPlaneBundle, RepositoryError> {
    load_from_repository_with_stores(repo, seed, seed_on_start, ControlPlaneStores::default())
}

pub fn load_from_repository_with_stores(
    repo: &dyn BusinessRepository,
    seed: Option<&BusinessSnapshot>,
    seed_on_start: bool,
    stores: ControlPlaneStores,
) -> Result<ControlPlaneBundle, RepositoryError> {
    if seed_on_start {
        if let Some(seed_value) = seed {
            seed_if_empty(repo, seed_value)?;
        }
    }
    let snapshot = repo.load_snapshot()?;
    Ok(from_snapshot_with_stores(&snapshot, stores))
}

pub fn load_from_system_config(
    config: &SystemConfig,
    seed: Option<&BusinessSnapshot>,
) -> Result<ControlPlaneBundle, RepositoryError> {
    let seed_on_start = config.get_bool("bootstrap.seed_on_start");

    let repo = resolve_repository(config)?;
    let stores = resolve_stores(config)?;
    load_from_repository_with_stores(repo.as_ref(), seed, seed_on_start, stores)
}

fn resolve_tsdb(config: &SystemConfig) -> Result<Arc<dyn TsdbSink>, RepositoryError> {
    let endpoint = config.get_string("tsdb.endpoint");
    if endpoint.trim().is_empty() {
        let path = config.get_string("tsdb.sqlite_path");
        let sqlite = SqliteTsdbSink::open(&path)
            .map_err(|err| RepositoryError::Store(err.to_string()))?;
        return Ok(Arc::new(sqlite));
    }
    let timeout_ms = config.get_number("tsdb.timeout_ms");
    let timeout_ms = if timeout_ms <= 0 { 1000 } else { timeout_ms };
    let sink = TcpLineProtocolSink::connect(&endpoint, timeout_ms as u64)
        .map_err(|err| RepositoryError::Store(err.to_string()))?;
    Ok(Arc::new(sink))
}

fn resolve_repository(
    config: &SystemConfig,
) -> Result<Box<dyn BusinessRepository>, RepositoryError> {
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

fn resolve_stores(config: &SystemConfig) -> Result<ControlPlaneStores, RepositoryError> {
    let redis_url = config.get_string("cache.redis_url");
    let metrics = resolve_tsdb(config)?;
    if redis_url.trim().is_empty() {
        let mut stores = ControlPlaneStores::in_memory();
        stores.metrics = metrics;
        return Ok(stores);
    }
    let client =
        redis::Client::open(redis_url).map_err(|err| RepositoryError::Store(err.to_string()))?;
    let store_config = RedisStoreConfig::default();
    Ok(ControlPlaneStores {
        sessions: Arc::new(RedisSessionStore::new(
            client.clone(),
            store_config.clone(),
        )),
        rate_limiter: Arc::new(RedisRateLimiter::new(
            client.clone(),
            store_config.clone(),
        )),
        health: InMemoryHealthStore::shared(CircuitBreakerConfig::default()),
        audit: Arc::new(RedisAuditSink::new(
            client.clone(),
            store_config.clone(),
        )),
        context_store: Arc::new(RedisContextStore::new(client, store_config)),
        metrics,
    })
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

fn token_records_to_map(records: &[TokenRecord]) -> HashMap<String, crate::SecurityToken> {
    records
        .iter()
        .map(|record| (record.token_key.clone(), record.token.clone()))
        .collect()
}
