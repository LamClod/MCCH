use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use redis::{Commands, Script};

use crate::audit::{AuditEvent, AuditSink};
use crate::context::{ContextMessage, ContextStore};
use crate::rate_limit::{RateLimitPermit, RateLimitRelease, RateLimiter};
use crate::session::SessionStore;

#[derive(Clone, Debug)]
pub struct RedisStoreConfig {
    pub key_prefix: String,
    pub session_ttl_seconds: usize,
    pub context_ttl_seconds: usize,
    pub audit_ttl_seconds: usize,
    pub rate_limit_window_seconds: u64,
}

impl Default for RedisStoreConfig {
    fn default() -> Self {
        Self {
            key_prefix: "mcch".to_string(),
            session_ttl_seconds: 3600,
            context_ttl_seconds: 3600,
            audit_ttl_seconds: 3600,
            rate_limit_window_seconds: 60,
        }
    }
}

#[derive(Clone)]
pub struct RedisSessionStore {
    client: redis::Client,
    config: RedisStoreConfig,
}

impl RedisSessionStore {
    pub fn new(client: redis::Client, config: RedisStoreConfig) -> Self {
        Self { client, config }
    }

    fn session_bind_key(&self, session_id: &str) -> String {
        format!("{}:session:bind:{}", self.config.key_prefix, session_id)
    }

    fn session_set_key(&self, provider_id: &str) -> String {
        format!("{}:session:set:{}", self.config.key_prefix, provider_id)
    }

    fn session_seq_key(&self, session_id: &str) -> String {
        format!("{}:session:seq:{}", self.config.key_prefix, session_id)
    }
}

impl SessionStore for RedisSessionStore {
    fn get_binding(&self, session_id: &str) -> Option<String> {
        let mut conn = self.client.get_connection().ok()?;
        conn.get(self.session_bind_key(session_id)).ok()
    }

    fn bind_on_success(&self, session_id: &str, provider_id: &str) {
        let mut conn = match self.client.get_connection() {
            Ok(conn) => conn,
            Err(_) => return,
        };
        let key = self.session_bind_key(session_id);
        let _: Result<i32, _> = redis::cmd("SETNX")
            .arg(&key)
            .arg(provider_id)
            .query(&mut conn);
        if self.config.session_ttl_seconds > 0 {
            let _: Result<i32, _> = redis::cmd("EXPIRE")
                .arg(&key)
                .arg(self.config.session_ttl_seconds)
                .query(&mut conn);
        }
    }

    fn acquire_concurrency(&self, provider_id: &str, session_id: &str, limit: u32) -> bool {
        if limit == 0 {
            return true;
        }
        let mut conn = match self.client.get_connection() {
            Ok(conn) => conn,
            Err(_) => return false,
        };
        let key = self.session_set_key(provider_id);
        let script = Script::new(
            r#"
            local key = KEYS[1]
            local session_id = ARGV[1]
            local limit = tonumber(ARGV[2])
            local ttl = tonumber(ARGV[3])
            if limit <= 0 then
                return 1
            end
            if redis.call("SISMEMBER", key, session_id) == 1 then
                return 1
            end
            local count = redis.call("SCARD", key)
            if count >= limit then
                return 0
            end
            redis.call("SADD", key, session_id)
            if ttl > 0 then
                redis.call("EXPIRE", key, ttl)
            end
            return 1
        "#,
        );
        let result: i32 = match script
            .key(key)
            .arg(session_id)
            .arg(limit as i64)
            .arg(self.config.session_ttl_seconds as i64)
            .invoke(&mut conn)
        {
            Ok(value) => value,
            Err(_) => return false,
        };
        result == 1
    }

    fn release_concurrency(&self, provider_id: &str, session_id: &str) {
        let mut conn = match self.client.get_connection() {
            Ok(conn) => conn,
            Err(_) => return,
        };
        let _: Result<i32, _> = redis::cmd("SREM")
            .arg(self.session_set_key(provider_id))
            .arg(session_id)
            .query(&mut conn);
    }

    fn next_sequence(&self, session_id: &str) -> u64 {
        let mut conn = match self.client.get_connection() {
            Ok(conn) => conn,
            Err(_) => return 0,
        };
        let key = self.session_seq_key(session_id);
        let value: u64 = conn.incr(key.clone(), 1_u64).unwrap_or(0);
        if self.config.session_ttl_seconds > 0 {
            let _: Result<i32, _> = redis::cmd("EXPIRE")
                .arg(&key)
                .arg(self.config.session_ttl_seconds)
                .query(&mut conn);
        }
        value
    }
}

#[derive(Clone)]
pub struct RedisContextStore {
    client: redis::Client,
    config: RedisStoreConfig,
}

impl RedisContextStore {
    pub fn new(client: redis::Client, config: RedisStoreConfig) -> Self {
        Self { client, config }
    }

    fn context_key(&self, session_id: &str) -> String {
        format!("{}:context:{}", self.config.key_prefix, session_id)
    }
}

impl ContextStore for RedisContextStore {
    fn load(&self, session_id: &str) -> Vec<ContextMessage> {
        let mut conn = match self.client.get_connection() {
            Ok(conn) => conn,
            Err(_) => return Vec::new(),
        };
        let key = self.context_key(session_id);
        let list: Vec<String> = conn.lrange(key, 0, -1).unwrap_or_default();
        list.into_iter()
            .filter_map(|value| serde_json::from_str(&value).ok())
            .collect()
    }

    fn append(&self, session_id: &str, messages: &[ContextMessage]) {
        let mut conn = match self.client.get_connection() {
            Ok(conn) => conn,
            Err(_) => return,
        };
        let key = self.context_key(session_id);
        let payloads: Vec<String> = messages
            .iter()
            .filter_map(|msg| serde_json::to_string(msg).ok())
            .collect();
        if payloads.is_empty() {
            return;
        }
        let _: Result<i32, _> = redis::cmd("RPUSH")
            .arg(&key)
            .arg(payloads)
            .query(&mut conn);
        if self.config.context_ttl_seconds > 0 {
            let _: Result<i32, _> = redis::cmd("EXPIRE")
                .arg(&key)
                .arg(self.config.context_ttl_seconds)
                .query(&mut conn);
        }
    }

    fn truncate(&self, session_id: &str, max_messages: usize) {
        if max_messages == 0 {
            return;
        }
        let mut conn = match self.client.get_connection() {
            Ok(conn) => conn,
            Err(_) => return,
        };
        let key = self.context_key(session_id);
        let start = -(max_messages as isize);
        let _: Result<i32, _> = redis::cmd("LTRIM")
            .arg(&key)
            .arg(start)
            .arg(-1)
            .query(&mut conn);
    }
}

#[derive(Clone)]
pub struct RedisAuditSink {
    client: redis::Client,
    config: RedisStoreConfig,
}

impl RedisAuditSink {
    pub fn new(client: redis::Client, config: RedisStoreConfig) -> Self {
        Self { client, config }
    }

    fn audit_key(&self) -> String {
        format!("{}:audit", self.config.key_prefix)
    }
}

impl AuditSink for RedisAuditSink {
    fn record(&self, event: AuditEvent) {
        let mut conn = match self.client.get_connection() {
            Ok(conn) => conn,
            Err(_) => return,
        };
        let payload = match serde_json::to_string(&event) {
            Ok(payload) => payload,
            Err(_) => return,
        };
        let key = self.audit_key();
        let _: Result<i32, _> = redis::cmd("RPUSH").arg(&key).arg(payload).query(&mut conn);
        if self.config.audit_ttl_seconds > 0 {
            let _: Result<i32, _> = redis::cmd("EXPIRE")
                .arg(&key)
                .arg(self.config.audit_ttl_seconds)
                .query(&mut conn);
        }
    }

    fn list(&self) -> Vec<AuditEvent> {
        let mut conn = match self.client.get_connection() {
            Ok(conn) => conn,
            Err(_) => return Vec::new(),
        };
        let list: Vec<String> = conn.lrange(self.audit_key(), 0, -1).unwrap_or_default();
        list.into_iter()
            .filter_map(|value| serde_json::from_str(&value).ok())
            .collect()
    }
}

#[derive(Clone)]
pub struct RedisRateLimiter {
    client: redis::Client,
    config: RedisStoreConfig,
}

impl RedisRateLimiter {
    pub fn new(client: redis::Client, config: RedisStoreConfig) -> Self {
        Self { client, config }
    }

    fn count_key(&self, scope: &str, window: u64) -> String {
        format!(
            "{}:rate:count:{}:{}",
            self.config.key_prefix, scope, window
        )
    }

    fn concurrent_key(&self, scope: &str) -> String {
        format!("{}:rate:concurrent:{}", self.config.key_prefix, scope)
    }

    fn window_index(&self) -> u64 {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let window = self.config.rate_limit_window_seconds.max(1);
        now / window
    }
}

impl RateLimitRelease for RedisRateLimiter {
    fn release(&self, scope: &str) {
        let mut conn = match self.client.get_connection() {
            Ok(conn) => conn,
            Err(_) => return,
        };
        let _: Result<i32, _> = redis::cmd("DECR")
            .arg(self.concurrent_key(scope))
            .query(&mut conn);
    }
}

impl RateLimiter for RedisRateLimiter {
    fn try_acquire(&self, scope: &str, rpm: u32, concurrent: u32) -> Option<RateLimitPermit> {
        if rpm == 0 && concurrent == 0 {
            return Some(RateLimitPermit::new(
                scope.to_string(),
                Arc::new(self.clone()),
                false,
            ));
        }
        let mut conn = self.client.get_connection().ok()?;
        let window = self.window_index();
        let count_key = self.count_key(scope, window);
        let concurrent_key = self.concurrent_key(scope);
        let ttl = self.config.rate_limit_window_seconds.max(1);
        let script = Script::new(
            r#"
            local count_key = KEYS[1]
            local concurrent_key = KEYS[2]
            local rpm = tonumber(ARGV[1])
            local concurrent = tonumber(ARGV[2])
            local ttl = tonumber(ARGV[3])
            if rpm > 0 then
                local count = redis.call("INCR", count_key)
                if count == 1 then
                    redis.call("EXPIRE", count_key, ttl)
                end
            if count > rpm then
                redis.call("DECR", count_key)
                return 0
            end
            end
            if concurrent > 0 then
                local c = redis.call("INCR", concurrent_key)
                if c == 1 then
                    redis.call("EXPIRE", concurrent_key, ttl)
                end
                if c > concurrent then
                    redis.call("DECR", concurrent_key)
                    return 0
                end
            end
            return 1
        "#,
        );
        let allowed: i32 = script
            .key(count_key)
            .key(concurrent_key)
            .arg(rpm as i64)
            .arg(concurrent as i64)
            .arg(ttl as i64)
            .invoke(&mut conn)
            .ok()?;

        if allowed != 1 {
            return None;
        }

        Some(RateLimitPermit::new(
            scope.to_string(),
            Arc::new(self.clone()),
            concurrent > 0,
        ))
    }
}

fn _assert_send_sync<T: Send + Sync>() {}

#[allow(dead_code)]
fn _assert_redis_types() {
    _assert_send_sync::<RedisSessionStore>();
    _assert_send_sync::<RedisContextStore>();
    _assert_send_sync::<RedisRateLimiter>();
    _assert_send_sync::<RedisAuditSink>();
}
