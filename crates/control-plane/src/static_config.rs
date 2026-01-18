#[derive(Clone, Debug)]
pub struct StaticConfigItem {
    pub key: &'static str,
    pub description: &'static str,
    pub value_type: &'static str,
    pub default_value: &'static str,
}

pub static STATIC_CONFIG_TABLE: &[StaticConfigItem] = &[
    StaticConfigItem {
        key: "storage.dsn",
        description: "Primary database connection string",
        value_type: "string",
        default_value: "",
    },
    StaticConfigItem {
        key: "storage.sqlite_path",
        description: "SQLite database path (used when storage.dsn is empty)",
        value_type: "string",
        default_value: "mcch.sqlite",
    },
    StaticConfigItem {
        key: "cache.redis_url",
        description: "Redis connection string",
        value_type: "string",
        default_value: "",
    },
    StaticConfigItem {
        key: "tsdb.endpoint",
        description: "External time series endpoint",
        value_type: "string",
        default_value: "",
    },
    StaticConfigItem {
        key: "tsdb.sqlite_path",
        description: "Embedded TSDB SQLite path (used when tsdb.endpoint is empty)",
        value_type: "string",
        default_value: "mcch_tsdb.sqlite",
    },
    StaticConfigItem {
        key: "tsdb.timeout_ms",
        description: "TSDB connection timeout in milliseconds",
        value_type: "number",
        default_value: "1000",
    },
    StaticConfigItem {
        key: "security.kernel_token",
        description: "Kernel bootstrap token",
        value_type: "string",
        default_value: "",
    },
    StaticConfigItem {
        key: "security.master_key",
        description: "Master encryption key",
        value_type: "string",
        default_value: "",
    },
    StaticConfigItem {
        key: "runtime.thread_pool",
        description: "Runtime worker threads",
        value_type: "number",
        default_value: "8",
    },
    StaticConfigItem {
        key: "runtime.cache_ttl_seconds",
        description: "Cache TTL for configuration snapshots",
        value_type: "number",
        default_value: "30",
    },
    StaticConfigItem {
        key: "bootstrap.seed_on_start",
        description: "Seed business data into database on first start",
        value_type: "boolean",
        default_value: "true",
    },
];
