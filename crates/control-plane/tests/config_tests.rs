use control_plane::{ConfigError, SystemConfigLoader};

#[test]
fn config_loader_accepts_valid_keys() {
    let input = r#"
[storage]
dsn = "sqlite://local"
sqlite_path = "mcch.sqlite"
[runtime]
thread_pool = 4
cache_ttl_seconds = 10
[bootstrap]
seed_on_start = true
[tsdb]
sqlite_path = "mcch_tsdb.sqlite"
"#;
    let config = SystemConfigLoader::from_str(input).expect("config");
    assert_eq!(config.get_string("storage.dsn"), "sqlite://local");
    assert_eq!(config.get_number("runtime.thread_pool"), 4);
    assert!(config.get_bool("bootstrap.seed_on_start"));
}

#[test]
fn config_loader_rejects_unknown_key() {
    let input = r#"
unknown = { value = "x" }
"#;
    let err = SystemConfigLoader::from_str(input).expect_err("error");
    match err {
        ConfigError::UnknownKey(key) => assert_eq!(key, "unknown.value"),
        _ => panic!("expected unknown key error"),
    }
}

#[test]
fn config_loader_rejects_type_mismatch() {
    let input = r#"
runtime = { thread_pool = "x" }
"#;
    let err = SystemConfigLoader::from_str(input).expect_err("error");
    match err {
        ConfigError::TypeMismatch(key, _) => assert_eq!(key, "runtime.thread_pool"),
        _ => panic!("expected type mismatch"),
    }
}
