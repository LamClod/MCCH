use control_plane::{load_from_system_config, SystemConfigLoader};

#[test]
fn bootstrap_defaults_to_sqlite_and_memory() {
    let config = SystemConfigLoader::from_str(
        r#"
        [storage]
        sqlite_path = ":memory:"
        [tsdb]
        sqlite_path = ":memory:"
        "#,
    )
    .expect("config");
    let bundle = load_from_system_config(&config, None).expect("bundle");
    let events = bundle.audit.list();
    assert!(events.is_empty());
}
