use control_plane::{BusinessRepository, BusinessSnapshot, SqliteBusinessRepository};

#[test]
fn sqlite_repository_roundtrip() {
    let repo = SqliteBusinessRepository::open(":memory:").expect("repo");
    repo.ensure_schema().expect("schema");
    let snapshot = BusinessSnapshot::default();
    repo.save_snapshot(&snapshot).expect("save");
    let loaded = repo.load_snapshot().expect("load");
    assert_eq!(loaded.tokens.len(), snapshot.tokens.len());
}
