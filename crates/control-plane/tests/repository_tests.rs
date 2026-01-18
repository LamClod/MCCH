use control_plane::{
    seed_if_empty, BusinessRepository, BusinessSnapshot, GuardConfig, InMemoryBusinessRepository,
};

#[test]
fn seed_if_empty_writes_snapshot() {
    let repo = InMemoryBusinessRepository::new(BusinessSnapshot::default());
    let seed = BusinessSnapshot {
        guard_config: GuardConfig {
            steps: vec!["auth".to_string()],
            count_tokens_steps: Vec::new(),
        },
        ..BusinessSnapshot::default()
    };

    let seeded = seed_if_empty(&repo, &seed).expect("seed");
    assert!(seeded);

    let loaded = repo.load_snapshot().expect("snapshot");
    assert_eq!(loaded.guard_config.steps.len(), 1);

    let seeded_again = seed_if_empty(&repo, &seed).expect("seed");
    assert!(!seeded_again);
}
