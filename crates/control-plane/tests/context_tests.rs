use control_plane::{ContextMessage, ContextStore, InMemoryContextStore};

#[test]
fn context_store_appends_and_truncates() {
    let store = InMemoryContextStore::new();
    let messages = vec![
        ContextMessage {
            role: "user".to_string(),
            content: "a".to_string(),
        },
        ContextMessage {
            role: "assistant".to_string(),
            content: "b".to_string(),
        },
    ];
    store.append("s1", &messages);
    store.append(
        "s1",
        &[ContextMessage {
            role: "user".to_string(),
            content: "c".to_string(),
        }],
    );

    let loaded = store.load("s1");
    assert_eq!(loaded.len(), 3);

    store.truncate("s1", 2);
    let truncated = store.load("s1");
    assert_eq!(truncated.len(), 2);
    assert_eq!(truncated[0].content, "b");
}
