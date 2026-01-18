use control_plane::{InMemorySessionStore, SessionStore};

#[test]
fn session_binding_is_sticky() {
    let store = InMemorySessionStore::new();
    store.bind_on_success("s1", "p1");
    store.bind_on_success("s1", "p2");
    let binding = store.get_binding("s1").expect("binding");
    assert_eq!(binding, "p1");
}

#[test]
fn session_concurrency_limits() {
    let store = InMemorySessionStore::new();
    assert!(store.acquire_concurrency("p1", "s1", 1));
    assert!(!store.acquire_concurrency("p1", "s2", 1));
    store.release_concurrency("p1", "s1");
    assert!(store.acquire_concurrency("p1", "s2", 1));
}

#[test]
fn session_sequence_increments() {
    let store = InMemorySessionStore::new();
    let first = store.next_sequence("s1");
    let second = store.next_sequence("s1");
    assert_eq!(first, 1);
    assert_eq!(second, 2);
}
