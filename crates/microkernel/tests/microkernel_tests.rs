use std::sync::{Arc, Mutex};

use microkernel::{CapabilityRegistry, Event, EventBus, EventHandler};

struct CounterHandler {
    count: Arc<Mutex<u32>>,
}

impl EventHandler for CounterHandler {
    fn handle(&self, _event: &Event) {
        let mut guard = self.count.lock().expect("count lock");
        *guard += 1;
    }
}

#[test]
fn capability_registry_roundtrip() {
    let mut registry = CapabilityRegistry::new();
    let value = Arc::new(String::from("ok"));
    registry.insert(value.clone());
    let fetched = registry.get::<String>().expect("value");
    assert_eq!(fetched.as_str(), "ok");
}

#[test]
fn event_bus_dispatches() {
    let bus = EventBus::new();
    let counter = Arc::new(Mutex::new(0));
    bus.subscribe(
        "tick",
        Arc::new(CounterHandler {
            count: counter.clone(),
        }),
    );
    bus.publish(Event {
        name: "tick".to_string(),
        payload: "x".to_string(),
    });
    let guard = counter.lock().expect("count lock");
    assert_eq!(*guard, 1);
}
