use std::any::{Any, TypeId};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

pub struct CapabilityRegistry {
    store: HashMap<TypeId, Arc<dyn Any + Send + Sync>>,
}

impl CapabilityRegistry {
    pub fn new() -> Self {
        Self {
            store: HashMap::new(),
        }
    }

    pub fn insert<T: Send + Sync + 'static>(&mut self, value: Arc<T>) {
        self.store.insert(TypeId::of::<T>(), value);
    }

    pub fn get<T: Send + Sync + 'static>(&self) -> Option<Arc<T>> {
        self.store
            .get(&TypeId::of::<T>())
            .and_then(|entry| entry.clone().downcast::<T>().ok())
    }
}

#[derive(Clone, Debug)]
pub struct Event {
    pub name: String,
    pub payload: String,
}

pub trait EventHandler: Send + Sync {
    fn handle(&self, event: &Event);
}

pub struct EventBus {
    handlers: Mutex<HashMap<String, Vec<Arc<dyn EventHandler>>>>,
}

impl EventBus {
    pub fn new() -> Self {
        Self {
            handlers: Mutex::new(HashMap::new()),
        }
    }

    pub fn subscribe(&self, name: &str, handler: Arc<dyn EventHandler>) {
        let mut handlers = self.handlers.lock().expect("event bus lock");
        handlers
            .entry(name.to_string())
            .or_default()
            .push(handler);
    }

    pub fn publish(&self, event: Event) {
        let handlers = self.handlers.lock().expect("event bus lock");
        if let Some(list) = handlers.get(&event.name) {
            for handler in list {
                handler.handle(&event);
            }
        }
    }
}

pub trait KernelPlugin: Send + Sync {
    fn register(&self, registry: &mut CapabilityRegistry);
}

pub struct PluginHost {
    plugins: Vec<Arc<dyn KernelPlugin>>,
}

impl PluginHost {
    pub fn new() -> Self {
        Self { plugins: Vec::new() }
    }

    pub fn register_plugin(&mut self, plugin: Arc<dyn KernelPlugin>) {
        self.plugins.push(plugin);
    }

    pub fn register_all(&self, registry: &mut CapabilityRegistry) {
        for plugin in &self.plugins {
            plugin.register(registry);
        }
    }
}

pub struct KernelRuntime {
    registry: CapabilityRegistry,
    event_bus: EventBus,
    plugin_host: PluginHost,
}

impl KernelRuntime {
    pub fn new() -> Self {
        Self {
            registry: CapabilityRegistry::new(),
            event_bus: EventBus::new(),
            plugin_host: PluginHost::new(),
        }
    }

    pub fn registry(&self) -> &CapabilityRegistry {
        &self.registry
    }

    pub fn registry_mut(&mut self) -> &mut CapabilityRegistry {
        &mut self.registry
    }

    pub fn event_bus(&self) -> &EventBus {
        &self.event_bus
    }

    pub fn plugin_host_mut(&mut self) -> &mut PluginHost {
        &mut self.plugin_host
    }

    pub fn bootstrap(&mut self) {
        self.plugin_host.register_all(&mut self.registry);
    }
}
