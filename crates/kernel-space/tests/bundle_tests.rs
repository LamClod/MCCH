use std::sync::Arc;

use kernel_space::{BasicProtocol, EchoProvider, KernelSpaceBundle, KernelSpacePlugin};
use microkernel::{CapabilityRegistry, KernelPlugin};

#[test]
fn bundle_registers() {
    let bundle = KernelSpaceBundle {
        protocols: vec![Arc::new(BasicProtocol)],
        providers: vec![Arc::new(EchoProvider)],
        guard_plugins: Vec::new(),
    };
    let plugin = KernelSpacePlugin::new(bundle.clone());
    let mut registry = CapabilityRegistry::new();
    plugin.register(&mut registry);
    let stored = registry.get::<KernelSpaceBundle>();
    assert!(stored.is_some());
}

#[test]
fn discover_collects_plugins() {
    let bundle = KernelSpaceBundle::discover();
    assert!(!bundle.protocols.is_empty());
    assert!(!bundle.providers.is_empty());
}
