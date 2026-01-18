use std::sync::Arc;

use kernel::{GuardStepPlugin, ProtocolPlugin, ProviderPlugin};

pub struct ProtocolFactory {
    pub build: fn() -> Arc<dyn ProtocolPlugin>,
}

pub struct ProviderFactory {
    pub build: fn() -> Arc<dyn ProviderPlugin>,
}

pub struct GuardFactory {
    pub build: fn() -> Arc<dyn GuardStepPlugin>,
}

inventory::collect!(ProtocolFactory);
inventory::collect!(ProviderFactory);
inventory::collect!(GuardFactory);

pub fn collect_protocols() -> Vec<Arc<dyn ProtocolPlugin>> {
    inventory::iter::<ProtocolFactory>
        .into_iter()
        .map(|factory| (factory.build)())
        .collect()
}

pub fn collect_providers() -> Vec<Arc<dyn ProviderPlugin>> {
    inventory::iter::<ProviderFactory>
        .into_iter()
        .map(|factory| (factory.build)())
        .collect()
}

pub fn collect_guards() -> Vec<Arc<dyn GuardStepPlugin>> {
    inventory::iter::<GuardFactory>
        .into_iter()
        .map(|factory| (factory.build)())
        .collect()
}
