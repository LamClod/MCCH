use std::collections::HashSet;
use std::sync::Arc;

use rand::Rng;

use control_plane::{
    AccessCheckEngine, AccessDecision, AccessMask, AddressSpec, Context1mPreference, HealthStore,
    KeyAddressLink, KeySpec, ProviderSnapshot, ProviderSpec, RateLimitPermit, RateLimiter,
    SecurityToken,
};

use crate::Protocol;

pub struct SelectionDecision {
    pub provider: ProviderSpec,
    pub key: KeySpec,
    pub address: AddressSpec,
    pub resolved_model: String,
    pub provider_permit: Option<RateLimitPermit>,
    pub key_permit: Option<RateLimitPermit>,
    pub address_permit: Option<RateLimitPermit>,
}

pub struct SelectionCriteria {
    pub model: String,
    pub protocol: Protocol,
    pub group: Option<String>,
    pub requires_context_1m: bool,
}

#[derive(Debug, thiserror::Error)]
pub enum SelectorError {
    #[error("no available provider")]
    NoProvider,
}

#[derive(Default)]
pub struct SelectionExclusions {
    pub providers: HashSet<String>,
    pub keys: HashSet<String>,
    pub addresses: HashSet<String>,
}

pub struct SelectionEngine {
    access: Arc<dyn AccessCheckEngine>,
    health: Arc<dyn HealthStore>,
    rate_limiter: Arc<dyn RateLimiter>,
}

impl SelectionEngine {
    pub fn new(
        access: Arc<dyn AccessCheckEngine>,
        health: Arc<dyn HealthStore>,
        rate_limiter: Arc<dyn RateLimiter>,
    ) -> Self {
        Self {
            access,
            health,
            rate_limiter,
        }
    }

    pub fn select(
        &self,
        snapshot: &ProviderSnapshot,
        criteria: &SelectionCriteria,
        exclusions: &SelectionExclusions,
        token: Option<&SecurityToken>,
    ) -> Result<SelectionDecision, SelectorError> {
        let mut candidates: Vec<ProviderSpec> = snapshot
            .providers
            .iter()
            .filter(|p| p.enabled && !exclusions.providers.contains(&p.id))
            .filter(|p| supports_model(p, &criteria.model))
            .filter(|p| format_compatible(criteria.protocol, p))
            .filter(|p| group_allows(criteria.group.as_deref(), p.group_tag.as_deref()))
            .filter(|p| {
                !criteria.requires_context_1m
                    || p.context_1m_preference != Context1mPreference::Disabled
            })
            .filter(|p| self.health.is_available(&p.id))
            .filter(|p| {
                if let Some(token) = token {
                    self.access
                        .check(token, &p.security_descriptor, AccessMask::PROVIDER_USE)
                        == AccessDecision::Allow
                } else {
                    true
                }
            })
            .cloned()
            .collect();

        if candidates.is_empty() {
            return Err(SelectorError::NoProvider);
        }

        loop {
            if candidates.is_empty() {
                return Err(SelectorError::NoProvider);
            }
            candidates.sort_by(|a, b| (a.priority, &a.id).cmp(&(b.priority, &b.id)));
            let best_priority = candidates[0].priority;
            let mut same_priority: Vec<ProviderSpec> = candidates
                .iter()
                .filter(|p| p.priority == best_priority)
                .cloned()
                .collect();
            if same_priority.is_empty() {
                return Err(SelectorError::NoProvider);
            }
            let selected = weighted_pick(&mut same_priority, |p| p.weight);
            if let Some(decision) = self.select_for_provider(
                snapshot,
                &selected,
                criteria,
                exclusions,
                token,
            ) {
                return Ok(decision);
            }
            candidates.retain(|p| p.id != selected.id);
        }
    }

    pub fn select_for_provider_id(
        &self,
        snapshot: &ProviderSnapshot,
        provider_id: &str,
        criteria: &SelectionCriteria,
        exclusions: &SelectionExclusions,
        token: Option<&SecurityToken>,
    ) -> Option<SelectionDecision> {
        let provider = snapshot.providers.iter().find(|p| p.id == provider_id)?;
        if !provider.enabled || exclusions.providers.contains(&provider.id) {
            return None;
        }
        if !supports_model(provider, &criteria.model)
            || !format_compatible(criteria.protocol, provider)
            || !group_allows(criteria.group.as_deref(), provider.group_tag.as_deref())
            || (criteria.requires_context_1m
                && provider.context_1m_preference == Context1mPreference::Disabled)
        {
            return None;
        }
        if !self.health.is_available(&provider.id) {
            return None;
        }
        if let Some(token) = token {
            if self
                .access
                .check(token, &provider.security_descriptor, AccessMask::PROVIDER_USE)
                != AccessDecision::Allow
            {
                return None;
            }
        }
        self.select_for_provider(snapshot, provider, criteria, exclusions, token)
    }

    fn select_for_provider(
        &self,
        snapshot: &ProviderSnapshot,
        provider: &ProviderSpec,
        criteria: &SelectionCriteria,
        exclusions: &SelectionExclusions,
        token: Option<&SecurityToken>,
    ) -> Option<SelectionDecision> {
        let resolved_model = resolve_model(provider, &criteria.model);
        let keys = snapshot
            .keys_by_provider
            .get(&provider.id)
            .cloned()
            .unwrap_or_default();

        let mut candidates: Vec<KeySpec> = keys
            .into_iter()
            .filter(|k| k.enabled && !exclusions.keys.contains(&k.id))
            .filter(|k| supports_key_model(k, &resolved_model))
            .filter(|k| self.health.is_available(&key_scope(&k.id)))
            .filter(|k| {
                if let Some(token) = token {
                    self.access
                        .check(token, &k.security_descriptor, AccessMask::KEY_USE)
                        == AccessDecision::Allow
                } else {
                    true
                }
            })
            .collect();

        if candidates.is_empty() {
            return None;
        }

        loop {
            if candidates.is_empty() {
                return None;
            }
            candidates.sort_by(|a, b| (a.priority, &a.id).cmp(&(b.priority, &b.id)));
            let best_priority = candidates[0].priority;
            let mut same_priority: Vec<KeySpec> = candidates
                .iter()
                .filter(|k| k.priority == best_priority)
                .cloned()
                .collect();
            if same_priority.is_empty() {
                return None;
            }
            let selected = weighted_pick(&mut same_priority, |k| k.weight);
            if let Some(decision) = self.select_address_for_key(
                snapshot,
                provider,
                &selected,
                &resolved_model,
                exclusions,
                token,
            ) {
                return Some(decision);
            }
            candidates.retain(|k| k.id != selected.id);
        }
    }

    fn select_address_for_key(
        &self,
        snapshot: &ProviderSnapshot,
        provider: &ProviderSpec,
        key: &KeySpec,
        resolved_model: &str,
        exclusions: &SelectionExclusions,
        token: Option<&SecurityToken>,
    ) -> Option<SelectionDecision> {
        let provider_permit = self.rate_limiter.try_acquire(
            &provider_scope(&provider.id),
            provider.limit_rpm,
            provider.limit_concurrent,
        )?;
        let key_permit = self
            .rate_limiter
            .try_acquire(&key_scope(&key.id), key.limit_rpm, key.limit_concurrent)?;

        let links = snapshot
            .links_by_key
            .get(&key.id)
            .cloned()
            .unwrap_or_default();

        let mut candidates = Vec::new();
        for link in links {
            if !link.enabled || link.provider_id != provider.id {
                continue;
            }
            let Some(address) = snapshot.addresses_by_id.get(&link.address_id) else {
                continue;
            };
            if !address.enabled || exclusions.addresses.contains(&address.id) {
                continue;
            }
            if !self.health.is_available(&address_scope(&address.id)) {
                continue;
            }
            if let Some(token) = token {
                if self
                    .access
                    .check(token, &address.security_descriptor, AccessMask::ADDRESS_USE)
                    != AccessDecision::Allow
                {
                    continue;
                }
            }
            candidates.push(AddressCandidate::new(address.clone(), link.clone()));
        }

        if candidates.is_empty() {
            drop(key_permit);
            return None;
        }

        loop {
            if candidates.is_empty() {
                drop(key_permit);
                return None;
            }
            candidates.sort_by(|a, b| (a.priority, &a.address.id).cmp(&(b.priority, &b.address.id)));
            let best_priority = candidates[0].priority;
            let mut same_priority: Vec<AddressCandidate> = candidates
                .iter()
                .filter(|c| c.priority == best_priority)
                .cloned()
                .collect();
            if same_priority.is_empty() {
                drop(key_permit);
                return None;
            }
            let selected = weighted_pick(&mut same_priority, |c| c.weight);
            let address_permit = self
                .rate_limiter
                .try_acquire(
                    &address_scope(&selected.address.id),
                    selected.address.limit_rpm,
                    selected.address.limit_concurrent,
                )?;
            return Some(SelectionDecision {
                provider: provider.clone(),
                key: key.clone(),
                address: selected.address,
                resolved_model: resolved_model.to_string(),
                provider_permit: Some(provider_permit),
                key_permit: Some(key_permit),
                address_permit: Some(address_permit),
            });
        }
    }
}

#[derive(Clone, Debug)]
struct AddressCandidate {
    address: AddressSpec,
    weight: i32,
    priority: i32,
}

impl AddressCandidate {
    fn new(address: AddressSpec, link: KeyAddressLink) -> Self {
        let priority = link.priority.saturating_add(address.priority);
        let weight = combined_weight(link.weight, address.weight);
        Self {
            address,
            weight,
            priority,
        }
    }
}

fn combined_weight(link_weight: i32, address_weight: i32) -> i32 {
    let lw = link_weight.max(1) as i64;
    let aw = address_weight.max(1) as i64;
    let combined = lw.saturating_mul(aw);
    combined.min(i32::MAX as i64) as i32
}

fn key_scope(id: &str) -> String {
    format!("key:{id}")
}

fn address_scope(id: &str) -> String {
    format!("addr:{id}")
}

fn provider_scope(id: &str) -> String {
    format!("provider:{id}")
}

fn supports_model(provider: &ProviderSpec, model: &str) -> bool {
    let is_claude_model = model.starts_with("claude-");
    let explicit = provider
        .allowed_models
        .iter()
        .any(|m| m == model)
        || provider.model_redirects.contains_key(model);

    match provider.provider_type {
        control_plane::ProviderType::Anthropic => {
            if explicit {
                return true;
            }
            if provider.allowed_models.is_empty() {
                return is_claude_model;
            }
            false
        }
        _ => {
            if is_claude_model && !provider.join_claude_pool {
                return false;
            }
            if provider.allowed_models.is_empty() {
                return true;
            }
            explicit
        }
    }
}

fn supports_key_model(key: &KeySpec, model: &str) -> bool {
    if key.allowed_models.is_empty() {
        return true;
    }
    key.allowed_models.iter().any(|m| m == model)
}

fn resolve_model(provider: &ProviderSpec, model: &str) -> String {
    provider
        .model_redirects
        .get(model)
        .cloned()
        .unwrap_or_else(|| model.to_string())
}

fn format_compatible(protocol: Protocol, provider: &ProviderSpec) -> bool {
    match protocol {
        Protocol::Anthropic => provider.provider_type == control_plane::ProviderType::Anthropic,
        Protocol::OpenAi => {
            provider.provider_type == control_plane::ProviderType::OpenAiCompatible
        }
        Protocol::Codex => provider.provider_type == control_plane::ProviderType::Codex,
        Protocol::Gemini => provider.provider_type == control_plane::ProviderType::Gemini,
    }
}

fn group_allows(group: Option<&str>, provider_tag: Option<&str>) -> bool {
    let Some(group) = group else {
        return true;
    };
    let group_list = parse_group_list(group);
    if group_list.iter().any(|g| g == "all") {
        return true;
    }
    let provider_tags = provider_tag
        .map(parse_group_list)
        .unwrap_or_else(|| vec!["default".to_string()]);
    provider_tags
        .iter()
        .any(|tag| group_list.iter().any(|g| g == tag))
}

fn parse_group_list(value: &str) -> Vec<String> {
    value
        .split(',')
        .map(|entry| entry.trim().to_string())
        .filter(|entry| !entry.is_empty())
        .collect()
}

fn weighted_pick<T: Clone, F: Fn(&T) -> i32>(items: &mut [T], weight_fn: F) -> T {
    let total: i32 = items.iter().map(|p| weight_fn(p).max(1)).sum();
    let seed = rand::thread_rng().gen_range(0..total.max(1));
    let mut cursor = seed;

    for item in items.iter() {
        let weight = weight_fn(item).max(1);
        if cursor < weight {
            return item.clone();
        }
        cursor -= weight;
    }

    items[0].clone()
}
