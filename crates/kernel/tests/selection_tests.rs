use std::collections::HashMap;
use std::sync::Arc;

use control_plane::{
    AccessCheckConfig, AccessChecker, AccessMask, Ace, AceType, CircuitBreakerConfig,
    Context1mPreference, InMemoryHealthStore, InMemoryRateLimiter, ProviderSnapshot, ProviderSpec,
    ProviderType, SecurityDescriptor, SecurityToken, Sid,
};
use kernel::{SelectionCriteria, SelectionEngine, SelectionExclusions};

fn allow_all_descriptor() -> SecurityDescriptor {
    SecurityDescriptor {
        owner_sid: Sid("owner".to_string()),
        group_sid: Sid("group".to_string()),
        dacl: vec![Ace {
            ace_type: AceType::Allow,
            sid: Sid("user".to_string()),
            access_mask: AccessMask::PROVIDER_USE | AccessMask::KEY_USE | AccessMask::ADDRESS_USE,
            condition: None,
        }],
        sacl: Vec::new(),
        mandatory_label: control_plane::IntegrityLevel::Low,
    }
}

fn base_snapshot() -> ProviderSnapshot {
    let provider_a = ProviderSpec {
        id: "p1".to_string(),
        name: "provider-a".to_string(),
        provider_type: ProviderType::OpenAiCompatible,
        priority: 0,
        weight: 1,
        enabled: true,
        group_tag: Some("alpha".to_string()),
        allowed_models: Vec::new(),
        model_redirects: HashMap::new(),
        join_claude_pool: false,
        limit_concurrent_sessions: 0,
        limit_rpm: 0,
        limit_concurrent: 0,
        context_1m_preference: Context1mPreference::Inherit,
        security_descriptor: allow_all_descriptor(),
        base_url: "http://example".to_string(),
        auth_header: None,
        auth_prefix: None,
        auth_query_param: None,
        default_headers: HashMap::new(),
    };

    let provider_b = ProviderSpec {
        id: "p2".to_string(),
        name: "provider-b".to_string(),
        provider_type: ProviderType::Anthropic,
        priority: 0,
        weight: 1,
        enabled: true,
        group_tag: Some("beta".to_string()),
        allowed_models: vec!["claude-3".to_string()],
        model_redirects: HashMap::new(),
        join_claude_pool: false,
        limit_concurrent_sessions: 0,
        limit_rpm: 0,
        limit_concurrent: 0,
        context_1m_preference: Context1mPreference::Inherit,
        security_descriptor: allow_all_descriptor(),
        base_url: "http://example".to_string(),
        auth_header: None,
        auth_prefix: None,
        auth_query_param: None,
        default_headers: HashMap::new(),
    };

    let key = control_plane::KeySpec {
        id: "k1".to_string(),
        provider_id: "p1".to_string(),
        name: "key".to_string(),
        secret: "secret".to_string(),
        enabled: true,
        priority: 0,
        weight: 1,
        allowed_models: Vec::new(),
        limit_rpm: 0,
        limit_concurrent: 0,
        security_descriptor: allow_all_descriptor(),
    };

    let key_b = control_plane::KeySpec {
        id: "k2".to_string(),
        provider_id: "p2".to_string(),
        name: "key".to_string(),
        secret: "secret".to_string(),
        enabled: true,
        priority: 0,
        weight: 1,
        allowed_models: Vec::new(),
        limit_rpm: 0,
        limit_concurrent: 0,
        security_descriptor: allow_all_descriptor(),
    };

    let address = control_plane::AddressSpec {
        id: "a1".to_string(),
        provider_id: "p1".to_string(),
        name: "addr".to_string(),
        base_url: "http://example".to_string(),
        enabled: true,
        priority: 0,
        weight: 1,
        limit_rpm: 0,
        limit_concurrent: 0,
        security_descriptor: allow_all_descriptor(),
    };

    let address_b = control_plane::AddressSpec {
        id: "a2".to_string(),
        provider_id: "p2".to_string(),
        name: "addr".to_string(),
        base_url: "http://example".to_string(),
        enabled: true,
        priority: 0,
        weight: 1,
        limit_rpm: 0,
        limit_concurrent: 0,
        security_descriptor: allow_all_descriptor(),
    };

    let link = control_plane::KeyAddressLink {
        provider_id: "p1".to_string(),
        key_id: "k1".to_string(),
        address_id: "a1".to_string(),
        priority: 0,
        weight: 1,
        enabled: true,
    };

    let link_b = control_plane::KeyAddressLink {
        provider_id: "p2".to_string(),
        key_id: "k2".to_string(),
        address_id: "a2".to_string(),
        priority: 0,
        weight: 1,
        enabled: true,
    };

    ProviderSnapshot::new(
        vec![provider_a, provider_b],
        vec![key, key_b],
        vec![address, address_b],
        vec![link, link_b],
    )
}

fn base_token() -> SecurityToken {
    SecurityToken {
        token_id: "t1".to_string(),
        user_sid: Sid("user".to_string()),
        group_sids: Vec::new(),
        restricted_sids: Vec::new(),
        privileges: Vec::new(),
        integrity_level: control_plane::IntegrityLevel::Medium,
        claims: HashMap::new(),
        flags: control_plane::TokenFlags::empty(),
    }
}

#[test]
fn selection_honors_group_filter() {
    let snapshot = base_snapshot();
    let access = Arc::new(AccessChecker::new(AccessCheckConfig::default()));
    let health = InMemoryHealthStore::shared(CircuitBreakerConfig::default());
    let rate_limiter = InMemoryRateLimiter::shared(60);
    let selector = SelectionEngine::new(access, health, rate_limiter);

    let criteria = SelectionCriteria {
        model: "gpt-4".to_string(),
        protocol: kernel::Protocol::OpenAi,
        group: Some("alpha".to_string()),
        requires_context_1m: false,
    };
    let decision = selector
        .select(&snapshot, &criteria, &SelectionExclusions::default(), Some(&base_token()))
        .expect("selection");
    assert_eq!(decision.provider.id, "p1");
}

#[test]
fn selection_filters_by_protocol() {
    let snapshot = base_snapshot();
    let access = Arc::new(AccessChecker::new(AccessCheckConfig::default()));
    let health = InMemoryHealthStore::shared(CircuitBreakerConfig::default());
    let rate_limiter = InMemoryRateLimiter::shared(60);
    let selector = SelectionEngine::new(access, health, rate_limiter);

    let criteria = SelectionCriteria {
        model: "claude-3".to_string(),
        protocol: kernel::Protocol::Anthropic,
        group: None,
        requires_context_1m: false,
    };
    let decision = selector
        .select(&snapshot, &criteria, &SelectionExclusions::default(), Some(&base_token()))
        .expect("selection");
    assert_eq!(decision.provider.id, "p2");
}
