use std::collections::HashMap;

use control_plane::{
    AccessMask, Ace, AceType, AddressSpec, Context1mPreference, KeySpec, ProviderSpec, ProviderType,
    SecurityDescriptor, Sid,
};
use kernel::{Protocol, ProviderPlugin, RequestEnvelope};
use kernel_space::ApiKeyProvider;

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

fn build_provider(provider_type: ProviderType, base_url: &str) -> ProviderSpec {
    ProviderSpec {
        id: "p1".to_string(),
        name: "provider".to_string(),
        provider_type,
        priority: 0,
        weight: 1,
        enabled: true,
        group_tag: None,
        allowed_models: Vec::new(),
        model_redirects: HashMap::new(),
        join_claude_pool: false,
        limit_concurrent_sessions: 0,
        limit_rpm: 0,
        limit_concurrent: 0,
        context_1m_preference: Context1mPreference::Inherit,
        security_descriptor: allow_all_descriptor(),
        base_url: base_url.to_string(),
        auth_header: None,
        auth_prefix: None,
        auth_query_param: None,
        default_headers: HashMap::new(),
    }
}

fn build_key(provider_id: &str, secret: &str) -> KeySpec {
    KeySpec {
        id: "k1".to_string(),
        provider_id: provider_id.to_string(),
        name: "key".to_string(),
        secret: secret.to_string(),
        enabled: true,
        priority: 0,
        weight: 1,
        allowed_models: Vec::new(),
        limit_rpm: 0,
        limit_concurrent: 0,
        security_descriptor: allow_all_descriptor(),
    }
}

fn build_address(provider_id: &str, base_url: &str) -> AddressSpec {
    AddressSpec {
        id: "a1".to_string(),
        provider_id: provider_id.to_string(),
        name: "addr".to_string(),
        base_url: base_url.to_string(),
        enabled: true,
        priority: 0,
        weight: 1,
        limit_rpm: 0,
        limit_concurrent: 0,
        security_descriptor: allow_all_descriptor(),
    }
}

fn build_request(path: &str) -> RequestEnvelope {
    RequestEnvelope {
        request_id: "r1".to_string(),
        protocol: Protocol::OpenAi,
        model: "gpt-4".to_string(),
        stream: false,
        session_id: None,
        token_key: Some("user-token".to_string()),
        client_id: Some("client".to_string()),
        client_version: Some("1.0".to_string()),
        is_probe: false,
        is_warmup: false,
        requires_context_1m: false,
        headers: HashMap::from([
            ("authorization".to_string(), "Bearer user".to_string()),
            ("x-client-id".to_string(), "client".to_string()),
        ]),
        raw_body: b"{}".to_vec(),
        kernel_request: None,
        extra: HashMap::from([(String::from("path"), path.to_string())]),
    }
}

#[test]
fn openai_provider_sets_auth_and_path() {
    let provider = ApiKeyProvider::openai();
    let provider_spec = build_provider(ProviderType::OpenAiCompatible, "https://api.openai.com/v1");
    let key = build_key(&provider_spec.id, "secret");
    let address = build_address(&provider_spec.id, "https://api.openai.com/v1");
    let req = build_request("/v1/chat/completions");

    let upstream = provider
        .build_upstream(&req, &provider_spec, &key, &address)
        .expect("upstream");
    assert_eq!(
        upstream.url,
        "https://api.openai.com/v1/chat/completions"
    );
    assert_eq!(
        upstream.headers.get("authorization"),
        Some(&"Bearer secret".to_string())
    );
    assert_eq!(
        upstream.headers.get("content-type"),
        Some(&"application/json".to_string())
    );
    assert!(upstream.headers.get("x-client-id").is_none());
}

#[test]
fn anthropic_provider_sets_headers() {
    let provider = ApiKeyProvider::anthropic();
    let provider_spec = build_provider(ProviderType::Anthropic, "https://api.anthropic.com");
    let key = build_key(&provider_spec.id, "secret");
    let address = build_address(&provider_spec.id, "https://api.anthropic.com");
    let req = build_request("/v1/messages");

    let upstream = provider
        .build_upstream(&req, &provider_spec, &key, &address)
        .expect("upstream");
    assert_eq!(
        upstream.headers.get("x-api-key"),
        Some(&"secret".to_string())
    );
    assert_eq!(
        upstream.headers.get("anthropic-version"),
        Some(&"2023-06-01".to_string())
    );
    assert!(upstream.headers.get("authorization").is_none());
}

#[test]
fn gemini_provider_sets_api_key() {
    let provider = ApiKeyProvider::gemini();
    let provider_spec = build_provider(ProviderType::Gemini, "https://generativelanguage.googleapis.com");
    let key = build_key(&provider_spec.id, "secret");
    let address = build_address(&provider_spec.id, "https://generativelanguage.googleapis.com");
    let req = build_request("/v1beta/models/gemini-pro:generateContent");

    let upstream = provider
        .build_upstream(&req, &provider_spec, &key, &address)
        .expect("upstream");
    assert_eq!(
        upstream.headers.get("x-goog-api-key"),
        Some(&"secret".to_string())
    );
    assert_eq!(
        upstream.headers.get("content-type"),
        Some(&"application/json".to_string())
    );
}

#[test]
fn gemini_query_param_override_disables_header() {
    let provider = ApiKeyProvider::gemini();
    let mut provider_spec = build_provider(ProviderType::Gemini, "https://example.com/v1beta");
    provider_spec.auth_query_param = Some("key".to_string());
    provider_spec.auth_header = Some(String::new());
    let key = build_key(&provider_spec.id, "secret");
    let address = build_address(&provider_spec.id, "https://example.com/v1beta");
    let req = build_request("/v1beta/models/gemini-pro:generateContent");

    let upstream = provider
        .build_upstream(&req, &provider_spec, &key, &address)
        .expect("upstream");
    assert!(upstream.url.contains("key=secret"));
    assert!(upstream.headers.get("x-goog-api-key").is_none());
}
