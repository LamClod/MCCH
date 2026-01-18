use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use control_plane::{
    AccessCheckConfig, AccessChecker, AccessMask, Ace, AceType, CircuitBreakerConfig,
    Context1mPreference, ContextStore, GuardConfig, InMemoryAuditSink, InMemoryContextStore,
    InMemoryHealthStore, InMemoryPolicyService, InMemoryProviderRegistry, InMemoryRateLimiter,
    InMemorySessionStore, InMemoryTsdbSink, ProviderSnapshot, ProviderSpec, ProviderType,
    SecurityDescriptor, SecurityToken, Sid, StaticSecurityAuthority, ToolPolicy,
};
use kernel::{
    ContentBlock, Forwarder, HttpRequest, Kernel, KernelConfig, KernelRequest, KernelResponse,
    Message, Protocol, ProtocolPlugin, ProviderPlugin, RequestEnvelope, ToolSpec, UpstreamRequest,
    UpstreamResponse,
};
use kernel::ResponseBody;

struct TestProtocol;

impl ProtocolPlugin for TestProtocol {
    fn protocol(&self) -> Protocol {
        Protocol::Anthropic
    }

    fn matches(&self, method: &str, path: &str) -> bool {
        method == "POST" && path == "/v1/messages"
    }

    fn decode(&self, req: HttpRequest) -> Result<RequestEnvelope, kernel::KernelError> {
        let token_key = req.headers.get("authorization").map(|v| v.replace("Bearer ", ""));
        let tool_name = req.headers.get("x-tool").cloned();
        let session_id = req.headers.get("x-session-id").cloned();
        let is_probe = header_is_true(&req.headers, "x-probe");
        let is_warmup = header_is_true(&req.headers, "x-warmup");
        let requires_context_1m = header_is_true(&req.headers, "x-context-1m");
        let kernel_request = tool_name.map(|name| KernelRequest {
            messages: vec![Message {
                role: "user".to_string(),
                content: vec![ContentBlock::ToolUse {
                    name: name.clone(),
                    arguments: "{}".to_string(),
                }],
            }],
            tools: vec![ToolSpec { name }],
        });

        Ok(RequestEnvelope {
            request_id: String::new(),
            protocol: Protocol::Anthropic,
            model: "claude-3".to_string(),
            stream: false,
            session_id,
            token_key,
            client_id: None,
            client_version: None,
            is_probe,
            is_warmup,
            requires_context_1m,
            headers: req.headers,
            raw_body: req.body,
            kernel_request,
            extra: HashMap::from([(String::from("path"), String::from("/v1/messages"))]),
        })
    }

    fn encode(&self, response: KernelResponse, _req: &RequestEnvelope) -> kernel::HttpResponse {
        kernel::HttpResponse {
            status: response.status,
            headers: response.headers,
            body: response.body,
        }
    }
}

struct TestProvider;

impl ProviderPlugin for TestProvider {
    fn provider_type(&self) -> ProviderType {
        ProviderType::Anthropic
    }

    fn build_upstream(
        &self,
        req: &RequestEnvelope,
        _provider: &ProviderSpec,
        _key: &control_plane::KeySpec,
        _address: &control_plane::AddressSpec,
    ) -> Result<UpstreamRequest, kernel::KernelError> {
        Ok(UpstreamRequest {
            method: "POST".to_string(),
            url: "http://example".to_string(),
            headers: req.headers.clone(),
            body: req.raw_body.clone(),
            stream: req.stream,
        })
    }

    fn map_response(
        &self,
        upstream: UpstreamResponse,
        _req: &RequestEnvelope,
        _provider: &ProviderSpec,
    ) -> Result<KernelResponse, kernel::KernelError> {
        Ok(KernelResponse {
            status: upstream.status,
            headers: upstream.headers,
            body: upstream.body,
        })
    }
}

struct TestForwarder;

#[async_trait]
impl Forwarder for TestForwarder {
    async fn send(&self, _upstream: &UpstreamRequest) -> Result<UpstreamResponse, kernel::KernelError> {
        Ok(UpstreamResponse {
            status: 200,
            headers: HashMap::new(),
            body: ResponseBody::Bytes(b"ok".to_vec()),
        })
    }
}

fn header_is_true(headers: &HashMap<String, String>, key: &str) -> bool {
    headers
        .get(key)
        .map(|value| matches!(value.as_str(), "1" | "true" | "yes" | "on"))
        .unwrap_or(false)
}

fn allow_all_descriptor() -> SecurityDescriptor {
    SecurityDescriptor {
        owner_sid: Sid("owner".to_string()),
        group_sid: Sid("group".to_string()),
        dacl: vec![Ace {
            ace_type: AceType::Allow,
            sid: Sid("user".to_string()),
            access_mask: AccessMask::PROVIDER_USE
                | AccessMask::KEY_USE
                | AccessMask::ADDRESS_USE,
            condition: None,
        }],
        sacl: Vec::new(),
        mandatory_label: control_plane::IntegrityLevel::Low,
    }
}

struct TestHarness {
    kernel: Kernel,
    policy: Arc<InMemoryPolicyService>,
    context_store: Arc<InMemoryContextStore>,
}

fn build_kernel() -> TestHarness {
    let token = SecurityToken {
        token_id: "t1".to_string(),
        user_sid: Sid("user".to_string()),
        group_sids: Vec::new(),
        restricted_sids: Vec::new(),
        privileges: Vec::new(),
        integrity_level: control_plane::IntegrityLevel::Medium,
        claims: HashMap::new(),
        flags: control_plane::TokenFlags::empty(),
    };

    let mut tokens = HashMap::new();
    tokens.insert("token".to_string(), token);

    let security = StaticSecurityAuthority::shared(tokens);
    let access = Arc::new(AccessChecker::new(AccessCheckConfig::default()));
    let policy = InMemoryPolicyService::shared();
    policy.set_guard_config(GuardConfig::empty());

    let provider = ProviderSpec {
        id: "p1".to_string(),
        name: "provider".to_string(),
        provider_type: ProviderType::Anthropic,
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

    let link = control_plane::KeyAddressLink {
        provider_id: "p1".to_string(),
        key_id: "k1".to_string(),
        address_id: "a1".to_string(),
        priority: 0,
        weight: 1,
        enabled: true,
    };

    let snapshot = ProviderSnapshot::new(vec![provider], vec![key], vec![address], vec![link]);
    let providers = InMemoryProviderRegistry::shared(snapshot);

    let sessions = InMemorySessionStore::shared();
    let rate_limiter = InMemoryRateLimiter::shared(60);
    let health = InMemoryHealthStore::shared(CircuitBreakerConfig::default());
    let audit = InMemoryAuditSink::shared();
    let metrics = InMemoryTsdbSink::shared();
    let context_store = InMemoryContextStore::shared();
    let forwarder = Arc::new(TestForwarder);

    let mut kernel = Kernel::new(
        KernelConfig::default(),
        security,
        access,
        policy.clone(),
        providers,
        sessions,
        rate_limiter,
        health,
        audit,
        metrics,
        context_store.clone(),
        forwarder,
    );

    kernel.register_protocol_plugin(Arc::new(TestProtocol));
    kernel.register_provider_plugin(Arc::new(TestProvider));

    TestHarness {
        kernel,
        policy,
        context_store,
    }
}

#[tokio::test]
async fn kernel_flow_success() {
    let harness = build_kernel();
    let request = HttpRequest {
        method: "POST".to_string(),
        path: "/v1/messages".to_string(),
        headers: HashMap::from([(String::from("authorization"), String::from("Bearer token"))]),
        body: b"hello".to_vec(),
    };

    let response = harness.kernel.handle_http(request).await.expect("response");
    assert_eq!(response.status, 200);
    assert_eq!(response.body.into_bytes_async().await, b"ok");
}

#[tokio::test]
async fn sensitive_word_blocks() {
    let harness = build_kernel();
    harness
        .policy
        .set_sensitive_words(vec!["secret".to_string()]);

    let request = HttpRequest {
        method: "POST".to_string(),
        path: "/v1/messages".to_string(),
        headers: HashMap::from([(String::from("authorization"), String::from("Bearer token"))]),
        body: b"secret".to_vec(),
    };

    let result = harness.kernel.handle_http(request).await;
    assert!(result.is_err());
}

#[tokio::test]
async fn tool_policy_denies() {
    let harness = build_kernel();
    let mut policy = ToolPolicy::allow_all();
    policy.deny.insert("danger".to_string());
    harness.policy.set_tool_policy("t1", policy);

    let request = HttpRequest {
        method: "POST".to_string(),
        path: "/v1/messages".to_string(),
        headers: HashMap::from([
            (String::from("authorization"), String::from("Bearer token")),
            (String::from("x-tool"), String::from("danger")),
        ]),
        body: b"hello".to_vec(),
    };

    let result = harness.kernel.handle_http(request).await;
    assert!(result.is_err());
}

#[tokio::test]
async fn warmup_returns_early() {
    let harness = build_kernel();
    let request = HttpRequest {
        method: "POST".to_string(),
        path: "/v1/messages".to_string(),
        headers: HashMap::from([
            (String::from("authorization"), String::from("Bearer token")),
            (String::from("x-warmup"), String::from("true")),
        ]),
        body: b"hello".to_vec(),
    };

    let response = harness.kernel.handle_http(request).await.expect("response");
    assert_eq!(response.status, 200);
    assert_eq!(
        response.body.into_bytes_async().await,
        b"{\"status\":\"warmup\"}".to_vec()
    );
}

#[tokio::test]
async fn probe_returns_early() {
    let harness = build_kernel();
    let request = HttpRequest {
        method: "POST".to_string(),
        path: "/v1/messages".to_string(),
        headers: HashMap::from([
            (String::from("authorization"), String::from("Bearer token")),
            (String::from("x-probe"), String::from("true")),
        ]),
        body: b"hello".to_vec(),
    };

    let response = harness.kernel.handle_http(request).await.expect("response");
    assert_eq!(response.status, 200);
    assert_eq!(
        response.body.into_bytes_async().await,
        b"{\"input_tokens\":0}".to_vec()
    );
}

#[tokio::test]
async fn request_filter_blocks() {
    use control_plane::{FilterAction, RequestFilterRule};

    let harness = build_kernel();
    harness.policy.set_request_filters(vec![RequestFilterRule {
        pattern: "secret".to_string(),
        action: FilterAction::Block,
        case_sensitive: false,
    }]);

    let request = HttpRequest {
        method: "POST".to_string(),
        path: "/v1/messages".to_string(),
        headers: HashMap::from([(String::from("authorization"), String::from("Bearer token"))]),
        body: b"secret".to_vec(),
    };

    let result = harness.kernel.handle_http(request).await;
    assert!(result.is_err());
}

#[tokio::test]
async fn context_store_appends_on_success() {
    let harness = build_kernel();
    let request = HttpRequest {
        method: "POST".to_string(),
        path: "/v1/messages".to_string(),
        headers: HashMap::from([
            (String::from("authorization"), String::from("Bearer token")),
            (String::from("x-session-id"), String::from("s-1")),
        ]),
        body: b"hello".to_vec(),
    };

    let _response = harness.kernel.handle_http(request).await.expect("response");
    let stored = harness.context_store.load("s-1");
    assert_eq!(stored.len(), 1);
    assert_eq!(stored[0].role, "user");
}
