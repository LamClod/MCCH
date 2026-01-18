use std::collections::HashMap;
use std::sync::Arc;

mod protocols;
mod providers;
mod discovery;

use control_plane::ProviderType;
use kernel::{
    GuardStepPlugin, HttpRequest, KernelError, KernelRequest, KernelResponse, Protocol,
    ProtocolPlugin, ProviderPlugin, RequestEnvelope, ToolSpec, UpstreamRequest, UpstreamResponse,
};
use microkernel::{CapabilityRegistry, KernelPlugin};
pub use protocols::{AnthropicProtocol, CodexResponsesProtocol, GeminiProtocol, OpenAiChatProtocol};
pub use providers::{ApiKeyProvider, BearerProvider};
pub use discovery::{GuardFactory, ProtocolFactory, ProviderFactory};

#[derive(Clone)]
pub struct KernelSpaceBundle {
    pub protocols: Vec<Arc<dyn ProtocolPlugin>>,
    pub providers: Vec<Arc<dyn ProviderPlugin>>,
    pub guard_plugins: Vec<Arc<dyn GuardStepPlugin>>,
}

impl KernelSpaceBundle {
    pub fn empty() -> Self {
        Self {
            protocols: Vec::new(),
            providers: Vec::new(),
            guard_plugins: Vec::new(),
        }
    }

    pub fn discover() -> Self {
        Self {
            protocols: discovery::collect_protocols(),
            providers: discovery::collect_providers(),
            guard_plugins: discovery::collect_guards(),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.protocols.is_empty() && self.providers.is_empty() && self.guard_plugins.is_empty()
    }

    pub fn with_defaults() -> Self {
        let bundle = Self::discover();
        if bundle.is_empty() {
            return Self {
                protocols: vec![
                    Arc::new(AnthropicProtocol),
                    Arc::new(OpenAiChatProtocol),
                    Arc::new(CodexResponsesProtocol),
                    Arc::new(GeminiProtocol),
                ],
                providers: vec![
                    Arc::new(ApiKeyProvider::anthropic()),
                    Arc::new(ApiKeyProvider::openai()),
                    Arc::new(ApiKeyProvider::codex()),
                    Arc::new(ApiKeyProvider::gemini()),
                ],
                guard_plugins: Vec::new(),
            };
        }
        bundle
    }
}

inventory::submit! {
    ProtocolFactory {
        build: || Arc::new(AnthropicProtocol),
    }
}

inventory::submit! {
    ProtocolFactory {
        build: || Arc::new(OpenAiChatProtocol),
    }
}

inventory::submit! {
    ProtocolFactory {
        build: || Arc::new(CodexResponsesProtocol),
    }
}

inventory::submit! {
    ProtocolFactory {
        build: || Arc::new(GeminiProtocol),
    }
}

inventory::submit! {
    ProviderFactory {
        build: || Arc::new(ApiKeyProvider::anthropic()),
    }
}

inventory::submit! {
    ProviderFactory {
        build: || Arc::new(ApiKeyProvider::openai()),
    }
}

inventory::submit! {
    ProviderFactory {
        build: || Arc::new(ApiKeyProvider::codex()),
    }
}

inventory::submit! {
    ProviderFactory {
        build: || Arc::new(ApiKeyProvider::gemini()),
    }
}

pub struct KernelSpacePlugin {
    bundle: KernelSpaceBundle,
}

impl KernelSpacePlugin {
    pub fn new(bundle: KernelSpaceBundle) -> Self {
        Self { bundle }
    }
}

impl KernelPlugin for KernelSpacePlugin {
    fn register(&self, registry: &mut CapabilityRegistry) {
        registry.insert(Arc::new(self.bundle.clone()));
    }
}

pub struct BasicProtocol;

impl ProtocolPlugin for BasicProtocol {
    fn protocol(&self) -> Protocol {
        Protocol::Anthropic
    }

    fn matches(&self, method: &str, path: &str) -> bool {
        method == "POST" && path == "/v1/messages"
    }

    fn decode(&self, req: HttpRequest) -> Result<RequestEnvelope, KernelError> {
        let token_key = req.headers.get("authorization").map(|v| v.replace("Bearer ", ""));
        let client_id = req.headers.get("x-client-id").cloned();
        let client_version = req.headers.get("x-client-version").cloned();
        let session_id = req.headers.get("x-session-id").cloned();
        let is_probe = header_is_true(&req.headers, "x-probe");
        let is_warmup = header_is_true(&req.headers, "x-warmup");
        let requires_context_1m = header_is_true(&req.headers, "x-context-1m");
        Ok(RequestEnvelope {
            request_id: String::new(),
            protocol: Protocol::Anthropic,
            model: "default".to_string(),
            stream: false,
            session_id,
            token_key,
            client_id,
            client_version,
            is_probe,
            is_warmup,
            requires_context_1m,
            headers: req.headers,
            raw_body: req.body,
            kernel_request: Some(KernelRequest {
                messages: Vec::new(),
                tools: vec![ToolSpec {
                    name: "default".to_string(),
                }],
            }),
            extra: HashMap::from([(String::from("path"), req.path)]),
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

pub struct EchoProvider;

impl ProviderPlugin for EchoProvider {
    fn provider_type(&self) -> ProviderType {
        ProviderType::Anthropic
    }

    fn build_upstream(
        &self,
        req: &RequestEnvelope,
        _provider: &control_plane::ProviderSpec,
        _key: &control_plane::KeySpec,
        _address: &control_plane::AddressSpec,
    ) -> Result<UpstreamRequest, KernelError> {
        Ok(UpstreamRequest {
            method: "POST".to_string(),
            url: "http://echo".to_string(),
            headers: req.headers.clone(),
            body: req.raw_body.clone(),
            stream: req.stream,
        })
    }

    fn map_response(
        &self,
        upstream: UpstreamResponse,
        _req: &RequestEnvelope,
        _provider: &control_plane::ProviderSpec,
    ) -> Result<KernelResponse, KernelError> {
        Ok(KernelResponse {
            status: upstream.status,
            headers: upstream.headers,
            body: upstream.body,
        })
    }
}

fn header_is_true(headers: &HashMap<String, String>, key: &str) -> bool {
    headers
        .get(key)
        .map(|value| matches!(value.as_str(), "1" | "true" | "yes" | "on"))
        .unwrap_or(false)
}
