use control_plane::{GuardConfig};

use crate::types::{KernelRequest, RequestEnvelope};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RequestType {
    Chat,
    CountTokens,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum GuardStepKey {
    Auth,
    TokenPermission,
    Sensitive,
    Client,
    Model,
    Version,
    Probe,
    Session,
    Warmup,
    RequestFilter,
    RateLimit,
    ProviderSelect,
    ProviderRequestFilter,
    MessageContext,
    ContextEnricher,
}

impl GuardStepKey {
    fn parse(value: &str) -> Option<Self> {
        match value {
            "auth" => Some(Self::Auth),
            "token_permission" | "token-permission" => Some(Self::TokenPermission),
            "sensitive" => Some(Self::Sensitive),
            "client" => Some(Self::Client),
            "model" => Some(Self::Model),
            "version" => Some(Self::Version),
            "probe" => Some(Self::Probe),
            "session" => Some(Self::Session),
            "warmup" => Some(Self::Warmup),
            "request_filter" | "request-filter" | "requestFilter" => Some(Self::RequestFilter),
            "rate_limit" | "rate-limit" => Some(Self::RateLimit),
            "provider_select" | "provider-select" => Some(Self::ProviderSelect),
            "provider_request_filter" | "provider-request-filter" => Some(Self::ProviderRequestFilter),
            "message_context" | "message-context" | "messageContext" => Some(Self::MessageContext),
            "context_enricher" | "context-enricher" => Some(Self::ContextEnricher),
            _ => None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct GuardPipeline {
    pub steps: Vec<GuardStepKey>,
}

pub struct GuardStepPlan {
    pub preflight: Vec<GuardStepKey>,
    pub attempt: Vec<GuardStepKey>,
    pub has_provider_select: bool,
}

impl GuardPipeline {
    pub fn from_config(config: &GuardConfig, request_type: RequestType) -> Self {
        let steps = match request_type {
            RequestType::CountTokens => {
                if config.count_tokens_steps.is_empty() {
                    default_count_tokens_steps()
                } else {
                    parse_steps(&config.count_tokens_steps)
                }
            }
            RequestType::Chat => {
                if config.steps.is_empty() {
                    default_chat_steps()
                } else {
                    parse_steps(&config.steps)
                }
            }
        };
        Self { steps }
    }

    pub fn split_for_selection(&self) -> GuardStepPlan {
        let mut preflight = Vec::new();
        let mut attempt = Vec::new();
        let mut in_attempt = false;

        for step in &self.steps {
            if *step == GuardStepKey::ProviderSelect {
                in_attempt = true;
            }
            if in_attempt {
                attempt.push(*step);
            } else {
                preflight.push(*step);
            }
        }

        GuardStepPlan {
            preflight,
            attempt,
            has_provider_select: in_attempt,
        }
    }
}

pub fn classify_request(req: &RequestEnvelope) -> RequestType {
    let path = req.extra.get("path").map(String::as_str).unwrap_or("");
    if path.ends_with("/count_tokens") || path.contains("count_tokens") {
        return RequestType::CountTokens;
    }
    RequestType::Chat
}

pub fn build_kernel_request(req: &RequestEnvelope) -> KernelRequest {
    req.kernel_request.clone().unwrap_or(KernelRequest {
        messages: Vec::new(),
        tools: Vec::new(),
    })
}

fn parse_steps(values: &[String]) -> Vec<GuardStepKey> {
    values
        .iter()
        .filter_map(|value| GuardStepKey::parse(value))
        .collect()
}

fn default_chat_steps() -> Vec<GuardStepKey> {
    vec![
        GuardStepKey::Auth,
        GuardStepKey::TokenPermission,
        GuardStepKey::Sensitive,
        GuardStepKey::Client,
        GuardStepKey::Model,
        GuardStepKey::Version,
        GuardStepKey::Probe,
        GuardStepKey::Session,
        GuardStepKey::Warmup,
        GuardStepKey::RequestFilter,
        GuardStepKey::RateLimit,
        GuardStepKey::ProviderSelect,
        GuardStepKey::ProviderRequestFilter,
        GuardStepKey::MessageContext,
    ]
}

fn default_count_tokens_steps() -> Vec<GuardStepKey> {
    vec![
        GuardStepKey::Auth,
        GuardStepKey::TokenPermission,
        GuardStepKey::Client,
        GuardStepKey::Model,
        GuardStepKey::Version,
        GuardStepKey::Probe,
        GuardStepKey::RequestFilter,
        GuardStepKey::ProviderSelect,
        GuardStepKey::ProviderRequestFilter,
    ]
}
