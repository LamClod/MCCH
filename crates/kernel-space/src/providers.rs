use std::collections::HashMap;

use control_plane::{AddressSpec, KeySpec, ProviderSpec, ProviderType};
use kernel::{
    ContentBlock, KernelError, Message, ProviderPlugin, RequestEnvelope, UpstreamRequest,
    UpstreamResponse,
};
use serde_json::{Map, Value};

pub struct ApiKeyProvider {
    provider_type: ProviderType,
    default_auth_header: String,
    default_auth_prefix: Option<String>,
    default_auth_query_param: Option<String>,
    default_headers: HashMap<String, String>,
}

impl ApiKeyProvider {
    pub fn openai() -> Self {
        Self::with_bearer(ProviderType::OpenAiCompatible)
    }

    pub fn codex() -> Self {
        Self::with_bearer(ProviderType::Codex)
    }

    pub fn anthropic() -> Self {
        let mut defaults = default_json_headers();
        defaults.insert("anthropic-version".to_string(), "2023-06-01".to_string());
        Self {
            provider_type: ProviderType::Anthropic,
            default_auth_header: "x-api-key".to_string(),
            default_auth_prefix: None,
            default_auth_query_param: None,
            default_headers: defaults,
        }
    }

    pub fn gemini() -> Self {
        Self {
            provider_type: ProviderType::Gemini,
            default_auth_header: "x-goog-api-key".to_string(),
            default_auth_prefix: None,
            default_auth_query_param: None,
            default_headers: default_json_headers(),
        }
    }

    fn with_bearer(provider_type: ProviderType) -> Self {
        Self {
            provider_type,
            default_auth_header: "authorization".to_string(),
            default_auth_prefix: Some("Bearer ".to_string()),
            default_auth_query_param: None,
            default_headers: default_json_headers(),
        }
    }
}

impl ProviderPlugin for ApiKeyProvider {
    fn provider_type(&self) -> ProviderType {
        self.provider_type
    }

    fn build_upstream(
        &self,
        req: &RequestEnvelope,
        provider: &ProviderSpec,
        key: &KeySpec,
        address: &AddressSpec,
    ) -> Result<UpstreamRequest, KernelError> {
        let base_url = select_base_url(provider, address);
        let path = req.extra.get("path").map(String::as_str).unwrap_or("/");
        let mut url = join_url(base_url, path);
        let mut headers = normalize_headers(&req.headers);
        strip_internal_headers(&mut headers);
        let auth_header = provider
            .auth_header
            .as_deref()
            .unwrap_or(&self.default_auth_header)
            .trim();
        let auth_prefix = resolve_prefix(
            provider.auth_prefix.as_deref(),
            self.default_auth_prefix.as_deref(),
        );
        let auth_query_param = provider
            .auth_query_param
            .as_deref()
            .or(self.default_auth_query_param.as_deref())
            .map(str::trim)
            .filter(|value| !value.is_empty());

        if let Some(param) = auth_query_param {
            url = add_query_param(&url, param, &key.secret);
        }

        if !auth_header.is_empty() {
            let auth_value = match auth_prefix {
                Some(prefix) => format!("{prefix}{}", key.secret),
                None => key.secret.clone(),
            };
            headers.insert(auth_header.to_string(), auth_value);
        }

        for (key, value) in &self.default_headers {
            headers.entry(key.clone()).or_insert_with(|| value.clone());
        }
        for (key, value) in &provider.default_headers {
            headers.insert(key.to_lowercase(), value.clone());
        }
        apply_stream_accept(&mut headers, req.stream);

        Ok(UpstreamRequest {
            method: "POST".to_string(),
            url,
            headers,
            body: build_request_body(req),
            stream: req.stream,
        })
    }

    fn map_response(
        &self,
        upstream: UpstreamResponse,
        _req: &RequestEnvelope,
        _provider: &ProviderSpec,
    ) -> Result<kernel::KernelResponse, KernelError> {
        Ok(kernel::KernelResponse {
            status: upstream.status,
            headers: upstream.headers,
            body: upstream.body,
        })
    }
}

pub struct BearerProvider {
    provider_type: ProviderType,
    header_name: String,
}

impl BearerProvider {
    pub fn new(provider_type: ProviderType) -> Self {
        Self {
            provider_type,
            header_name: "authorization".to_string(),
        }
    }

    pub fn with_header(provider_type: ProviderType, header_name: &str) -> Self {
        Self {
            provider_type,
            header_name: header_name.to_string(),
        }
    }
}

impl ProviderPlugin for BearerProvider {
    fn provider_type(&self) -> ProviderType {
        self.provider_type
    }

    fn build_upstream(
        &self,
        req: &RequestEnvelope,
        provider: &ProviderSpec,
        key: &KeySpec,
        address: &AddressSpec,
    ) -> Result<UpstreamRequest, KernelError> {
        let base_url = select_base_url(provider, address);
        let path = req.extra.get("path").map(String::as_str).unwrap_or("/");
        let url = join_url(base_url, path);
        let mut headers = normalize_headers(&req.headers);
        strip_internal_headers(&mut headers);
        headers.insert(
            self.header_name.clone(),
            format!("Bearer {}", key.secret),
        );
        for (key, value) in default_json_headers() {
            headers.entry(key).or_insert(value);
        }
        apply_stream_accept(&mut headers, req.stream);

        Ok(UpstreamRequest {
            method: "POST".to_string(),
            url,
            headers,
            body: build_request_body(req),
            stream: req.stream,
        })
    }

    fn map_response(
        &self,
        upstream: UpstreamResponse,
        _req: &RequestEnvelope,
        _provider: &ProviderSpec,
    ) -> Result<kernel::KernelResponse, KernelError> {
        Ok(kernel::KernelResponse {
            status: upstream.status,
            headers: upstream.headers,
            body: upstream.body,
        })
    }
}

fn default_json_headers() -> HashMap<String, String> {
    HashMap::from([(
        "content-type".to_string(),
        "application/json".to_string(),
    )])
}

fn normalize_headers(headers: &HashMap<String, String>) -> HashMap<String, String> {
    headers
        .iter()
        .map(|(key, value)| (key.to_lowercase(), value.clone()))
        .collect()
}

fn apply_stream_accept(headers: &mut HashMap<String, String>, stream: bool) {
    if !stream {
        return;
    }
    headers
        .entry("accept".to_string())
        .or_insert_with(|| "text/event-stream".to_string());
}

fn resolve_prefix<'a>(override_value: Option<&'a str>, default_value: Option<&'a str>) -> Option<&'a str> {
    match override_value {
        Some(value) => {
            if value.is_empty() {
                None
            } else {
                Some(value)
            }
        }
        None => default_value,
    }
}

fn add_query_param(url: &str, key: &str, value: &str) -> String {
    let separator = if url.contains('?') { '&' } else { '?' };
    let mut result = String::with_capacity(url.len() + key.len() + value.len() + 2);
    result.push_str(url);
    result.push(separator);
    result.push_str(&encode_component(key));
    result.push('=');
    result.push_str(&encode_component(value));
    result
}

fn encode_component(value: &str) -> String {
    let mut out = String::new();
    for byte in value.bytes() {
        let ch = byte as char;
        if ch.is_ascii_alphanumeric() || matches!(ch, '-' | '.' | '_' | '~') {
            out.push(ch);
        } else {
            out.push('%');
            out.push_str(&format!("{:02X}", byte));
        }
    }
    out
}

fn strip_internal_headers(headers: &mut HashMap<String, String>) {
    let keys = [
        "authorization",
        "x-client-id",
        "x-client-version",
        "x-session-id",
        "x-probe",
        "x-warmup",
        "x-context-1m",
        "content-length",
        "host",
        "connection",
        "transfer-encoding",
    ];
    for key in keys {
        headers.remove(key);
    }
}

fn build_request_body(req: &RequestEnvelope) -> Vec<u8> {
    let Some(kernel_request) = req.kernel_request.as_ref() else {
        return req.raw_body.clone();
    };
    let value = if req.raw_body.is_empty() {
        Value::Object(Map::new())
    } else {
        match serde_json::from_slice::<Value>(&req.raw_body) {
            Ok(value) => value,
            Err(_) => return req.raw_body.clone(),
        }
    };
    let Value::Object(mut root) = value else {
        return req.raw_body.clone();
    };

    if !req.model.trim().is_empty() {
        root.insert("model".to_string(), Value::String(req.model.clone()));
    }
    root.insert("stream".to_string(), Value::Bool(req.stream));

    let message_values = messages_for_protocol(req.protocol, &kernel_request.messages);
    if !message_values.is_empty() {
        match req.protocol {
            kernel::Protocol::Gemini => {
                root.insert("contents".to_string(), Value::Array(message_values));
            }
            _ => {
                root.insert("messages".to_string(), Value::Array(message_values));
            }
        }
    }

    if let kernel::Protocol::Codex = req.protocol {
        let input = join_messages_for_input(&kernel_request.messages);
        if !input.is_empty() {
            root.insert("input".to_string(), Value::String(input));
        }
    }

    if !kernel_request.tools.is_empty() {
        let tools: Vec<Value> = kernel_request
            .tools
            .iter()
            .map(|tool| Value::Object(Map::from_iter([(
                "name".to_string(),
                Value::String(tool.name.clone()),
            )])))
            .collect();
        root.insert("tools".to_string(), Value::Array(tools));
    }

    serde_json::to_vec(&Value::Object(root)).unwrap_or_else(|_| req.raw_body.clone())
}

fn messages_for_protocol(protocol: kernel::Protocol, messages: &[Message]) -> Vec<Value> {
    match protocol {
        kernel::Protocol::Anthropic => messages
            .iter()
            .map(|msg| {
                let content = Value::Array(vec![Value::Object(Map::from_iter([(
                    "type".to_string(),
                    Value::String("text".to_string()),
                ), (
                    "text".to_string(),
                    Value::String(message_text(msg)),
                )]))]);
                Value::Object(Map::from_iter([
                    ("role".to_string(), Value::String(msg.role.clone())),
                    ("content".to_string(), content),
                ]))
            })
            .collect(),
        kernel::Protocol::Gemini => messages
            .iter()
            .map(|msg| {
                let role = match msg.role.as_str() {
                    "assistant" => "model".to_string(),
                    other => other.to_string(),
                };
                let parts = Value::Array(vec![Value::Object(Map::from_iter([(
                    "text".to_string(),
                    Value::String(message_text(msg)),
                )]))]);
                Value::Object(Map::from_iter([
                    ("role".to_string(), Value::String(role)),
                    ("parts".to_string(), parts),
                ]))
            })
            .collect(),
        _ => messages
            .iter()
            .map(|msg| {
                Value::Object(Map::from_iter([
                    ("role".to_string(), Value::String(msg.role.clone())),
                    ("content".to_string(), Value::String(message_text(msg))),
                ]))
            })
            .collect(),
    }
}

fn message_text(message: &Message) -> String {
    let mut output = String::new();
    for block in &message.content {
        match block {
            ContentBlock::Text(text) => output.push_str(text),
            ContentBlock::ToolUse { name, arguments } => {
                output.push_str("[tool:");
                output.push_str(name);
                output.push(']');
                output.push_str(arguments);
            }
            ContentBlock::ToolResult { name, result } => {
                output.push_str("[tool_result:");
                output.push_str(name);
                output.push(']');
                output.push_str(result);
            }
        }
    }
    output
}

fn join_messages_for_input(messages: &[Message]) -> String {
    let mut parts = Vec::new();
    for message in messages {
        let text = message_text(message);
        if !text.is_empty() {
            parts.push(text);
        }
    }
    parts.join("\n")
}

fn select_base_url<'a>(provider: &'a ProviderSpec, address: &'a AddressSpec) -> &'a str {
    if !address.base_url.trim().is_empty() {
        address.base_url.as_str()
    } else {
        provider.base_url.as_str()
    }
}

fn join_url(base: &str, path: &str) -> String {
    if path.starts_with("http://") || path.starts_with("https://") {
        return path.to_string();
    }
    let base_trim = base.trim_end_matches('/');
    if base_trim.is_empty() {
        return format!("/{}", path.trim_start_matches('/'));
    }
    let mut path_trim = path.trim_start_matches('/');
    if let Some(pos) = path_trim.find('/') {
        let first = &path_trim[..pos];
        let suffix = format!("/{first}");
        if base_trim.ends_with(&suffix) {
            path_trim = &path_trim[pos + 1..];
        }
    } else {
        let suffix = format!("/{path_trim}");
        if base_trim.ends_with(&suffix) {
            return base_trim.to_string();
        }
    }
    if path_trim.is_empty() {
        base_trim.to_string()
    } else {
        format!("{base_trim}/{path_trim}")
    }
}
