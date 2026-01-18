use std::collections::HashMap;

use kernel::{
    ContentBlock, HttpRequest, KernelError, KernelRequest, Message, Protocol, ProtocolPlugin,
    RequestEnvelope, ToolSpec,
};
use serde_json::Value;

pub struct OpenAiChatProtocol;

impl ProtocolPlugin for OpenAiChatProtocol {
    fn protocol(&self) -> Protocol {
        Protocol::OpenAi
    }

    fn matches(&self, method: &str, path: &str) -> bool {
        method == "POST" && path == "/v1/chat/completions"
    }

    fn decode(&self, req: HttpRequest) -> Result<RequestEnvelope, KernelError> {
        decode_json_request(req, Protocol::OpenAi)
    }

    fn encode(&self, response: kernel::KernelResponse, _req: &RequestEnvelope) -> kernel::HttpResponse {
        kernel::HttpResponse {
            status: response.status,
            headers: response.headers,
            body: response.body,
        }
    }
}

pub struct AnthropicProtocol;

impl ProtocolPlugin for AnthropicProtocol {
    fn protocol(&self) -> Protocol {
        Protocol::Anthropic
    }

    fn matches(&self, method: &str, path: &str) -> bool {
        method == "POST" && path == "/v1/messages"
    }

    fn decode(&self, req: HttpRequest) -> Result<RequestEnvelope, KernelError> {
        decode_json_request(req, Protocol::Anthropic)
    }

    fn encode(&self, response: kernel::KernelResponse, _req: &RequestEnvelope) -> kernel::HttpResponse {
        kernel::HttpResponse {
            status: response.status,
            headers: response.headers,
            body: response.body,
        }
    }
}

pub struct CodexResponsesProtocol;

impl ProtocolPlugin for CodexResponsesProtocol {
    fn protocol(&self) -> Protocol {
        Protocol::Codex
    }

    fn matches(&self, method: &str, path: &str) -> bool {
        method == "POST" && path == "/v1/responses"
    }

    fn decode(&self, req: HttpRequest) -> Result<RequestEnvelope, KernelError> {
        decode_json_request(req, Protocol::Codex)
    }

    fn encode(&self, response: kernel::KernelResponse, _req: &RequestEnvelope) -> kernel::HttpResponse {
        kernel::HttpResponse {
            status: response.status,
            headers: response.headers,
            body: response.body,
        }
    }
}

pub struct GeminiProtocol;

impl ProtocolPlugin for GeminiProtocol {
    fn protocol(&self) -> Protocol {
        Protocol::Gemini
    }

    fn matches(&self, method: &str, path: &str) -> bool {
        method == "POST" && (path.contains("/v1beta/models") || path.contains("/v1/models"))
    }

    fn decode(&self, req: HttpRequest) -> Result<RequestEnvelope, KernelError> {
        decode_json_request(req, Protocol::Gemini)
    }

    fn encode(&self, response: kernel::KernelResponse, _req: &RequestEnvelope) -> kernel::HttpResponse {
        kernel::HttpResponse {
            status: response.status,
            headers: response.headers,
            body: response.body,
        }
    }
}

fn decode_json_request(req: HttpRequest, protocol: Protocol) -> Result<RequestEnvelope, KernelError> {
    let CommonFields {
        token_key,
        client_id,
        client_version,
        session_id,
        is_probe,
        is_warmup,
        requires_context_1m,
    } = extract_common_fields(&req.headers);

    let raw_body = req.body;
    let value: Value = if raw_body.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(&raw_body)
            .map_err(|_| KernelError::BadRequest("invalid json".to_string()))?
    };

    let model = value
        .get("model")
        .and_then(Value::as_str)
        .unwrap_or("default")
        .to_string();
    let stream = value.get("stream").and_then(Value::as_bool).unwrap_or(false);
    let mut messages = parse_messages(value.get("messages"));
    if messages.is_empty() {
        if let Some(input) = value.get("input").and_then(Value::as_str) {
            messages.push(Message {
                role: "user".to_string(),
                content: vec![ContentBlock::Text(input.to_string())],
            });
        }
    }
    let tools = parse_tools(value.get("tools"));
    let kernel_request = if messages.is_empty() && tools.is_empty() {
        None
    } else {
        Some(KernelRequest { messages, tools })
    };

    Ok(RequestEnvelope {
        request_id: String::new(),
        protocol,
        model,
        stream,
        session_id,
        token_key,
        client_id,
        client_version,
        is_probe,
        is_warmup,
        requires_context_1m,
        headers: req.headers,
        raw_body,
        kernel_request,
        extra: HashMap::from([(String::from("path"), req.path)]),
    })
}

struct CommonFields {
    token_key: Option<String>,
    client_id: Option<String>,
    client_version: Option<String>,
    session_id: Option<String>,
    is_probe: bool,
    is_warmup: bool,
    requires_context_1m: bool,
}

fn extract_common_fields(headers: &HashMap<String, String>) -> CommonFields {
    let token_key = headers.get("authorization").map(|v| v.replace("Bearer ", ""));
    CommonFields {
        token_key,
        client_id: headers.get("x-client-id").cloned(),
        client_version: headers.get("x-client-version").cloned(),
        session_id: headers.get("x-session-id").cloned(),
        is_probe: header_is_true(headers, "x-probe"),
        is_warmup: header_is_true(headers, "x-warmup"),
        requires_context_1m: header_is_true(headers, "x-context-1m"),
    }
}

fn parse_messages(value: Option<&Value>) -> Vec<Message> {
    let Some(Value::Array(items)) = value else {
        return Vec::new();
    };
    items
        .iter()
        .filter_map(|item| {
            let role = item.get("role").and_then(Value::as_str)?.to_string();
            let content = parse_content(item.get("content"));
            Some(Message { role, content })
        })
        .collect()
}

fn parse_content(value: Option<&Value>) -> Vec<ContentBlock> {
    match value {
        Some(Value::String(text)) => vec![ContentBlock::Text(text.to_string())],
        Some(Value::Array(items)) => items
            .iter()
            .filter_map(|item| {
                if let Some(text) = item.get("text").and_then(Value::as_str) {
                    return Some(ContentBlock::Text(text.to_string()));
                }
                if let Some(text) = item.get("content").and_then(Value::as_str) {
                    return Some(ContentBlock::Text(text.to_string()));
                }
                None
            })
            .collect(),
        _ => Vec::new(),
    }
}

fn parse_tools(value: Option<&Value>) -> Vec<ToolSpec> {
    let Some(Value::Array(items)) = value else {
        return Vec::new();
    };
    items
        .iter()
        .filter_map(|item| {
            let name = item
                .get("name")
                .and_then(Value::as_str)
                .or_else(|| item.get("function").and_then(|func| func.get("name")).and_then(Value::as_str))?;
            Some(ToolSpec {
                name: name.to_string(),
            })
        })
        .collect()
}

fn header_is_true(headers: &HashMap<String, String>, key: &str) -> bool {
    headers
        .get(key)
        .map(|value| matches!(value.as_str(), "1" | "true" | "yes" | "on"))
        .unwrap_or(false)
}
