use std::collections::HashMap;

use kernel::{HttpRequest, Protocol, ProtocolPlugin};
use kernel_space::{AnthropicProtocol, CodexResponsesProtocol, OpenAiChatProtocol};

#[test]
fn openai_chat_decodes_model_and_tools() {
    let protocol = OpenAiChatProtocol;
    let request = HttpRequest {
        method: "POST".to_string(),
        path: "/v1/chat/completions".to_string(),
        headers: HashMap::new(),
        body: br#"{"model":"gpt-4","messages":[{"role":"user","content":"hi"}],"tools":[{"name":"t1"}]}"#
            .to_vec(),
    };

    let envelope = protocol.decode(request).expect("decode");
    assert_eq!(envelope.protocol, Protocol::OpenAi);
    assert_eq!(envelope.model, "gpt-4");
    assert!(envelope.kernel_request.is_some());
    let req = envelope.kernel_request.expect("kernel request");
    assert_eq!(req.messages.len(), 1);
    assert_eq!(req.tools.len(), 1);
}

#[test]
fn anthropic_decodes_messages() {
    let protocol = AnthropicProtocol;
    let request = HttpRequest {
        method: "POST".to_string(),
        path: "/v1/messages".to_string(),
        headers: HashMap::new(),
        body: br#"{"model":"claude-3","messages":[{"role":"user","content":[{"text":"hi"}]}]}"#
            .to_vec(),
    };

    let envelope = protocol.decode(request).expect("decode");
    assert_eq!(envelope.protocol, Protocol::Anthropic);
    assert_eq!(envelope.model, "claude-3");
    let req = envelope.kernel_request.expect("kernel request");
    assert_eq!(req.messages.len(), 1);
}

#[test]
fn codex_responses_defaults_model() {
    let protocol = CodexResponsesProtocol;
    let request = HttpRequest {
        method: "POST".to_string(),
        path: "/v1/responses".to_string(),
        headers: HashMap::new(),
        body: br#"{"input":"hi"}"#.to_vec(),
    };

    let envelope = protocol.decode(request).expect("decode");
    assert_eq!(envelope.protocol, Protocol::Codex);
    assert_eq!(envelope.model, "default");
}
