use std::collections::HashMap;
use std::io::Read;
use std::pin::Pin;

use bytes::Bytes;
use futures_core::Stream;
use futures_util::StreamExt;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum Protocol {
    OpenAi,
    Anthropic,
    Codex,
    Gemini,
}

#[derive(Clone, Debug)]
pub struct HttpRequest {
    pub method: String,
    pub path: String,
    pub headers: HashMap<String, String>,
    pub body: Vec<u8>,
}

pub enum ResponseBody {
    Bytes(Vec<u8>),
    Reader(Box<dyn Read + Send>),
    Stream(Pin<Box<dyn Stream<Item = Result<Bytes, std::io::Error>> + Send>>),
}

impl std::fmt::Debug for ResponseBody {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ResponseBody::Bytes(bytes) => write!(f, "Bytes({})", bytes.len()),
            ResponseBody::Reader(_) => write!(f, "Reader"),
            ResponseBody::Stream(_) => write!(f, "Stream"),
        }
    }
}

impl ResponseBody {
    pub fn into_bytes(self) -> Vec<u8> {
        match self {
            ResponseBody::Bytes(bytes) => bytes,
            ResponseBody::Reader(mut reader) => {
                let mut buf = Vec::new();
                let _ = reader.read_to_end(&mut buf);
                buf
            }
            ResponseBody::Stream(_) => Vec::new(),
        }
    }

    pub async fn into_bytes_async(self) -> Vec<u8> {
        match self {
            ResponseBody::Bytes(bytes) => bytes,
            ResponseBody::Reader(mut reader) => {
                let mut buf = Vec::new();
                let _ = reader.read_to_end(&mut buf);
                buf
            }
            ResponseBody::Stream(mut stream) => {
                let mut out = Vec::new();
                while let Some(chunk) = stream.next().await {
                    if let Ok(bytes) = chunk {
                        out.extend_from_slice(&bytes);
                    }
                }
                out
            }
        }
    }

    pub fn is_streaming(&self) -> bool {
        matches!(self, ResponseBody::Reader(_) | ResponseBody::Stream(_))
    }
}

#[derive(Debug)]
pub struct HttpResponse {
    pub status: u16,
    pub headers: HashMap<String, String>,
    pub body: ResponseBody,
}

#[derive(Clone, Debug)]
pub struct UpstreamRequest {
    pub method: String,
    pub url: String,
    pub headers: HashMap<String, String>,
    pub body: Vec<u8>,
    pub stream: bool,
}

#[derive(Debug)]
pub struct UpstreamResponse {
    pub status: u16,
    pub headers: HashMap<String, String>,
    pub body: ResponseBody,
}

#[derive(Clone, Debug)]
pub struct ToolSpec {
    pub name: String,
}

#[derive(Clone, Debug)]
pub struct Message {
    pub role: String,
    pub content: Vec<ContentBlock>,
}

#[derive(Clone, Debug)]
pub enum ContentBlock {
    Text(String),
    ToolUse { name: String, arguments: String },
    ToolResult { name: String, result: String },
}

#[derive(Clone, Debug)]
pub struct KernelRequest {
    pub messages: Vec<Message>,
    pub tools: Vec<ToolSpec>,
}

#[derive(Clone, Debug)]
pub struct RequestEnvelope {
    pub request_id: String,
    pub protocol: Protocol,
    pub model: String,
    pub stream: bool,
    pub session_id: Option<String>,
    pub token_key: Option<String>,
    pub client_id: Option<String>,
    pub client_version: Option<String>,
    pub is_probe: bool,
    pub is_warmup: bool,
    pub requires_context_1m: bool,
    pub headers: HashMap<String, String>,
    pub raw_body: Vec<u8>,
    pub kernel_request: Option<KernelRequest>,
    pub extra: HashMap<String, String>,
}

#[derive(Debug)]
pub struct KernelResponse {
    pub status: u16,
    pub headers: HashMap<String, String>,
    pub body: ResponseBody,
}
