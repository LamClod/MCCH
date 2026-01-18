use std::collections::HashMap;
use std::time::Duration;

use async_trait::async_trait;
use futures_util::StreamExt;
use reqwest::header::{HeaderMap, HeaderName, HeaderValue, USER_AGENT};
use reqwest::Method;

use crate::{Forwarder, KernelError, ResponseBody, UpstreamRequest, UpstreamResponse};

#[derive(Clone, Debug)]
pub struct HttpForwarderConfig {
    pub timeout_ms: u64,
    pub user_agent: String,
}

impl Default for HttpForwarderConfig {
    fn default() -> Self {
        Self {
            timeout_ms: 30_000,
            user_agent: "mcch-kernel".to_string(),
        }
    }
}

#[derive(Clone)]
pub struct HttpForwarder {
    client: reqwest::Client,
    config: HttpForwarderConfig,
}

impl HttpForwarder {
    pub fn new(config: HttpForwarderConfig) -> Self {
        let timeout = Duration::from_millis(config.timeout_ms.max(1));
        let client = reqwest::Client::builder()
            .timeout(timeout)
            .build()
            .unwrap_or_else(|_| reqwest::Client::new());
        Self { client, config }
    }

    async fn send_request(&self, upstream: &UpstreamRequest) -> Result<UpstreamResponse, KernelError> {
        let method = Method::from_bytes(upstream.method.as_bytes())
            .map_err(|err| KernelError::BadRequest(err.to_string()))?;
        let mut headers = HeaderMap::new();
        let mut has_user_agent = false;
        for (key, value) in &upstream.headers {
            if key.eq_ignore_ascii_case("user-agent") {
                has_user_agent = true;
            }
            if let (Ok(name), Ok(value)) =
                (HeaderName::from_bytes(key.as_bytes()), HeaderValue::from_str(value))
            {
                headers.insert(name, value);
            }
        }
        if !has_user_agent {
            if let Ok(value) = HeaderValue::from_str(&self.config.user_agent) {
                headers.insert(USER_AGENT, value);
            }
        }

        let request = self
            .client
            .request(method, &upstream.url)
            .headers(headers)
            .body(upstream.body.clone());
        let response = request
            .send()
            .await
            .map_err(|err| KernelError::Upstream(err.to_string()))?;
        response_to_upstream(response, upstream.stream).await
    }
}

#[async_trait]
impl Forwarder for HttpForwarder {
    async fn send(&self, upstream: &UpstreamRequest) -> Result<UpstreamResponse, KernelError> {
        self.send_request(upstream).await
    }
}

async fn response_to_upstream(
    resp: reqwest::Response,
    stream: bool,
) -> Result<UpstreamResponse, KernelError> {
    let status = resp.status().as_u16();
    let headers = collect_headers(resp.headers());
    let body = if stream {
        let stream = resp.bytes_stream().map(|item| {
            item.map_err(|err| std::io::Error::new(std::io::ErrorKind::Other, err.to_string()))
        });
        ResponseBody::Stream(Box::pin(stream))
    } else {
        let bytes = resp
            .bytes()
            .await
            .map_err(|err| KernelError::Upstream(err.to_string()))?;
        ResponseBody::Bytes(bytes.to_vec())
    };
    Ok(UpstreamResponse { status, headers, body })
}

fn collect_headers(resp: &HeaderMap) -> HashMap<String, String> {
    let mut headers = HashMap::new();
    for (name, value) in resp {
        if let Ok(value) = value.to_str() {
            headers.insert(name.as_str().to_lowercase(), value.to_string());
        }
    }
    headers
}
