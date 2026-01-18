use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::thread;

use kernel::{Forwarder, HttpForwarder, HttpForwarderConfig, UpstreamRequest};

fn spawn_server(status: u16, body: &'static str) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().expect("addr");
    thread::spawn(move || {
        if let Ok((mut stream, _)) = listener.accept() {
            let mut buf = [0u8; 1024];
            let _ = stream.read(&mut buf);
            let response = format!(
                "HTTP/1.1 {status} OK\r\nContent-Length: {}\r\n\r\n{body}",
                body.len()
            );
            let _ = stream.write_all(response.as_bytes());
        }
    });
    format!("http://{}", addr)
}

#[tokio::test]
async fn http_forwarder_reads_body_on_success() {
    let url = spawn_server(200, "ok");
    let forwarder = HttpForwarder::new(HttpForwarderConfig {
        timeout_ms: 2_000,
        user_agent: "mcch-test".to_string(),
    });
    let req = UpstreamRequest {
        method: "POST".to_string(),
        url,
        headers: HashMap::new(),
        body: b"ping".to_vec(),
        stream: false,
    };
    let resp = forwarder.send(&req).await.expect("response");
    assert_eq!(resp.status, 200);
    assert_eq!(resp.body.into_bytes_async().await, b"ok");
}

#[tokio::test]
async fn http_forwarder_reads_body_on_error_status() {
    let url = spawn_server(500, "fail");
    let forwarder = HttpForwarder::new(HttpForwarderConfig::default());
    let req = UpstreamRequest {
        method: "POST".to_string(),
        url,
        headers: HashMap::new(),
        body: Vec::new(),
        stream: false,
    };
    let resp = forwarder.send(&req).await.expect("response");
    assert_eq!(resp.status, 500);
    assert_eq!(resp.body.into_bytes_async().await, b"fail");
}
