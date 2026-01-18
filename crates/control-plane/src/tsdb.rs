use std::collections::HashMap;
use std::io::Write;
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use parking_lot::Mutex;
use rusqlite::{params, Connection};
use thiserror::Error;

#[derive(Clone, Debug)]
pub struct MetricPoint {
    pub name: String,
    pub value: f64,
    pub timestamp_ms: u64,
    pub tags: HashMap<String, String>,
}

impl MetricPoint {
    pub fn now(name: impl Into<String>, value: f64, tags: HashMap<String, String>) -> Self {
        let timestamp_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;
        Self {
            name: name.into(),
            value,
            timestamp_ms,
            tags,
        }
    }

    pub fn with_timestamp_ms(
        name: impl Into<String>,
        value: f64,
        tags: HashMap<String, String>,
        timestamp_ms: u64,
    ) -> Self {
        Self {
            name: name.into(),
            value,
            timestamp_ms,
            tags,
        }
    }

    pub fn to_line_protocol(&self) -> String {
        let mut line = String::new();
        line.push_str(&escape_line_protocol(&self.name));

        let mut tags: Vec<(&String, &String)> = self.tags.iter().collect();
        tags.sort_by(|a, b| a.0.cmp(b.0));
        for (key, value) in tags {
            line.push(',');
            line.push_str(&escape_line_protocol(key));
            line.push('=');
            line.push_str(&escape_line_protocol(value));
        }

        line.push(' ');
        line.push_str("value=");
        line.push_str(&format_float(self.value));
        line.push(' ');
        line.push_str(&timestamp_ns(self.timestamp_ms).to_string());
        line
    }
}

pub trait TsdbSink: Send + Sync {
    fn write(&self, point: MetricPoint);
    fn list(&self) -> Vec<MetricPoint> {
        Vec::new()
    }
}

#[derive(Clone)]
pub struct InMemoryTsdbSink {
    points: Arc<Mutex<Vec<MetricPoint>>>,
}

impl InMemoryTsdbSink {
    pub fn new() -> Self {
        Self {
            points: Arc::new(Mutex::new(Vec::new())),
        }
    }

    pub fn shared() -> Arc<Self> {
        Arc::new(Self::new())
    }
}

impl TsdbSink for InMemoryTsdbSink {
    fn write(&self, point: MetricPoint) {
        self.points.lock().push(point);
    }

    fn list(&self) -> Vec<MetricPoint> {
        self.points.lock().clone()
    }
}

#[derive(Clone)]
pub struct SqliteTsdbSink {
    conn: Arc<Mutex<Connection>>,
}

impl SqliteTsdbSink {
    pub fn open(path: &str) -> Result<Self, TsdbError> {
        let conn = Connection::open(path).map_err(|err| TsdbError::InvalidEndpoint(err.to_string()))?;
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS metrics (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                value REAL NOT NULL,
                timestamp_ms INTEGER NOT NULL,
                tags_json TEXT NOT NULL
            );",
        )
        .map_err(|err| TsdbError::InvalidEndpoint(err.to_string()))?;
        Ok(Self {
            conn: Arc::new(Mutex::new(conn)),
        })
    }
}

impl TsdbSink for SqliteTsdbSink {
    fn write(&self, point: MetricPoint) {
        let payload = serde_json::to_string(&point.tags).unwrap_or_else(|_| "{}".to_string());
        let conn = self.conn.lock();
        let _ = conn.execute(
            "INSERT INTO metrics (name, value, timestamp_ms, tags_json) VALUES (?1, ?2, ?3, ?4)",
            params![point.name, point.value, point.timestamp_ms as i64, payload],
        );
    }

    fn list(&self) -> Vec<MetricPoint> {
        let conn = self.conn.lock();
        let mut stmt = match conn.prepare(
            "SELECT name, value, timestamp_ms, tags_json FROM metrics ORDER BY id ASC",
        ) {
            Ok(stmt) => stmt,
            Err(_) => return Vec::new(),
        };
        let rows = match stmt.query([]) {
            Ok(rows) => rows,
            Err(_) => return Vec::new(),
        };
        let mut points = Vec::new();
        let mut rows = rows;
        while let Ok(Some(row)) = rows.next() {
            let name: String = match row.get(0) {
                Ok(value) => value,
                Err(_) => continue,
            };
            let value: f64 = match row.get(1) {
                Ok(value) => value,
                Err(_) => continue,
            };
            let timestamp_ms: i64 = match row.get(2) {
                Ok(value) => value,
                Err(_) => continue,
            };
            let tags_json: String = match row.get(3) {
                Ok(value) => value,
                Err(_) => continue,
            };
            let tags: HashMap<String, String> =
                serde_json::from_str(&tags_json).unwrap_or_default();
            points.push(MetricPoint {
                name,
                value,
                timestamp_ms: timestamp_ms.max(0) as u64,
                tags,
            });
        }
        points
    }
}

#[derive(Debug, Error)]
pub enum TsdbError {
    #[error("invalid tsdb endpoint: {0}")]
    InvalidEndpoint(String),
    #[error("failed to resolve tsdb endpoint: {0}")]
    Resolve(String),
}

#[derive(Clone)]
pub struct TcpLineProtocolSink {
    address: SocketAddr,
    timeout: Duration,
}

impl TcpLineProtocolSink {
    pub fn connect(endpoint: &str, timeout_ms: u64) -> Result<Self, TsdbError> {
        let address = parse_endpoint(endpoint)?;
        let timeout = Duration::from_millis(timeout_ms.max(1));
        Ok(Self { address, timeout })
    }
}

impl TsdbSink for TcpLineProtocolSink {
    fn write(&self, point: MetricPoint) {
        let mut stream = match TcpStream::connect_timeout(&self.address, self.timeout) {
            Ok(stream) => stream,
            Err(_) => return,
        };
        let _ = stream.set_write_timeout(Some(self.timeout));
        let payload = point.to_line_protocol();
        let _ = stream.write_all(payload.as_bytes());
        let _ = stream.write_all(b"\n");
    }
}

fn parse_endpoint(endpoint: &str) -> Result<SocketAddr, TsdbError> {
    let trimmed = endpoint.trim();
    if trimmed.is_empty() {
        return Err(TsdbError::InvalidEndpoint("empty endpoint".to_string()));
    }
    let without_scheme = match trimmed.split("://").last() {
        Some(value) if !value.is_empty() => value,
        _ => trimmed,
    };
    let host_port = without_scheme
        .split('/')
        .next()
        .ok_or_else(|| TsdbError::InvalidEndpoint(trimmed.to_string()))?;
    if host_port.trim().is_empty() {
        return Err(TsdbError::InvalidEndpoint(trimmed.to_string()));
    }
    let mut addrs = host_port
        .to_socket_addrs()
        .map_err(|err| TsdbError::Resolve(err.to_string()))?;
    addrs
        .next()
        .ok_or_else(|| TsdbError::Resolve(trimmed.to_string()))
}

fn escape_line_protocol(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len());
    for ch in value.chars() {
        match ch {
            ' ' | ',' | '=' => {
                escaped.push('\\');
                escaped.push(ch);
            }
            '\\' => {
                escaped.push('\\');
                escaped.push('\\');
            }
            _ => escaped.push(ch),
        }
    }
    escaped
}

fn format_float(value: f64) -> String {
    let mut text = value.to_string();
    if !text.contains('.') && !text.contains('e') && !text.contains('E') {
        text.push_str(".0");
    }
    text
}

fn timestamp_ns(timestamp_ms: u64) -> u64 {
    timestamp_ms.saturating_mul(1_000_000)
}
