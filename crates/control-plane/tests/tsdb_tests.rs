use std::collections::HashMap;

use control_plane::{InMemoryTsdbSink, MetricPoint, SqliteTsdbSink, TsdbSink};

#[test]
fn in_memory_tsdb_records_points() {
    let sink = InMemoryTsdbSink::new();
    let point = MetricPoint::with_timestamp_ms(
        "requests_total",
        1.0,
        HashMap::new(),
        1_700_000_000_000,
    );
    sink.write(point.clone());
    let stored = sink.list();
    assert_eq!(stored.len(), 1);
    assert_eq!(stored[0].name, "requests_total");
}

#[test]
fn line_protocol_encodes_tags_and_timestamp() {
    let mut tags = HashMap::new();
    tags.insert("protocol".to_string(), "openai".to_string());
    let point =
        MetricPoint::with_timestamp_ms("request_latency_ms", 12.5, tags, 1_700_000_000_000);
    let line = point.to_line_protocol();
    assert!(line.starts_with("request_latency_ms,protocol=openai value=12.5 "));
    assert!(line.ends_with("1700000000000000000"));
}

#[test]
fn sqlite_tsdb_records_points() {
    let sink = SqliteTsdbSink::open(":memory:").expect("sink");
    let point = MetricPoint::with_timestamp_ms(
        "requests_total",
        1.0,
        HashMap::new(),
        1_700_000_000_000,
    );
    sink.write(point.clone());
    let stored = sink.list();
    assert_eq!(stored.len(), 1);
    assert_eq!(stored[0].name, "requests_total");
}
