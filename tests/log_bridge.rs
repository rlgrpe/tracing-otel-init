use opentelemetry::logs::AnyValue;
use opentelemetry_sdk::logs::{InMemoryLogExporter, SdkLogRecord, SdkLoggerProvider};
use tracing::{info, info_span};
use tracing_otel_init::{OtelTracingBridge, TracingSpanAttributes};
use tracing_subscriber::{layer::SubscriberExt, Registry};

fn capture_with(mode: Option<TracingSpanAttributes>, body: impl FnOnce()) -> SdkLogRecord {
    let exporter = InMemoryLogExporter::default();
    let provider = SdkLoggerProvider::builder()
        .with_simple_exporter(exporter.clone())
        .build();
    let builder = OtelTracingBridge::builder(&provider);
    let bridge = match mode {
        Some(mode) => builder.with_tracing_span_attributes(mode).build(),
        None => builder.build(),
    };
    let subscriber = Registry::default().with(bridge);
    tracing::subscriber::with_default(subscriber, body);
    provider.force_flush().expect("logs should flush");
    let mut logs = exporter.get_emitted_logs().expect("logs should export");
    assert_eq!(logs.len(), 1, "exactly one log record");
    logs.remove(0).record
}

fn capture(mode: TracingSpanAttributes, body: impl FnOnce()) -> SdkLogRecord {
    capture_with(Some(mode), body)
}

fn attrs(record: &SdkLogRecord) -> Vec<(String, AnyValue)> {
    record
        .attributes_iter()
        .map(|(key, value)| (key.as_str().to_owned(), value.clone()))
        .collect()
}

fn keys(record: &SdkLogRecord) -> Vec<String> {
    attrs(record).into_iter().map(|(key, _)| key).collect()
}

fn values_of(record: &SdkLogRecord, key: &str) -> Vec<AnyValue> {
    attrs(record)
        .into_iter()
        .filter(|(k, _)| k == key)
        .map(|(_, v)| v)
        .collect()
}

fn s(value: &str) -> AnyValue {
    AnyValue::from(value.to_owned())
}

#[test]
fn span_rerecord_replaces_value() {
    let record = capture(TracingSpanAttributes::all(), || {
        let span = info_span!("s", proxy_id = "p1");
        span.record("proxy_id", "p2");
        let _entered = span.enter();
        info!("x");
    });
    assert_eq!(values_of(&record, "proxy_id"), vec![s("p2")]);
}

#[test]
fn empty_span_field_recorded_once() {
    let record = capture(TracingSpanAttributes::all(), || {
        let span = info_span!("s", confirmed = tracing::field::Empty);
        span.record("confirmed", true);
        let _entered = span.enter();
        info!("x");
    });
    assert_eq!(values_of(&record, "confirmed"), vec![AnyValue::from(true)]);
}

#[test]
fn nearest_span_overrides_ancestor() {
    let record = capture(TracingSpanAttributes::all(), || {
        let root = info_span!("root", a = "1", k = "root");
        let _root = root.enter();
        let child = info_span!("child", k = "child", b = "2");
        let _child = child.enter();
        info!("x");
    });
    assert_eq!(keys(&record), vec!["a", "k", "b"]);
    assert_eq!(values_of(&record, "k"), vec![s("child")]);
}

#[test]
fn event_field_overrides_span_field() {
    let record = capture(TracingSpanAttributes::all(), || {
        let span = info_span!("s", provider = "proxy");
        let _entered = span.enter();
        info!(provider = "solver", "x");
    });
    assert_eq!(values_of(&record, "provider"), vec![s("solver")]);
    assert_eq!(keys(&record).last().map(String::as_str), Some("provider"));
}

#[test]
fn empty_event_field_keeps_span_field() {
    let record = capture(TracingSpanAttributes::all(), || {
        let span = info_span!("s", proxy_id = "p1");
        let _entered = span.enter();
        info!(proxy_id = tracing::field::Empty, "x");
    });
    assert_eq!(values_of(&record, "proxy_id"), vec![s("p1")]);
}

#[test]
fn allowlist_filters_new_and_recorded_fields() {
    let record = capture(TracingSpanAttributes::allowlist(["kept"]), || {
        let span = info_span!("s", kept = "1", dropped = tracing::field::Empty);
        span.record("dropped", "2");
        span.record("kept", "3");
        let _entered = span.enter();
        info!("x");
    });
    assert_eq!(attrs(&record), vec![("kept".to_owned(), s("3"))]);
}

#[test]
fn attributes_ordered_root_to_leaf_then_event() {
    let record = capture(TracingSpanAttributes::all(), || {
        let root = info_span!("root", a = 1);
        let _root = root.enter();
        let child = info_span!("child", b = 2);
        let _child = child.enter();
        info!(c = 3, "x");
    });
    assert_eq!(keys(&record), vec!["a", "b", "c"]);
}

#[test]
fn no_span_attributes_when_disabled() {
    let record = capture_with(None, || {
        let span = info_span!("s", a = 1);
        let _entered = span.enter();
        info!(c = 3, "x");
    });
    assert_eq!(keys(&record), vec!["c"]);
}
