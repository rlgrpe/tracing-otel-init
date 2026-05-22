use opentelemetry::logs::AnyValue;
use opentelemetry::trace::TracerProvider as _;
use opentelemetry_sdk::logs::{InMemoryLogExporter, SdkLoggerProvider};
use opentelemetry_sdk::trace::{InMemorySpanExporter, SdkTracerProvider};
use tracing::{info, span, Level};
use tracing_opentelemetry::OpenTelemetryLayer;
use tracing_otel_init::{OtelTracingBridge, TracingSpanAttributes};
use tracing_subscriber::{layer::SubscriberExt, Registry};

#[test]
fn tracing_logs_inside_tracing_span_include_trace_context() {
    let log_exporter = InMemoryLogExporter::default();
    let logger_provider = SdkLoggerProvider::builder()
        .with_simple_exporter(log_exporter.clone())
        .build();

    let span_exporter = InMemorySpanExporter::default();
    let tracer_provider = SdkTracerProvider::builder()
        .with_simple_exporter(span_exporter.clone())
        .build();
    let tracer = tracer_provider.tracer("test-tracer");

    let subscriber = Registry::default()
        .with(OpenTelemetryLayer::new(tracer))
        .with(
            OtelTracingBridge::builder(&logger_provider)
                .with_tracing_span_attributes(TracingSpanAttributes::all())
                .build(),
        );

    tracing::subscriber::with_default(subscriber, || {
        let request_span = span!(Level::INFO, "request", request_id = "req-1");
        let _entered = request_span.enter();

        info!(name: "request.handled", target: "test", user_id = "user-1", "handled request");
    });

    logger_provider.force_flush().expect("logs should flush");
    tracer_provider.force_flush().expect("spans should flush");

    let logs = log_exporter
        .get_emitted_logs()
        .expect("logs should be exported");
    let spans = span_exporter
        .get_finished_spans()
        .expect("spans should be exported");

    assert_eq!(logs.len(), 1);
    assert_eq!(spans.len(), 1);

    let trace_context = logs[0]
        .record
        .trace_context()
        .expect("log record should have trace context");
    let span_context = &spans[0].span_context;

    assert_eq!(trace_context.trace_id, span_context.trace_id());
    assert_eq!(trace_context.span_id, span_context.span_id());

    assert_log_string_attribute(&logs[0].record, "request_id", "req-1");
}

fn assert_log_string_attribute(
    record: &opentelemetry_sdk::logs::SdkLogRecord,
    key: &str,
    expected: &str,
) {
    let value = record
        .attributes_iter()
        .find_map(|(attribute_key, value)| (attribute_key.as_str() == key).then_some(value))
        .unwrap_or_else(|| panic!("log record should include {key} attribute"));

    match value {
        AnyValue::String(actual) => assert_eq!(actual.as_str(), expected),
        other => panic!("{key} should be a string attribute, got {other:?}"),
    }
}
