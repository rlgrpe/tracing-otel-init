use opentelemetry::logs::{AnyValue, LogRecord, Logger, LoggerProvider, Severity};
use opentelemetry::{Array, Key, Value};
use tracing::field::Visit;
use tracing::Level;
use tracing_subscriber::layer::Context;
use tracing_subscriber::registry::LookupSpan;
use tracing_subscriber::Layer;

trait ToAnyValue {
    fn to_any_value(self) -> AnyValue;
}

impl ToAnyValue for Value {
    fn to_any_value(self) -> AnyValue {
        match self {
            Value::Bool(v) => AnyValue::Boolean(v),
            Value::I64(v) => AnyValue::Int(v),
            Value::F64(v) => AnyValue::Double(v),
            Value::String(v) => AnyValue::String(v),
            Value::Array(v) => match v {
                Array::Bool(vec) => {
                    AnyValue::ListAny(Box::new(vec.into_iter().map(AnyValue::Boolean).collect()))
                }
                Array::I64(vec) => {
                    AnyValue::ListAny(Box::new(vec.into_iter().map(AnyValue::Int).collect()))
                }
                Array::F64(vec) => {
                    AnyValue::ListAny(Box::new(vec.into_iter().map(AnyValue::Double).collect()))
                }
                Array::String(vec) => {
                    AnyValue::ListAny(Box::new(vec.into_iter().map(AnyValue::String).collect()))
                }
                _ => AnyValue::String("unsupported_array_type".into()),
            },
            _ => AnyValue::String("unsupported_value_type".into()),
        }
    }
}

struct EventVisitor<'a, LR: LogRecord> {
    log_record: &'a mut LR,
}

fn is_duplicated_metadata(field: &'static str) -> bool {
    field
        .strip_prefix("log.")
        .map(|remainder| matches!(remainder, "file" | "line" | "module_path" | "target"))
        .unwrap_or(false)
}

impl<'a, LR: LogRecord> EventVisitor<'a, LR> {
    fn new(log_record: &'a mut LR) -> Self {
        EventVisitor { log_record }
    }
}

impl<LR: LogRecord> Visit for EventVisitor<'_, LR> {
    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        if is_duplicated_metadata(field.name()) {
            return;
        }
        if field.name() == "message" {
            self.log_record.set_body(format!("{:?}", value).into());
        } else {
            self.log_record
                .add_attribute(Key::new(field.name()), AnyValue::from(format!("{value:?}")));
        }
    }

    fn record_error(
        &mut self,
        _field: &tracing::field::Field,
        value: &(dyn std::error::Error + 'static),
    ) {
        self.log_record.add_attribute(
            Key::new("exception.message"),
            AnyValue::from(value.to_string()),
        );
    }

    fn record_bytes(&mut self, field: &tracing::field::Field, value: &[u8]) {
        self.log_record
            .add_attribute(Key::new(field.name()), AnyValue::from(value));
    }

    fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
        if is_duplicated_metadata(field.name()) {
            return;
        }
        if field.name() == "message" {
            self.log_record.set_body(AnyValue::from(value.to_owned()));
        } else {
            self.log_record
                .add_attribute(Key::new(field.name()), AnyValue::from(value.to_owned()));
        }
    }

    fn record_bool(&mut self, field: &tracing::field::Field, value: bool) {
        self.log_record
            .add_attribute(Key::new(field.name()), AnyValue::from(value));
    }

    fn record_f64(&mut self, field: &tracing::field::Field, value: f64) {
        self.log_record
            .add_attribute(Key::new(field.name()), AnyValue::from(value));
    }

    fn record_i64(&mut self, field: &tracing::field::Field, value: i64) {
        if is_duplicated_metadata(field.name()) {
            return;
        }
        self.log_record
            .add_attribute(Key::new(field.name()), AnyValue::from(value));
    }

    fn record_u64(&mut self, field: &tracing::field::Field, value: u64) {
        if is_duplicated_metadata(field.name()) {
            return;
        }
        if let Ok(signed) = i64::try_from(value) {
            self.log_record
                .add_attribute(Key::new(field.name()), AnyValue::from(signed));
        } else {
            self.log_record
                .add_attribute(Key::new(field.name()), AnyValue::from(format!("{value:?}")));
        }
    }

    fn record_i128(&mut self, field: &tracing::field::Field, value: i128) {
        if is_duplicated_metadata(field.name()) {
            return;
        }
        if let Ok(signed) = i64::try_from(value) {
            self.log_record
                .add_attribute(Key::new(field.name()), AnyValue::from(signed));
        } else {
            self.log_record
                .add_attribute(Key::new(field.name()), AnyValue::from(format!("{value:?}")));
        }
    }

    fn record_u128(&mut self, field: &tracing::field::Field, value: u128) {
        if is_duplicated_metadata(field.name()) {
            return;
        }
        if let Ok(signed) = i64::try_from(value) {
            self.log_record
                .add_attribute(Key::new(field.name()), AnyValue::from(signed));
        } else {
            self.log_record
                .add_attribute(Key::new(field.name()), AnyValue::from(format!("{value:?}")));
        }
    }
}

/// A tracing layer that bridges tracing events to OpenTelemetry logs.
///
/// This layer captures tracing events and converts them to OpenTelemetry log records,
/// preserving span context (trace_id, span_id) for correlation.
pub struct OtelTracingBridge<P, L>
where
    P: LoggerProvider<Logger = L> + Send + Sync,
    L: Logger + Send + Sync,
{
    logger: L,
    _phantom: std::marker::PhantomData<P>,
}

impl<P, L> OtelTracingBridge<P, L>
where
    P: LoggerProvider<Logger = L> + Send + Sync,
    L: Logger + Send + Sync,
{
    pub fn new(provider: &P) -> Self {
        Self {
            logger: provider.logger(""),
            _phantom: Default::default(),
        }
    }
}

impl<S, P, L> Layer<S> for OtelTracingBridge<P, L>
where
    S: tracing::Subscriber + for<'a> LookupSpan<'a>,
    P: LoggerProvider<Logger = L> + Send + Sync + 'static,
    L: Logger + Send + Sync + 'static,
{
    fn on_event(&self, event: &tracing::Event<'_>, ctx: Context<'_, S>) {
        let metadata = event.metadata();
        let severity = severity_of_level(metadata.level());
        let target = metadata.target();
        let name = metadata.name();

        let mut log_record = self.logger.create_log_record();

        log_record.set_target(target);
        log_record.set_event_name(name);
        log_record.set_severity_number(severity);
        log_record.set_severity_text(metadata.level().as_str());
        let mut visitor = EventVisitor::new(&mut log_record);
        event.record(&mut visitor);

        if let Some(span) = ctx.event_span(event) {
            use opentelemetry::trace::TraceContextExt;
            use tracing_opentelemetry::OtelData;
            if let Some(otd) = span.extensions().get::<OtelData>() {
                if let Some(attributes) = &otd.builder.attributes {
                    for attribute in attributes {
                        log_record.add_attribute(
                            attribute.key.clone(),
                            attribute.value.clone().to_any_value(),
                        )
                    }
                }
                if let Some(span_id) = otd.builder.span_id {
                    let opt_trace_id = if otd.parent_cx.has_active_span() {
                        Some(otd.parent_cx.span().span_context().trace_id())
                    } else {
                        span.scope().last().and_then(|root_span| {
                            root_span
                                .extensions()
                                .get::<OtelData>()
                                .and_then(|otd| otd.builder.trace_id)
                        })
                    };
                    if let Some(trace_id) = opt_trace_id {
                        log_record.set_trace_context(trace_id, span_id, None);
                    }
                }
            }
        }

        self.logger.emit(log_record);
    }
}

const fn severity_of_level(level: &Level) -> Severity {
    match *level {
        Level::TRACE => Severity::Trace,
        Level::DEBUG => Severity::Debug,
        Level::INFO => Severity::Info,
        Level::WARN => Severity::Warn,
        Level::ERROR => Severity::Error,
    }
}