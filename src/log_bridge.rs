// Vendored from opentelemetry-appender-tracing 0.32.0, src/layer.rs
// (https://github.com/open-telemetry/opentelemetry-rust/tree/main/opentelemetry-appender-tracing),
// Copyright The OpenTelemetry Authors, licensed under the Apache License, Version 2.0
// (http://www.apache.org/licenses/LICENSE-2.0).
// Modified: one value per attribute key. Span re-records replace the stored value;
// event fields override span fields and the nearest span overrides its ancestors.

use opentelemetry::{
    logs::{AnyValue, LogRecord, Logger, LoggerProvider, Severity},
    Key,
};
use std::borrow::Cow;
use std::collections::HashSet;
use tracing::field::{Field, Visit};
use tracing::span::{Attributes, Id, Record};
use tracing::Level;
use tracing_subscriber::registry::{LookupSpan, Scope};
use tracing_subscriber::Layer;

/// Visitor to record the fields from the event record.
///
/// The `message` field becomes the record body; every other field is
/// collected into `attributes` so span attributes can be merged first.
struct EventVisitor<'a, LR: LogRecord> {
    log_record: &'a mut LR,
    attributes: &'a mut Vec<(Key, AnyValue)>,
}

impl<LR: LogRecord> Visit for EventVisitor<'_, LR> {
    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        if field.name() == "message" {
            self.log_record.set_body(format!("{value:?}").into());
        } else {
            self.attributes
                .push((Key::new(field.name()), AnyValue::from(format!("{value:?}"))));
        }
    }

    fn record_error(&mut self, _field: &Field, value: &(dyn std::error::Error + 'static)) {
        self.attributes.push((
            Key::new("exception.message"),
            AnyValue::from(value.to_string()),
        ));
        // No ability to get exception.stacktrace or exception.type from the error today.
    }

    fn record_bytes(&mut self, field: &Field, value: &[u8]) {
        self.attributes
            .push((Key::new(field.name()), AnyValue::from(value)));
    }

    fn record_str(&mut self, field: &Field, value: &str) {
        if field.name() == "message" {
            self.log_record.set_body(AnyValue::from(value.to_owned()));
        } else {
            self.attributes
                .push((Key::new(field.name()), AnyValue::from(value.to_owned())));
        }
    }

    fn record_bool(&mut self, field: &Field, value: bool) {
        self.attributes
            .push((Key::new(field.name()), AnyValue::from(value)));
    }

    fn record_f64(&mut self, field: &Field, value: f64) {
        self.attributes
            .push((Key::new(field.name()), AnyValue::from(value)));
    }

    fn record_i64(&mut self, field: &Field, value: i64) {
        self.attributes
            .push((Key::new(field.name()), AnyValue::from(value)));
    }

    fn record_u64(&mut self, field: &Field, value: u64) {
        if let Ok(signed) = i64::try_from(value) {
            self.attributes
                .push((Key::new(field.name()), AnyValue::from(signed)));
        } else {
            self.attributes
                .push((Key::new(field.name()), AnyValue::from(format!("{value:?}"))));
        }
    }

    fn record_i128(&mut self, field: &Field, value: i128) {
        if let Ok(signed) = i64::try_from(value) {
            self.attributes
                .push((Key::new(field.name()), AnyValue::from(signed)));
        } else {
            self.attributes
                .push((Key::new(field.name()), AnyValue::from(format!("{value:?}"))));
        }
    }

    fn record_u128(&mut self, field: &Field, value: u128) {
        if let Ok(signed) = i64::try_from(value) {
            self.attributes
                .push((Key::new(field.name()), AnyValue::from(signed)));
        } else {
            self.attributes
                .push((Key::new(field.name()), AnyValue::from(format!("{value:?}"))));
        }
    }
}

/// Visitor to extract fields from a tracing span.
/// Takes a mutable reference to the span's stored attributes, and an optional
/// allowlist to include only named attributes. A key already present is
/// replaced in place, so a span holds one value per key.
struct SpanFieldVisitor<'a> {
    attributes: &'a mut Vec<(Key, AnyValue)>,
    allowlist: Option<&'a HashSet<Cow<'static, str>>>,
}

impl SpanFieldVisitor<'_> {
    #[inline]
    fn allowed(&self, field: &Field) -> bool {
        self.allowlist.is_none_or(|set| set.contains(field.name()))
    }

    fn put(&mut self, key: Key, value: AnyValue) {
        if let Some(slot) = self.attributes.iter_mut().find(|(k, _)| *k == key) {
            slot.1 = value;
        } else {
            self.attributes.push((key, value));
        }
    }
}

impl Visit for SpanFieldVisitor<'_> {
    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        if self.allowed(field) {
            self.put(
                Key::from(field.name()),
                AnyValue::from(format!("{value:?}")),
            );
        }
    }

    fn record_error(&mut self, field: &Field, value: &(dyn std::error::Error + 'static)) {
        if self.allowed(field) {
            self.put(
                Key::new("exception.message"),
                AnyValue::from(value.to_string()),
            );
        }
    }

    fn record_bytes(&mut self, field: &Field, value: &[u8]) {
        if self.allowed(field) {
            self.put(Key::from(field.name()), AnyValue::from(value));
        }
    }

    fn record_str(&mut self, field: &Field, value: &str) {
        if self.allowed(field) {
            self.put(Key::from(field.name()), AnyValue::from(value.to_owned()));
        }
    }

    fn record_i64(&mut self, field: &Field, value: i64) {
        if self.allowed(field) {
            self.put(Key::from(field.name()), AnyValue::from(value));
        }
    }

    fn record_u64(&mut self, field: &Field, value: u64) {
        if self.allowed(field) {
            if let Ok(signed) = i64::try_from(value) {
                self.put(Key::from(field.name()), AnyValue::from(signed));
            } else {
                self.put(Key::from(field.name()), AnyValue::from(format!("{value}")));
            }
        }
    }

    fn record_bool(&mut self, field: &Field, value: bool) {
        if self.allowed(field) {
            self.put(Key::from(field.name()), AnyValue::from(value));
        }
    }

    fn record_f64(&mut self, field: &Field, value: f64) {
        if self.allowed(field) {
            self.put(Key::from(field.name()), AnyValue::from(value));
        }
    }

    fn record_i128(&mut self, field: &Field, value: i128) {
        if self.allowed(field) {
            if let Ok(signed) = i64::try_from(value) {
                self.put(Key::from(field.name()), AnyValue::from(signed));
            } else {
                self.put(Key::from(field.name()), AnyValue::from(format!("{value}")));
            }
        }
    }

    fn record_u128(&mut self, field: &Field, value: u128) {
        if self.allowed(field) {
            if let Ok(signed) = i64::try_from(value) {
                self.put(Key::from(field.name()), AnyValue::from(signed));
            } else {
                self.put(Key::from(field.name()), AnyValue::from(format!("{value}")));
            }
        }
    }
}

/// Stored span attributes in the span's extensions.
/// Similar to how `tracing_subscriber::fmt::FormattedFields` stores formatted
/// field data directly in span extensions - the Registry's internal locking
/// provides the necessary synchronization.
#[derive(Debug)]
struct StoredSpanAttributes {
    attributes: Vec<(Key, AnyValue)>,
}

/// Configures which attributes from active [`tracing`] spans are copied onto
/// each emitted log record.
///
/// "Span" here refers to a [`tracing::span!`] from the [`tracing`] crate,
/// **not** an `opentelemetry::trace::Span`.
///
/// Pass this to `OtelTracingBridge::builder(..).with_tracing_span_attributes(..)`
/// to enable tracing-span attribute enrichment.
///
/// [`tracing`]: https://crates.io/crates/tracing
/// [`tracing::span!`]: https://docs.rs/tracing/latest/tracing/macro.span.html
pub struct TracingSpanAttributes(TracingSpanAttributesInner);

enum TracingSpanAttributesInner {
    All,
    Allowlist(HashSet<Cow<'static, str>>),
}

impl TracingSpanAttributes {
    /// Copy **all** tracing-span attributes onto log records.
    pub fn all() -> Self {
        Self(TracingSpanAttributesInner::All)
    }

    /// Copy only the tracing-span attributes whose keys are in the given
    /// allowlist.
    pub fn allowlist(keys: impl IntoIterator<Item = impl Into<Cow<'static, str>>>) -> Self {
        Self(TracingSpanAttributesInner::Allowlist(
            keys.into_iter().map(Into::into).collect(),
        ))
    }
}

impl std::fmt::Debug for TracingSpanAttributes {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.0 {
            TracingSpanAttributesInner::All => f.write_str("TracingSpanAttributes::all()"),
            TracingSpanAttributesInner::Allowlist(set) => f
                .debug_tuple("TracingSpanAttributes::allowlist")
                .field(set)
                .finish(),
        }
    }
}

/// A [`Layer`] that turns [`tracing`] events into OpenTelemetry log records,
/// keeping one value per attribute key.
///
/// [`tracing`]: https://crates.io/crates/tracing
pub struct OpenTelemetryTracingBridge<P, L>
where
    P: LoggerProvider<Logger = L> + Send + Sync,
    L: Logger + Send + Sync,
{
    logger: L,
    _phantom: std::marker::PhantomData<P>, // P is not used.
    // Tracing-span attribute enrichment configuration:
    // - `None` => disabled (default). No per-span work, no scope walk.
    // - `Some(All)` => copy all tracing-span attributes onto log records.
    // - `Some(Allowlist(set))` => copy only attributes whose keys are in `set`.
    span_attributes: Option<TracingSpanAttributesInner>,
}

impl<P, L> OpenTelemetryTracingBridge<P, L>
where
    P: LoggerProvider<Logger = L> + Send + Sync,
    L: Logger + Send + Sync,
{
    /// Builds a bridge without tracing-span attribute enrichment.
    pub fn new(provider: &P) -> Self {
        Self::builder(provider).build()
    }

    /// Starts a builder for a bridge that logs through `provider`.
    pub fn builder(provider: &P) -> OpenTelemetryTracingBridgeBuilder<P, L> {
        OpenTelemetryTracingBridgeBuilder {
            // Using empty scope name.
            // The name/version of this library itself can be added
            // as a Scope attribute, once a semantic convention is
            // defined for the same.
            // See https://github.com/open-telemetry/semantic-conventions/issues/1550
            logger: provider.logger(""),
            _phantom: Default::default(),
            span_attributes: None,
        }
    }
}

/// Builder for [`OpenTelemetryTracingBridge`].
pub struct OpenTelemetryTracingBridgeBuilder<P, L>
where
    P: LoggerProvider<Logger = L> + Send + Sync,
    L: Logger + Send + Sync,
{
    logger: L,
    _phantom: std::marker::PhantomData<P>,
    span_attributes: Option<TracingSpanAttributesInner>,
}

impl<P, L> OpenTelemetryTracingBridgeBuilder<P, L>
where
    P: LoggerProvider<Logger = L> + Send + Sync,
    L: Logger + Send + Sync,
{
    /// Enable copying attributes from active [`tracing`] spans onto each
    /// emitted log record. ("Span" here means a [`tracing::span!`] from the
    /// [`tracing`] crate, **not** an `opentelemetry::trace::Span`.)
    ///
    /// By default, enrichment is **disabled** and no per-span work is
    /// performed.
    ///
    /// Use [`TracingSpanAttributes::all()`] to copy every tracing-span attribute, or
    /// [`TracingSpanAttributes::allowlist(keys)`](TracingSpanAttributes::allowlist) to copy
    /// only named attributes.
    ///
    /// Calling this method multiple times replaces any prior configuration —
    /// the last call wins.
    ///
    /// [`tracing`]: https://crates.io/crates/tracing
    /// [`tracing::span!`]: https://docs.rs/tracing/latest/tracing/macro.span.html
    pub fn with_tracing_span_attributes(mut self, span_attributes: TracingSpanAttributes) -> Self {
        self.span_attributes = Some(span_attributes.0);
        self
    }

    /// Finishes the bridge.
    pub fn build(self) -> OpenTelemetryTracingBridge<P, L> {
        OpenTelemetryTracingBridge {
            logger: self.logger,
            _phantom: self._phantom,
            span_attributes: self.span_attributes,
        }
    }
}

/// Picks span attributes for one event: a key the event already carries is
/// skipped, and the nearest span wins over its ancestors. The result is
/// ordered root to leaf, each span in its field order.
fn collect_span_attributes<S>(
    scope: Scope<'_, S>,
    event_attrs: &[(Key, AnyValue)],
) -> Vec<(Key, AnyValue)>
where
    S: for<'a> LookupSpan<'a>,
{
    let mut picked: Vec<(Key, AnyValue)> = Vec::new();
    // `Scope` walks from the leaf to the root.
    for span_ref in scope {
        let extensions = span_ref.extensions();
        let Some(stored) = extensions.get::<StoredSpanAttributes>() else {
            continue;
        };
        for (key, value) in stored.attributes.iter().rev() {
            let taken =
                event_attrs.iter().any(|(k, _)| k == key) || picked.iter().any(|(k, _)| k == key);
            if !taken {
                picked.push((key.clone(), value.clone()));
            }
        }
    }
    picked.reverse();
    picked
}

impl<S, P, L> Layer<S> for OpenTelemetryTracingBridge<P, L>
where
    S: tracing::Subscriber + for<'a> LookupSpan<'a>,
    P: LoggerProvider<Logger = L> + Send + Sync + 'static,
    L: Logger + Send + Sync + 'static,
{
    fn on_event(&self, event: &tracing::Event<'_>, ctx: tracing_subscriber::layer::Context<'_, S>) {
        let metadata = event.metadata();
        let severity = severity_of_level(metadata.level());
        let target = metadata.target();
        let name = metadata.name();
        if !self.logger.event_enabled(severity, target, Some(name)) {
            return;
        }

        let mut log_record = self.logger.create_log_record();

        log_record.set_target(target);
        log_record.set_event_name(name);
        log_record.set_severity_number(severity);
        log_record.set_severity_text(metadata.level().as_str());

        // Fields with `tracing::field::Empty` are never visited, so an empty
        // event field does not hide the span field of the same name.
        let mut event_attrs = Vec::with_capacity(event.fields().count());
        event.record(&mut EventVisitor {
            log_record: &mut log_record,
            attributes: &mut event_attrs,
        });

        if self.span_attributes.is_some() {
            if let Some(scope) = ctx.event_scope(event) {
                for (key, value) in collect_span_attributes(scope, &event_attrs) {
                    log_record.add_attribute(key, value);
                }
            }
        }
        for (key, value) in event_attrs {
            log_record.add_attribute(key, value);
        }

        self.logger.emit(log_record);
    }

    fn on_new_span(
        &self,
        attrs: &Attributes<'_>,
        id: &Id,
        ctx: tracing_subscriber::layer::Context<'_, S>,
    ) {
        // Skip entirely when tracing-span attribute enrichment is disabled to
        // avoid any per-span overhead.
        let Some(config) = self.span_attributes.as_ref() else {
            return;
        };
        let allowlist = match config {
            TracingSpanAttributesInner::All => None,
            TracingSpanAttributesInner::Allowlist(set) => Some(set),
        };

        let span = ctx.span(id).expect("Span not found; this is a bug");
        let mut fields = Vec::with_capacity(attrs.fields().len());
        let mut visitor = SpanFieldVisitor {
            attributes: &mut fields,
            allowlist,
        };
        attrs.record(&mut visitor);

        // Only store if we actually found attributes to avoid empty allocations
        if !fields.is_empty() {
            let stored = StoredSpanAttributes { attributes: fields };

            let mut extensions = span.extensions_mut();
            extensions.insert(stored);
        }
    }

    fn on_record(
        &self,
        id: &Id,
        values: &Record<'_>,
        ctx: tracing_subscriber::layer::Context<'_, S>,
    ) {
        let Some(config) = self.span_attributes.as_ref() else {
            return;
        };
        let allowlist = match config {
            TracingSpanAttributesInner::All => None,
            TracingSpanAttributesInner::Allowlist(set) => Some(set),
        };

        let span = ctx.span(id).expect("Span not found; this is a bug");
        let mut extensions = span.extensions_mut();

        if let Some(stored) = extensions.get_mut::<StoredSpanAttributes>() {
            // Replace or append - extensions_mut() gives us mutable access
            let mut visitor = SpanFieldVisitor {
                attributes: &mut stored.attributes,
                allowlist,
            };
            values.record(&mut visitor);
        } else {
            // No existing attributes, create new storage
            let mut fields = Vec::with_capacity(values.len());
            let mut visitor = SpanFieldVisitor {
                attributes: &mut fields,
                allowlist,
            };
            values.record(&mut visitor);
            if !fields.is_empty() {
                let stored = StoredSpanAttributes { attributes: fields };
                extensions.insert(stored);
            }
        }
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
