mod tracing_bridge;

pub use tracing_bridge::OtelTracingBridge;

use opentelemetry::{global, trace::TracerProvider as _, KeyValue};
use opentelemetry_otlp::{LogExporter, MetricExporter, SpanExporter, WithExportConfig};
use opentelemetry_sdk::logs::SdkLoggerProvider;
use opentelemetry_sdk::metrics::{Instrument, PeriodicReader, SdkMeterProvider, Stream, Temporality};
use opentelemetry_sdk::propagation::TraceContextPropagator;
use opentelemetry_sdk::trace::SdkTracerProvider;
use opentelemetry_sdk::Resource;

/// Type alias for a metric view function.
///
/// A view is a function that takes an instrument and optionally returns a modified stream
/// configuration for that instrument. This is commonly used for customizing histogram buckets.
///
/// # Example
/// ```ignore
/// use opentelemetry_sdk::metrics::{Aggregation, Instrument, Stream};
///
/// fn my_histogram_view(instrument: &Instrument) -> Option<Stream> {
///     if instrument.name() == "http.client.duration" {
///         Some(Stream::builder()
///             .with_aggregation(Aggregation::ExplicitBucketHistogram {
///                 boundaries: vec![0.1, 0.5, 1.0, 2.0, 5.0, 10.0],
///                 record_min_max: false,
///             })
///             .build()
///             .unwrap())
///     } else {
///         None
///     }
/// }
/// ```
pub type MetricView = Box<dyn Fn(&Instrument) -> Option<Stream> + Send + Sync + 'static>;
use std::time::Duration;
use tracing_appender::rolling;
use tracing_error::ErrorLayer;
use tracing_opentelemetry::{MetricsLayer, OpenTelemetryLayer};
use tracing_panic::panic_hook;
use tracing_subscriber::fmt::format::{FmtSpan, JsonFields};
use tracing_subscriber::fmt::time::ChronoUtc;
use tracing_subscriber::fmt::{self, format};
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::{registry, EnvFilter, Layer};

#[derive(Debug, thiserror::Error)]
pub enum OtelInitError {
    #[error("Failed to initialize OTLP log exporter")]
    LogExporter(#[source] opentelemetry_otlp::ExporterBuildError),
    #[error("Failed to initialize OTLP trace exporter")]
    TraceExporter(#[source] opentelemetry_otlp::ExporterBuildError),
    #[error("Failed to initialize OTLP metrics exporter")]
    MetricsExporter(#[source] opentelemetry_otlp::ExporterBuildError),
}

/// Configuration for OpenTelemetry initialization.
#[derive(Debug, Clone)]
pub struct OtelConfig {
    /// OTLP endpoint URL (e.g., "http://localhost:4318")
    pub otlp_endpoint: String,
    /// Service name for resource attribution
    pub service_name: String,
    /// Service instance ID (e.g., IP address, hostname, pod name)
    pub service_instance_id: String,
    /// Service version (typically from CARGO_PKG_VERSION)
    pub service_version: String,
    /// Deployment environment (e.g., "dev", "prod")
    pub environment: String,
    /// Log level for OTLP logger layer
    pub logger_level: String,
    /// Log level for OTLP tracer layer
    pub tracer_level: String,
    /// Log level for stdout fmt layer
    pub fmt_level: String,
    /// Log level for file layer (None to disable file logging)
    pub file_level: Option<String>,
    /// Directory for log files (default: "logs")
    pub log_directory: String,
    /// Log file name prefix (default: "app.log")
    pub log_file_prefix: String,
    /// Additional filter directives (e.g., ["hyper=off", "sqlx::query=info"])
    pub filter_directives: Vec<String>,
    /// Metrics export interval in seconds (default: 1)
    pub metrics_interval_secs: u64,
}

impl Default for OtelConfig {
    fn default() -> Self {
        Self {
            otlp_endpoint: "http://localhost:4318".to_string(),
            service_name: "unknown".to_string(),
            service_instance_id: "unknown".to_string(),
            service_version: "0.0.0".to_string(),
            environment: "dev".to_string(),
            logger_level: "info".to_string(),
            tracer_level: "info".to_string(),
            fmt_level: "info".to_string(),
            file_level: Some("debug".to_string()),
            log_directory: "logs".to_string(),
            log_file_prefix: "app.log".to_string(),
            filter_directives: vec![],
            metrics_interval_secs: 1,
        }
    }
}

/// Guard that handles graceful shutdown of OTEL providers.
///
/// Call `shutdown()` before application exit to flush pending telemetry.
pub struct OtelGuard {
    logger: SdkLoggerProvider,
    tracer: SdkTracerProvider,
    metrics: SdkMeterProvider,
}

impl OtelGuard {
    /// Flushes all pending telemetry data.
    pub fn shutdown(&self) {
        self.flush_all();
    }

    fn flush_all(&self) {
        if let Err(e) = self.logger.force_flush() {
            eprintln!("Logger flush error: {e:?}")
        }
        if let Err(e) = self.tracer.force_flush() {
            eprintln!("Tracer flush error: {e:?}")
        }
        if let Err(e) = self.metrics.force_flush() {
            eprintln!("Metrics flush error: {e:?}")
        }
    }
}

impl Drop for OtelGuard {
    fn drop(&mut self) {
        self.flush_all();
    }
}

fn build_resource(config: &OtelConfig) -> Resource {
    Resource::builder()
        .with_service_name(config.service_name.clone())
        .with_attributes([
            KeyValue::new("service.instance.id", config.service_instance_id.clone()),
            KeyValue::new("service.version", config.service_version.clone()),
            KeyValue::new("deployment.environment", config.environment.clone()),
        ])
        .build()
}

fn build_filter(level: &str, directives: &[String]) -> EnvFilter {
    let mut filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(level));

    // Default directives to reduce noise from common crates
    let default_directives = [
        "opentelemetry_sdk=warn",
        "opentelemetry-otlp=warn",
        "opentelemetry-http=warn",
        "tower=warn",
        "hyper_util=off",
        "hyper=off",
        "h2=off",
        "reqwest::connect=off",
    ];

    for directive in default_directives {
        match directive.parse() {
            Ok(d) => filter = filter.add_directive(d),
            Err(e) => eprintln!("Invalid default filter directive '{directive}': {e}"),
        }
    }

    for directive in directives {
        match directive.parse() {
            Ok(d) => filter = filter.add_directive(d),
            Err(e) => eprintln!("Invalid filter directive '{directive}': {e}"),
        }
    }

    filter
}

fn init_otlp_logger(config: &OtelConfig) -> Result<SdkLoggerProvider, OtelInitError> {
    let logs_url = format!("{}/v1/logs", config.otlp_endpoint);
    let log_exporter = LogExporter::builder()
        .with_http()
        .with_endpoint(logs_url)
        .build()
        .map_err(OtelInitError::LogExporter)?;

    Ok(SdkLoggerProvider::builder()
        .with_resource(build_resource(config))
        .with_batch_exporter(log_exporter)
        .build())
}

fn init_otlp_tracer(config: &OtelConfig) -> Result<SdkTracerProvider, OtelInitError> {
    let tracer_url = format!("{}/v1/traces", config.otlp_endpoint);
    let trace_exporter = SpanExporter::builder()
        .with_http()
        .with_endpoint(tracer_url)
        .build()
        .map_err(OtelInitError::TraceExporter)?;

    Ok(SdkTracerProvider::builder()
        .with_resource(build_resource(config))
        .with_batch_exporter(trace_exporter)
        .build())
}

fn init_otlp_metrics(
    config: &OtelConfig,
    views: Vec<MetricView>,
) -> Result<SdkMeterProvider, OtelInitError> {
    let metrics_url = format!("{}/v1/metrics", config.otlp_endpoint);
    let metrics_exporter = MetricExporter::builder()
        .with_http()
        .with_endpoint(metrics_url)
        .with_temporality(Temporality::Cumulative)
        .build()
        .map_err(OtelInitError::MetricsExporter)?;

    let reader = PeriodicReader::builder(metrics_exporter)
        .with_interval(Duration::from_secs(config.metrics_interval_secs))
        .build();

    let mut provider_builder = SdkMeterProvider::builder()
        .with_resource(build_resource(config))
        .with_reader(reader);

    for view in views {
        provider_builder = provider_builder.with_view(view);
    }

    Ok(provider_builder.build())
}

/// Initialize the tracing subscriber with OpenTelemetry integration.
///
/// This sets up:
/// - OTLP log exporter (logs to Loki/etc via OTLP)
/// - OTLP trace exporter (traces to Tempo/Jaeger/etc via OTLP)
/// - OTLP metrics exporter (metrics to Prometheus/etc via OTLP)
/// - Stdout fmt layer (colored console output)
/// - Optional file layer (JSON logs to rotating files)
/// - Error layer for SpanTrace support
/// - Panic hook for tracing panics
///
/// Returns an `OtelGuard` that should be kept alive for the application lifetime.
/// Call `guard.shutdown()` before exit to flush pending telemetry.
///
/// For custom histogram bucket boundaries or other metric views, use
/// [`init_tracing_with_views`] instead.
pub fn init_tracing(config: OtelConfig) -> Result<OtelGuard, OtelInitError> {
    init_tracing_with_views(config, vec![])
}

/// Initialize the tracing subscriber with OpenTelemetry integration and custom metric views.
///
/// This is the same as [`init_tracing`] but allows you to pass custom metric views
/// for customizing histogram bucket boundaries or other aggregation settings.
///
/// # Example
/// ```ignore
/// use tracing_otel_init::{OtelConfigBuilder, init_tracing_with_views, MetricView};
/// use opentelemetry_sdk::metrics::{Aggregation, Instrument, Stream};
///
/// fn histogram_view(name: &'static str, buckets: &'static [f64]) -> MetricView {
///     Box::new(move |i: &Instrument| {
///         (i.name() == name).then(|| {
///             Stream::builder()
///                 .with_aggregation(Aggregation::ExplicitBucketHistogram {
///                     boundaries: buckets.to_vec(),
///                     record_min_max: false,
///                 })
///                 .build()
///                 .expect("valid stream")
///         })
///     })
/// }
///
/// const HTTP_BUCKETS: &[f64] = &[0.1, 0.5, 1.0, 2.0, 5.0, 10.0, 30.0, 60.0];
///
/// let views = vec![
///     histogram_view("http.client.duration", HTTP_BUCKETS),
///     histogram_view("http.client.ttfb", HTTP_BUCKETS),
/// ];
///
/// let config = OtelConfigBuilder::new()
///     .service_name("my-service")
///     .build();
///
/// let guard = init_tracing_with_views(config, views)?;
/// ```
pub fn init_tracing_with_views(
    config: OtelConfig,
    metric_views: Vec<MetricView>,
) -> Result<OtelGuard, OtelInitError> {
    // Logger (logs)
    let otlp_logger_provider = init_otlp_logger(&config)?;
    let otlp_logger_filter = build_filter(&config.logger_level, &config.filter_directives);
    let otlp_logger_layer =
        OtelTracingBridge::new(&otlp_logger_provider).with_filter(otlp_logger_filter);

    // Tracer (spans)
    let otlp_tracer_provider = init_otlp_tracer(&config)?;
    let otlp_tracer = otlp_tracer_provider.tracer("tracing-otel-subscriber");
    let otlp_tracer_filter = build_filter(&config.tracer_level, &config.filter_directives);
    let otlp_tracer_layer = OpenTelemetryLayer::new(otlp_tracer).with_filter(otlp_tracer_filter);
    global::set_text_map_propagator(TraceContextPropagator::new());

    // Metrics (with optional views)
    let otlp_metrics_provider = init_otlp_metrics(&config, metric_views)?;
    let otlp_metrics_layer = MetricsLayer::new(otlp_metrics_provider.clone());
    global::set_meter_provider(otlp_metrics_provider.clone());

    // Stdout fmt layer
    let fmt_filter = build_filter(&config.fmt_level, &config.filter_directives);
    let fmt_layer = fmt::Layer::new()
        .event_format(
            format()
                .with_ansi(true)
                .with_timer(ChronoUtc::rfc_3339())
                .with_line_number(true),
        )
        .with_filter(fmt_filter);

    // Set up panic hook
    let prev_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |panic_info| {
        panic_hook(panic_info);
        prev_hook(panic_info);
    }));

    // Build the subscriber
    let subscriber = registry()
        .with(otlp_logger_layer)
        .with(otlp_tracer_layer)
        .with(otlp_metrics_layer)
        .with(fmt_layer)
        .with(ErrorLayer::default());

    // Optionally add file layer
    if let Some(ref file_level) = config.file_level {
        let file_filter = build_filter(file_level, &config.filter_directives);
        let file_provider = rolling::daily(&config.log_directory, &config.log_file_prefix);
        let file_layer = fmt::Layer::new()
            .with_writer(file_provider)
            .with_span_events(FmtSpan::CLOSE)
            .event_format(
                format()
                    .with_ansi(false)
                    .with_timer(ChronoUtc::rfc_3339())
                    .with_line_number(true)
                    .json(),
            )
            .fmt_fields(JsonFields::default())
            .with_filter(file_filter);

        subscriber.with(file_layer).init();
    } else {
        subscriber.init();
    }

    Ok(OtelGuard {
        logger: otlp_logger_provider,
        tracer: otlp_tracer_provider,
        metrics: otlp_metrics_provider,
    })
}

/// Builder for `OtelConfig` with a fluent API.
#[derive(Debug, Clone, Default)]
pub struct OtelConfigBuilder {
    config: OtelConfig,
}

impl OtelConfigBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn otlp_endpoint(mut self, endpoint: impl Into<String>) -> Self {
        self.config.otlp_endpoint = endpoint.into();
        self
    }

    pub fn service_name(mut self, name: impl Into<String>) -> Self {
        self.config.service_name = name.into();
        self
    }

    pub fn service_instance_id(mut self, id: impl Into<String>) -> Self {
        self.config.service_instance_id = id.into();
        self
    }

    pub fn service_version(mut self, version: impl Into<String>) -> Self {
        self.config.service_version = version.into();
        self
    }

    pub fn environment(mut self, env: impl Into<String>) -> Self {
        self.config.environment = env.into();
        self
    }

    pub fn logger_level(mut self, level: impl Into<String>) -> Self {
        self.config.logger_level = level.into();
        self
    }

    pub fn tracer_level(mut self, level: impl Into<String>) -> Self {
        self.config.tracer_level = level.into();
        self
    }

    pub fn fmt_level(mut self, level: impl Into<String>) -> Self {
        self.config.fmt_level = level.into();
        self
    }

    pub fn file_level(mut self, level: Option<impl Into<String>>) -> Self {
        self.config.file_level = level.map(|l| l.into());
        self
    }

    pub fn log_directory(mut self, dir: impl Into<String>) -> Self {
        self.config.log_directory = dir.into();
        self
    }

    pub fn log_file_prefix(mut self, prefix: impl Into<String>) -> Self {
        self.config.log_file_prefix = prefix.into();
        self
    }

    pub fn filter_directive(mut self, directive: impl Into<String>) -> Self {
        self.config.filter_directives.push(directive.into());
        self
    }

    pub fn filter_directives(mut self, directives: impl IntoIterator<Item = impl Into<String>>) -> Self {
        self.config.filter_directives.extend(directives.into_iter().map(|d| d.into()));
        self
    }

    pub fn metrics_interval_secs(mut self, secs: u64) -> Self {
        self.config.metrics_interval_secs = secs;
        self
    }

    #[must_use]
    pub fn build(self) -> OtelConfig {
        self.config
    }
}