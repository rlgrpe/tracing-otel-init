mod tracing_bridge;

pub use opentelemetry::KeyValue;
pub use tracing_bridge::OtelTracingBridge;

use opentelemetry::{global, trace::TracerProvider as _};
use opentelemetry_otlp::{LogExporter, MetricExporter, SpanExporter, WithExportConfig};
use opentelemetry_sdk::logs::SdkLoggerProvider;
use opentelemetry_sdk::metrics::{
    Instrument, PeriodicReader, SdkMeterProvider, Stream, Temporality,
};
use opentelemetry_sdk::propagation::TraceContextPropagator;
use opentelemetry_sdk::trace::{Sampler, SdkTracerProvider};
use opentelemetry_sdk::Resource;
use std::fmt;
use std::str::FromStr;
use std::time::Duration;
use tracing_appender::rolling;
use tracing_error::ErrorLayer;
use tracing_opentelemetry::{MetricsLayer, OpenTelemetryLayer};
use tracing_panic::panic_hook;
use tracing_subscriber::filter::{LevelFilter, Targets};
use tracing_subscriber::fmt::format::{FmtSpan, JsonFields};
use tracing_subscriber::fmt::time::ChronoUtc;
use tracing_subscriber::fmt::{format, Layer as FmtLayer};
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::{registry, EnvFilter, Layer};

// ============================================================================
// Error types
// ============================================================================

#[derive(Debug, thiserror::Error)]
pub enum OtelInitError {
    #[error("Failed to initialize OTLP log exporter")]
    LogExporter(#[source] opentelemetry_otlp::ExporterBuildError),
    #[error("Failed to initialize OTLP trace exporter")]
    TraceExporter(#[source] opentelemetry_otlp::ExporterBuildError),
    #[error("Failed to initialize OTLP metrics exporter")]
    MetricsExporter(#[source] opentelemetry_otlp::ExporterBuildError),
    #[error("Configuration validation failed: {0}")]
    Validation(String),
}

// ============================================================================
// Log level enum
// ============================================================================

/// Log level for tracing layers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum LogLevel {
    Trace,
    Debug,
    #[default]
    Info,
    Warn,
    Error,
    Off,
}

impl LogLevel {
    fn as_str(&self) -> &'static str {
        match self {
            LogLevel::Trace => "trace",
            LogLevel::Debug => "debug",
            LogLevel::Info => "info",
            LogLevel::Warn => "warn",
            LogLevel::Error => "error",
            LogLevel::Off => "off",
        }
    }
}

impl fmt::Display for LogLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl FromStr for LogLevel {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "trace" => Ok(LogLevel::Trace),
            "debug" => Ok(LogLevel::Debug),
            "info" => Ok(LogLevel::Info),
            "warn" | "warning" => Ok(LogLevel::Warn),
            "error" => Ok(LogLevel::Error),
            "off" => Ok(LogLevel::Off),
            _ => Err(format!("Invalid log level: {s}")),
        }
    }
}

impl From<LogLevel> for LevelFilter {
    fn from(level: LogLevel) -> Self {
        match level {
            LogLevel::Trace => LevelFilter::TRACE,
            LogLevel::Debug => LevelFilter::DEBUG,
            LogLevel::Info => LevelFilter::INFO,
            LogLevel::Warn => LevelFilter::WARN,
            LogLevel::Error => LevelFilter::ERROR,
            LogLevel::Off => LevelFilter::OFF,
        }
    }
}

// ============================================================================
// Transport protocol
// ============================================================================

/// OTLP transport protocol.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum OtlpProtocol {
    /// HTTP/protobuf (default)
    #[default]
    Http,
    /// gRPC (requires `grpc` feature)
    #[cfg(feature = "grpc")]
    Grpc,
}

// ============================================================================
// Sampling configuration
// ============================================================================

/// Trace sampling strategy.
#[derive(Debug, Clone, Default)]
pub enum SamplingStrategy {
    /// Always sample all traces (default)
    #[default]
    AlwaysOn,
    /// Never sample traces
    AlwaysOff,
    /// Sample traces based on parent decision
    ParentBased,
    /// Sample a ratio of traces (0.0 to 1.0)
    TraceIdRatio(f64),
    /// Parent-based with trace ID ratio fallback
    ParentBasedTraceIdRatio(f64),
}

impl SamplingStrategy {
    fn to_sampler(&self) -> Sampler {
        match self {
            SamplingStrategy::AlwaysOn => Sampler::AlwaysOn,
            SamplingStrategy::AlwaysOff => Sampler::AlwaysOff,
            SamplingStrategy::ParentBased => Sampler::ParentBased(Box::new(Sampler::AlwaysOn)),
            SamplingStrategy::TraceIdRatio(ratio) => Sampler::TraceIdRatioBased(*ratio),
            SamplingStrategy::ParentBasedTraceIdRatio(ratio) => {
                Sampler::ParentBased(Box::new(Sampler::TraceIdRatioBased(*ratio)))
            }
        }
    }
}

// ============================================================================
// Exporter settings
// ============================================================================

/// Settings for batch exporter behavior.
#[derive(Debug, Clone)]
pub struct BatchSettings {
    /// Maximum number of spans/logs in a batch (default: 512)
    pub max_queue_size: usize,
    /// Maximum batch size before export (default: 512)
    pub max_export_batch_size: usize,
    /// Scheduled delay between exports (default: 5s)
    pub scheduled_delay: Duration,
    /// Maximum time to wait for export (default: 30s)
    pub max_export_timeout: Duration,
}

impl Default for BatchSettings {
    fn default() -> Self {
        Self {
            max_queue_size: 512,
            max_export_batch_size: 512,
            scheduled_delay: Duration::from_secs(5),
            max_export_timeout: Duration::from_secs(30),
        }
    }
}

/// Settings for individual exporters.
#[derive(Debug, Clone, Default)]
pub struct ExporterSettings {
    /// Enable logs export (default: true)
    pub logs_enabled: bool,
    /// Enable traces export (default: true)
    pub traces_enabled: bool,
    /// Enable metrics export (default: true)
    pub metrics_enabled: bool,
    /// HTTP request timeout (default: 10s)
    pub timeout: Duration,
}

impl ExporterSettings {
    fn new() -> Self {
        Self {
            logs_enabled: true,
            traces_enabled: true,
            metrics_enabled: true,
            timeout: Duration::from_secs(10),
        }
    }
}

// ============================================================================
// Metric view type alias
// ============================================================================

/// Type alias for a metric view function.
///
/// A view is a function that takes an instrument and optionally returns a modified stream
/// configuration for that instrument. This is commonly used for customizing histogram buckets.
pub type MetricView = Box<dyn Fn(&Instrument) -> Option<Stream> + Send + Sync + 'static>;

// ============================================================================
// Main configuration
// ============================================================================

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
    pub logger_level: LogLevel,
    /// Log level for OTLP tracer layer
    pub tracer_level: LogLevel,
    /// Log level for stdout fmt layer
    pub fmt_level: LogLevel,
    /// Log level for file layer (None to disable file logging)
    pub file_level: Option<LogLevel>,
    /// Directory for log files (default: "logs")
    pub log_directory: String,
    /// Log file name prefix (default: "app.log")
    pub log_file_prefix: String,
    /// Additional filter directives (e.g., `["hyper=off", "sqlx::query=info"]`).
    ///
    /// OTLP layers only support `target=level` format. Console and file layers
    /// additionally support bare levels (`"debug"`) and `EnvFilter` syntax
    /// (`"my_crate[span_name]=debug"`). Unsupported directives are ignored
    /// for OTLP layers with a warning on stderr.
    pub filter_directives: Vec<String>,
    /// Metrics export interval (default: 1s)
    pub metrics_interval: Duration,
    /// Custom resource attributes (e.g., host.name, cloud.provider)
    pub resource_attributes: Vec<KeyValue>,
    /// Transport protocol (HTTP or gRPC)
    pub protocol: OtlpProtocol,
    /// Sampling strategy for traces
    pub sampling: SamplingStrategy,
    /// Batch exporter settings
    pub batch_settings: BatchSettings,
    /// Exporter enable/disable settings
    pub exporter_settings: ExporterSettings,

    // Pre-computed URLs (internal)
    logs_url: String,
    traces_url: String,
    metrics_url: String,
}

impl Default for OtelConfig {
    fn default() -> Self {
        let endpoint = "http://localhost:4318".to_string();
        Self {
            logs_url: format!("{endpoint}/v1/logs"),
            traces_url: format!("{endpoint}/v1/traces"),
            metrics_url: format!("{endpoint}/v1/metrics"),
            otlp_endpoint: endpoint,
            service_name: "unknown".to_string(),
            service_instance_id: "unknown".to_string(),
            service_version: "0.0.0".to_string(),
            environment: "dev".to_string(),
            logger_level: LogLevel::Info,
            tracer_level: LogLevel::Info,
            fmt_level: LogLevel::Info,
            file_level: Some(LogLevel::Debug),
            log_directory: "logs".to_string(),
            log_file_prefix: "app.log".to_string(),
            filter_directives: vec![],
            metrics_interval: Duration::from_secs(1),
            resource_attributes: vec![],
            protocol: OtlpProtocol::default(),
            sampling: SamplingStrategy::default(),
            batch_settings: BatchSettings::default(),
            exporter_settings: ExporterSettings::new(),
        }
    }
}

impl OtelConfig {
    /// Validate the configuration.
    pub fn validate(&self) -> Result<(), OtelInitError> {
        if self.service_name.is_empty() || self.service_name == "unknown" {
            return Err(OtelInitError::Validation(
                "service_name must be set to a meaningful value".to_string(),
            ));
        }

        if self.otlp_endpoint.is_empty() {
            return Err(OtelInitError::Validation(
                "otlp_endpoint must not be empty".to_string(),
            ));
        }

        if !self.otlp_endpoint.starts_with("http://") && !self.otlp_endpoint.starts_with("https://")
        {
            return Err(OtelInitError::Validation(format!(
                "otlp_endpoint must start with http:// or https://, got: {}",
                self.otlp_endpoint
            )));
        }

        if let SamplingStrategy::TraceIdRatio(ratio)
        | SamplingStrategy::ParentBasedTraceIdRatio(ratio) = self.sampling
        {
            if !(0.0..=1.0).contains(&ratio) {
                return Err(OtelInitError::Validation(format!(
                    "sampling ratio must be between 0.0 and 1.0, got: {ratio}"
                )));
            }
        }

        Ok(())
    }
}

// ============================================================================
// OtelGuard
// ============================================================================

/// Guard that handles graceful shutdown of OTEL providers.
///
/// Call `shutdown()` before application exit to flush pending telemetry.
pub struct OtelGuard {
    logger: Option<SdkLoggerProvider>,
    tracer: Option<SdkTracerProvider>,
    metrics: Option<SdkMeterProvider>,
}

impl OtelGuard {
    /// Flushes all pending telemetry data.
    pub fn shutdown(&self) {
        self.flush_all();
    }

    fn flush_all(&self) {
        if let Some(ref logger) = self.logger {
            if let Err(e) = logger.force_flush() {
                eprintln!("Logger flush error: {e:?}")
            }
        }
        if let Some(ref tracer) = self.tracer {
            if let Err(e) = tracer.force_flush() {
                eprintln!("Tracer flush error: {e:?}")
            }
        }
        if let Some(ref metrics) = self.metrics {
            if let Err(e) = metrics.force_flush() {
                eprintln!("Metrics flush error: {e:?}")
            }
        }
    }
}

impl Drop for OtelGuard {
    fn drop(&mut self) {
        self.flush_all();
    }
}

// ============================================================================
// Internal helpers
// ============================================================================

fn build_resource(config: &mut OtelConfig) -> Resource {
    let mut attributes = vec![
        KeyValue::new(
            "service.instance.id",
            std::mem::take(&mut config.service_instance_id),
        ),
        KeyValue::new(
            "service.version",
            std::mem::take(&mut config.service_version),
        ),
        KeyValue::new(
            "deployment.environment",
            std::mem::take(&mut config.environment),
        ),
    ];
    attributes.append(&mut config.resource_attributes);

    Resource::builder()
        .with_service_name(std::mem::take(&mut config.service_name))
        .with_attributes(attributes)
        .build()
}

/// Build a stateless `Targets` filter for per-layer use (OTLP layers).
///
/// Unlike `EnvFilter`, `Targets` has no thread-local state, so it works
/// correctly for spans that are created on one thread and closed on another.
/// It also ignores `RUST_LOG`, ensuring configured levels are not silently overridden.
fn build_targets_filter(level: LogLevel, directives: &[String]) -> Targets {
    let default_level: LevelFilter = level.into();

    let mut filter = Targets::new().with_default(default_level);

    for directive in directives {
        if let Some((target, lvl_str)) = directive.split_once('=') {
            if let Ok(lvl) = lvl_str.parse::<LevelFilter>() {
                filter = filter.with_target(target, lvl);
            } else {
                eprintln!("Invalid filter directive '{directive}': unknown level '{lvl_str}'");
            }
        } else {
            eprintln!("Filter directive '{directive}' ignored for OTLP layer (expected 'target=level' format)");
        }
    }

    filter
}

/// Build an `EnvFilter` for local layers (fmt, file) that benefit from
/// `RUST_LOG` support and full directive syntax.
fn build_fmt_filter(level: LogLevel, directives: &[String]) -> EnvFilter {
    let mut filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(level.as_str()));

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

fn init_otlp_logger(
    config: &OtelConfig,
    resource: Resource,
) -> Result<SdkLoggerProvider, OtelInitError> {
    let log_exporter = LogExporter::builder()
        .with_http()
        .with_endpoint(&config.logs_url)
        .with_timeout(config.exporter_settings.timeout)
        .build()
        .map_err(OtelInitError::LogExporter)?;

    Ok(SdkLoggerProvider::builder()
        .with_resource(resource)
        .with_batch_exporter(log_exporter)
        .build())
}

fn init_otlp_tracer(
    config: &OtelConfig,
    resource: Resource,
) -> Result<SdkTracerProvider, OtelInitError> {
    let trace_exporter = SpanExporter::builder()
        .with_http()
        .with_endpoint(&config.traces_url)
        .with_timeout(config.exporter_settings.timeout)
        .build()
        .map_err(OtelInitError::TraceExporter)?;

    Ok(SdkTracerProvider::builder()
        .with_resource(resource)
        .with_sampler(config.sampling.to_sampler())
        .with_batch_exporter(trace_exporter)
        .build())
}

fn init_otlp_metrics(
    config: &OtelConfig,
    resource: Resource,
    views: Vec<MetricView>,
) -> Result<SdkMeterProvider, OtelInitError> {
    let metrics_exporter = MetricExporter::builder()
        .with_http()
        .with_endpoint(&config.metrics_url)
        .with_timeout(config.exporter_settings.timeout)
        .with_temporality(Temporality::Cumulative)
        .build()
        .map_err(OtelInitError::MetricsExporter)?;

    let reader = PeriodicReader::builder(metrics_exporter)
        .with_interval(config.metrics_interval)
        .build();

    let mut provider_builder = SdkMeterProvider::builder()
        .with_resource(resource)
        .with_reader(reader);

    for view in views {
        provider_builder = provider_builder.with_view(view);
    }

    Ok(provider_builder.build())
}

// ============================================================================
// Public initialization functions
// ============================================================================

/// Initialize the tracing subscriber with OpenTelemetry integration.
///
/// This sets up:
/// - OTLP log exporter (logs to Loki/etc via OTLP) - if enabled
/// - OTLP trace exporter (traces to Tempo/Jaeger/etc via OTLP) - if enabled
/// - OTLP metrics exporter (metrics to Prometheus/etc via OTLP) - if enabled
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
pub fn init_tracing_with_views(
    mut config: OtelConfig,
    metric_views: Vec<MetricView>,
) -> Result<OtelGuard, OtelInitError> {
    // Validate configuration
    config.validate()?;

    // Build resource once and clone for each provider
    let resource = build_resource(&mut config);

    let mut guard = OtelGuard {
        logger: None,
        tracer: None,
        metrics: None,
    };

    // Logger (logs)
    let otlp_logger_layer = if config.exporter_settings.logs_enabled {
        let otlp_logger_provider = init_otlp_logger(&config, resource.clone())?;
        let otlp_logger_filter =
            build_targets_filter(config.logger_level, &config.filter_directives);
        let layer = OtelTracingBridge::new(&otlp_logger_provider).with_filter(otlp_logger_filter);
        guard.logger = Some(otlp_logger_provider);
        Some(layer)
    } else {
        None
    };

    // Tracer (spans)
    let otlp_tracer_layer = if config.exporter_settings.traces_enabled {
        let otlp_tracer_provider = init_otlp_tracer(&config, resource.clone())?;
        let otlp_tracer = otlp_tracer_provider.tracer("tracing-otel-subscriber");
        let otlp_tracer_filter =
            build_targets_filter(config.tracer_level, &config.filter_directives);
        let layer = OpenTelemetryLayer::new(otlp_tracer).with_filter(otlp_tracer_filter);
        global::set_text_map_propagator(TraceContextPropagator::new());
        guard.tracer = Some(otlp_tracer_provider);
        Some(layer)
    } else {
        None
    };

    // Metrics (with optional views)
    let otlp_metrics_layer = if config.exporter_settings.metrics_enabled {
        let otlp_metrics_provider = init_otlp_metrics(&config, resource, metric_views)?;
        let layer = MetricsLayer::new(otlp_metrics_provider.clone());
        global::set_meter_provider(otlp_metrics_provider.clone());
        guard.metrics = Some(otlp_metrics_provider);
        Some(layer)
    } else {
        None
    };

    // Stdout fmt layer
    let fmt_filter = build_fmt_filter(config.fmt_level, &config.filter_directives);
    let fmt_layer = FmtLayer::new()
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
    if let Some(file_level) = config.file_level {
        let file_filter = build_fmt_filter(file_level, &config.filter_directives);
        let file_provider = rolling::daily(&config.log_directory, &config.log_file_prefix);
        let file_layer = FmtLayer::new()
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

    Ok(guard)
}

// ============================================================================
// Builder
// ============================================================================

/// Builder for `OtelConfig` with a fluent API.
#[derive(Debug, Clone, Default)]
pub struct OtelConfigBuilder {
    config: OtelConfig,
}

impl OtelConfigBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    /// Load configuration from environment variables.
    ///
    /// Supported variables:
    /// - `OTEL_EXPORTER_OTLP_ENDPOINT` - OTLP endpoint URL
    /// - `OTEL_SERVICE_NAME` - Service name
    /// - `OTEL_SERVICE_VERSION` - Service version
    /// - `OTEL_SERVICE_INSTANCE_ID` - Service instance ID
    /// - `OTEL_ENVIRONMENT` or `DEPLOYMENT_ENVIRONMENT` - Environment name
    /// - `OTEL_LOG_LEVEL` - Default log level for all layers
    /// - `OTEL_TRACES_SAMPLER_ARG` - Sampling ratio (0.0-1.0) when using ratio sampler
    pub fn from_env() -> Self {
        let mut builder = Self::new();

        if let Ok(endpoint) = std::env::var("OTEL_EXPORTER_OTLP_ENDPOINT") {
            builder = builder.otlp_endpoint(endpoint);
        }

        if let Ok(name) = std::env::var("OTEL_SERVICE_NAME") {
            builder = builder.service_name(name);
        }

        if let Ok(version) = std::env::var("OTEL_SERVICE_VERSION") {
            builder = builder.service_version(version);
        }

        if let Ok(instance_id) = std::env::var("OTEL_SERVICE_INSTANCE_ID") {
            builder = builder.service_instance_id(instance_id);
        }

        if let Ok(env) =
            std::env::var("OTEL_ENVIRONMENT").or_else(|_| std::env::var("DEPLOYMENT_ENVIRONMENT"))
        {
            builder = builder.environment(env);
        }

        if let Ok(level_str) = std::env::var("OTEL_LOG_LEVEL") {
            if let Ok(level) = level_str.parse::<LogLevel>() {
                builder = builder
                    .logger_level(level)
                    .tracer_level(level)
                    .fmt_level(level);
            }
        }

        if let Ok(ratio_str) = std::env::var("OTEL_TRACES_SAMPLER_ARG") {
            if let Ok(ratio) = ratio_str.parse::<f64>() {
                builder = builder.sampling(SamplingStrategy::ParentBasedTraceIdRatio(ratio));
            }
        }

        builder
    }

    pub fn otlp_endpoint(mut self, endpoint: impl Into<String>) -> Self {
        let endpoint = endpoint.into();
        self.config.logs_url = format!("{endpoint}/v1/logs");
        self.config.traces_url = format!("{endpoint}/v1/traces");
        self.config.metrics_url = format!("{endpoint}/v1/metrics");
        self.config.otlp_endpoint = endpoint;
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

    pub fn logger_level(mut self, level: LogLevel) -> Self {
        self.config.logger_level = level;
        self
    }

    pub fn tracer_level(mut self, level: LogLevel) -> Self {
        self.config.tracer_level = level;
        self
    }

    pub fn fmt_level(mut self, level: LogLevel) -> Self {
        self.config.fmt_level = level;
        self
    }

    pub fn file_level(mut self, level: Option<LogLevel>) -> Self {
        self.config.file_level = level;
        self
    }

    /// Disable file logging.
    pub fn disable_file_logging(mut self) -> Self {
        self.config.file_level = None;
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

    pub fn filter_directives(
        mut self,
        directives: impl IntoIterator<Item = impl Into<String>>,
    ) -> Self {
        self.config
            .filter_directives
            .extend(directives.into_iter().map(|d| d.into()));
        self
    }

    pub fn metrics_interval(mut self, interval: Duration) -> Self {
        self.config.metrics_interval = interval;
        self
    }

    /// Set metrics interval in seconds (convenience method).
    pub fn metrics_interval_secs(mut self, secs: u64) -> Self {
        self.config.metrics_interval = Duration::from_secs(secs);
        self
    }

    /// Add a single custom resource attribute.
    pub fn resource_attribute(
        mut self,
        key: impl Into<opentelemetry::Key>,
        value: impl Into<opentelemetry::Value>,
    ) -> Self {
        self.config
            .resource_attributes
            .push(KeyValue::new(key, value));
        self
    }

    /// Add multiple custom resource attributes at once.
    pub fn resource_attributes(mut self, attrs: impl IntoIterator<Item = KeyValue>) -> Self {
        self.config.resource_attributes.extend(attrs);
        self
    }

    /// Set the transport protocol.
    pub fn protocol(mut self, protocol: OtlpProtocol) -> Self {
        self.config.protocol = protocol;
        self
    }

    /// Set the sampling strategy for traces.
    pub fn sampling(mut self, strategy: SamplingStrategy) -> Self {
        self.config.sampling = strategy;
        self
    }

    /// Set a trace ID ratio sampler (convenience method).
    pub fn sample_ratio(mut self, ratio: f64) -> Self {
        self.config.sampling = SamplingStrategy::ParentBasedTraceIdRatio(ratio);
        self
    }

    /// Configure batch exporter settings.
    pub fn batch_settings(mut self, settings: BatchSettings) -> Self {
        self.config.batch_settings = settings;
        self
    }

    /// Set exporter timeout.
    pub fn exporter_timeout(mut self, timeout: Duration) -> Self {
        self.config.exporter_settings.timeout = timeout;
        self
    }

    /// Enable or disable logs export.
    pub fn logs_enabled(mut self, enabled: bool) -> Self {
        self.config.exporter_settings.logs_enabled = enabled;
        self
    }

    /// Enable or disable traces export.
    pub fn traces_enabled(mut self, enabled: bool) -> Self {
        self.config.exporter_settings.traces_enabled = enabled;
        self
    }

    /// Enable or disable metrics export.
    pub fn metrics_enabled(mut self, enabled: bool) -> Self {
        self.config.exporter_settings.metrics_enabled = enabled;
        self
    }

    /// Disable all OTLP exporters (logs, traces, metrics).
    /// Useful for local development without a collector.
    pub fn disable_otlp(mut self) -> Self {
        self.config.exporter_settings.logs_enabled = false;
        self.config.exporter_settings.traces_enabled = false;
        self.config.exporter_settings.metrics_enabled = false;
        self
    }

    /// Build the configuration.
    ///
    /// Note: Call `validate()` on the result or use `try_build()` to catch configuration errors
    /// before calling `init_tracing()`.
    #[must_use]
    pub fn build(self) -> OtelConfig {
        self.config
    }

    /// Build and validate the configuration.
    pub fn try_build(self) -> Result<OtelConfig, OtelInitError> {
        let config = self.config;
        config.validate()?;
        Ok(config)
    }
}
