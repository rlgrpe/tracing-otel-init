# tracing-otel-init

Opinionated OpenTelemetry tracing initialization for Rust applications with OTLP export.

## Features

- **OTLP Logs** - Export logs via OpenTelemetry Protocol to Loki, Elasticsearch, etc.
- **OTLP Traces** - Export distributed traces to Tempo, Jaeger, etc.
- **OTLP Metrics** - Export metrics to Prometheus, etc.
- **Console Output** - Colored, formatted stdout logging
- **File Logging** - Optional JSON logs with daily rotation
- **Panic Capture** - Automatic panic tracing
- **Span Context** - Log-trace correlation via trace_id/span_id
- **Span Attributes** - Active `tracing` span fields copied onto OTLP log records
- **Sampling** - Configurable trace sampling strategies
- **HTTP Compression** - Optional gzip compression for OTLP HTTP export (via `gzip-http` feature)
- **rustls TLS** - Optional pure Rust TLS implementation (via `rustls-tls` feature)
- **gRPC Transport** - Optional gRPC transport (via `grpc` feature)

## Installation

Add to your `Cargo.toml`:

```toml
[dependencies]
tracing-otel-init = { git = "https://github.com/rlgrpe/tracing-otel-init", tag = "v0.2.2" }
tracing = "0.1"
```

### With OTLP HTTP gzip compression

```toml
[dependencies]
tracing-otel-init = { git = "https://github.com/rlgrpe/tracing-otel-init", tag = "v0.2.2", features = ["gzip-http"] }
```

### With rustls TLS

```toml
[dependencies]
tracing-otel-init = { git = "https://github.com/rlgrpe/tracing-otel-init", tag = "v0.2.2", features = ["rustls-tls"] }
```

### With gRPC transport

```toml
[dependencies]
tracing-otel-init = { git = "https://github.com/rlgrpe/tracing-otel-init", tag = "v0.2.2", features = ["grpc"] }
```

## Quick Start

```rust
use tracing_otel_init::{OtelConfigBuilder, init_tracing, LogLevel};
use tracing::{info, instrument};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = OtelConfigBuilder::new()
        .otlp_endpoint("http://localhost:4318")
        .service_name("my-service")
        .service_version(env!("CARGO_PKG_VERSION"))
        .environment("dev")
        .build();

    let guard = init_tracing(config)?;

    info!("Application started");
    do_work().await;

    guard.shutdown();
    Ok(())
}

#[instrument]
async fn do_work() {
    info!("Doing work");
}
```

### Load from Environment Variables

```rust
use tracing_otel_init::{OtelConfigBuilder, init_tracing};

let config = OtelConfigBuilder::from_env()
    .service_name("my-service") // Override or set defaults
    .build();

let guard = init_tracing(config)?;
```

Supported environment variables:

- `OTEL_EXPORTER_OTLP_ENDPOINT` - OTLP endpoint URL
- `OTEL_SERVICE_NAME` - Service name
- `OTEL_SERVICE_VERSION` - Service version
- `OTEL_SERVICE_INSTANCE_ID` - Service instance ID
- `OTEL_ENVIRONMENT` or `DEPLOYMENT_ENVIRONMENT` - Environment name
- `OTEL_LOG_LEVEL` - Default log level
- `OTEL_TRACES_SAMPLER_ARG` - Sampling ratio (0.0-1.0)

## Configuration

### OtelConfigBuilder

| Method | Default | Description |
|--------|---------|-------------|
| `otlp_endpoint` | `http://localhost:4318` | OTLP HTTP endpoint |
| `service_name` | `unknown` | Service name for resource |
| `service_instance_id` | `unknown` | Instance identifier (pod name, IP, etc.) |
| `service_version` | `0.0.0` | Service version |
| `environment` | `dev` | Deployment environment |
| `logger_level` | `LogLevel::Info` | Log level for OTLP logs |
| `tracer_level` | `LogLevel::Info` | Log level for OTLP traces |
| `fmt_level` | `LogLevel::Info` | Log level for console output |
| `file_level` | `Some(LogLevel::Debug)` | Log level for file output (`None` to disable) |
| `log_directory` | `logs` | Directory for log files |
| `log_file_prefix` | `app.log` | Log file name prefix |
| `filter_directive` | - | Add a single filter directive |
| `filter_directives` | `[]` | Add multiple filter directives |
| `metrics_interval` | `1s` | Metrics export interval |
| `metrics_interval_secs` | `1` | Metrics export interval (convenience) |
| `resource_attribute` | - | Add a single custom resource attribute |
| `resource_attributes` | `[]` | Add multiple custom resource attributes |
| `sampling` | `AlwaysOn` | Trace sampling strategy |
| `sample_ratio` | - | Set parent-based trace ID ratio sampler |
| `exporter_timeout` | `10s` | HTTP request timeout |
| `logs_enabled` | `true` | Enable/disable logs export |
| `traces_enabled` | `true` | Enable/disable traces export |
| `metrics_enabled` | `true` | Enable/disable metrics export |
| `disable_otlp` | - | Disable all OTLP exporters |

### LogLevel Enum

```rust
use tracing_otel_init::LogLevel;

let config = OtelConfigBuilder::new()
    .logger_level(LogLevel::Debug)
    .tracer_level(LogLevel::Info)
    .fmt_level(LogLevel::Warn)
    .file_level(Some(LogLevel::Trace))
    .build();
```

Available levels: `Trace`, `Debug`, `Info`, `Warn`, `Error`, `Off`

### Sampling Strategies

```rust
use tracing_otel_init::{OtelConfigBuilder, SamplingStrategy};

// Always sample (default)
let config = OtelConfigBuilder::new()
    .sampling(SamplingStrategy::AlwaysOn)
    .build();

// Never sample
let config = OtelConfigBuilder::new()
    .sampling(SamplingStrategy::AlwaysOff)
    .build();

// Sample 10% of traces
let config = OtelConfigBuilder::new()
    .sampling(SamplingStrategy::TraceIdRatio(0.1))
    .build();

// Parent-based with 50% ratio fallback (recommended for production)
let config = OtelConfigBuilder::new()
    .sample_ratio(0.5)
    .build();
```

### Disable Individual Exporters

```rust
let config = OtelConfigBuilder::new()
    .service_name("my-service")
    .logs_enabled(false)      // Disable logs
    .traces_enabled(true)     // Keep traces
    .metrics_enabled(false)   // Disable metrics
    .build();

// Or disable all OTLP for local development
let config = OtelConfigBuilder::new()
    .service_name("my-service")
    .disable_otlp()
    .build();
```

### Filter Directives

Control log verbosity per module:

```rust
let config = OtelConfigBuilder::new()
    .filter_directive("hyper=off")
    .filter_directive("sqlx::query=info")
    .filter_directives(["tokio=warn", "tower=warn"])
    .build();
```

Default noise reduction filters are applied automatically:

- `opentelemetry_sdk=warn`
- `opentelemetry-otlp=warn`
- `opentelemetry-http=warn`
- `hyper=off`, `h2=off`, `hyper_util=off`
- `tower=warn`
- `reqwest::connect=off`

### Custom Resource Attributes

```rust
use tracing_otel_init::{OtelConfigBuilder, KeyValue};

let config = OtelConfigBuilder::new()
    .service_name("my-service")
    .resource_attribute("host.name", "server-01")
    .resource_attribute("cloud.provider", "aws")
    .resource_attributes([
        KeyValue::new("cloud.region", "us-east-1"),
        KeyValue::new("cloud.availability_zone", "us-east-1a"),
    ])
    .build();
```

### Custom Metric Views

Use `init_tracing_with_views` to customize histogram bucket boundaries:

```rust
use tracing_otel_init::{OtelConfigBuilder, init_tracing_with_views, MetricView};
use opentelemetry_sdk::metrics::{Aggregation, Instrument, Stream};

fn histogram_view(name: &'static str, buckets: &'static [f64]) -> MetricView {
    Box::new(move |i: &Instrument| {
        (i.name() == name).then(|| {
            Stream::builder()
                .with_aggregation(Aggregation::ExplicitBucketHistogram {
                    boundaries: buckets.to_vec(),
                    record_min_max: false,
                })
                .build()
                .expect("valid stream")
        })
    })
}

const HTTP_BUCKETS: &[f64] = &[0.1, 0.5, 1.0, 2.0, 5.0, 10.0, 30.0, 60.0];

let views = vec![
    histogram_view("http.client.duration", HTTP_BUCKETS),
];

let config = OtelConfigBuilder::new()
    .service_name("my-service")
    .build();

let guard = init_tracing_with_views(config, views)?;
```

### Configuration Validation

```rust
// Validate before init
let config = OtelConfigBuilder::new()
    .service_name("my-service")
    .try_build()?; // Returns Result<OtelConfig, OtelInitError>

let guard = init_tracing(config)?;

// Or validate manually
let config = OtelConfigBuilder::new().build();
config.validate()?;
```

Validation checks:

- `service_name` must be set (not empty or "unknown")
- `otlp_endpoint` must start with `http://` or `https://`
- Sampling ratio must be between 0.0 and 1.0

## OtelGuard

The `init_tracing` function returns an `OtelGuard` that manages the lifecycle of OpenTelemetry providers. Keep it alive for the duration of your application.

```rust
let guard = init_tracing(config)?;

// ... application runs ...

// Flush pending telemetry before exit
guard.shutdown();
```

The guard also flushes on drop, but explicit `shutdown()` is recommended.

## Architecture

```text
┌─────────────────────────────────────────────────────────────┐
│                    tracing Subscriber                        │
├─────────────────────────────────────────────────────────────┤
│  OtelTracingBridge  │  Logs → OTLP /v1/logs                 │
│  (otel appender)    │  + active span attributes             │
│  OpenTelemetryLayer │  Traces → OTLP /v1/traces             │
│  MetricsLayer       │  Metrics → OTLP /v1/metrics           │
│  FmtLayer           │  Console (colored)                    │
│  FmtLayer (file)    │  JSON → logs/app.log.YYYY-MM-DD       │
│  ErrorLayer         │  SpanTrace support                    │
└─────────────────────────────────────────────────────────────┘
```

## Migration from 0.1.x

### Breaking Changes

1. **LogLevel enum instead of strings**:

   ```rust
   // Before (0.1.x)
   .logger_level("info")

   // After (0.2.x)
   .logger_level(LogLevel::Info)
   ```

2. **Configuration validation** - `init_tracing` now validates config and may return `OtelInitError::Validation`

3. **metrics_interval now takes Duration**:

   ```rust
   // Before (0.1.x)
   .metrics_interval_secs(5)

   // After (0.2.x) - both work
   .metrics_interval(Duration::from_secs(5))
   .metrics_interval_secs(5)  // convenience method still available
   ```

## Examples

Run examples with:

```sh
cargo run --example <name>
```

| Example | Description |
| ------- | ----------- |
| `basic` | Minimal setup with console output |
| `from_env` | Load configuration from environment variables |
| `sampling` | Trace sampling strategies (10% ratio) |
| `custom_resources` | Add custom resource attributes |
| `custom_views` | Custom histogram bucket boundaries |
| `disable_exporters` | Disable OTLP for local development |
| `selective_export` | Enable only specific exporters |

## Requirements

- Rust 2021 edition
- Tokio runtime (for metrics periodic reader)
- OTLP-compatible collector (e.g., OpenTelemetry Collector, Grafana Alloy)

## License

MIT
