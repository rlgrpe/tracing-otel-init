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

## Installation

Add to your `Cargo.toml`:

```toml
[dependencies]
tracing-otel-init = { git = "https://github.com/rlgrpe/tracing-otel-init", tag="v.0.1.0" }
tracing = "0.1"
```

## Quick Start

```rust
use tracing_otel_init::{OtelConfigBuilder, init_tracing};
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

## Configuration

### OtelConfigBuilder

| Method | Default | Description |
|--------|---------|-------------|
| `otlp_endpoint` | `http://localhost:4318` | OTLP HTTP endpoint |
| `service_name` | `unknown` | Service name for resource |
| `service_instance_id` | `unknown` | Instance identifier (pod name, IP, etc.) |
| `service_version` | `0.0.0` | Service version |
| `environment` | `dev` | Deployment environment |
| `logger_level` | `info` | Log level for OTLP logs |
| `tracer_level` | `info` | Log level for OTLP traces |
| `fmt_level` | `info` | Log level for console output |
| `file_level` | `Some("debug")` | Log level for file output (`None` to disable) |
| `log_directory` | `logs` | Directory for log files |
| `log_file_prefix` | `app.log` | Log file name prefix |
| `filter_directive` | - | Add a single filter directive |
| `filter_directives` | `[]` | Add multiple filter directives |
| `metrics_interval_secs` | `1` | Metrics export interval |

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
- `hyper=off`, `h2=off`, `hyper_util=off`
- `tower=warn`
- `reqwest::connect=off`

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

```
┌─────────────────────────────────────────────────────────────┐
│                    tracing Subscriber                        │
├─────────────────────────────────────────────────────────────┤
│  OtelTracingBridge  │  Logs → OTLP /v1/logs                 │
│  OpenTelemetryLayer │  Traces → OTLP /v1/traces             │
│  MetricsLayer       │  Metrics → OTLP /v1/metrics           │
│  fmt::Layer         │  Console (colored)                    │
│  fmt::Layer (file)  │  JSON → logs/app.log.YYYY-MM-DD       │
│  ErrorLayer         │  SpanTrace support                    │
└─────────────────────────────────────────────────────────────┘
```

## Requirements

- Rust 2021 edition
- Tokio runtime (for metrics periodic reader)
- OTLP-compatible collector (e.g., OpenTelemetry Collector, Grafana Alloy)

## License

MIT