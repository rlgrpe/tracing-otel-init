# Agent Commands

Commands for AI agents and automation tools.

## Build

```bash
# Check compilation
cargo check --all-features

# Build
cargo build --all-features

# Build release
cargo build --release --all-features
```

## Test

```bash
# Run all tests
cargo test --all-features

# Run tests with output
cargo test --all-features -- --show-output

# Test specific feature
cargo test --features "rustls-tls"
cargo test --features "grpc"
```

## Lint

```bash
# Format check
cargo fmt --all -- --check

# Format fix
cargo fmt --all

# Clippy
cargo clippy --all-targets --all-features -- -D warnings

# Full pre-commit
pre-commit run --all-files
```

## Documentation

```bash
# Generate docs
cargo doc --all-features --no-deps

# Open docs
cargo doc --all-features --no-deps --open
```

## Examples

```bash
# Run example
cargo run --example basic
cargo run --example from_env
cargo run --example sampling
cargo run --example custom_resources
cargo run --example custom_views
cargo run --example disable_exporters
cargo run --example selective_export
```

## Project Structure

```
src/
├── lib.rs              # Main library: OtelConfig, OtelConfigBuilder, init_tracing
└── tracing_bridge.rs   # OtelTracingBridge: tracing events → OTLP logs

examples/
├── basic.rs            # Minimal setup
├── from_env.rs         # Environment variable configuration
├── sampling.rs         # Trace sampling strategies
├── custom_resources.rs # Custom resource attributes
├── custom_views.rs     # Custom metric histogram buckets
├── disable_exporters.rs# Disable OTLP for local dev
└── selective_export.rs # Enable specific exporters only
```

## Key Types

- `OtelConfig` - Configuration struct
- `OtelConfigBuilder` - Fluent builder for config
- `OtelGuard` - RAII guard for provider lifecycle
- `LogLevel` - Log level enum (Trace, Debug, Info, Warn, Error, Off)
- `SamplingStrategy` - Trace sampling configuration
- `MetricView` - Custom metric view function type
- `OtelTracingBridge` - tracing Layer for OTLP logs

## Features

- `default` - HTTP transport
- `rustls-tls` - Use rustls instead of native TLS
- `grpc` - Enable gRPC transport
