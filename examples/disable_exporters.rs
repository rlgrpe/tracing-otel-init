//! Example showing how to disable specific exporters.
//!
//! Useful for local development without a collector.
//!
//! Run with: cargo run --example disable_exporters

use tracing::{info, warn};
use tracing_otel_init::{init_tracing, LogLevel, OtelConfigBuilder};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Option 1: Disable all OTLP exporters (console and file only)
    let config = OtelConfigBuilder::new()
        .service_name("local-dev-example")
        .service_version(env!("CARGO_PKG_VERSION"))
        .disable_otlp() // No logs, traces, or metrics to collector
        .fmt_level(LogLevel::Debug)
        .disable_file_logging() // Also disable file logging
        .build();

    let guard = init_tracing(config)?;

    info!("Running in local development mode");
    info!("Logs only go to console, no OTLP export");
    warn!("This is useful when you don't have a collector running");

    guard.shutdown();
    Ok(())
}
