//! Example showing selective enabling of exporters.
//!
//! Run with: cargo run --example selective_export

use tracing::{info, instrument};
use tracing_otel_init::{init_tracing, OtelConfigBuilder};

#[instrument]
fn traced_function() {
    info!("This is a traced function call");
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Only export traces, disable logs and metrics
    let config = OtelConfigBuilder::new()
        .otlp_endpoint("http://localhost:4318")
        .service_name("selective-export-example")
        .service_version(env!("CARGO_PKG_VERSION"))
        .logs_enabled(false) // Don't send logs to collector
        .traces_enabled(true) // Send traces to collector
        .metrics_enabled(false) // Don't send metrics to collector
        .build();

    let guard = init_tracing(config)?;

    info!("This log won't go to OTLP, only to console");

    // But this trace will be exported
    traced_function();

    guard.shutdown();
    Ok(())
}
