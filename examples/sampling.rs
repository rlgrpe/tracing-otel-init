//! Example showing trace sampling configuration.
//!
//! Run with: cargo run --example sampling

use tracing::{info, instrument};
use tracing_otel_init::{init_tracing, OtelConfigBuilder, SamplingStrategy};

#[instrument]
fn process_request(id: u32) {
    info!(request_id = id, "Processing request");
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Sample only 10% of traces (recommended for high-traffic production)
    let config = OtelConfigBuilder::new()
        .otlp_endpoint("http://localhost:4318")
        .service_name("sampling-example")
        .service_version(env!("CARGO_PKG_VERSION"))
        .sampling(SamplingStrategy::ParentBasedTraceIdRatio(0.1))
        // Or use the convenience method:
        // .sample_ratio(0.1)
        .build();

    let guard = init_tracing(config)?;

    info!("Starting with 10% trace sampling");

    // Simulate many requests - only ~10% will be traced
    for i in 0..100 {
        process_request(i);
    }

    guard.shutdown();
    Ok(())
}
