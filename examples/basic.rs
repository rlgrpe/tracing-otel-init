//! Basic example showing minimal setup.
//!
//! Run with: cargo run --example basic

use tracing::{info, instrument, warn};
use tracing_otel_init::{init_tracing, LogLevel, OtelConfigBuilder};

#[instrument]
async fn do_work(item: &str) {
    info!(item, "Processing item");
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    info!("Item processed");
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = OtelConfigBuilder::new()
        .otlp_endpoint("http://localhost:4318")
        .service_name("basic-example")
        .service_version(env!("CARGO_PKG_VERSION"))
        .environment("dev")
        .fmt_level(LogLevel::Debug)
        .build();

    let guard = init_tracing(config)?;

    info!("Application started");

    for i in 0..3 {
        do_work(&format!("item-{i}")).await;
    }

    warn!("Application shutting down");
    guard.shutdown();

    Ok(())
}
