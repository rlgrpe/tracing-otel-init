//! Example showing configuration from environment variables.
//!
//! Set environment variables before running:
//! ```sh
//! export OTEL_EXPORTER_OTLP_ENDPOINT=http://localhost:4318
//! export OTEL_SERVICE_NAME=env-example
//! export OTEL_LOG_LEVEL=debug
//! cargo run --example from_env
//! ```

use tracing::{debug, info};
use tracing_otel_init::{init_tracing, OtelConfigBuilder};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Load from environment with fallback defaults
    let config = OtelConfigBuilder::from_env()
        .service_name("env-example") // Fallback if OTEL_SERVICE_NAME not set
        .service_version(env!("CARGO_PKG_VERSION"))
        .build();

    let guard = init_tracing(config)?;

    info!("Loaded configuration from environment");
    debug!("Debug logging enabled via OTEL_LOG_LEVEL=debug");

    guard.shutdown();
    Ok(())
}
