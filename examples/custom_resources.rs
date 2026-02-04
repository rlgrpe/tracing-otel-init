//! Example showing custom resource attributes.
//!
//! Run with: cargo run --example custom_resources

use tracing::info;
use tracing_otel_init::{init_tracing, KeyValue, OtelConfigBuilder};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = OtelConfigBuilder::new()
        .otlp_endpoint("http://localhost:4318")
        .service_name("custom-resources-example")
        .service_version(env!("CARGO_PKG_VERSION"))
        .service_instance_id(gethostname())
        .environment("staging")
        // Add individual attributes
        .resource_attribute("host.name", gethostname())
        .resource_attribute("cloud.provider", "aws")
        // Add multiple attributes at once
        .resource_attributes([
            KeyValue::new("cloud.region", "us-east-1"),
            KeyValue::new("cloud.availability_zone", "us-east-1a"),
            KeyValue::new("deployment.id", "deploy-12345"),
        ])
        .build();

    let guard = init_tracing(config)?;

    info!("Started with custom resource attributes");
    info!("Check your collector to see the resource attributes");

    guard.shutdown();
    Ok(())
}

fn gethostname() -> String {
    std::env::var("HOSTNAME")
        .or_else(|_| std::env::var("COMPUTERNAME"))
        .unwrap_or_else(|_| "unknown-host".to_string())
}
