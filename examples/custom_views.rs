//! Example showing custom metric views for histogram buckets.
//!
//! Run with: cargo run --example custom_views

use opentelemetry_sdk::metrics::{Aggregation, Instrument, Stream};
use tracing::info;
use tracing_otel_init::{init_tracing_with_views, MetricView, OtelConfigBuilder};

/// Create a histogram view with custom bucket boundaries.
fn histogram_view(name: &'static str, buckets: &'static [f64]) -> MetricView {
    Box::new(move |instrument: &Instrument| {
        if instrument.name() == name {
            Some(
                Stream::builder()
                    .with_aggregation(Aggregation::ExplicitBucketHistogram {
                        boundaries: buckets.to_vec(),
                        record_min_max: true,
                    })
                    .build()
                    .expect("valid stream"),
            )
        } else {
            None
        }
    })
}

// Custom bucket boundaries for different metric types
const HTTP_LATENCY_BUCKETS: &[f64] = &[
    0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0,
];
const DB_LATENCY_BUCKETS: &[f64] = &[0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1.0, 5.0];
const QUEUE_SIZE_BUCKETS: &[f64] = &[0.0, 10.0, 50.0, 100.0, 500.0, 1000.0, 5000.0];

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let views = vec![
        histogram_view("http.server.duration", HTTP_LATENCY_BUCKETS),
        histogram_view("http.client.duration", HTTP_LATENCY_BUCKETS),
        histogram_view("db.query.duration", DB_LATENCY_BUCKETS),
        histogram_view("queue.size", QUEUE_SIZE_BUCKETS),
    ];

    let config = OtelConfigBuilder::new()
        .otlp_endpoint("http://localhost:4318")
        .service_name("custom-views-example")
        .service_version(env!("CARGO_PKG_VERSION"))
        .build();

    let guard = init_tracing_with_views(config, views)?;

    info!("Started with custom histogram bucket boundaries");
    info!("HTTP latency buckets: {:?}", HTTP_LATENCY_BUCKETS);
    info!("DB latency buckets: {:?}", DB_LATENCY_BUCKETS);

    guard.shutdown();
    Ok(())
}
