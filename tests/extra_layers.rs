use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering};
use tracing::{Event, Subscriber};
use tracing_otel_init::{
    init_tracing_with_views_and_layers, ExtraLayer, LogLevel, OtelConfigBuilder,
};
use tracing_subscriber::filter::{LevelFilter, Targets};
use tracing_subscriber::layer::{Context, Layer};

const CHILD_ENV: &str = "TRACING_OTEL_INIT_EXTRA_LAYERS_CHILD";
const PROBE_TARGET: &str = "extra_layers::probe";
const TRACE_MARKER: &str = "extra-layer-trace-event";
const WARN_MARKER: &str = "extra-layer-warn-event";
const OTHER_MARKER: &str = "extra-layer-other-target-event";

static SEEN: AtomicUsize = AtomicUsize::new(0);

struct CountingLayer;

impl<S: Subscriber> Layer<S> for CountingLayer {
    fn on_event(&self, _event: &Event<'_>, _ctx: Context<'_, S>) {
        SEEN.fetch_add(1, Ordering::Relaxed);
    }
}

#[test]
fn extra_layer_receives_events_below_configured_levels_without_changing_stdout() {
    // Public init installs a global subscriber, so run the producer in isolation.
    if std::env::var_os(CHILD_ENV).is_some() {
        let probe: ExtraLayer = Box::new(
            CountingLayer.with_filter(Targets::new().with_target(PROBE_TARGET, LevelFilter::TRACE)),
        );
        let guard = init_tracing_with_views_and_layers(
            OtelConfigBuilder::new()
                .service_name("extra-layers-test")
                .disable_otlp()
                .disable_file_logging()
                .fmt_level(LogLevel::Info)
                .build(),
            Vec::new(),
            vec![probe],
        )
        .expect("public tracing initialization should succeed");

        tracing::trace!(target: PROBE_TARGET, "extra-layer-trace-event");
        tracing::warn!(target: PROBE_TARGET, "extra-layer-warn-event");
        tracing::info!("extra-layer-other-target-event");

        assert_eq!(
            SEEN.load(Ordering::Relaxed),
            2,
            "the extra layer sees both probe events, including the one below fmt_level, \
             and nothing its own filter rejects"
        );
        drop(guard);
        return;
    }

    let output = Command::new(std::env::current_exe().expect("test executable should exist"))
        .args([
            "--exact",
            "extra_layer_receives_events_below_configured_levels_without_changing_stdout",
            "--nocapture",
        ])
        .env(CHILD_ENV, "1")
        .env_remove("RUST_LOG")
        .output()
        .expect("extra layer subprocess should run");
    assert!(
        output.status.success(),
        "extra layer subprocess failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8(output.stdout).expect("formatted stdout should be UTF-8");
    assert!(
        !stdout.contains(TRACE_MARKER),
        "stdout keeps its own info filter: {stdout}"
    );
    assert_eq!(stdout.matches(WARN_MARKER).count(), 1, "{stdout}");
    assert_eq!(stdout.matches(OTHER_MARKER).count(), 1, "{stdout}");
}
