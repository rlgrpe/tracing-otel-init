use std::process::Command;
use tracing_otel_init::{init_tracing, LogLevel, OtelConfigBuilder};

const CHILD_ENV: &str = "TRACING_OTEL_INIT_STDOUT_DRAIN_CHILD";
const EVENT_COUNT: usize = 10_000;
const EVENT_MARKER: &str = "stdout-drain-event:";

#[test]
fn stdout_burst_survives_guard_lifetime_and_exit() {
    // Public init installs a global subscriber, so run the producer in isolation.
    if std::env::var_os(CHILD_ENV).is_some() {
        let guard = init_tracing(
            OtelConfigBuilder::new()
                .service_name("stdout-drain-test")
                .disable_otlp()
                .disable_file_logging()
                .fmt_level(LogLevel::Info)
                .build(),
        )
        .expect("public tracing initialization should succeed");
        let payload = "x".repeat(128);

        // More events than the bounded queue can hold. The parent drains the pipe
        // concurrently; there are no sleeps or throughput assertions.
        for sequence in 0..EVENT_COUNT {
            if sequence == EVENT_COUNT / 2 {
                // shutdown() must leave stdout usable for the remaining events.
                guard.shutdown();
            }
            tracing::info!(payload = %payload, "stdout-drain-event:{sequence}:complete");
        }
        drop(guard);
        return;
    }

    let output = Command::new(std::env::current_exe().expect("test executable should exist"))
        .args([
            "--exact",
            "stdout_burst_survives_guard_lifetime_and_exit",
            "--nocapture",
        ])
        .env(CHILD_ENV, "1")
        .env_remove("RUST_LOG")
        .output()
        .expect("stdout producer subprocess should run");
    assert!(
        output.status.success(),
        "stdout producer failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8(output.stdout).expect("formatted stdout should be UTF-8");
    let events: Vec<_> = stdout
        .lines()
        .filter(|line| line.contains(EVENT_MARKER))
        .collect();
    assert_eq!(events.len(), EVENT_COUNT, "every event should reach stdout");

    let payload = "x".repeat(128);
    for (sequence, line) in events.into_iter().enumerate() {
        assert!(
            line.contains(&format!("{EVENT_MARKER}{sequence}:complete")),
            "event {sequence} should arrive once, in order: {line}"
        );
        assert!(
            line.contains(&payload),
            "event {sequence} should retain its full payload"
        );
    }
}
