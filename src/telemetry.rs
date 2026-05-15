//! OpenTelemetry tracing layer (Phase 5.5).
//!
//! Wires a `tracing-opentelemetry` Layer into the existing `tracing`
//! subscriber stack. When `OTEL_EXPORTER_OTLP_ENDPOINT` is set, spans
//! are exported via OTLP/gRPC (to Alloy at the configured address).
//! When the env var is absent the function returns `None` and the
//! caller adds no extra layer — local development is unaffected.
//!
//! ## Envelope-only rule
//!
//! Span **attributes** must carry envelope metadata only:
//! - `tool`, `mxid`, `room_id`, `outcome`, `latency_ms`, `step`
//! - `token_hash` (SHA-256 prefix, same as the Loki audit log)
//!
//! Span attributes must NOT include message bodies, recovery keys,
//! access tokens, room display names, or any other user-supplied
//! free-form text. Same invariant as the Loki audit log in `audit.rs`.

use opentelemetry::trace::TracerProvider as _;
use opentelemetry_otlp::WithExportConfig as _;
use opentelemetry_sdk::{Resource, trace::SdkTracerProvider};
use tracing_opentelemetry::OpenTelemetryLayer;
use tracing_subscriber::Layer;

/// Try to build an OTLP tracing `Layer`.
///
/// Returns `Some(layer)` when `OTEL_EXPORTER_OTLP_ENDPOINT` is set in
/// the environment; `None` otherwise (no-op — local dev, CI).
///
/// Registers a process-shutdown hook via `opentelemetry::global::
/// set_tracer_provider` so in-flight spans are flushed before the
/// binary exits (triggered by the existing SIGTERM/SIGINT handler in
/// `main.rs`).
///
/// Configuration failures (invalid endpoint, Tonic transport errors) are
/// printed to stderr and swallowed: tracing is instrumentation, not
/// load-bearing. The function returns `None` on any error so startup is
/// never blocked.
pub fn try_build_otel_layer<S>() -> Option<impl Layer<S>>
where
    S: tracing::Subscriber + for<'span> tracing_subscriber::registry::LookupSpan<'span>,
{
    let endpoint = std::env::var("OTEL_EXPORTER_OTLP_ENDPOINT").ok()?;

    let resource = Resource::builder()
        .with_service_name("matrix-mcp")
        .with_attribute(opentelemetry::KeyValue::new(
            "service.version",
            env!("CARGO_PKG_VERSION"),
        ))
        .build();

    let exporter = match opentelemetry_otlp::SpanExporter::builder()
        .with_tonic()
        .with_endpoint(endpoint)
        .build()
    {
        Ok(e) => e,
        Err(err) => {
            // tracing isn't set up yet so use eprintln — this only fires
            // at startup before the subscriber is installed.
            eprintln!("matrix-mcp: OTLP exporter init failed: {err}; disabling OTel tracing");
            return None;
        }
    };

    let provider = SdkTracerProvider::builder()
        .with_resource(resource)
        .with_batch_exporter(exporter)
        .build();

    // Register globally so `opentelemetry::global::shutdown_tracer_provider()`
    // flushes the batch queue on process exit.
    opentelemetry::global::set_tracer_provider(provider.clone());

    let tracer = provider.tracer("matrix-mcp");
    Some(OpenTelemetryLayer::new(tracer))
}
