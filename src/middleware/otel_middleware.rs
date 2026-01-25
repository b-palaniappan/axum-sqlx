use axum::{extract::Request, middleware::Next, response::Response};
use opentelemetry::trace::{FutureExt, TraceContextExt, Tracer};
use opentelemetry::{Context, KeyValue, global};
use opentelemetry_http::HeaderExtractor;
use std::time::Instant;
use tracing::{Instrument, info_span};

/// HTTP tracing middleware that creates spans for all HTTP requests
pub async fn trace_layer(request: Request, next: Next) -> Response {
    let method = request.method().clone();
    let uri = request.uri().clone();
    let path = uri.path().to_string();
    let version = request.version();

    // Extract trace context from incoming headers (W3C TraceContext propagation)
    let parent_context = global::get_text_map_propagator(|propagator| {
        propagator.extract(&HeaderExtractor(request.headers()))
    });

    // Get tracer
    let tracer = global::tracer("axum-sqlx");

    // Create span with HTTP semantic conventions
    let mut span_builder = tracer
        .span_builder(format!("{} {}", method, path))
        .with_kind(opentelemetry::trace::SpanKind::Server);

    // Add HTTP attributes
    span_builder = span_builder.with_attributes(vec![
        KeyValue::new(
            opentelemetry_semantic_conventions::trace::HTTP_REQUEST_METHOD,
            method.to_string(),
        ),
        KeyValue::new(
            opentelemetry_semantic_conventions::trace::URL_PATH,
            path.clone(),
        ),
        KeyValue::new(
            opentelemetry_semantic_conventions::trace::URL_SCHEME,
            uri.scheme_str().unwrap_or("http").to_string(),
        ),
        KeyValue::new(
            opentelemetry_semantic_conventions::trace::NETWORK_PROTOCOL_VERSION,
            format!("{:?}", version),
        ),
    ]);

    // Start span with parent context
    let span = tracer.build_with_context(span_builder, &parent_context);
    let cx = Context::current_with_span(span);

    let start = Instant::now();

    // Execute the request within the span context
    let response = {
        // Create tracing span for logging integration
        let tracing_span = info_span!(
            "http_request",
            method = %method,
            path = %path,
            status = tracing::field::Empty,
            duration_ms = tracing::field::Empty,
        );

        let result = next
            .run(request)
            .instrument(tracing_span.clone())
            .with_context(cx.clone())
            .await;

        // Record response status and duration
        let duration = start.elapsed();
        let status = result.status();

        tracing_span.record("status", status.as_u16());
        tracing_span.record("duration_ms", duration.as_millis() as u64);

        // Add response attributes to OpenTelemetry span
        cx.span().set_attribute(KeyValue::new(
            opentelemetry_semantic_conventions::trace::HTTP_RESPONSE_STATUS_CODE,
            status.as_u16() as i64,
        ));

        // Set span status based on HTTP status code
        if status.is_server_error() {
            cx.span().set_status(opentelemetry::trace::Status::error(
                status
                    .canonical_reason()
                    .unwrap_or("Server Error")
                    .to_string(),
            ));
        } else if status.is_client_error() {
            // Client errors (4xx) are not considered span errors in OpenTelemetry
            cx.span().set_status(opentelemetry::trace::Status::Ok);
        } else {
            cx.span().set_status(opentelemetry::trace::Status::Ok);
        }

        result
    };

    // End span
    cx.span().end();

    response
}
