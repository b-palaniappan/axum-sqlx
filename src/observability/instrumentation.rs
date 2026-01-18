use opentelemetry::trace::TraceContextExt;

/// Extension trait for recording errors in spans
pub trait SpanExt {
    /// Record an error in the current span
    fn record_error(&self, error: &dyn std::error::Error);

    /// Set span status to error with a message
    fn set_error_status(&self, message: String);
}

impl SpanExt for tracing::Span {
    fn record_error(&self, error: &dyn std::error::Error) {
        self.record("error", true);
        self.record("error.message", error.to_string().as_str());

        // Also set OpenTelemetry status if we're in an OpenTelemetry context
        let context = opentelemetry::Context::current();
        let span = context.span();
        let span_context = span.span_context();
        if span_context.is_valid() {
            // The span is valid and part of OpenTelemetry
        }
    }

    fn set_error_status(&self, message: String) {
        self.record("error", true);
        self.record("error.message", message.as_str());
    }
}

/// Helper function to get the current trace ID as a string
pub fn current_trace_id() -> Option<String> {
    let context = opentelemetry::Context::current();
    let span = context.span();
    let span_context = span.span_context();

    if span_context.is_valid() {
        Some(span_context.trace_id().to_string())
    } else {
        None
    }
}

/// Helper function to get the current span ID as a string
pub fn current_span_id() -> Option<String> {
    let context = opentelemetry::Context::current();
    let span = context.span();
    let span_context = span.span_context();

    if span_context.is_valid() {
        Some(span_context.span_id().to_string())
    } else {
        None
    }
}
