use std::env;

#[derive(Debug, Clone)]
pub struct OtelConfig {
    pub service_name: String,
    pub service_version: String,
    pub environment: String,
    pub otlp_endpoint: String,
    pub enable_traces: bool,
    pub enable_metrics: bool,
    pub enable_logs: bool,
    pub trace_sampler: String,
}

impl Default for OtelConfig {
    fn default() -> Self {
        Self {
            service_name: env!("CARGO_PKG_NAME").to_string(),
            service_version: env!("CARGO_PKG_VERSION").to_string(),
            environment: "development".to_string(),
            otlp_endpoint: "http://localhost:4317".to_string(),
            enable_traces: true,
            enable_metrics: true,
            enable_logs: true,
            trace_sampler: "always_on".to_string(),
        }
    }
}

impl OtelConfig {
    /// Load OpenTelemetry configuration from environment variables
    pub fn from_env() -> Self {
        Self {
            service_name: env::var("OTEL_SERVICE_NAME")
                .unwrap_or_else(|_| "axum-sqlx-api".to_string()),
            service_version: env::var("OTEL_SERVICE_VERSION")
                .unwrap_or_else(|_| "0.1.3".to_string()),
            environment: env::var("OTEL_ENVIRONMENT").unwrap_or_else(|_| "development".to_string()),
            otlp_endpoint: env::var("OTEL_EXPORTER_OTLP_ENDPOINT")
                .unwrap_or_else(|_| "http://localhost:4317".to_string()),
            enable_traces: env::var("OTEL_ENABLE_TRACES")
                .unwrap_or_else(|_| "true".to_string())
                .parse()
                .unwrap_or(true),
            enable_metrics: env::var("OTEL_ENABLE_METRICS")
                .unwrap_or_else(|_| "true".to_string())
                .parse()
                .unwrap_or(true),
            enable_logs: env::var("OTEL_ENABLE_LOGS")
                .unwrap_or_else(|_| "true".to_string())
                .parse()
                .unwrap_or(true),
            trace_sampler: env::var("OTEL_TRACES_SAMPLER")
                .unwrap_or_else(|_| "always_on".to_string()),
        }
    }
}

/// Load OTEL configuration from environment variables
pub fn load_otel_config() -> OtelConfig {
    OtelConfig::from_env()
}
