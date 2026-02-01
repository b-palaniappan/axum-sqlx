use opentelemetry::KeyValue;
use opentelemetry_otlp::{WithExportConfig, WithTonicConfig};
use opentelemetry_sdk::{
    Resource,
    logs::{BatchLogProcessor, SdkLoggerProvider},
};
use std::time::Duration;

use crate::config::otel_config::OtelConfig;

/// Initialize the OpenTelemetry logger provider with OTLP exporter
pub fn init_logger_provider(
    config: &OtelConfig,
) -> Result<SdkLoggerProvider, Box<dyn std::error::Error>> {
    if !config.enable_logs {
        tracing::info!("OpenTelemetry logs are disabled");
        return Err("Logs disabled".into());
    }

    tracing::info!(
        "Initializing OpenTelemetry logger provider with endpoint: {}",
        config.otlp_endpoint
    );

    // Create resource with service information
    let resource = Resource::builder_empty()
        .with_attributes([
            KeyValue::new(
                opentelemetry_semantic_conventions::resource::SERVICE_NAME,
                config.service_name.clone(),
            ),
            KeyValue::new(
                opentelemetry_semantic_conventions::resource::SERVICE_VERSION,
                config.service_version.clone(),
            ),
            KeyValue::new("deployment.environment", config.environment.clone()),
        ])
        .build();

    let mut metadata = tonic::metadata::MetadataMap::new();
    metadata.insert(
        "signoz-ingestion-key",
        tonic::metadata::MetadataValue::try_from("umcDCbdXthAp5pqkr2phWMbt42vEjUnfxwlx").unwrap(),
    );

    // Configure the OTLP exporter
    let mut exporter_builder = opentelemetry_otlp::LogExporter::builder()
        .with_tonic()
        .with_endpoint(&config.otlp_endpoint)
        .with_metadata(metadata)
        .with_timeout(Duration::from_secs(10));
    if config.otlp_endpoint.starts_with("https://") {
        exporter_builder = exporter_builder.with_tls_config(
            tonic::transport::ClientTlsConfig::new().with_native_roots(),
        );
    }
    let exporter = exporter_builder.build()?;

    // Configure batch processor
    let processor = BatchLogProcessor::builder(exporter).build();

    // Build logger provider
    let logger_provider = SdkLoggerProvider::builder()
        .with_log_processor(processor)
        .with_resource(resource)
        .build();

    tracing::info!("OpenTelemetry logger provider initialized successfully");

    Ok(logger_provider)
}
