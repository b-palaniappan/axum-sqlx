use opentelemetry::{KeyValue, global};
use opentelemetry_otlp::{WithExportConfig, WithTonicConfig};
use opentelemetry_sdk::{
    Resource,
    metrics::{PeriodicReader, SdkMeterProvider},
};
use std::time::Duration;

use crate::config::otel_config::OtelConfig;

/// Initialize the OpenTelemetry meter provider with OTLP exporter
pub fn init_meter_provider(
    config: &OtelConfig,
) -> Result<SdkMeterProvider, Box<dyn std::error::Error>> {
    if !config.enable_metrics {
        tracing::info!("OpenTelemetry metrics are disabled");
        return Err("Metrics disabled".into());
    }

    tracing::info!(
        "Initializing OpenTelemetry meter provider with endpoint: {}",
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
    let mut exporter_builder = opentelemetry_otlp::MetricExporter::builder()
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

    // Configure periodic reader with 30-second interval
    let reader = PeriodicReader::builder(exporter)
        .with_interval(Duration::from_secs(30))
        .build();

    // Build meter provider
    let meter_provider = SdkMeterProvider::builder()
        .with_reader(reader)
        .with_resource(resource)
        .build();

    // Set global meter provider
    global::set_meter_provider(meter_provider.clone());

    tracing::info!("OpenTelemetry meter provider initialized successfully");

    Ok(meter_provider)
}
