use opentelemetry::KeyValue;
use opentelemetry_otlp::WithExportConfig;
use opentelemetry_sdk::{
    Resource,
    trace::{BatchSpanProcessor, RandomIdGenerator, Sampler, SdkTracerProvider},
};
use std::time::Duration;

use crate::config::otel_config::OtelConfig;

/// Initialize the OpenTelemetry tracer provider with OTLP exporter
pub fn init_tracer_provider(
    config: &OtelConfig,
) -> Result<SdkTracerProvider, Box<dyn std::error::Error>> {
    if !config.enable_traces {
        tracing::info!("OpenTelemetry traces are disabled");
        return Err("Traces disabled".into());
    }

    tracing::info!(
        "Initializing OpenTelemetry tracer provider with endpoint: {}",
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

    // Configure the OTLP exporter
    let exporter = opentelemetry_otlp::SpanExporter::builder()
        .with_tonic()
        .with_endpoint(&config.otlp_endpoint)
        .with_timeout(Duration::from_secs(10))
        .build()?;

    // Configure sampler based on configuration
    let sampler = match config.trace_sampler.as_str() {
        "always_on" => Sampler::AlwaysOn,
        "always_off" => Sampler::AlwaysOff,
        "traceidratio" => Sampler::TraceIdRatioBased(0.1), // 10% sampling
        _ => Sampler::ParentBased(Box::new(Sampler::TraceIdRatioBased(0.1))),
    };

    // Configure batch span processor
    let batch_processor = BatchSpanProcessor::builder(exporter).build();

    // Build tracer provider
    let tracer_provider = SdkTracerProvider::builder()
        .with_span_processor(batch_processor)
        .with_resource(resource)
        .with_sampler(sampler)
        .with_id_generator(RandomIdGenerator::default())
        .build();

    // Set global tracer provider
    opentelemetry::global::set_tracer_provider(tracer_provider.clone());

    tracing::info!("OpenTelemetry tracer provider initialized successfully");

    Ok(tracer_provider)
}
