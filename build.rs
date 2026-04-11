fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("cargo:rerun-if-changed=proto/user_registration.proto");

    let protoc_path = protoc_bin_vendored::protoc_bin_path()?;
    // SAFETY: build scripts run in a controlled single-process context for this crate.
    unsafe {
        std::env::set_var("PROTOC", protoc_path);
    }

    let out_dir = std::path::PathBuf::from(std::env::var("OUT_DIR")?);
    tonic_prost_build::configure()
        .file_descriptor_set_path(out_dir.join("user_v1_descriptor.bin"))
        .compile_protos(&["proto/user_registration.proto"], &["proto"])?;
    Ok(())
}
