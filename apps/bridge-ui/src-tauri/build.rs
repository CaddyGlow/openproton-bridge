fn main() -> Result<(), Box<dyn std::error::Error>> {
    tauri_build::build();

    tonic_build::configure()
        .build_client(true)
        .build_server(false)
        .compile_protos(&["proto/bridge.proto"], &["proto"])?;

    println!("cargo:rerun-if-changed=proto/bridge.proto");

    Ok(())
}
