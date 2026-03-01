pub mod adapter;
pub mod config;

#[allow(clippy::enum_variant_names)]
pub mod pb {
    tonic::include_proto!("grpc");
}
