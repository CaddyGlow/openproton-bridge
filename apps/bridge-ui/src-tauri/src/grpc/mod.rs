pub mod adapter;
pub mod config;

pub mod pb {
    tonic::include_proto!("grpc");
}
