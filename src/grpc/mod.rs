pub mod user_registration_controller;

pub mod user_v1 {
    tonic::include_proto!("user.v1");
    pub const FILE_DESCRIPTOR_SET: &[u8] =
        tonic::include_file_descriptor_set!("user_v1_descriptor");
}
