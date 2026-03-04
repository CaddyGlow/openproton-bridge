use openproton_bridge::frontend::grpc::pb;

#[test]
fn grpc_wire_login_request_password_is_bytes() {
    let req = pb::LoginRequest {
        username: "alice@example.com".to_string(),
        password: vec![0x61, 0x62, 0x63],
        use_hv_details: None,
        human_verification_token: None,
        api_mode: None,
    };

    assert_eq!(req.password, b"abc");
}
