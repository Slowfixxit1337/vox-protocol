use vox_protocol::{
    CAP_AUTH, CAP_FRAME_E2EE, ClientHello, MAJOR,
    auth::{AuthReply, AuthRequest, Operation, Outcome},
    decode, encode, negotiate_with,
};

#[test]
fn auth_capability_and_operations_round_trip() {
    let hello = ClientHello {
        min_minor: 0,
        max_minor: 0,
        capabilities: CAP_AUTH | CAP_FRAME_E2EE,
        required: CAP_AUTH | CAP_FRAME_E2EE,
    };
    assert!(negotiate_with(MAJOR, &hello, CAP_FRAME_E2EE).is_err());
    assert!(negotiate_with(MAJOR, &hello, CAP_AUTH | CAP_FRAME_E2EE).is_ok());
    let request = AuthRequest {
        operation: Operation::ConfirmEmail {
            verification: "synthetic-challenge".into(),
            code: "012345".into(),
        },
    };
    let encoded = encode(0, 2, &request).unwrap();
    let decoded = decode(&encoded).unwrap();
    assert_eq!((decoded.kind, decoded.request_id), (13, 2));
    assert!(decoded.body::<AuthRequest>().unwrap() == request);

    let reply = AuthReply {
        outcome: Outcome::SignedOut,
    };
    let encoded = encode(0, 2, &reply).unwrap();
    let decoded = decode(&encoded).unwrap();
    assert_eq!((decoded.kind, decoded.request_id), (14, 2));
    assert!(decoded.body::<AuthReply>().unwrap() == reply);
}
