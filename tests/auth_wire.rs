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
#[test]
fn password_reset_requires_negotiation_and_round_trips() {
    use vox_protocol::CAP_PASSWORD_RESET;
    let supported = CAP_AUTH | CAP_FRAME_E2EE;
    let hello = ClientHello {
        min_minor: 0,
        max_minor: 0,
        capabilities: supported | CAP_PASSWORD_RESET,
        required: supported | CAP_PASSWORD_RESET,
    };
    assert!(negotiate_with(MAJOR, &hello, supported).is_err());
    assert!(negotiate_with(MAJOR, &hello, hello.capabilities).is_ok());
    let request = AuthRequest {
        operation: Operation::ResetPassword {
            token: "synthetic token".into(),
            password: "synthetic password".into(),
        },
    };
    let bytes = encode(0, 9, &request).unwrap();
    assert!(decode(&bytes).unwrap().body::<AuthRequest>().unwrap() == request);
}
#[test]
fn change_password_requires_its_own_capability() {
    use vox_protocol::{CAP_CHANGE_PASSWORD, CAP_PASSWORD_RESET};
    let old = CAP_AUTH | CAP_FRAME_E2EE | CAP_PASSWORD_RESET;
    let operation = Operation::ChangePassword {
        session: "synthetic session".into(),
        current_password: "old password".into(),
        new_password: "new password".into(),
    };
    assert_eq!(operation.required_capability(), CAP_CHANGE_PASSWORD);
    let hello = ClientHello {
        min_minor: 0,
        max_minor: 0,
        capabilities: old | CAP_CHANGE_PASSWORD,
        required: old | CAP_CHANGE_PASSWORD,
    };
    assert!(negotiate_with(MAJOR, &hello, old).is_err());
    assert!(negotiate_with(MAJOR, &hello, hello.capabilities).is_ok());
    let request = AuthRequest { operation };
    assert!(
        decode(&encode(0, 4, &request).unwrap())
            .unwrap()
            .body::<AuthRequest>()
            .unwrap()
            == request
    );
}
#[test]
fn two_factor_challenge_round_trips_without_a_session() {
    use vox_protocol::CAP_TWO_FACTOR;
    let operation = Operation::CompleteTwoFactorSignIn {
        challenge: "synthetic challenge".into(),
        code: "123456".into(),
    };
    assert_eq!(operation.required_capability(), CAP_TWO_FACTOR);
    let reply = AuthReply {
        outcome: Outcome::TwoFactorRequired {
            challenge: "synthetic challenge".into(),
            expires_in_seconds: 300,
        },
    };
    assert!(
        decode(&encode(0, 2, &reply).unwrap())
            .unwrap()
            .body::<AuthReply>()
            .unwrap()
            == reply
    );
}
#[test]
fn two_factor_management_negotiates_separately() {
    use vox_protocol::{CAP_TWO_FACTOR, CAP_TWO_FACTOR_MANAGE, auth::TwoFactorAction};
    let operation = Operation::ManageTwoFactor {
        session: "synthetic session".into(),
        password: "synthetic password".into(),
        code: "123456".into(),
        action: TwoFactorAction::ReplaceBackupCodes,
    };
    assert_eq!(operation.required_capability(), CAP_TWO_FACTOR_MANAGE);
    let old = CAP_FRAME_E2EE | CAP_AUTH | CAP_TWO_FACTOR;
    let supported = old | CAP_TWO_FACTOR_MANAGE;
    let hello = ClientHello {
        min_minor: 0,
        max_minor: 0,
        capabilities: supported,
        required: supported,
    };
    assert!(negotiate_with(MAJOR, &hello, old).is_err());
    let request = AuthRequest { operation };
    assert!(
        decode(&encode(0, 4, &request).unwrap())
            .unwrap()
            .body::<AuthRequest>()
            .unwrap()
            == request
    );
}
#[test]
fn device_enrollment_transcript_binds_account_session_id_and_key() {
    use vox_protocol::{CAP_DEVICE_DIRECTORY, auth::device_enrollment_message};
    let id = [1; 16];
    let key = [2; 32];
    let message = device_enrollment_message("Vox", "session-a", &id, &key);
    assert_ne!(
        message,
        device_enrollment_message("Vox", "session-b", &id, &key)
    );
    assert_ne!(
        message,
        device_enrollment_message("Other", "session-a", &id, &key)
    );
    assert_ne!(
        message,
        device_enrollment_message("Vox", "session-a", &[2; 16], &key)
    );
    assert_ne!(
        message,
        device_enrollment_message("Vox", "session-a", &id, &[3; 32])
    );
    let operation = Operation::EnrollDevice {
        session: "synthetic".into(),
        device_id: id,
        public_key: key,
        signature: vec![0; 64],
    };
    assert_eq!(operation.required_capability(), CAP_DEVICE_DIRECTORY);
    let request = AuthRequest { operation };
    assert!(
        decode(&encode(0, 4, &request).unwrap())
            .unwrap()
            .body::<AuthRequest>()
            .unwrap()
            == request
    );
}
