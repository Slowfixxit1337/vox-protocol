use vox_protocol::*;

#[test]
fn hello_v1_has_stable_wire_bytes() {
    let hello = ClientHello {
        min_minor: 0,
        max_minor: 0,
        capabilities: CAP_FRAME_E2EE,
        required: CAP_FRAME_E2EE,
    };
    let frame = encode(0, 42, &hello).unwrap();
    assert_eq!(
        frame,
        [
            0, 1, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 42, 0, 0, 0, 4, 0, 0, 1, 1
        ]
    );
    assert_eq!(
        decode(&frame).unwrap().body::<ClientHello>().unwrap(),
        hello
    );
}

#[test]
fn bounds_and_routing_are_checked_before_body_decode() {
    let mut frame = encode(
        0,
        12,
        &TrackEnded {
            track: Track::ShareAudio,
        },
    )
    .unwrap();
    assert_eq!(
        decode(&frame).unwrap().body::<ClientHello>(),
        Err(WireError::WrongKind)
    );
    frame.push(0);
    assert!(matches!(decode(&frame), Err(WireError::InvalidLength)));
    frame[15..19].copy_from_slice(&u32::MAX.to_be_bytes());
    assert!(matches!(decode(&frame), Err(WireError::TooLarge)));
}

#[test]
fn unknown_optional_is_skippable_and_unknown_required_is_rejected() {
    let mut frame = encode(0, 12, &TrackEnded { track: Track::Mic }).unwrap();
    frame[4..6].copy_from_slice(&999u16.to_be_bytes());
    assert!(matches!(decode(&frame), Err(WireError::UnsupportedFeature)));
    frame[6] = 0;
    assert_eq!(decode(&frame).unwrap().kind, 999);
}

#[test]
fn hello_requires_e2ee_and_rejects_unsupported_requirements() {
    let mut hello = ClientHello {
        min_minor: 0,
        max_minor: 2,
        capabilities: CAP_FRAME_E2EE | 8,
        required: CAP_FRAME_E2EE,
    };
    assert_eq!(negotiate(1, &hello).unwrap().minor, 0);
    assert_eq!(negotiate(1, &hello).unwrap().capabilities, CAP_FRAME_E2EE);
    hello.required |= 8;
    assert_eq!(negotiate(1, &hello), Err(WireError::UnsupportedFeature));
    hello.capabilities = 0;
    assert_eq!(negotiate(1, &hello), Err(WireError::UnsupportedFeature));
    assert_eq!(negotiate(2, &hello), Err(WireError::UnsupportedVersion));
}

#[test]
fn sfu_transport_negotiates_and_attaches_with_a_stable_kind() {
    let hello = ClientHello {
        min_minor: MINOR,
        max_minor: MINOR,
        capabilities: CAP_FRAME_E2EE | CAP_SFU_TRANSPORT,
        required: CAP_FRAME_E2EE | CAP_SFU_TRANSPORT,
    };
    assert_eq!(
        negotiate(MAJOR, &hello).unwrap().capabilities,
        hello.capabilities
    );
    let attach = AttachMedia {
        ticket: "fixture".into(),
        offer: SdpOffer {
            generation: 4,
            sdp: "v=0".into(),
        },
    };
    let frame = encode(MINOR, 9, &attach).unwrap();
    let frame = decode(&frame).unwrap();
    assert_eq!(frame.kind, 10);
    assert_eq!(frame.body::<AttachMedia>().unwrap(), attach);
}
