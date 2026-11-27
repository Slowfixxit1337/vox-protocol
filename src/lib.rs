//! The public signaling contract. Media keys never appear on this wire.
use serde::{Deserialize, Serialize, de::DeserializeOwned};
pub mod auth;

pub const MAJOR: u16 = 1;
pub const MINOR: u16 = 0;
pub const CAP_FRAME_E2EE: u64 = 1;
pub const CAP_SFU_TRANSPORT: u64 = 1 << 1;
pub const CAP_AUTH: u64 = 1 << 2;
pub const CAP_PASSWORD_RESET: u64 = 1 << 3;
pub const CAP_CHANGE_PASSWORD: u64 = 1 << 4;
pub const HEADER_LEN: usize = 19;
pub const MAX_PAYLOAD: usize = 256 * 1024;
pub const MAX_FRAME: usize = HEADER_LEN + MAX_PAYLOAD;
const REQUIRED: u8 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WireError {
    InvalidLength,
    TooLarge,
    UnsupportedVersion,
    UnsupportedFeature,
    InvalidBody,
    WrongKind,
}
impl std::fmt::Display for WireError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for WireError {}

pub trait Message: Serialize + DeserializeOwned {
    const KIND: u16;
}

macro_rules! messages {
    ($($kind:literal => $name:ident { $($field:ident: $ty:ty),* $(,)? }),+ $(,)?) => {
        $(
            #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
            pub struct $name { $(pub $field: $ty),* }
            impl Message for $name { const KIND: u16 = $kind; }
        )+
        fn known(kind: u16) -> bool {
            [$($kind),+].contains(&kind) || matches!(kind, auth::AuthRequest::KIND | auth::AuthReply::KIND)
        }
    };
}

messages! {
    1 => ClientHello { min_minor: u16, max_minor: u16, capabilities: u64, required: u64 },
    2 => ServerHello { minor: u16, capabilities: u64 },
    3 => JoinRoom { room: String, device: String, credential: String },
    4 => RoomJoined { generation: u64, ticket: String, sfu_url: String, ice: Vec<IceServer>, allowed_tracks: Vec<Track> },
    5 => SdpOffer { generation: u64, sdp: String },
    6 => SdpAnswer { generation: u64, sdp: String },
    7 => IceCandidate { generation: u64, mid: String, candidate: String },
    8 => TrackEnded { track: Track },
    9 => ProtocolError { code: ErrorCode },
    10 => AttachMedia { ticket: String, offer: SdpOffer },
    11 => GetTransportState { generation: u64 },
    12 => TransportState { generation: u64, connected: bool },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IceServer {
    pub urls: Vec<String>,
    pub username: Option<String>,
    pub credential: Option<String>,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Track {
    Mic,
    ShareVideo,
    ShareAudio,
    Camera,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ErrorCode {
    UnsupportedVersion,
    UnsupportedFeature,
    Unauthenticated,
    RoomUnavailable,
    InvalidRequest,
}

pub fn negotiate(major: u16, hello: &ClientHello) -> Result<ServerHello, WireError> {
    negotiate_with(major, hello, CAP_FRAME_E2EE | CAP_SFU_TRANSPORT)
}

pub fn negotiate_with(
    major: u16,
    hello: &ClientHello,
    supported: u64,
) -> Result<ServerHello, WireError> {
    if major != MAJOR || hello.min_minor > hello.max_minor || hello.min_minor > MINOR {
        return Err(WireError::UnsupportedVersion);
    }
    let capabilities = hello.capabilities & supported;
    if capabilities & CAP_FRAME_E2EE == 0 || hello.required & !capabilities != 0 {
        return Err(WireError::UnsupportedFeature);
    }
    Ok(ServerHello {
        minor: MINOR,
        capabilities,
    })
}

pub fn encode<M: Message>(minor: u16, request_id: u64, message: &M) -> Result<Vec<u8>, WireError> {
    let payload = postcard::to_allocvec(message).map_err(|_| WireError::InvalidBody)?;
    if payload.len() > MAX_PAYLOAD {
        return Err(WireError::TooLarge);
    }
    let mut frame = Vec::with_capacity(HEADER_LEN + payload.len());
    frame.extend_from_slice(&MAJOR.to_be_bytes());
    frame.extend_from_slice(&minor.to_be_bytes());
    frame.extend_from_slice(&M::KIND.to_be_bytes());
    frame.push(REQUIRED);
    frame.extend_from_slice(&request_id.to_be_bytes());
    frame.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    frame.extend_from_slice(&payload);
    Ok(frame)
}

pub struct Envelope<'a> {
    pub major: u16,
    pub minor: u16,
    pub kind: u16,
    pub request_id: u64,
    payload: &'a [u8],
}

impl Envelope<'_> {
    pub fn body<M: Message>(&self) -> Result<M, WireError> {
        if self.kind != M::KIND {
            return Err(WireError::WrongKind);
        }
        let (message, remaining) =
            postcard::take_from_bytes(self.payload).map_err(|_| WireError::InvalidBody)?;
        if !remaining.is_empty() {
            return Err(WireError::InvalidBody);
        }
        Ok(message)
    }
}

pub fn decode(frame: &[u8]) -> Result<Envelope<'_>, WireError> {
    let (header, payload) = frame
        .split_at_checked(HEADER_LEN)
        .ok_or(WireError::InvalidLength)?;
    let length = u32::from_be_bytes(header[15..19].try_into().unwrap()) as usize;
    if length > MAX_PAYLOAD || frame.len() > MAX_FRAME {
        return Err(WireError::TooLarge);
    }
    if length != payload.len() {
        return Err(WireError::InvalidLength);
    }
    let major = u16::from_be_bytes([header[0], header[1]]);
    let minor = u16::from_be_bytes([header[2], header[3]]);
    let kind = u16::from_be_bytes([header[4], header[5]]);
    let flags = header[6];
    if flags & !REQUIRED != 0 || (!known(kind) && flags & REQUIRED != 0) {
        return Err(WireError::UnsupportedFeature);
    }
    Ok(Envelope {
        major,
        minor,
        kind,
        request_id: u64::from_be_bytes(header[7..15].try_into().unwrap()),
        payload,
    })
}
