//! Account operations on `/v1/auth`, after a successful Hello over TLS.
//!
//! These messages intentionally omit Debug because they carry credentials.
use crate::{
    CAP_CHANGE_PASSWORD, CAP_DEVICE_DIRECTORY, CAP_PASSWORD_RESET, CAP_TWO_FACTOR,
    CAP_TWO_FACTOR_MANAGE, Message,
};
use serde::{Deserialize, Serialize};

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthRequest {
    pub operation: Operation,
}

impl Message for AuthRequest {
    const KIND: u16 = 13;
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Operation {
    Register {
        username: String,
        email: String,
        password: String,
    },
    SignIn {
        login: String,
        password: String,
    },
    ConfirmEmail {
        verification: String,
        code: String,
    },
    ResendCode {
        verification: String,
    },
    ResumeSession {
        session: String,
    },
    SignOut {
        session: String,
    },
    RequestPasswordReset {
        email: String,
    },
    ResetPassword {
        token: String,
        password: String,
    },
    ChangePassword {
        session: String,
        current_password: String,
        new_password: String,
    },
    BeginTwoFactor {
        session: String,
        password: String,
    },
    ConfirmTwoFactor {
        session: String,
        code: String,
    },
    CompleteTwoFactorSignIn {
        challenge: String,
        code: String,
    },
    GetTwoFactorStatus {
        session: String,
    },
    ManageTwoFactor {
        session: String,
        password: String,
        code: String,
        action: TwoFactorAction,
    },
    EnrollDevice {
        session: String,
        device_id: [u8; 16],
        public_key: [u8; 32],
        signature: Vec<u8>,
    },
    ListDevices {
        session: String,
    },
    RevokeDevice {
        session: String,
        device_id: [u8; 16],
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TwoFactorAction {
    Disable,
    ReplaceBackupCodes,
}

impl Operation {
    pub fn required_capability(&self) -> u64 {
        match self {
            Self::RequestPasswordReset { .. } | Self::ResetPassword { .. } => CAP_PASSWORD_RESET,
            Self::ChangePassword { .. } => CAP_CHANGE_PASSWORD,
            Self::BeginTwoFactor { .. }
            | Self::ConfirmTwoFactor { .. }
            | Self::CompleteTwoFactorSignIn { .. } => CAP_TWO_FACTOR,
            Self::GetTwoFactorStatus { .. } | Self::ManageTwoFactor { .. } => CAP_TWO_FACTOR_MANAGE,
            Self::EnrollDevice { .. } | Self::ListDevices { .. } | Self::RevokeDevice { .. } => {
                CAP_DEVICE_DIRECTORY
            }
            _ => 0,
        }
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthReply {
    pub outcome: Outcome,
}

impl Message for AuthReply {
    const KIND: u16 = 14;
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Outcome {
    VerificationRequired {
        verification: String,
        email: String,
        retry_after_seconds: u32,
        expires_in_seconds: u32,
    },
    Authenticated {
        username: String,
        session: String,
        expires_in_seconds: u32,
    },
    SignedOut,
    Rejected {
        code: AuthError,
        retry_after_seconds: u32,
    },
    PasswordResetRequested,
    PasswordReset,
    PasswordChanged,
    TwoFactorSetup {
        secret: String,
        expires_in_seconds: u32,
    },
    TwoFactorEnabled {
        backup_codes: Vec<String>,
    },
    TwoFactorRequired {
        challenge: String,
        expires_in_seconds: u32,
    },
    TwoFactorStatus {
        enabled: bool,
        backup_codes_left: u32,
    },
    TwoFactorDisabled,
    DeviceEnrolled,
    DeviceDirectory {
        devices: Vec<DeviceRecord>,
    },
    DeviceRevoked,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AuthError {
    InvalidInput,
    AlreadyExists,
    InvalidCredentials,
    InvalidCode,
    ExpiredCode,
    RateLimited,
    SessionExpired,
    Unavailable,
    TwoFactorAlreadyEnabled,
    DeviceKeyConflict,
    DeviceRevoked,
    DeviceLimit,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceRecord {
    pub device_id: [u8; 16],
    pub public_key: [u8; 32],
    pub revoked: bool,
}

pub fn device_enrollment_message(
    account: &str,
    session: &str,
    id: &[u8; 16],
    key: &[u8; 32],
) -> Vec<u8> {
    let mut bytes = b"vox/account/device-enrollment/v1\0".to_vec();
    bytes.extend_from_slice(&(account.len() as u64).to_be_bytes());
    bytes.extend_from_slice(account.as_bytes());
    bytes.extend_from_slice(&(session.len() as u64).to_be_bytes());
    bytes.extend_from_slice(session.as_bytes());
    bytes.extend_from_slice(id);
    bytes.extend_from_slice(key);
    bytes
}
