//! Account operations on `/v1/auth`, after a successful Hello over TLS.
//!
//! These messages intentionally omit Debug because they carry credentials.
use crate::Message;
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
}

impl Operation {
    pub fn requires_password_reset(&self) -> bool {
        matches!(
            self,
            Self::RequestPasswordReset { .. } | Self::ResetPassword { .. }
        )
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
}
