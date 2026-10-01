use thiserror::Error;

pub type Result<T> = std::result::Result<T, BrokerError>;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum BrokerError {
    #[error("invalid credential field: {0}")]
    InvalidField(&'static str),
    #[error("credential was not found")]
    NotFound,
    #[error("credential use was denied")]
    AccessDenied,
    #[error("credential lease expired")]
    Expired,
    #[error("credential lease was revoked")]
    Revoked,
    #[error("credential lease is not available")]
    UnknownLease,
    #[error("credential changed after lease issuance")]
    CredentialChanged,
    #[error("credential lease capacity was reached")]
    LeaseCapacity,
    #[error("credential backend is unavailable")]
    BackendUnavailable,
    #[error("credential backend denied access")]
    BackendDenied,
    #[error("secure random generation failed")]
    EntropyUnavailable,
    #[error("credential encoding is invalid")]
    InvalidEncoding,
}

/// A metadata-only diagnosis for the platform credential store.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum CustodyAvailabilityError {
    #[error("platform custody provider is unavailable")]
    Unavailable,
    #[error("platform custody provider denied access")]
    Denied,
}
