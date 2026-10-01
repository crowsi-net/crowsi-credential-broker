use thiserror::Error;

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum IpcError {
    #[error("authorization was rejected")]
    AuthorizationRejected,
    #[error("authorization binding was rejected")]
    BindingRejected,
    #[error("IPC frame is invalid")]
    InvalidFrame,
    #[error("IPC frame exceeds the size limit")]
    FrameOversized,
    #[error("IPC frame ended before completion")]
    PartialFrame,
    #[error("IPC stream contains trailing data")]
    TrailingData,
    #[error("IPC operation timed out")]
    Timeout,
    #[error("IPC transport is unavailable")]
    TransportUnavailable,
    #[error("secret digest does not match the enrollment request")]
    SecretDigest,
    #[error("credential store is unavailable")]
    StoreUnavailable,
}

pub type IpcResult<T> = std::result::Result<T, IpcError>;
