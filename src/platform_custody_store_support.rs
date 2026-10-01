use crowsi_windows_custody_provider::{CustodyError, ReasonCode, ResponseState};

use crate::{BrokerError, CustodyAvailabilityError, Result};

pub(super) fn request_id() -> Result<String> {
    let mut value = [0_u8; 16];
    getrandom::fill(&mut value).map_err(|_| BrokerError::EntropyUnavailable)?;
    Ok(hex::encode(value))
}

pub(super) fn require_ready(state: &ResponseState) -> Result<()> {
    match state {
        ResponseState::Ready {
            secret_follows: false,
            ..
        } => Ok(()),
        ResponseState::Error { reason_code } => Err(map_reason(*reason_code)),
        _ => Err(BrokerError::InvalidEncoding),
    }
}

pub(super) fn map_error(error: CustodyError) -> BrokerError {
    map_reason(error.reason())
}

pub(super) fn map_reason(reason: ReasonCode) -> BrokerError {
    match reason {
        ReasonCode::CredentialNotFound => BrokerError::NotFound,
        ReasonCode::CredentialChanged => BrokerError::CredentialChanged,
        ReasonCode::HelperIdentityRejected
        | ReasonCode::IntegrityRejected
        | ReasonCode::ContractRejected => BrokerError::AccessDenied,
        _ => BrokerError::BackendUnavailable,
    }
}

pub(super) fn map_availability(error: CustodyError) -> CustodyAvailabilityError {
    map_availability_code(error.reason())
}

pub(super) fn map_availability_code(reason: ReasonCode) -> CustodyAvailabilityError {
    match reason {
        ReasonCode::HelperIdentityRejected
        | ReasonCode::IntegrityRejected
        | ReasonCode::ContractRejected => CustodyAvailabilityError::Denied,
        _ => CustodyAvailabilityError::Unavailable,
    }
}
