use std::fmt;

use serde::Serialize;
use zeroize::Zeroize;

use crate::{BrokerError, Result, SecretRef, SecretValue};

pub struct LeaseToken(pub(crate) [u8; 32]);

impl fmt::Debug for LeaseToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("LeaseToken([REDACTED])")
    }
}

impl Drop for LeaseToken {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

#[derive(Clone, Debug)]
pub(crate) enum AuditAction {
    LeaseIssued,
    CredentialUsed,
    LeaseRevoked,
}

impl AuditAction {
    fn as_str(&self) -> &'static str {
        match self {
            Self::LeaseIssued => "lease-issued",
            Self::CredentialUsed => "credential-used",
            Self::LeaseRevoked => "lease-revoked",
        }
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct LeaseReceipt {
    pub event_id: String,
    pub action: String,
    pub credential_ref: String,
    pub tenant: String,
    pub service: String,
    pub purpose: String,
    pub audience: String,
    pub host: String,
    pub occurred_at: u64,
    pub expires_at: u64,
}

pub struct LeaseGrant {
    pub(crate) token: LeaseToken,
    pub receipt: LeaseReceipt,
}

impl LeaseGrant {
    pub fn token(&self) -> &LeaseToken {
        &self.token
    }
}

pub struct SecretUse {
    pub secret: SecretValue,
    pub receipt: LeaseReceipt,
}

pub(crate) fn receipt(
    action: AuditAction,
    reference: &SecretRef,
    host: &str,
    now: u64,
    expires_at: u64,
) -> Result<LeaseReceipt> {
    Ok(LeaseReceipt {
        event_id: hex::encode(random_array::<16>()?),
        action: action.as_str().to_owned(),
        credential_ref: reference.canonical_id(),
        tenant: reference.scope().tenant().to_owned(),
        service: reference.scope().service().to_owned(),
        purpose: reference.scope().purpose().to_owned(),
        audience: reference.scope().audience().to_owned(),
        host: host.to_owned(),
        occurred_at: now,
        expires_at,
    })
}

pub(crate) fn random_array<const N: usize>() -> Result<[u8; N]> {
    let mut bytes = [0_u8; N];
    getrandom::fill(&mut bytes).map_err(|_| BrokerError::EntropyUnavailable)?;
    Ok(bytes)
}
