use std::collections::HashSet;

use serde::Serialize;

use crate::status::CredentialStatus;
use crate::validation::valid_finding_code;
use crate::{BrokerError, Result};

pub const CREDENTIAL_STATUS_SCHEMA: &str = "crowsi://credentials/status/v1";
pub const MAX_STATUS_CREDENTIALS: usize = 1_024;
pub const MAX_FINDING_CODES: usize = 64;
pub const MAX_FINDING_CODE_LENGTH: usize = 128;
pub const MAX_UNIX_SECONDS: u64 = 253_402_300_799;

#[derive(Clone, Debug, Serialize)]
pub struct CredentialStatusDocument {
    schema: &'static str,
    generated_at: u64,
    external_actions: bool,
    contains_secret_values: bool,
    credential_count: usize,
    credentials: Vec<CredentialStatus>,
}

impl CredentialStatusDocument {
    pub fn new(generated_at: u64, credentials: Vec<CredentialStatus>) -> Result<Self> {
        validate(generated_at, &credentials)?;
        Ok(Self {
            schema: CREDENTIAL_STATUS_SCHEMA,
            generated_at,
            external_actions: false,
            contains_secret_values: false,
            credential_count: credentials.len(),
            credentials,
        })
    }
}

fn validate(generated_at: u64, credentials: &[CredentialStatus]) -> Result<()> {
    if generated_at > MAX_UNIX_SECONDS {
        return Err(BrokerError::InvalidField("generated_at"));
    }
    if credentials.len() > MAX_STATUS_CREDENTIALS {
        return Err(BrokerError::InvalidField("credentials"));
    }
    if credentials
        .iter()
        .any(|status| status.checked_at() > MAX_UNIX_SECONDS)
    {
        return Err(BrokerError::InvalidField("checked_at"));
    }
    if credentials.iter().any(|status| {
        status
            .expires_at()
            .is_some_and(|value| value > MAX_UNIX_SECONDS)
    }) {
        return Err(BrokerError::InvalidField("expires_at"));
    }
    if credentials.iter().any(|status| {
        status
            .rotation_due_at()
            .is_some_and(|value| value > MAX_UNIX_SECONDS)
    }) {
        return Err(BrokerError::InvalidField("rotation_due_at"));
    }
    if credentials
        .iter()
        .any(|status| status.finding_codes().len() > MAX_FINDING_CODES)
    {
        return Err(BrokerError::InvalidField("finding_codes"));
    }
    if credentials
        .iter()
        .flat_map(CredentialStatus::finding_codes)
        .any(|code| !valid_finding_code(code))
    {
        return Err(BrokerError::InvalidField("finding_code"));
    }
    let mut ids = HashSet::with_capacity(credentials.len());
    if credentials.iter().any(|status| !ids.insert(status.id())) {
        return Err(BrokerError::InvalidField("credential_ids"));
    }
    Ok(())
}
