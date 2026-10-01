use std::fmt;

use serde::{Deserialize, Serialize};

use crate::{SecretRef, SecretScope};

use super::error::{IpcError, IpcResult};

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CredentialReferenceV1 {
    id: String,
    tenant: String,
    service: String,
    purpose: String,
    audience: String,
}

impl fmt::Debug for CredentialReferenceV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("CredentialReferenceV1([REDACTED])")
    }
}

impl CredentialReferenceV1 {
    pub fn new(
        id: &str,
        tenant: &str,
        service: &str,
        purpose: &str,
        audience: &str,
    ) -> IpcResult<Self> {
        let value = Self {
            id: id.into(),
            tenant: tenant.into(),
            service: service.into(),
            purpose: purpose.into(),
            audience: audience.into(),
        };
        value.to_secret_ref().map(|_| value)
    }

    pub fn to_secret_ref(&self) -> IpcResult<SecretRef> {
        let scope = SecretScope::new(&self.tenant, &self.service, &self.purpose, &self.audience)
            .map_err(|_| IpcError::InvalidFrame)?;
        SecretRef::new(&self.id, scope).map_err(|_| IpcError::InvalidFrame)
    }
}
