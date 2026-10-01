use serde::Serialize;

use crate::status_document::MAX_UNIX_SECONDS;
use crate::validation::{component, display_label};
use crate::{BrokerError, CredentialStore, Result, SecretRef, SecretScope};

#[derive(Clone, Debug, Serialize)]
pub struct StatusScope {
    pub tenant: String,
    pub service: String,
    pub audience: String,
}

impl From<&SecretScope> for StatusScope {
    fn from(scope: &SecretScope) -> Self {
        Self {
            tenant: scope.tenant().to_owned(),
            service: scope.service().to_owned(),
            audience: scope.audience().to_owned(),
        }
    }
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum CredentialHealth {
    Ready,
    /// Reserved for a future factory backed by provider expiry evidence.
    Expired,
    /// Reserved for a future factory backed by revocation evidence.
    Revoked,
    /// Reserved for a future factory backed by a failed store health check.
    Unavailable,
}

#[derive(Clone, Debug, Serialize)]
pub struct CredentialStatus {
    id: String,
    label: String,
    provider: String,
    purpose: String,
    status: CredentialHealth,
    store_kind: String,
    scope: StatusScope,
    checked_at: u64,
    expires_at: Option<u64>,
    rotation_due_at: Option<u64>,
    finding_codes: Vec<String>,
}

impl CredentialStatus {
    pub fn id(&self) -> &str {
        &self.id
    }

    pub(crate) fn checked_at(&self) -> u64 {
        self.checked_at
    }

    pub(crate) fn expires_at(&self) -> Option<u64> {
        self.expires_at
    }

    pub(crate) fn rotation_due_at(&self) -> Option<u64> {
        self.rotation_due_at
    }

    pub(crate) fn finding_codes(&self) -> &[String] {
        &self.finding_codes
    }

    pub fn ready_from_store<S: CredentialStore>(
        backend: &S,
        reference: &SecretRef,
        label: &str,
        provider: &str,
        store_kind: &str,
        now: u64,
    ) -> Result<Self> {
        if now > MAX_UNIX_SECONDS {
            return Err(BrokerError::InvalidField("checked_at"));
        }
        let metadata = backend.metadata(reference)?;
        if metadata.reference() != reference {
            return Err(BrokerError::CredentialChanged);
        }
        Ok(Self {
            id: reference.canonical_id(),
            label: display_label(label)?,
            provider: component("provider", provider, 64)?,
            purpose: reference.scope().purpose().to_owned(),
            status: CredentialHealth::Ready,
            store_kind: component("store_kind", store_kind, 64)?,
            scope: StatusScope::from(reference.scope()),
            checked_at: now,
            expires_at: None,
            rotation_due_at: None,
            finding_codes: Vec::new(),
        })
    }
}

#[cfg(test)]
#[path = "status_tests.rs"]
mod tests;
