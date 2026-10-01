use std::fmt;

use serde::{Deserialize, Serialize};

use crate::SecretRef;
use crate::validation::{component, display_label, normalize_host};

use super::canonical::secret_sha256;
use super::error::{IpcError, IpcResult};
use super::reference::CredentialReferenceV1;

pub const ENROLLMENT_REQUEST_SCHEMA: &str = "crowsi://credentials/ipc/enrollment-request/v1";

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EnrollmentRequestV1 {
    schema: String,
    request_id: String,
    credential: CredentialReferenceV1,
    label: String,
    provider: String,
    allowed_hosts: Vec<String>,
    secret_length: u64,
    secret_sha256: String,
}

impl fmt::Debug for EnrollmentRequestV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("EnrollmentRequestV1([REDACTED])")
    }
}

impl EnrollmentRequestV1 {
    pub fn new<I, H>(
        request_id: &str,
        credential: CredentialReferenceV1,
        label: &str,
        provider: &str,
        allowed_hosts: I,
        secret: &[u8],
    ) -> IpcResult<Self>
    where
        I: IntoIterator<Item = H>,
        H: AsRef<str>,
    {
        Self {
            schema: ENROLLMENT_REQUEST_SCHEMA.into(),
            request_id: request_id.into(),
            credential,
            label: label.into(),
            provider: provider.into(),
            allowed_hosts: allowed_hosts
                .into_iter()
                .map(|host| host.as_ref().into())
                .collect(),
            secret_length: u64::try_from(secret.len()).map_err(|_| IpcError::FrameOversized)?,
            secret_sha256: secret_sha256(secret),
        }
        .validated()
    }

    /// Builds the request from a digest calculated before the secret crosses
    /// the browser/native boundary.
    ///
    /// # Errors
    ///
    /// Rejects invalid metadata with the same rules as [`Self::new`].
    pub fn from_secret_metadata<I, H>(
        request_id: &str,
        credential: CredentialReferenceV1,
        label: &str,
        provider: &str,
        allowed_hosts: I,
        secret_length: u64,
        secret_sha256: &str,
    ) -> IpcResult<Self>
    where
        I: IntoIterator<Item = H>,
        H: AsRef<str>,
    {
        Self {
            schema: ENROLLMENT_REQUEST_SCHEMA.into(),
            request_id: request_id.into(),
            credential,
            label: label.into(),
            provider: provider.into(),
            allowed_hosts: allowed_hosts
                .into_iter()
                .map(|host| host.as_ref().into())
                .collect(),
            secret_length,
            secret_sha256: secret_sha256.into(),
        }
        .validated()
    }

    pub(crate) fn validated(mut self) -> IpcResult<Self> {
        let invalid = self.schema != ENROLLMENT_REQUEST_SCHEMA
            || self.allowed_hosts.is_empty()
            || self.allowed_hosts.len() > 16
            || !(1..=65_536).contains(&self.secret_length)
            || !valid_digest(&self.secret_sha256);
        if invalid {
            return Err(IpcError::InvalidFrame);
        }
        component("request_id", &self.request_id, 96).map_err(|_| IpcError::InvalidFrame)?;
        component("provider", &self.provider, 64).map_err(|_| IpcError::InvalidFrame)?;
        display_label(&self.label).map_err(|_| IpcError::InvalidFrame)?;
        self.credential.to_secret_ref()?;
        self.allowed_hosts = self
            .allowed_hosts
            .iter()
            .map(|host| normalize_host(host))
            .collect::<crate::Result<Vec<_>>>()
            .map_err(|_| IpcError::InvalidFrame)?;
        self.allowed_hosts.sort();
        self.allowed_hosts.dedup();
        Ok(self)
    }

    pub fn credential(&self) -> &CredentialReferenceV1 {
        &self.credential
    }

    pub fn request_id(&self) -> &str {
        &self.request_id
    }

    pub fn allowed_hosts(&self) -> &[String] {
        &self.allowed_hosts
    }

    pub const fn secret_length(&self) -> u64 {
        self.secret_length
    }

    pub fn secret_sha256(&self) -> &str {
        &self.secret_sha256
    }

    pub fn canonical_credential_ref(&self) -> String {
        self.to_secret_ref()
            .map_or_else(|_| String::new(), |value| value.canonical_id())
    }

    pub fn to_secret_ref(&self) -> IpcResult<SecretRef> {
        self.credential.to_secret_ref()
    }
}

fn valid_digest(value: &str) -> bool {
    value.len() == 71
        && value.starts_with("sha256:")
        && value[7..]
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}
