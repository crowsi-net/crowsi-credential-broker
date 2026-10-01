use crate::validation::normalize_host;
use crate::{BrokerError, Result, SecretRef, SecretValue};

const REVISION_BYTES: usize = 16;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CredentialRevision(String);

impl CredentialRevision {
    fn generate() -> Result<Self> {
        let mut bytes = [0_u8; REVISION_BYTES];
        getrandom::fill(&mut bytes).map_err(|_| BrokerError::EntropyUnavailable)?;
        Ok(Self(hex::encode(bytes)))
    }

    pub(crate) fn parse(value: &str) -> Result<Self> {
        let valid = value.len() == REVISION_BYTES * 2
            && value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'));
        valid
            .then(|| Self(value.to_owned()))
            .ok_or(BrokerError::InvalidField("revision"))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CredentialMetadata {
    reference: SecretRef,
    allowed_hosts: Vec<String>,
    revision: CredentialRevision,
}

impl CredentialMetadata {
    pub(crate) fn restore(
        reference: SecretRef,
        allowed_hosts: impl IntoIterator<Item = String>,
        revision: &str,
    ) -> Result<Self> {
        let mut hosts = allowed_hosts
            .into_iter()
            .map(|host| normalize_host(&host))
            .collect::<Result<Vec<_>>>()?;
        hosts.sort();
        hosts.dedup();
        if hosts.is_empty() {
            return Err(BrokerError::InvalidField("allowed_hosts"));
        }
        Ok(Self {
            reference,
            allowed_hosts: hosts,
            revision: CredentialRevision::parse(revision)?,
        })
    }

    pub fn reference(&self) -> &SecretRef {
        &self.reference
    }

    pub fn allowed_hosts(&self) -> &[String] {
        &self.allowed_hosts
    }

    pub fn revision(&self) -> &CredentialRevision {
        &self.revision
    }
}

pub struct CredentialEntry {
    metadata: CredentialMetadata,
    secret: SecretValue,
}

impl CredentialEntry {
    pub fn new(
        reference: SecretRef,
        allowed_hosts: impl IntoIterator<Item = String>,
        secret: SecretValue,
    ) -> Result<Self> {
        let revision = CredentialRevision::generate()?;
        Ok(Self {
            metadata: CredentialMetadata::restore(reference, allowed_hosts, revision.as_str())?,
            secret,
        })
    }

    pub(crate) fn restore(metadata: CredentialMetadata, secret: SecretValue) -> Self {
        Self { metadata, secret }
    }

    pub fn metadata(&self) -> CredentialMetadata {
        self.metadata.clone()
    }

    pub fn into_secret(self) -> SecretValue {
        self.secret
    }

    pub(crate) fn secret_hex(&self) -> zeroize::Zeroizing<String> {
        zeroize::Zeroizing::new(self.secret.expose(|value| hex::encode(value)))
    }

    pub(crate) fn duplicate(&self) -> Self {
        Self {
            metadata: self.metadata.clone(),
            secret: self.secret.duplicate(),
        }
    }
}
