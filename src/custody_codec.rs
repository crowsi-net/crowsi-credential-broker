use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, Zeroizing};

use crate::{BrokerError, CredentialEntry, CredentialMetadata, Result, SecretRef, SecretValue};

const ENVELOPE_SCHEMA: &str = "crowsi-platform-custody-credential-v1";

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct CredentialEnvelope {
    schema: String,
    reference: String,
    revision: String,
    allowed_hosts: Vec<String>,
    secret_hex: String,
}

impl Drop for CredentialEnvelope {
    fn drop(&mut self) {
        self.secret_hex.zeroize();
    }
}

pub(crate) fn encode(entry: &CredentialEntry) -> Result<Zeroizing<String>> {
    let metadata = entry.metadata();
    let secret_hex = entry.secret_hex();
    let envelope = CredentialEnvelope {
        schema: ENVELOPE_SCHEMA.to_owned(),
        reference: metadata.reference().canonical_id(),
        revision: metadata.revision().as_str().to_owned(),
        allowed_hosts: metadata.allowed_hosts().to_vec(),
        secret_hex: secret_hex.to_string(),
    };
    serde_json::to_string(&envelope)
        .map(Zeroizing::new)
        .map_err(|_| BrokerError::InvalidEncoding)
}

pub(crate) fn decode(
    reference: &SecretRef,
    expected_revision: Option<&str>,
    payload: &str,
) -> Result<CredentialEntry> {
    let envelope: CredentialEnvelope =
        serde_json::from_str(payload).map_err(|_| BrokerError::InvalidEncoding)?;
    if envelope.schema != ENVELOPE_SCHEMA || envelope.reference != reference.canonical_id() {
        return Err(BrokerError::AccessDenied);
    }
    if expected_revision.is_some_and(|expected| expected != envelope.revision) {
        return Err(BrokerError::CredentialChanged);
    }
    let metadata = CredentialMetadata::restore(
        reference.clone(),
        envelope.allowed_hosts.clone(),
        &envelope.revision,
    )?;
    let bytes = hex::decode(&envelope.secret_hex).map_err(|_| BrokerError::InvalidEncoding)?;
    Ok(CredentialEntry::restore(metadata, SecretValue::new(bytes)?))
}

pub(crate) fn revision(reference: &SecretRef, payload: &str) -> Result<String> {
    Ok(decode(reference, None, payload)?
        .metadata()
        .revision()
        .as_str()
        .to_owned())
}

pub(crate) fn confirm_write(
    reference: &SecretRef,
    expected_revision: &str,
    expected_payload: &str,
    read_back: &str,
) -> Result<()> {
    if expected_payload != read_back {
        return Err(BrokerError::CredentialChanged);
    }
    if revision(reference, read_back)? != expected_revision {
        return Err(BrokerError::CredentialChanged);
    }
    Ok(())
}

#[cfg(test)]
#[path = "custody_codec_tests.rs"]
mod tests;
