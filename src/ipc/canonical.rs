use sha2::{Digest, Sha256};

use super::error::{IpcError, IpcResult};
use super::reference::CredentialReferenceV1;
use super::request::EnrollmentRequestV1;

pub fn enrollment_body_sha256(request: &EnrollmentRequestV1) -> IpcResult<String> {
    let normalized = request.clone().validated()?;
    let encoded = serde_json::to_vec(&normalized).map_err(|_| IpcError::InvalidFrame)?;
    Ok(domain_digest(
        b"crowsi:credential-enrollment-body:v1\0",
        &encoded,
    ))
}

pub fn credential_resource(reference: &CredentialReferenceV1) -> IpcResult<String> {
    let canonical = reference.to_secret_ref()?.canonical_id();
    Ok(format!(
        "credential-{}",
        &domain_digest(b"crowsi:credential-resource:v1\0", canonical.as_bytes())[7..]
    ))
}

pub(crate) fn secret_sha256(secret: &[u8]) -> String {
    domain_digest(b"crowsi:credential-secret:v1\0", secret)
}

fn domain_digest(domain: &[u8], value: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update(value);
    format!("sha256:{:x}", hasher.finalize())
}
