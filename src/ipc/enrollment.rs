use std::os::unix::net::UnixStream;
use std::sync::Arc;
use std::time::Duration;

use crate::validation::component;
use crate::{CredentialEntry, CredentialStore, SecretValue};

use super::authorization::AuthorizationVerifier;
use super::canonical::{credential_resource, enrollment_body_sha256, secret_sha256};
use super::codec;
use super::error::{IpcError, IpcResult};
use super::receipt::{ENROLLMENT_RECEIPT_SCHEMA, EnrollmentReceiptV1};
use super::request::EnrollmentRequestV1;

const ACTION: &str = "credential-enroll";

pub struct EnrollmentService<S, V> {
    store: Arc<S>,
    verifier: V,
    timeout: Duration,
    store_kind: String,
}

impl<S: CredentialStore, V: AuthorizationVerifier> EnrollmentService<S, V> {
    pub fn new(store: Arc<S>, verifier: V, timeout: Duration, store_kind: &str) -> IpcResult<Self> {
        if timeout.is_zero() {
            return Err(IpcError::Timeout);
        }
        let store_kind =
            component("store_kind", store_kind, 64).map_err(|_| IpcError::InvalidFrame)?;
        Ok(Self {
            store,
            verifier,
            timeout,
            store_kind,
        })
    }

    /// Authorizes, consumes, and stores one enrollment on the same stream.
    pub fn handle(&mut self, stream: &mut UnixStream) -> IpcResult<EnrollmentReceiptV1> {
        super::transport::configure(stream, self.timeout)?;
        let authorization = self.verifier.verify(stream)?;
        let request: EnrollmentRequestV1 = codec::read_json(stream, self.timeout)?;
        let request = request.validated()?;
        validate_authorization(&authorization, &request)?;
        let secret = codec::read_secret(stream, self.timeout)?;
        super::transport::expect_eof(stream, self.timeout)?;
        if request.secret_length() != u64::try_from(secret.len()).unwrap_or(u64::MAX)
            || request.secret_sha256() != secret_sha256(&secret)
        {
            return Err(IpcError::SecretDigest);
        }
        let reference = request.to_secret_ref()?;
        let entry = CredentialEntry::new(
            reference.clone(),
            request.allowed_hosts().to_vec(),
            SecretValue::from_zeroizing(secret).map_err(|_| IpcError::InvalidFrame)?,
        )
        .map_err(|_| IpcError::InvalidFrame)?;
        self.store
            .put(entry)
            .map_err(|_| IpcError::StoreUnavailable)?;
        let metadata = self
            .store
            .metadata(&reference)
            .map_err(|_| IpcError::StoreUnavailable)?;
        if metadata.reference() != &reference || metadata.allowed_hosts() != request.allowed_hosts()
        {
            return Err(IpcError::StoreUnavailable);
        }
        let receipt = EnrollmentReceiptV1 {
            schema: ENROLLMENT_RECEIPT_SCHEMA.into(),
            request_id: request.request_id().into(),
            reservation_id: authorization.reservation_id().into(),
            credential_ref: reference.canonical_id(),
            store_kind: self.store_kind.clone(),
            status: "ready".into(),
            contains_secret_values: false,
        };
        codec::write_json(stream, &receipt, self.timeout)?;
        super::transport::finish_writes(stream)?;
        Ok(receipt)
    }
}

fn validate_authorization(
    authorization: &super::VerifiedAuthorization,
    request: &EnrollmentRequestV1,
) -> IpcResult<()> {
    let expected_resource = credential_resource(request.credential())?;
    let expected_body = enrollment_body_sha256(request)?;
    let exact = authorization.action() == ACTION
        && authorization.resource() == expected_resource
        && authorization.body_sha256() == expected_body;
    exact.then_some(()).ok_or(IpcError::BindingRejected)
}
