use std::os::unix::net::UnixStream;
use std::time::Duration;

use super::codec;
use super::error::{IpcError, IpcResult};
use super::receipt::{ENROLLMENT_RECEIPT_SCHEMA, EnrollmentReceiptV1};
use super::request::EnrollmentRequestV1;

pub struct EnrollmentClient {
    timeout: Duration,
}

impl EnrollmentClient {
    #[must_use]
    pub const fn new(timeout: Duration) -> Self {
        Self { timeout }
    }

    /// Exchanges enrollment frames after an external authorization handshake.
    ///
    /// The caller must use the same stream for its authorization protocol.
    /// This client never opens platform custody or supplies fallback authority.
    pub fn exchange_after_authorization(
        &self,
        stream: &mut UnixStream,
        request: &EnrollmentRequestV1,
        secret: &[u8],
    ) -> IpcResult<EnrollmentReceiptV1> {
        super::transport::configure(stream, self.timeout)?;
        let request = request.clone().validated()?;
        if request.secret_length() != u64::try_from(secret.len()).unwrap_or(u64::MAX)
            || request.secret_sha256() != super::canonical::secret_sha256(secret)
        {
            return Err(IpcError::SecretDigest);
        }
        codec::write_json(stream, &request, self.timeout)?;
        codec::write_secret(stream, secret, self.timeout)?;
        super::transport::finish_writes(stream)?;
        let receipt: EnrollmentReceiptV1 = codec::read_json(stream, self.timeout)?;
        super::transport::expect_eof(stream, self.timeout)?;
        validate_receipt(&receipt, &request)?;
        Ok(receipt)
    }
}

fn validate_receipt(receipt: &EnrollmentReceiptV1, request: &EnrollmentRequestV1) -> IpcResult<()> {
    let valid = receipt.schema == ENROLLMENT_RECEIPT_SCHEMA
        && receipt.status == "ready"
        && !receipt.contains_secret_values
        && receipt.request_id == request.request_id()
        && receipt.credential_ref == request.canonical_credential_ref()
        && !receipt.reservation_id.is_empty()
        && !receipt.store_kind.is_empty();
    valid.then_some(()).ok_or(IpcError::InvalidFrame)
}
