use std::{sync::Mutex, time::Duration};

use crowsi_windows_custody_provider::{CustodyClient, Metadata, PROVIDER_KIND, ResponseState};
use sha2::{Digest, Sha256};

use crate::custody_codec::{confirm_write, decode, encode};
use crate::{
    BrokerError, CredentialEntry, CredentialMetadata, CredentialStore, CustodyAvailabilityError,
    PlatformCustodyConfigV1, Result, SecretRef,
};

#[path = "platform_custody_store_support.rs"]
mod support;
use support::{
    map_availability, map_availability_code, map_error, map_reason, request_id, require_ready,
};

pub struct PlatformCustodyStore {
    client: CustodyClient,
    gate: Mutex<()>,
}

impl PlatformCustodyStore {
    pub fn new(config: &PlatformCustodyConfigV1) -> Result<Self> {
        let client = config
            .clone()
            .into_client(Duration::from_secs(10))
            .map_err(map_error)?;
        Ok(Self {
            client,
            gate: Mutex::new(()),
        })
    }

    pub fn require_available(&self) -> Result<()> {
        self.availability().map_err(|error| match error {
            CustodyAvailabilityError::Denied => BrokerError::BackendDenied,
            CustodyAvailabilityError::Unavailable => BrokerError::BackendUnavailable,
        })
    }

    pub fn availability(&self) -> std::result::Result<(), CustodyAvailabilityError> {
        let request_id = request_id().map_err(|_| CustodyAvailabilityError::Unavailable)?;
        let response = self.client.doctor(request_id).map_err(map_availability)?;
        match &response.response.result {
            ResponseState::Ready { .. } => Ok(()),
            ResponseState::Error { reason_code } => Err(map_availability_code(*reason_code)),
        }
    }

    fn provider_metadata(&self, reference: &SecretRef) -> Result<Metadata> {
        let slot = self.slot(reference);
        let response = self
            .client
            .metadata(request_id()?, &slot)
            .map_err(map_error)?;
        match &response.response.result {
            ResponseState::Ready {
                metadata: Some(value),
                secret_follows: false,
                ..
            } if value.credential_id == slot && value.provider_kind == PROVIDER_KIND => {
                Ok(value.clone())
            }
            ResponseState::Error { reason_code } => Err(map_reason(*reason_code)),
            _ => Err(BrokerError::InvalidEncoding),
        }
    }

    fn payload(&self, reference: &SecretRef) -> Result<zeroize::Zeroizing<Vec<u8>>> {
        let metadata = self.provider_metadata(reference)?;
        let response = self
            .client
            .get(request_id()?, self.slot(reference), metadata.revision)
            .map_err(map_error)?;
        match &response.response.result {
            ResponseState::Ready {
                secret_follows: true,
                ..
            } => response.expose_secret(|secret| {
                secret
                    .map(|value| zeroize::Zeroizing::new(value.to_vec()))
                    .ok_or(BrokerError::InvalidEncoding)
            }),
            ResponseState::Error { reason_code } => Err(map_reason(*reason_code)),
            _ => Err(BrokerError::InvalidEncoding),
        }
    }

    fn slot(&self, reference: &SecretRef) -> String {
        let digest = Sha256::digest(reference.canonical_id().as_bytes());
        hex::encode(digest)
    }
}

impl CredentialStore for PlatformCustodyStore {
    fn put(&self, entry: CredentialEntry) -> Result<()> {
        let _guard = self
            .gate
            .lock()
            .map_err(|_| BrokerError::BackendUnavailable)?;
        let metadata = entry.metadata();
        let reference = metadata.reference();
        let prior = match self.provider_metadata(reference) {
            Ok(value) => Some(value.revision),
            Err(BrokerError::NotFound) => None,
            Err(error) => return Err(error),
        };
        let payload = encode(&entry)?;
        let response = self
            .client
            .put(
                request_id()?,
                self.slot(reference),
                prior,
                payload.as_bytes(),
            )
            .map_err(map_error)?;
        require_ready(&response.response.result)?;
        let confirmed = self.payload(reference)?;
        let confirmed =
            std::str::from_utf8(&confirmed).map_err(|_| BrokerError::InvalidEncoding)?;
        confirm_write(reference, metadata.revision().as_str(), &payload, confirmed)
    }

    fn metadata(&self, reference: &SecretRef) -> Result<CredentialMetadata> {
        let payload = self.payload(reference)?;
        let payload = std::str::from_utf8(&payload).map_err(|_| BrokerError::InvalidEncoding)?;
        Ok(decode(reference, None, payload)?.metadata())
    }

    fn get(&self, reference: &SecretRef, expected_revision: &str) -> Result<CredentialEntry> {
        let payload = self.payload(reference)?;
        let payload = std::str::from_utf8(&payload).map_err(|_| BrokerError::InvalidEncoding)?;
        decode(reference, Some(expected_revision), payload)
    }

    fn delete(&self, reference: &SecretRef) -> Result<()> {
        let _guard = self
            .gate
            .lock()
            .map_err(|_| BrokerError::BackendUnavailable)?;
        let metadata = self.provider_metadata(reference)?;
        let response = self
            .client
            .delete(request_id()?, self.slot(reference), metadata.revision)
            .map_err(map_error)?;
        require_ready(&response.response.result)
    }
}
