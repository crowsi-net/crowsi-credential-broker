use std::os::unix::net::UnixStream;
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use crowsi_credential_broker::{
    BrokerError, CredentialEntry, CredentialMetadata, CredentialStore, EnrollmentClient,
    EnrollmentService, IpcError, MemoryStore, Result, SecretRef,
};

use crate::ipc_support;

struct FailingStore;

impl CredentialStore for FailingStore {
    fn put(&self, _entry: CredentialEntry) -> Result<()> {
        Err(BrokerError::BackendUnavailable)
    }

    fn metadata(&self, _reference: &SecretRef) -> Result<CredentialMetadata> {
        Err(BrokerError::BackendUnavailable)
    }

    fn get(&self, _reference: &SecretRef, _revision: &str) -> Result<CredentialEntry> {
        Err(BrokerError::BackendUnavailable)
    }

    fn delete(&self, _reference: &SecretRef) -> Result<()> {
        Err(BrokerError::BackendUnavailable)
    }
}

#[test]
fn store_failure_returns_no_receipt_or_secret_material() {
    let request = ipc_support::request();
    let verifier =
        ipc_support::StaticVerifier::allowed(ipc_support::authorization(&request, "reservation-1"));
    let (mut client, mut server) = UnixStream::pair().expect("pair");
    let task = thread::spawn(move || {
        EnrollmentService::new(
            Arc::new(FailingStore),
            verifier,
            Duration::from_millis(200),
            "windows-dpapi-user",
        )
        .expect("service")
        .handle(&mut server)
    });
    let _ = EnrollmentClient::new(Duration::from_millis(200)).exchange_after_authorization(
        &mut client,
        &request,
        ipc_support::SECRET,
    );
    let error = task.join().expect("server").expect_err("store failure");
    assert_eq!(error, IpcError::StoreUnavailable);
    assert!(
        !error
            .to_string()
            .contains("TEST-ONLY-GITHUB-PRIVATE-KEY-MARKER")
    );
}

#[derive(Default)]
struct RereadFailStore {
    inner: MemoryStore,
}

impl CredentialStore for RereadFailStore {
    fn put(&self, entry: CredentialEntry) -> Result<()> {
        self.inner.put(entry)
    }

    fn metadata(&self, _reference: &SecretRef) -> Result<CredentialMetadata> {
        Err(BrokerError::BackendUnavailable)
    }

    fn get(&self, reference: &SecretRef, revision: &str) -> Result<CredentialEntry> {
        self.inner.get(reference, revision)
    }

    fn delete(&self, reference: &SecretRef) -> Result<()> {
        self.inner.delete(reference)
    }
}

#[test]
fn successful_put_without_metadata_reread_emits_no_receipt() {
    let request = ipc_support::request();
    let verifier = ipc_support::StaticVerifier::allowed(ipc_support::authorization(
        &request,
        "reservation-reread",
    ));
    let (mut client, mut server) = UnixStream::pair().expect("pair");
    let task = thread::spawn(move || {
        EnrollmentService::new(
            Arc::new(RereadFailStore::default()),
            verifier,
            Duration::from_millis(200),
            "memory",
        )
        .expect("service")
        .handle(&mut server)
    });
    let client_result = EnrollmentClient::new(Duration::from_millis(200))
        .exchange_after_authorization(&mut client, &request, ipc_support::SECRET);
    drop(client);
    let error = task.join().expect("server").expect_err("reread failure");
    assert!(client_result.is_err());
    assert_eq!(error, IpcError::StoreUnavailable);
}
