use std::os::unix::net::{UnixListener, UnixStream};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use crowsi_credential_broker::{CredentialStore, EnrollmentClient, EnrollmentService, MemoryStore};

use crate::ipc_support;

#[test]
fn listener_enrolls_once_and_returns_metadata_only() {
    let root = tempfile::tempdir().expect("socket root");
    let socket = root.path().join("credential.sock");
    let listener = UnixListener::bind(&socket).expect("listener");
    let request = ipc_support::request();
    let store = Arc::new(MemoryStore::default());
    let verifier =
        ipc_support::StaticVerifier::allowed(ipc_support::authorization(&request, "reservation-1"));
    let service_store = Arc::clone(&store);
    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept");
        EnrollmentService::new(service_store, verifier, Duration::from_secs(1), "memory")
            .expect("service")
            .handle(&mut stream)
    });

    let mut stream = UnixStream::connect(&socket).expect("connect");
    let receipt = EnrollmentClient::new(Duration::from_secs(1))
        .exchange_after_authorization(&mut stream, &request, ipc_support::SECRET)
        .expect("receipt");
    assert_eq!(receipt.status(), "ready");
    assert!(!receipt.contains_secret_values());
    assert_eq!(receipt.credential_ref(), request.canonical_credential_ref());
    let debug_receipt = format!("{receipt:?}");
    assert!(debug_receipt.contains("[REDACTED]"));
    assert!(!debug_receipt.contains("reservation-1"));
    assert!(!debug_receipt.contains(receipt.credential_ref()));
    let encoded = serde_json::to_string(&receipt).expect("receipt JSON");
    assert!(!encoded.contains("TEST-ONLY-GITHUB-PRIVATE-KEY-MARKER"));
    server
        .join()
        .expect("server thread")
        .expect("server receipt");
    assert!(
        store
            .metadata(&request.to_secret_ref().expect("reference"))
            .is_ok()
    );
}

#[test]
fn verifier_rejection_happens_before_credential_storage() {
    let (client, mut server) = UnixStream::pair().expect("pair");
    let store = Arc::new(MemoryStore::default());
    let service_store = Arc::clone(&store);
    let task = thread::spawn(move || {
        EnrollmentService::new(
            service_store,
            ipc_support::StaticVerifier::denied(),
            Duration::from_millis(200),
            "memory",
        )
        .expect("service")
        .handle(&mut server)
    });
    drop(client);
    let error = task.join().expect("server").expect_err("denied");
    assert_eq!(
        error,
        crowsi_credential_broker::IpcError::AuthorizationRejected
    );
}
