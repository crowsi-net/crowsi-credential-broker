use std::os::unix::net::UnixStream;
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use crowsi_credential_broker::{EnrollmentClient, EnrollmentService, IpcError, MemoryStore};

use crate::ipc_support;

#[test]
fn verifier_rejects_a_replayed_reservation_before_a_second_store() {
    let request = ipc_support::request();
    let verifier = ipc_support::ReplayVerifier::new(ipc_support::authorization(
        &request,
        "reservation-replay",
    ));
    let (mut first_client, mut first_server) = UnixStream::pair().expect("first pair");
    let (mut replay_client, mut replay_server) = UnixStream::pair().expect("replay pair");
    let task = thread::spawn(move || {
        let mut service = EnrollmentService::new(
            Arc::new(MemoryStore::default()),
            verifier,
            Duration::from_millis(200),
            "memory",
        )
        .expect("service");
        let first = service.handle(&mut first_server);
        let replay = service.handle(&mut replay_server);
        (first, replay)
    });

    EnrollmentClient::new(Duration::from_millis(200))
        .exchange_after_authorization(&mut first_client, &request, ipc_support::SECRET)
        .expect("first enrollment");
    drop(first_client);
    let replay = EnrollmentClient::new(Duration::from_millis(200)).exchange_after_authorization(
        &mut replay_client,
        &request,
        ipc_support::SECRET,
    );
    drop(replay_client);
    let (first, server_replay) = task.join().expect("server");
    first.expect("first server enrollment");
    assert!(replay.is_err());
    assert_eq!(
        server_replay.expect_err("replay denial"),
        IpcError::AuthorizationRejected
    );
}
