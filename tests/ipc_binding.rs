use std::os::unix::net::UnixStream;
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use crowsi_credential_broker::{
    BindingField, EnrollmentClient, EnrollmentService, IpcError, LeaseBinding, MemoryStore,
    RevocationSelector, VerifiedAuthorization,
};

use crate::ipc_support;

#[test]
fn secret_and_authorization_digests_are_exactly_bound() {
    let request = ipc_support::request();
    let mut wrong = ipc_support::SECRET.to_vec();
    wrong.push(b'!');
    let (mut isolated, _peer) = UnixStream::pair().expect("preflight pair");
    assert_eq!(
        EnrollmentClient::new(Duration::from_millis(20))
            .exchange_after_authorization(&mut isolated, &request, &wrong)
            .expect_err("client digest preflight"),
        IpcError::SecretDigest
    );
    assert_eq!(
        exchange(
            request.clone(),
            ipc_support::authorization(&request, "reservation-1"),
            &wrong
        ),
        IpcError::SecretDigest
    );
}

#[test]
fn forged_authorization_body_digest_is_rejected() {
    let request = ipc_support::request();
    let valid = ipc_support::authorization(&request, "reservation-2");
    let forged = VerifiedAuthorization::new(
        valid.subject_id(),
        valid.device_id(),
        valid.workload_id(),
        valid.reservation_id(),
        valid.resource(),
        valid.action(),
        &format!("sha256:{}", "0".repeat(64)),
        valid.binding().clone(),
    )
    .expect("well-formed forged authorization");
    assert_eq!(
        exchange(request, forged, ipc_support::SECRET),
        IpcError::BindingRejected
    );
}

#[test]
fn verified_peer_claims_must_match_the_lease_binding() {
    let request = ipc_support::request();
    let valid = ipc_support::authorization(&request, "reservation-binding");
    let mismatched = LeaseBinding::new(
        valid.subject_id(),
        "different-device",
        valid.workload_id(),
        "grant-enroll",
        valid.resource(),
        valid.action(),
        "proof-enrollment",
    )
    .expect("mismatched binding contract");
    let result = VerifiedAuthorization::new(
        valid.subject_id(),
        valid.device_id(),
        valid.workload_id(),
        valid.reservation_id(),
        valid.resource(),
        valid.action(),
        valid.body_sha256(),
        mismatched,
    );
    assert_eq!(
        result.expect_err("binding denial"),
        IpcError::BindingRejected
    );
}

#[test]
fn authorization_debug_output_is_redacted() {
    let request = ipc_support::request();
    let authorization = ipc_support::authorization(&request, "reservation-sensitive");
    let selector =
        RevocationSelector::new(BindingField::Subject, "subject-sensitive").expect("selector");
    let rendered = format!(
        "{authorization:?} {:?} {selector:?} {request:?} {:?}",
        authorization.binding(),
        request.credential()
    );
    assert!(rendered.contains("[REDACTED]"));
    for value in [
        "subject-coela",
        "device-workstation",
        "reservation-sensitive",
        "subject-sensitive",
        "github-app",
        "coela-github-app",
        request.secret_sha256(),
        authorization.body_sha256(),
    ] {
        assert!(!rendered.contains(value));
    }
}

fn exchange(
    request: crowsi_credential_broker::EnrollmentRequestV1,
    authorization: VerifiedAuthorization,
    secret: &[u8],
) -> IpcError {
    let (mut client, mut server) = UnixStream::pair().expect("pair");
    let task = thread::spawn(move || {
        EnrollmentService::new(
            Arc::new(MemoryStore::default()),
            ipc_support::StaticVerifier::allowed(authorization),
            Duration::from_millis(200),
            "memory",
        )
        .expect("service")
        .handle(&mut server)
    });
    let client_result = EnrollmentClient::new(Duration::from_millis(200))
        .exchange_after_authorization(&mut client, &request, secret);
    drop(client);
    let server_result = task.join().expect("server");
    if matches!(client_result, Err(IpcError::SecretDigest)) {
        return IpcError::SecretDigest;
    }
    match (client_result, server_result) {
        (_, Err(error)) => error,
        (Err(error), _) => error,
        _ => panic!("exchange unexpectedly succeeded"),
    }
}
