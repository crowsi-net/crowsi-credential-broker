use std::io::Write;
use std::net::Shutdown;
use std::os::unix::net::UnixStream;
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use crowsi_credential_broker::{EnrollmentService, IpcError, MemoryStore};

use crate::ipc_support;

#[test]
fn oversized_unknown_partial_and_trailing_frames_fail_closed() {
    assert_eq!(raw(&65_537_u32.to_be_bytes()), IpcError::FrameOversized);

    let mut unknown = serde_json::to_value(ipc_support::request()).expect("JSON");
    unknown["unexpected"] = true.into();
    assert_eq!(
        metadata_only(&serde_json::to_vec(&unknown).expect("JSON")),
        IpcError::InvalidFrame
    );

    assert_eq!(raw(&[0, 0, 0, 10, b'{']), IpcError::PartialFrame);

    let request = serde_json::to_vec(&ipc_support::request()).expect("JSON");
    let mut oversized_secret = frame(&request);
    oversized_secret.extend(65_537_u32.to_be_bytes());
    assert_eq!(raw(&oversized_secret), IpcError::FrameOversized);

    let mut partial_secret = frame(&request);
    partial_secret.extend([0, 0, 0, 10, b's']);
    assert_eq!(raw(&partial_secret), IpcError::PartialFrame);

    let mut bytes = frame(&request);
    bytes.extend(frame(ipc_support::SECRET));
    bytes.push(b'!');
    assert_eq!(raw(&bytes), IpcError::TrailingData);
}

#[test]
fn idle_peer_hits_the_read_deadline() {
    let (client, mut server) = UnixStream::pair().expect("pair");
    let request = ipc_support::request();
    let mut service = EnrollmentService::new(
        Arc::new(MemoryStore::default()),
        ipc_support::StaticVerifier::allowed(ipc_support::authorization(
            &request,
            "reservation-timeout",
        )),
        Duration::from_millis(20),
        "memory",
    )
    .expect("service");
    let task = thread::spawn(move || service.handle(&mut server));
    let error = task.join().expect("server").expect_err("timeout");
    drop(client);
    assert_eq!(error, IpcError::Timeout);
}

fn metadata_only(metadata: &[u8]) -> IpcError {
    raw(&frame(metadata))
}

fn raw(bytes: &[u8]) -> IpcError {
    let (mut client, mut server) = UnixStream::pair().expect("pair");
    let request = ipc_support::request();
    let task = thread::spawn(move || {
        EnrollmentService::new(
            Arc::new(MemoryStore::default()),
            ipc_support::StaticVerifier::allowed(ipc_support::authorization(
                &request,
                "reservation-frame",
            )),
            Duration::from_millis(100),
            "memory",
        )
        .expect("service")
        .handle(&mut server)
    });
    client.write_all(bytes).expect("write");
    client.shutdown(Shutdown::Write).expect("finish request");
    task.join().expect("server").expect_err("invalid frame")
}

fn frame(value: &[u8]) -> Vec<u8> {
    let mut result = u32::try_from(value.len())
        .expect("bounded")
        .to_be_bytes()
        .to_vec();
    result.extend(value);
    result
}
