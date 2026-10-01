use std::io::{ErrorKind, Read, Write};
use std::os::unix::net::UnixStream;
use std::time::{Duration, Instant};

use nix::poll::PollFlags;
use serde::Serialize;
use serde::de::DeserializeOwned;
use zeroize::Zeroizing;

use super::error::{IpcError, IpcResult};
use super::transport::{map_io, wait};

pub(crate) const MAX_FRAME_BYTES: usize = 65_536;

pub(crate) fn read_json<T: DeserializeOwned>(
    stream: &mut UnixStream,
    timeout: Duration,
) -> IpcResult<T> {
    let bytes = read_bytes(stream, false, timeout)?;
    serde_json::from_slice(&bytes).map_err(|_| IpcError::InvalidFrame)
}

pub(crate) fn write_json<T: Serialize>(
    stream: &mut UnixStream,
    value: &T,
    timeout: Duration,
) -> IpcResult<()> {
    let encoded = serde_json::to_vec(value).map_err(|_| IpcError::InvalidFrame)?;
    write_bytes(stream, &encoded, timeout)
}

pub(crate) fn read_secret(
    stream: &mut UnixStream,
    timeout: Duration,
) -> IpcResult<Zeroizing<Vec<u8>>> {
    read_bytes(stream, true, timeout).map(Zeroizing::new)
}

pub(crate) fn write_secret(
    stream: &mut UnixStream,
    secret: &[u8],
    timeout: Duration,
) -> IpcResult<()> {
    write_bytes(stream, secret, timeout)
}

fn read_bytes(stream: &mut UnixStream, secret: bool, timeout: Duration) -> IpcResult<Vec<u8>> {
    let deadline = Instant::now() + timeout;
    let mut length = [0_u8; 4];
    read_exact(stream, &mut length, deadline)?;
    let length =
        usize::try_from(u32::from_be_bytes(length)).map_err(|_| IpcError::FrameOversized)?;
    if length == 0 {
        return Err(IpcError::InvalidFrame);
    }
    if length > MAX_FRAME_BYTES {
        return Err(IpcError::FrameOversized);
    }
    let mut value = vec![0_u8; length];
    if let Err(error) = read_exact(stream, &mut value, deadline) {
        if secret {
            zeroize::Zeroize::zeroize(&mut value);
        }
        return Err(error);
    }
    Ok(value)
}

fn write_bytes(stream: &mut UnixStream, value: &[u8], timeout: Duration) -> IpcResult<()> {
    if value.is_empty() {
        return Err(IpcError::InvalidFrame);
    }
    if value.len() > MAX_FRAME_BYTES {
        return Err(IpcError::FrameOversized);
    }
    let length = u32::try_from(value.len()).map_err(|_| IpcError::FrameOversized)?;
    let deadline = Instant::now() + timeout;
    write_all(stream, &length.to_be_bytes(), deadline)?;
    write_all(stream, value, deadline)
}

fn read_exact(stream: &mut UnixStream, mut value: &mut [u8], deadline: Instant) -> IpcResult<()> {
    while !value.is_empty() {
        match stream.read(value) {
            Ok(0) => return Err(IpcError::PartialFrame),
            Ok(count) => value = &mut value[count..],
            Err(error) if error.kind() == ErrorKind::WouldBlock => {
                wait(stream, PollFlags::POLLIN, deadline)?;
            }
            Err(error) => return Err(map_io(error)),
        }
    }
    Ok(())
}

fn write_all(stream: &mut UnixStream, mut value: &[u8], deadline: Instant) -> IpcResult<()> {
    while !value.is_empty() {
        match stream.write(value) {
            Ok(0) => return Err(IpcError::TransportUnavailable),
            Ok(count) => value = &value[count..],
            Err(error) if error.kind() == ErrorKind::WouldBlock => {
                wait(stream, PollFlags::POLLOUT, deadline)?;
            }
            Err(error) => return Err(map_io(error)),
        }
    }
    Ok(())
}
