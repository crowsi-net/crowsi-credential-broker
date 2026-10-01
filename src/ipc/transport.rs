use std::io::{ErrorKind, Read};
use std::net::Shutdown;
use std::os::fd::AsFd;
use std::os::unix::net::UnixStream;
use std::time::{Duration, Instant};

use nix::poll::{PollFd, PollFlags, poll};

use super::error::{IpcError, IpcResult};

pub(crate) fn configure(stream: &UnixStream, timeout: Duration) -> IpcResult<()> {
    if timeout.is_zero() || timeout > Duration::from_secs(60) {
        return Err(IpcError::Timeout);
    }
    stream.set_nonblocking(true).map_err(map_io)
}

pub(crate) fn finish_writes(stream: &UnixStream) -> IpcResult<()> {
    stream.shutdown(Shutdown::Write).map_err(map_io)
}

pub(crate) fn expect_eof(stream: &mut UnixStream, timeout: Duration) -> IpcResult<()> {
    let deadline = Instant::now() + timeout;
    let mut trailing = [0_u8; 1];
    loop {
        match stream.read(&mut trailing) {
            Ok(0) => return Ok(()),
            Ok(_) => return Err(IpcError::TrailingData),
            Err(error) if error.kind() == ErrorKind::WouldBlock => {
                wait(stream, PollFlags::POLLIN, deadline)?;
            }
            Err(error) => return Err(map_io(error)),
        }
    }
}

pub(crate) fn wait(stream: &UnixStream, flags: PollFlags, deadline: Instant) -> IpcResult<()> {
    let remaining = deadline
        .checked_duration_since(Instant::now())
        .ok_or(IpcError::Timeout)?;
    let millis = remaining.as_millis().clamp(1, u128::from(u16::MAX));
    let timeout = u16::try_from(millis).map_err(|_| IpcError::Timeout)?;
    let mut descriptors = [PollFd::new(stream.as_fd(), flags)];
    let ready = poll(&mut descriptors, timeout).map_err(|_| IpcError::TransportUnavailable)?;
    if ready == 0 {
        return Err(IpcError::Timeout);
    }
    let events = descriptors[0].revents().unwrap_or(PollFlags::empty());
    if events.intersects(PollFlags::POLLNVAL | PollFlags::POLLERR) {
        return Err(IpcError::TransportUnavailable);
    }
    Ok(())
}

pub(crate) fn map_io(error: std::io::Error) -> IpcError {
    match error.kind() {
        ErrorKind::TimedOut | ErrorKind::WouldBlock => IpcError::Timeout,
        ErrorKind::UnexpectedEof => IpcError::PartialFrame,
        _ => IpcError::TransportUnavailable,
    }
}
