use std::time::{Instant, SystemTime, UNIX_EPOCH};

use crate::{BrokerError, Result};

pub trait Clock: Send + Sync {
    fn now(&self) -> Result<u64>;
}

pub struct SystemClock {
    started_at: Instant,
    unix_started_at: u64,
}

impl SystemClock {
    pub fn new() -> Result<Self> {
        let unix_started_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| BrokerError::BackendUnavailable)?
            .as_secs();
        Ok(Self {
            started_at: Instant::now(),
            unix_started_at,
        })
    }
}

impl Clock for SystemClock {
    fn now(&self) -> Result<u64> {
        self.unix_started_at
            .checked_add(self.started_at.elapsed().as_secs())
            .ok_or(BrokerError::BackendUnavailable)
    }
}
