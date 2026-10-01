use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use crate::LeaseBinding;
use crate::lease::{AuditAction, LeaseGrant, LeaseToken, SecretUse, random_array, receipt};
use crate::validation::normalize_host;
use crate::{
    AccessRequest, BrokerError, Clock, CredentialMetadata, CredentialStore, Result, SecretRef,
    SystemClock,
};

const MAX_LEASE_SECONDS: u64 = 300;
pub const MAX_ACTIVE_LEASES: usize = 1_024;

pub(crate) struct LeaseState {
    pub(crate) reference: SecretRef,
    audience: String,
    pub(crate) host: String,
    revision: String,
    pub(crate) expires_at: u64,
    pub(crate) revoked: bool,
    pub(crate) binding: LeaseBinding,
}

pub struct Broker<S, C = SystemClock> {
    store: Arc<S>,
    pub(crate) clock: C,
    pub(crate) leases: Mutex<HashMap<[u8; 32], LeaseState>>,
}

impl<S: CredentialStore> Broker<S, SystemClock> {
    pub fn new(store: Arc<S>) -> Result<Self> {
        Ok(Self::with_clock(store, SystemClock::new()?))
    }
}

impl<S: CredentialStore, C: Clock> Broker<S, C> {
    pub fn with_clock(store: Arc<S>, clock: C) -> Self {
        Self {
            store,
            clock,
            leases: Mutex::new(HashMap::new()),
        }
    }

    pub(crate) fn issue_with_binding(
        &self,
        request: AccessRequest,
        binding: LeaseBinding,
    ) -> Result<LeaseGrant> {
        let (reference, audience, host, ttl_seconds) = request.into_parts();
        if ttl_seconds == 0 || ttl_seconds > MAX_LEASE_SECONDS {
            return Err(BrokerError::AccessDenied);
        }
        let metadata = self.store.metadata(&reference)?;
        authorize(&metadata, &audience, &host)?;
        let now = self.clock.now()?;
        let expires_at = now
            .checked_add(ttl_seconds)
            .ok_or(BrokerError::AccessDenied)?;
        let key = random_array()?;
        let state = LeaseState {
            reference: reference.clone(),
            audience: audience.clone(),
            host: host.clone(),
            revision: metadata.revision().as_str().to_owned(),
            expires_at,
            revoked: false,
            binding,
        };
        let issued_receipt = receipt(AuditAction::LeaseIssued, &reference, &host, now, expires_at)?;
        let mut leases = self
            .leases
            .lock()
            .map_err(|_| BrokerError::BackendUnavailable)?;
        leases.retain(|_, lease| !lease.revoked && lease.expires_at > now);
        if leases.len() >= MAX_ACTIVE_LEASES {
            return Err(BrokerError::LeaseCapacity);
        }
        leases.insert(key, state);
        Ok(LeaseGrant {
            token: LeaseToken(key),
            receipt: issued_receipt,
        })
    }

    pub(crate) fn consume_with_binding(
        &self,
        token: &LeaseToken,
        audience: &str,
        host: &str,
        binding: &LeaseBinding,
    ) -> Result<SecretUse> {
        let host = normalize_host(host)?;
        let state = self
            .leases
            .lock()
            .map_err(|_| BrokerError::BackendUnavailable)?
            .remove(&token.0)
            .ok_or(BrokerError::UnknownLease)?;
        let now = self.clock.now()?;
        if state.revoked {
            return Err(BrokerError::Revoked);
        }
        if now >= state.expires_at {
            return Err(BrokerError::Expired);
        }
        if state.audience != audience || state.host != host {
            return Err(BrokerError::AccessDenied);
        }
        if &state.binding != binding {
            return Err(BrokerError::AccessDenied);
        }
        let entry = self.store.get(&state.reference, &state.revision)?;
        authorize(&entry.metadata(), audience, &host)?;
        Ok(SecretUse {
            secret: entry.into_secret(),
            receipt: receipt(
                AuditAction::CredentialUsed,
                &state.reference,
                &host,
                now,
                state.expires_at,
            )?,
        })
    }
}

fn authorize(metadata: &CredentialMetadata, audience: &str, host: &str) -> Result<()> {
    if metadata.reference().scope().audience() != audience
        || !metadata
            .allowed_hosts()
            .iter()
            .any(|allowed| allowed == host)
    {
        return Err(BrokerError::AccessDenied);
    }
    Ok(())
}
