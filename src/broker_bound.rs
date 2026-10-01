use crate::lease::{AuditAction, receipt};
use crate::{
    AccessRequest, Broker, BrokerError, BulkRevocationReceipt, Clock, CredentialStore,
    LeaseBinding, LeaseGrant, LeaseReceipt, LeaseToken, Result, RevocationSelector, SecretUse,
};

impl<S: CredentialStore, C: Clock> Broker<S, C> {
    pub fn revoke(&self, token: &LeaseToken) -> Result<LeaseReceipt> {
        let mut leases = self
            .leases
            .lock()
            .map_err(|_| BrokerError::BackendUnavailable)?;
        let state = leases.get_mut(&token.0).ok_or(BrokerError::UnknownLease)?;
        state.revoked = true;
        let now = self.clock.now()?;
        receipt(
            AuditAction::LeaseRevoked,
            &state.reference,
            &state.host,
            now,
            state.expires_at,
        )
    }

    pub fn issue_bound(&self, request: AccessRequest, binding: LeaseBinding) -> Result<LeaseGrant> {
        self.issue_with_binding(request, binding)
    }

    pub fn consume_bound(
        &self,
        token: &LeaseToken,
        audience: &str,
        host: &str,
        binding: &LeaseBinding,
    ) -> Result<SecretUse> {
        self.consume_with_binding(token, audience, host, binding)
    }

    pub fn revoke_matching(&self, selector: &RevocationSelector) -> Result<BulkRevocationReceipt> {
        let mut leases = self
            .leases
            .lock()
            .map_err(|_| BrokerError::BackendUnavailable)?;
        let mut revoked_count = 0;
        for state in leases.values_mut() {
            if !state.revoked && state.binding.matches(selector.field, &selector.value) {
                state.revoked = true;
                revoked_count += 1;
            }
        }
        Ok(BulkRevocationReceipt {
            field: selector.field,
            revoked_count,
            occurred_at: self.clock.now()?,
        })
    }
}
