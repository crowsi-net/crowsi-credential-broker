use serde::Serialize;

use crate::Result;
use crate::validation::{component, normalize_host};

#[derive(Clone, Debug, Eq, Hash, PartialEq, Serialize)]
pub struct SecretScope {
    tenant: String,
    service: String,
    purpose: String,
    audience: String,
}

impl SecretScope {
    pub fn new(tenant: &str, service: &str, purpose: &str, audience: &str) -> Result<Self> {
        Ok(Self {
            tenant: component("tenant", tenant, 64)?,
            service: component("service", service, 64)?,
            purpose: component("purpose", purpose, 96)?,
            audience: component("audience", audience, 96)?,
        })
    }

    pub fn tenant(&self) -> &str {
        &self.tenant
    }

    pub fn service(&self) -> &str {
        &self.service
    }

    pub fn purpose(&self) -> &str {
        &self.purpose
    }

    pub fn audience(&self) -> &str {
        &self.audience
    }
}

#[derive(Clone, Debug, Eq, Hash, PartialEq, Serialize)]
pub struct SecretRef {
    id: String,
    scope: SecretScope,
}

impl SecretRef {
    pub fn new(id: &str, scope: SecretScope) -> Result<Self> {
        Ok(Self {
            id: component("id", id, 96)?,
            scope,
        })
    }

    pub fn canonical_id(&self) -> String {
        format!(
            "{}/{}/{}/{}/{}",
            self.scope.tenant, self.scope.service, self.scope.purpose, self.scope.audience, self.id
        )
    }

    /// Parses the canonical opaque reference emitted by credential enrollment.
    ///
    /// # Errors
    ///
    /// Rejects a reference with missing, extra, or invalid scope components.
    pub fn parse_canonical(value: &str) -> Result<Self> {
        let mut parts = value.split('/');
        let tenant = parts
            .next()
            .ok_or(crate::BrokerError::InvalidField("reference"))?;
        let service = parts
            .next()
            .ok_or(crate::BrokerError::InvalidField("reference"))?;
        let purpose = parts
            .next()
            .ok_or(crate::BrokerError::InvalidField("reference"))?;
        let audience = parts
            .next()
            .ok_or(crate::BrokerError::InvalidField("reference"))?;
        let id = parts
            .next()
            .ok_or(crate::BrokerError::InvalidField("reference"))?;
        if parts.next().is_some() {
            return Err(crate::BrokerError::InvalidField("reference"));
        }
        Self::new(id, SecretScope::new(tenant, service, purpose, audience)?)
    }

    pub fn id(&self) -> &str {
        &self.id
    }

    pub fn scope(&self) -> &SecretScope {
        &self.scope
    }
}

#[derive(Clone, Debug)]
pub struct AccessRequest {
    reference: SecretRef,
    audience: String,
    host: String,
    ttl_seconds: u64,
}

impl AccessRequest {
    pub fn new(reference: SecretRef, audience: &str, host: &str, ttl_seconds: u64) -> Result<Self> {
        Ok(Self {
            reference,
            audience: component("audience", audience, 96)?,
            host: normalize_host(host)?,
            ttl_seconds,
        })
    }

    pub(crate) fn into_parts(self) -> (SecretRef, String, String, u64) {
        (self.reference, self.audience, self.host, self.ttl_seconds)
    }
}
