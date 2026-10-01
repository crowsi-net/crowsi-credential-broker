use std::fmt;

use crate::{
    Result,
    validation::{component, workload_id},
};

#[derive(Clone, Eq, PartialEq)]
pub struct LeaseBinding {
    pairwise_subject: String,
    device: String,
    workload: String,
    grant_id: String,
    resource: String,
    action: String,
    proof_key_ref: String,
}

impl fmt::Debug for LeaseBinding {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("LeaseBinding([REDACTED])")
    }
}

impl LeaseBinding {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        pairwise_subject: &str,
        device: &str,
        workload: &str,
        grant_id: &str,
        resource: &str,
        action: &str,
        proof_key_ref: &str,
    ) -> Result<Self> {
        Ok(Self {
            pairwise_subject: component("pairwise_subject", pairwise_subject, 128)?,
            device: component("device", device, 128)?,
            workload: workload_id(workload)?,
            grant_id: component("grant_id", grant_id, 128)?,
            resource: component("resource", resource, 128)?,
            action: component("action", action, 64)?,
            proof_key_ref: component("proof_key_ref", proof_key_ref, 128)?,
        })
    }

    pub(crate) fn matches(&self, field: BindingField, value: &str) -> bool {
        match field {
            BindingField::Subject => self.pairwise_subject == value,
            BindingField::Device => self.device == value,
            BindingField::Workload => self.workload == value,
            BindingField::Grant => self.grant_id == value,
        }
    }

    pub fn pairwise_subject(&self) -> &str {
        &self.pairwise_subject
    }

    pub fn device(&self) -> &str {
        &self.device
    }

    pub fn workload(&self) -> &str {
        &self.workload
    }

    pub fn resource(&self) -> &str {
        &self.resource
    }

    pub fn action(&self) -> &str {
        &self.action
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BindingField {
    Subject,
    Device,
    Workload,
    Grant,
}

#[derive(Clone)]
pub struct RevocationSelector {
    pub(crate) field: BindingField,
    pub(crate) value: String,
}

impl fmt::Debug for RevocationSelector {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("RevocationSelector([REDACTED])")
    }
}

impl RevocationSelector {
    pub fn new(field: BindingField, value: &str) -> Result<Self> {
        let value = match field {
            BindingField::Workload => workload_id(value)?,
            _ => component("revocation_selector", value, 128)?,
        };
        Ok(Self { field, value })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BulkRevocationReceipt {
    pub field: BindingField,
    pub revoked_count: usize,
    pub occurred_at: u64,
}
