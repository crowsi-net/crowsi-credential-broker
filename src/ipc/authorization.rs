use std::fmt;
use std::os::unix::net::UnixStream;

use crate::{
    LeaseBinding,
    validation::{component, workload_id as validate_workload_id},
};

use super::error::{IpcError, IpcResult};

#[derive(Clone)]
pub struct VerifiedAuthorization {
    subject_id: String,
    device_id: String,
    workload_id: String,
    reservation_id: String,
    resource: String,
    action: String,
    body_sha256: String,
    binding: LeaseBinding,
}

impl fmt::Debug for VerifiedAuthorization {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("VerifiedAuthorization([REDACTED])")
    }
}

impl VerifiedAuthorization {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        subject_id: &str,
        device_id: &str,
        workload_id: &str,
        reservation_id: &str,
        resource: &str,
        action: &str,
        body_sha256: &str,
        binding: LeaseBinding,
    ) -> IpcResult<Self> {
        let value = Self {
            subject_id: component("subject_id", subject_id, 128)
                .map_err(|_| IpcError::AuthorizationRejected)?,
            device_id: component("device_id", device_id, 128)
                .map_err(|_| IpcError::AuthorizationRejected)?,
            workload_id: validate_workload_id(workload_id)
                .map_err(|_| IpcError::AuthorizationRejected)?,
            reservation_id: component("reservation_id", reservation_id, 128)
                .map_err(|_| IpcError::AuthorizationRejected)?,
            resource: component("resource", resource, 128)
                .map_err(|_| IpcError::AuthorizationRejected)?,
            action: component("action", action, 64).map_err(|_| IpcError::AuthorizationRejected)?,
            body_sha256: digest(body_sha256)?,
            binding,
        };
        value
            .exact_binding()
            .then_some(value)
            .ok_or(IpcError::BindingRejected)
    }

    pub fn subject_id(&self) -> &str {
        &self.subject_id
    }

    pub fn device_id(&self) -> &str {
        &self.device_id
    }

    pub fn workload_id(&self) -> &str {
        &self.workload_id
    }

    pub fn reservation_id(&self) -> &str {
        &self.reservation_id
    }

    pub fn resource(&self) -> &str {
        &self.resource
    }

    pub fn action(&self) -> &str {
        &self.action
    }

    pub fn body_sha256(&self) -> &str {
        &self.body_sha256
    }

    pub fn binding(&self) -> &LeaseBinding {
        &self.binding
    }

    fn exact_binding(&self) -> bool {
        self.binding.pairwise_subject() == self.subject_id
            && self.binding.device() == self.device_id
            && self.binding.workload() == self.workload_id
            && self.binding.resource() == self.resource
            && self.binding.action() == self.action
    }
}

pub trait AuthorizationVerifier {
    /// Authenticates and authorizes the peer on this exact Unix stream.
    ///
    /// Implementations must derive identity from the stream and must not trust
    /// caller-supplied subject, device, workload, or binding fields.
    fn verify(&mut self, stream: &mut UnixStream) -> IpcResult<VerifiedAuthorization>;
}

fn digest(value: &str) -> IpcResult<String> {
    let valid = value.len() == 71
        && value.starts_with("sha256:")
        && value[7..]
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'));
    valid
        .then(|| value.to_owned())
        .ok_or(IpcError::AuthorizationRejected)
}
