#![allow(dead_code)]

use std::collections::HashSet;
use std::sync::{Arc, Mutex};

use crowsi_credential_broker::{
    AuthorizationVerifier, CredentialReferenceV1, EnrollmentRequestV1, IpcError, LeaseBinding,
    VerifiedAuthorization, credential_resource, enrollment_body_sha256,
};

pub const SECRET: &[u8] = b"TEST-ONLY-GITHUB-PRIVATE-KEY-MARKER";

pub fn request() -> EnrollmentRequestV1 {
    EnrollmentRequestV1::new(
        "request-001",
        CredentialReferenceV1::new(
            "github-app",
            "coela",
            "coela-github-app",
            "repository-read",
            "github",
        )
        .expect("credential reference"),
        "Coela GitHub App",
        "github",
        ["api.github.com"],
        SECRET,
    )
    .expect("enrollment request")
}

pub fn authorization(request: &EnrollmentRequestV1, reservation: &str) -> VerifiedAuthorization {
    let resource = credential_resource(request.credential()).expect("resource");
    let binding = LeaseBinding::new(
        "subject-coela",
        "device-workstation",
        "spiffe://crowsi/local/credential-enrollment",
        "grant-enroll",
        &resource,
        "credential-enroll",
        "proof-enrollment",
    )
    .expect("binding");
    VerifiedAuthorization::new(
        "subject-coela",
        "device-workstation",
        "spiffe://crowsi/local/credential-enrollment",
        reservation,
        &resource,
        "credential-enroll",
        &enrollment_body_sha256(request).expect("body digest"),
        binding,
    )
    .expect("verified authorization")
}

#[derive(Clone)]
pub struct StaticVerifier {
    result: Arc<Mutex<Option<Result<VerifiedAuthorization, IpcError>>>>,
}

impl StaticVerifier {
    pub fn allowed(value: VerifiedAuthorization) -> Self {
        Self {
            result: Arc::new(Mutex::new(Some(Ok(value)))),
        }
    }

    pub fn denied() -> Self {
        Self {
            result: Arc::new(Mutex::new(Some(Err(IpcError::AuthorizationRejected)))),
        }
    }
}

impl AuthorizationVerifier for StaticVerifier {
    fn verify(
        &mut self,
        _stream: &mut std::os::unix::net::UnixStream,
    ) -> Result<VerifiedAuthorization, IpcError> {
        self.result
            .lock()
            .map_err(|_| IpcError::AuthorizationRejected)?
            .take()
            .unwrap_or(Err(IpcError::AuthorizationRejected))
    }
}

#[derive(Clone)]
pub struct ReplayVerifier {
    authorization: VerifiedAuthorization,
    seen: Arc<Mutex<HashSet<String>>>,
}

impl ReplayVerifier {
    pub fn new(authorization: VerifiedAuthorization) -> Self {
        Self {
            authorization,
            seen: Arc::new(Mutex::new(HashSet::new())),
        }
    }
}

impl AuthorizationVerifier for ReplayVerifier {
    fn verify(
        &mut self,
        _stream: &mut std::os::unix::net::UnixStream,
    ) -> Result<VerifiedAuthorization, IpcError> {
        let mut seen = self
            .seen
            .lock()
            .map_err(|_| IpcError::AuthorizationRejected)?;
        if !seen.insert(self.authorization.reservation_id().to_owned()) {
            return Err(IpcError::AuthorizationRejected);
        }
        Ok(self.authorization.clone())
    }
}
