//! Crowsi's fail-closed boundary for credential references and short-lived use.
//!
//! Unbound issuance and consumption deliberately do not compile:
//! ```compile_fail
//! use crowsi_credential_broker::{
//!     AccessRequest, Broker, Clock, CredentialStore, LeaseToken,
//! };
//! fn bypass<S: CredentialStore, C: Clock>(
//!     broker: &Broker<S, C>,
//!     request: AccessRequest,
//!     token: &LeaseToken,
//! ) {
//!     let _ = broker.issue(request);
//!     let _ = broker.consume(token, "audience", "host");
//! }
//! ```

mod binding;
mod broker;
mod broker_bound;
mod clock;
mod custody_codec;
mod entry;
mod error;
mod ipc;
mod lease;
mod model;
mod platform_custody_store;
mod secret;
mod status;
mod status_document;
mod store;
mod validation;

pub use binding::{BindingField, BulkRevocationReceipt, LeaseBinding, RevocationSelector};
pub use broker::{Broker, MAX_ACTIVE_LEASES};
pub use clock::{Clock, SystemClock};
pub use crowsi_windows_custody_provider::RuntimeConfig as PlatformCustodyConfigV1;
pub use entry::{CredentialEntry, CredentialMetadata, CredentialRevision};
pub use error::{BrokerError, CustodyAvailabilityError, Result};
pub use ipc::{
    AuthorizationVerifier, CredentialReferenceV1, EnrollmentClient, EnrollmentReceiptV1,
    EnrollmentRequestV1, EnrollmentService, IpcError, VerifiedAuthorization, credential_resource,
    enrollment_body_sha256,
};
pub use lease::{LeaseGrant, LeaseReceipt, LeaseToken, SecretUse};
pub use model::{AccessRequest, SecretRef, SecretScope};
pub use platform_custody_store::PlatformCustodyStore;
pub use secret::SecretValue;
pub use status::{CredentialHealth, CredentialStatus, StatusScope};
pub use status_document::{
    CREDENTIAL_STATUS_SCHEMA, CredentialStatusDocument, MAX_FINDING_CODE_LENGTH, MAX_FINDING_CODES,
    MAX_STATUS_CREDENTIALS, MAX_UNIX_SECONDS,
};
pub use store::{CredentialStore, MemoryStore};
