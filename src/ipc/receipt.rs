use std::fmt;

use serde::{Deserialize, Serialize};

pub const ENROLLMENT_RECEIPT_SCHEMA: &str = "crowsi://credentials/ipc/enrollment-receipt/v1";

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EnrollmentReceiptV1 {
    pub(crate) schema: String,
    pub(crate) request_id: String,
    pub(crate) reservation_id: String,
    pub(crate) credential_ref: String,
    pub(crate) store_kind: String,
    pub(crate) status: String,
    pub(crate) contains_secret_values: bool,
}

impl fmt::Debug for EnrollmentReceiptV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("EnrollmentReceiptV1([REDACTED])")
    }
}

impl EnrollmentReceiptV1 {
    pub fn status(&self) -> &str {
        &self.status
    }

    pub fn credential_ref(&self) -> &str {
        &self.credential_ref
    }

    pub const fn contains_secret_values(&self) -> bool {
        self.contains_secret_values
    }
}
