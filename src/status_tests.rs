use super::{CredentialHealth, CredentialStatus, StatusScope};
use crate::{
    BrokerError, CredentialStatusDocument, MAX_FINDING_CODE_LENGTH, MAX_FINDING_CODES,
    MAX_UNIX_SECONDS,
};

fn status_with(codes: Vec<String>) -> CredentialStatus {
    CredentialStatus {
        id: "a/b/c/d/e".to_owned(),
        label: "Test".to_owned(),
        provider: "test".to_owned(),
        purpose: "test".to_owned(),
        status: CredentialHealth::Unavailable,
        store_kind: "memory".to_owned(),
        scope: StatusScope {
            tenant: "a".to_owned(),
            service: "b".to_owned(),
            audience: "d".to_owned(),
        },
        checked_at: 1,
        expires_at: None,
        rotation_due_at: None,
        finding_codes: codes,
    }
}

#[test]
fn document_rejects_finding_code_overflow() {
    let status = status_with(vec!["test".to_owned(); MAX_FINDING_CODES + 1]);
    assert!(matches!(
        CredentialStatusDocument::new(1, vec![status]),
        Err(BrokerError::InvalidField("finding_codes"))
    ));
}

#[test]
fn document_rejects_invalid_finding_code_identifiers() {
    for invalid in [
        "UPPERCASE".to_owned(),
        "x".repeat(MAX_FINDING_CODE_LENGTH + 1),
    ] {
        assert!(matches!(
            CredentialStatusDocument::new(1, vec![status_with(vec![invalid])]),
            Err(BrokerError::InvalidField("finding_code"))
        ));
    }
}

#[test]
fn document_rejects_out_of_range_credential_times() {
    let mut status = status_with(Vec::new());
    status.checked_at = MAX_UNIX_SECONDS + 1;
    assert!(matches!(
        CredentialStatusDocument::new(1, vec![status]),
        Err(BrokerError::InvalidField("checked_at"))
    ));

    let mut status = status_with(Vec::new());
    status.expires_at = Some(MAX_UNIX_SECONDS + 1);
    assert!(matches!(
        CredentialStatusDocument::new(1, vec![status]),
        Err(BrokerError::InvalidField("expires_at"))
    ));

    let mut status = status_with(Vec::new());
    status.rotation_due_at = Some(MAX_UNIX_SECONDS + 1);
    assert!(matches!(
        CredentialStatusDocument::new(1, vec![status]),
        Err(BrokerError::InvalidField("rotation_due_at"))
    ));
}
