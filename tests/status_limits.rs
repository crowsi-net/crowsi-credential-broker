use crowsi_credential_broker::{
    BrokerError, CredentialEntry, CredentialStatus, CredentialStatusDocument, CredentialStore,
    MAX_STATUS_CREDENTIALS, MAX_UNIX_SECONDS, MemoryStore, SecretRef, SecretScope, SecretValue,
};

fn ready_status_at(now: u64) -> Result<CredentialStatus, BrokerError> {
    let reference = SecretRef::new(
        "limit-test",
        SecretScope::new("tenant-a", "automation", "repository-read", "zixcel")
            .expect("valid scope"),
    )
    .expect("valid reference");
    let store = MemoryStore::default();
    store
        .put(
            CredentialEntry::new(
                reference.clone(),
                ["api.example.test".to_owned()],
                SecretValue::new(b"test-only-value".to_vec()).expect("valid test secret"),
            )
            .expect("valid entry"),
        )
        .expect("store available");
    CredentialStatus::ready_from_store(&store, &reference, "Ready", "github", "memory", now)
}

fn ready_status() -> CredentialStatus {
    ready_status_at(42).expect("ready status")
}

#[test]
fn status_document_rejects_credential_overflow() {
    assert!(matches!(
        CredentialStatusDocument::new(42, vec![ready_status(); MAX_STATUS_CREDENTIALS + 1]),
        Err(BrokerError::InvalidField("credentials"))
    ));
}

#[test]
fn status_document_rejects_duplicate_ids() {
    let status = ready_status();
    assert!(matches!(
        CredentialStatusDocument::new(42, vec![status.clone(), status]),
        Err(BrokerError::InvalidField("credential_ids"))
    ));
}

#[test]
fn status_factories_reject_out_of_range_times() {
    assert!(matches!(
        ready_status_at(MAX_UNIX_SECONDS + 1),
        Err(BrokerError::InvalidField("checked_at"))
    ));
    assert!(matches!(
        CredentialStatusDocument::new(MAX_UNIX_SECONDS + 1, vec![ready_status()]),
        Err(BrokerError::InvalidField("generated_at"))
    ));
}
