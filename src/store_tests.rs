use super::{CredentialStore, MemoryStore};
use crate::{BrokerError, CredentialEntry, SecretRef, SecretScope, SecretValue};

#[test]
fn one_revision_cannot_be_overwritten_with_new_material() {
    let reference = SecretRef::new(
        "revision-token",
        SecretScope::new("tenant-a", "service-a", "api-call", "worker-a").expect("valid scope"),
    )
    .expect("valid reference");
    let original = CredentialEntry::new(
        reference.clone(),
        ["api.example.test".to_owned()],
        SecretValue::new(b"original-value".to_vec()).expect("valid secret"),
    )
    .expect("valid entry");
    let metadata = original.metadata();
    let revision = metadata.revision().as_str().to_owned();
    let store = MemoryStore::default();
    store.put(original).expect("initial insert");

    let replacement = CredentialEntry::restore(
        metadata,
        SecretValue::new(b"replacement-value".to_vec()).expect("valid secret"),
    );
    assert!(matches!(
        store.put(replacement),
        Err(BrokerError::CredentialChanged)
    ));
    let loaded = store
        .get(&reference, &revision)
        .expect("original revision remains");
    assert_eq!(
        loaded.into_secret().expose(|value| value.to_vec()),
        b"original-value"
    );
}
