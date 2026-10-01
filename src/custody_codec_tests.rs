use super::{confirm_write, decode, encode, revision};
use crate::{BrokerError, CredentialEntry, SecretRef, SecretScope, SecretValue};

fn reference() -> SecretRef {
    SecretRef::new(
        "provider-token",
        SecretScope::new("tenant-a", "connector", "provider-call", "zixcel").expect("valid scope"),
    )
    .expect("valid reference")
}

fn entry(reference: SecretRef, value: &[u8]) -> CredentialEntry {
    CredentialEntry::new(
        reference,
        ["api.example.test".to_owned()],
        SecretValue::new(value.to_vec()).expect("valid secret"),
    )
    .expect("valid entry")
}

#[test]
fn custody_envelope_restores_metadata_and_material() {
    let reference = reference();
    let entry = entry(reference.clone(), b"first-value");
    let expected = entry.metadata().revision().as_str().to_owned();
    let payload = encode(&entry).expect("encodable");

    let restored = decode(&reference, Some(&expected), &payload).expect("consistent envelope");
    assert_eq!(
        restored.into_secret().expose(|value| value.to_vec()),
        b"first-value"
    );
}

#[test]
fn wrong_revision_is_rejected_without_mixing_material() {
    let reference = reference();
    let first = entry(reference.clone(), b"first-value");
    let rotated = entry(reference.clone(), b"rotated-value");
    let payload = encode(&rotated).expect("encodable");
    let stale = first.metadata().revision().as_str().to_owned();

    assert!(matches!(
        decode(&reference, Some(&stale), &payload),
        Err(BrokerError::CredentialChanged)
    ));
    assert!(matches!(
        confirm_write(&reference, &stale, &payload, &payload),
        Err(BrokerError::CredentialChanged)
    ));
    let first_payload = encode(&first).expect("encodable");
    let current = rotated.metadata().revision().as_str().to_owned();
    assert!(matches!(
        confirm_write(&reference, &current, &first_payload, &payload),
        Err(BrokerError::CredentialChanged)
    ));
}

#[test]
fn partial_or_corrupt_envelopes_are_rejected() {
    let reference = reference();
    assert!(matches!(
        decode(&reference, None, "{\"schema\":\"partial\"}"),
        Err(BrokerError::InvalidEncoding)
    ));
    let entry = entry(reference.clone(), b"first-value");
    let payload = encode(&entry).expect("encodable");
    let corrupted = payload.replace(&hex::encode(b"first-value"), "not-hex");
    assert!(matches!(
        revision(&reference, &corrupted),
        Err(BrokerError::InvalidEncoding)
    ));
}
