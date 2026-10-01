use std::sync::Arc;

use crowsi_credential_broker::{
    AccessRequest, BindingField, Broker, BrokerError, CredentialEntry, CredentialStore,
    LeaseBinding, MemoryStore, RevocationSelector, SecretRef, SecretScope, SecretValue,
};

fn setup() -> (Broker<MemoryStore>, SecretRef, LeaseBinding) {
    let reference = SecretRef::new(
        "github-app",
        SecretScope::new("tenant-a", "coela", "repository-read", "github").expect("valid scope"),
    )
    .expect("valid reference");
    let store = Arc::new(MemoryStore::default());
    store
        .put(
            CredentialEntry::new(
                reference.clone(),
                ["api.github.com".to_owned()],
                SecretValue::new(b"not-a-real-secret".to_vec()).expect("valid secret"),
            )
            .expect("valid entry"),
        )
        .expect("stored entry");
    let binding = LeaseBinding::new(
        "subject-a",
        "device-a",
        "spiffe://crowsi/local/workload-a",
        "grant-a",
        "github-api",
        "read",
        "proof-key-a",
    )
    .expect("valid binding");
    (
        Broker::new(store).expect("broker clock"),
        reference,
        binding,
    )
}

fn request(reference: SecretRef) -> AccessRequest {
    AccessRequest::new(reference, "github", "api.github.com", 30).expect("valid request")
}

#[test]
fn bound_lease_cannot_be_downgraded_or_rebound() {
    let (broker, reference, binding) = setup();
    let grant = broker
        .issue_bound(request(reference), binding.clone())
        .expect("bound grant");
    let wrong = LeaseBinding::new(
        "subject-a",
        "device-b",
        "spiffe://crowsi/local/workload-a",
        "grant-a",
        "github-api",
        "read",
        "proof-key-a",
    )
    .expect("valid mismatched binding");
    assert!(matches!(
        broker.consume_bound(grant.token(), "github", "api.github.com", &wrong),
        Err(BrokerError::AccessDenied)
    ));
}

#[test]
fn device_revocation_invalidates_all_matching_leases() {
    let (broker, reference, binding) = setup();
    let first = broker
        .issue_bound(request(reference.clone()), binding.clone())
        .expect("first grant");
    let second = broker
        .issue_bound(request(reference), binding.clone())
        .expect("second grant");
    let selector =
        RevocationSelector::new(BindingField::Device, "device-a").expect("valid selector");
    assert_eq!(
        broker
            .revoke_matching(&selector)
            .expect("bulk revocation")
            .revoked_count,
        2
    );
    for grant in [&first, &second] {
        assert!(matches!(
            broker.consume_bound(grant.token(), "github", "api.github.com", &binding),
            Err(BrokerError::Revoked)
        ));
    }
}
