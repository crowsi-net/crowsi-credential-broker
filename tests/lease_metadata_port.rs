use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use crowsi_credential_broker::{
    AccessRequest, Broker, Clock, CredentialEntry, CredentialMetadata, CredentialStore,
    MemoryStore, Result, SecretRef, SecretScope, SecretValue,
};

use crate::support;

struct FixedClock;

impl Clock for FixedClock {
    fn now(&self) -> Result<u64> {
        Ok(100)
    }
}

#[derive(Default)]
struct TrackingStore {
    inner: MemoryStore,
    secret_reads: AtomicUsize,
}

impl CredentialStore for TrackingStore {
    fn put(&self, entry: CredentialEntry) -> Result<()> {
        self.inner.put(entry)
    }

    fn metadata(&self, reference: &SecretRef) -> Result<CredentialMetadata> {
        self.inner.metadata(reference)
    }

    fn get(&self, reference: &SecretRef, expected_revision: &str) -> Result<CredentialEntry> {
        self.secret_reads.fetch_add(1, Ordering::SeqCst);
        self.inner.get(reference, expected_revision)
    }

    fn delete(&self, reference: &SecretRef) -> Result<()> {
        self.inner.delete(reference)
    }
}

#[test]
fn issuing_a_lease_does_not_call_the_material_port() {
    let reference = SecretRef::new(
        "test-token",
        SecretScope::new("tenant-a", "service-a", "api-call", "worker-a").expect("valid scope"),
    )
    .expect("valid reference");
    let store = Arc::new(TrackingStore::default());
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
    let broker = Broker::with_clock(Arc::clone(&store), FixedClock);
    let grant = broker
        .issue_bound(
            AccessRequest::new(reference, "worker-a", "api.example.test", 10)
                .expect("valid request"),
            support::binding(),
        )
        .expect("authorized lease");
    assert_eq!(store.secret_reads.load(Ordering::SeqCst), 0);

    broker
        .consume_bound(
            grant.token(),
            "worker-a",
            "api.example.test",
            &support::binding(),
        )
        .expect("authorized use");
    assert_eq!(store.secret_reads.load(Ordering::SeqCst), 1);
}
