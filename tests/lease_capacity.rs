use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use crowsi_credential_broker::{
    AccessRequest, Broker, BrokerError, Clock, CredentialEntry, CredentialStore, MAX_ACTIVE_LEASES,
    MemoryStore, Result, SecretRef, SecretScope, SecretValue,
};

use crate::support;

#[derive(Clone)]
struct TestClock(Arc<AtomicU64>);

impl Clock for TestClock {
    fn now(&self) -> Result<u64> {
        Ok(self.0.load(Ordering::SeqCst))
    }
}

#[test]
fn active_lease_limit_fails_closed_and_expired_leases_are_purged() {
    let reference = SecretRef::new(
        "capacity-token",
        SecretScope::new("tenant-a", "service-a", "api-call", "worker-a").expect("valid scope"),
    )
    .expect("valid reference");
    let store = Arc::new(MemoryStore::default());
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
    let now = Arc::new(AtomicU64::new(100));
    let broker = Broker::with_clock(store, TestClock(Arc::clone(&now)));

    for _ in 0..MAX_ACTIVE_LEASES {
        broker
            .issue_bound(
                AccessRequest::new(reference.clone(), "worker-a", "api.example.test", 10)
                    .expect("valid request"),
                support::binding(),
            )
            .expect("capacity available");
    }
    assert!(matches!(
        broker.issue_bound(
            AccessRequest::new(reference.clone(), "worker-a", "api.example.test", 10)
                .expect("valid request"),
            support::binding()
        ),
        Err(BrokerError::LeaseCapacity)
    ));

    now.store(110, Ordering::SeqCst);
    broker
        .issue_bound(
            AccessRequest::new(reference, "worker-a", "api.example.test", 10)
                .expect("valid request"),
            support::binding(),
        )
        .expect("expired leases were purged");
}
