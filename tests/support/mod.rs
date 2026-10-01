#![allow(dead_code)]

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use crowsi_credential_broker::{
    AccessRequest, Clock, CredentialEntry, CredentialStore, LeaseBinding, MemoryStore, Result,
    SecretRef, SecretScope, SecretValue,
};

#[derive(Clone)]
pub struct TestClock(Arc<AtomicU64>);

impl Clock for TestClock {
    fn now(&self) -> Result<u64> {
        Ok(self.0.load(Ordering::SeqCst))
    }
}

pub fn clock(now: u64) -> (TestClock, Arc<AtomicU64>) {
    let value = Arc::new(AtomicU64::new(now));
    (TestClock(Arc::clone(&value)), value)
}

pub fn fixture() -> (Arc<MemoryStore>, SecretRef) {
    let scope =
        SecretScope::new("tenant-a", "service-a", "api-call", "worker-a").expect("valid scope");
    let reference = SecretRef::new("test-token", scope).expect("valid reference");
    let store = Arc::new(MemoryStore::default());
    let secret = SecretValue::new(b"test-only-value".to_vec()).expect("valid test secret");
    let entry = CredentialEntry::new(reference.clone(), ["api.example.test".to_owned()], secret)
        .expect("valid entry");
    store.put(entry).expect("memory store available");
    (store, reference)
}

pub fn request(reference: SecretRef, audience: &str, host: &str, ttl: u64) -> AccessRequest {
    AccessRequest::new(reference, audience, host, ttl).expect("valid request")
}

pub fn binding() -> LeaseBinding {
    LeaseBinding::new(
        "subject-a",
        "device-a",
        "spiffe://crowsi/local/workload-a",
        "grant-a",
        "resource-a",
        "read",
        "proof-key-a",
    )
    .expect("valid test binding")
}
