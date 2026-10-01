use std::sync::Arc;
use std::sync::atomic::Ordering;

use crowsi_credential_broker::{
    Broker, BrokerError, CredentialEntry, CredentialStore, SecretValue,
};

use crate::support;

#[test]
fn lease_is_scoped_and_single_use() {
    let (store, reference) = support::fixture();
    let (clock, now) = support::clock(100);
    let broker = Broker::with_clock(store, clock);
    let grant = broker
        .issue_bound(
            support::request(reference, "worker-a", "api.example.test", 10),
            support::binding(),
        )
        .expect("authorized lease");
    let receipt = serde_json::to_value(&grant.receipt).expect("serializable receipt");
    assert!(receipt.get("secret").is_none());
    assert!(receipt.get("token").is_none());
    now.store(101, Ordering::SeqCst);
    let used = broker
        .consume_bound(
            grant.token(),
            "worker-a",
            "api.example.test",
            &support::binding(),
        )
        .expect("authorized use");
    assert_eq!(used.secret.expose(<[u8]>::len), 15);
    assert!(matches!(
        broker.consume_bound(
            grant.token(),
            "worker-a",
            "api.example.test",
            &support::binding()
        ),
        Err(BrokerError::UnknownLease)
    ));
}

#[test]
fn wrong_audience_or_host_is_denied() {
    let (store, reference) = support::fixture();
    let (clock, _) = support::clock(100);
    let broker = Broker::with_clock(store, clock);
    assert!(matches!(
        broker.issue_bound(
            support::request(reference.clone(), "worker-b", "api.example.test", 10),
            support::binding()
        ),
        Err(BrokerError::AccessDenied)
    ));
    assert!(matches!(
        broker.issue_bound(
            support::request(reference, "worker-a", "evil.example.test", 10),
            support::binding()
        ),
        Err(BrokerError::AccessDenied)
    ));
}

#[test]
fn expired_and_revoked_leases_fail_closed() {
    let (store, reference) = support::fixture();
    let (clock, now) = support::clock(100);
    let broker = Broker::with_clock(store, clock);
    let make_request = || support::request(reference.clone(), "worker-a", "api.example.test", 2);
    let expired = broker
        .issue_bound(make_request(), support::binding())
        .expect("authorized lease");
    now.store(102, Ordering::SeqCst);
    assert!(matches!(
        broker.consume_bound(
            expired.token(),
            "worker-a",
            "api.example.test",
            &support::binding()
        ),
        Err(BrokerError::Expired)
    ));
    now.store(200, Ordering::SeqCst);
    let revoked = broker
        .issue_bound(make_request(), support::binding())
        .expect("authorized lease");
    broker.revoke(revoked.token()).expect("known lease");
    assert!(matches!(
        broker.consume_bound(
            revoked.token(),
            "worker-a",
            "api.example.test",
            &support::binding()
        ),
        Err(BrokerError::Revoked)
    ));
}

#[test]
fn lease_cannot_consume_a_rotated_revision() {
    let (store, reference) = support::fixture();
    let (clock, _) = support::clock(100);
    let broker = Broker::with_clock(Arc::clone(&store), clock);
    let stale = broker
        .issue_bound(
            support::request(reference.clone(), "worker-a", "api.example.test", 10),
            support::binding(),
        )
        .expect("authorized lease");
    store
        .put(
            CredentialEntry::new(
                reference.clone(),
                ["api.example.test".to_owned()],
                SecretValue::new(b"rotated-value".to_vec()).expect("valid secret"),
            )
            .expect("valid rotated entry"),
        )
        .expect("rotation stored");

    assert!(matches!(
        broker.consume_bound(
            stale.token(),
            "worker-a",
            "api.example.test",
            &support::binding()
        ),
        Err(BrokerError::CredentialChanged)
    ));
    let current = broker
        .issue_bound(
            support::request(reference, "worker-a", "api.example.test", 10),
            support::binding(),
        )
        .expect("new revision lease");
    let used = broker
        .consume_bound(
            current.token(),
            "worker-a",
            "api.example.test",
            &support::binding(),
        )
        .expect("current revision use");
    assert_eq!(used.secret.expose(|value| value.to_vec()), b"rotated-value");
}
