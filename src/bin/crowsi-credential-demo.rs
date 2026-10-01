use std::sync::Arc;

use crowsi_credential_broker::{
    AccessRequest, Broker, BrokerError, CredentialEntry, CredentialStatus,
    CredentialStatusDocument, CredentialStore, LeaseBinding, MemoryStore, SecretRef, SecretScope,
    SecretValue,
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let reference = SecretRef::new(
        "ephemeral-demo",
        SecretScope::new("sample", "status-ui", "health-check", "local-ui")?,
    )?;
    let mut generated = vec![0_u8; 32];
    getrandom::fill(&mut generated).map_err(|_| BrokerError::EntropyUnavailable)?;

    let store = Arc::new(MemoryStore::default());
    store.put(CredentialEntry::new(
        reference.clone(),
        ["localhost".to_owned()],
        SecretValue::new(generated)?,
    )?)?;
    let broker = Broker::new(Arc::clone(&store))?;
    let binding = LeaseBinding::new(
        "sample-subject",
        "sample-device",
        "spiffe://crowsi/local/sample-workload",
        "sample-grant",
        "status-ui",
        "read",
        "sample-proof-key",
    )?;
    let request = AccessRequest::new(reference.clone(), "local-ui", "localhost", 30)?;
    let grant = broker.issue_bound(request, binding.clone())?;
    let used = broker.consume_bound(grant.token(), "local-ui", "localhost", &binding)?;
    used.secret.expose(|value| assert_eq!(value.len(), 32));

    let now = grant.receipt.occurred_at;
    let status = CredentialStatus::ready_from_store(
        store.as_ref(),
        &reference,
        "Ephemeral demo",
        "crowsi",
        "memory",
        now,
    )?;
    let document = CredentialStatusDocument::new(now, vec![status])?;
    println!("{}", serde_json::to_string_pretty(&document)?);
    Ok(())
}
