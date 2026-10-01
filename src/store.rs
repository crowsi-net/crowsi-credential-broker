use std::collections::HashMap;
use std::sync::RwLock;

use crate::{BrokerError, CredentialEntry, CredentialMetadata, Result, SecretRef};

pub trait CredentialStore: Send + Sync {
    fn put(&self, entry: CredentialEntry) -> Result<()>;
    /// Returns metadata only after the backend verifies one complete stored credential.
    fn metadata(&self, reference: &SecretRef) -> Result<CredentialMetadata>;
    fn get(&self, reference: &SecretRef, expected_revision: &str) -> Result<CredentialEntry>;
    fn delete(&self, reference: &SecretRef) -> Result<()>;
}

#[derive(Default)]
pub struct MemoryStore {
    entries: RwLock<HashMap<String, CredentialEntry>>,
}

impl CredentialStore for MemoryStore {
    fn put(&self, entry: CredentialEntry) -> Result<()> {
        let metadata = entry.metadata();
        let id = metadata.reference().canonical_id();
        let mut entries = self
            .entries
            .write()
            .map_err(|_| BrokerError::BackendUnavailable)?;
        if entries
            .get(&id)
            .is_some_and(|current| current.metadata().revision() == metadata.revision())
        {
            return Err(BrokerError::CredentialChanged);
        }
        entries.insert(id, entry);
        Ok(())
    }

    fn metadata(&self, reference: &SecretRef) -> Result<CredentialMetadata> {
        self.entries
            .read()
            .map_err(|_| BrokerError::BackendUnavailable)?
            .get(&reference.canonical_id())
            .map(CredentialEntry::metadata)
            .ok_or(BrokerError::NotFound)
    }

    fn get(&self, reference: &SecretRef, expected_revision: &str) -> Result<CredentialEntry> {
        let entries = self
            .entries
            .read()
            .map_err(|_| BrokerError::BackendUnavailable)?;
        let entry = entries
            .get(&reference.canonical_id())
            .ok_or(BrokerError::NotFound)?;
        if entry.metadata().revision().as_str() != expected_revision {
            return Err(BrokerError::CredentialChanged);
        }
        Ok(entry.duplicate())
    }

    fn delete(&self, reference: &SecretRef) -> Result<()> {
        self.entries
            .write()
            .map_err(|_| BrokerError::BackendUnavailable)?
            .remove(&reference.canonical_id())
            .map(|_| ())
            .ok_or(BrokerError::NotFound)
    }
}

#[cfg(test)]
#[path = "store_tests.rs"]
mod tests;
