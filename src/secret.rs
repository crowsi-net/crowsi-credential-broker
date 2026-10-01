use zeroize::Zeroizing;

use crate::{BrokerError, Result};

const MAX_SECRET_BYTES: usize = 64 * 1024;

/// Owned secret bytes that are zeroized on drop and deliberately do not implement `Debug`.
pub struct SecretValue(Zeroizing<Vec<u8>>);

impl SecretValue {
    pub fn new(value: Vec<u8>) -> Result<Self> {
        let value = Zeroizing::new(value);
        if value.is_empty() || value.len() > MAX_SECRET_BYTES {
            return Err(BrokerError::InvalidField("secret"));
        }
        Ok(Self(value))
    }

    /// Limits plaintext access to a closure so callers do not receive an owned copy by default.
    pub fn expose<R>(&self, operation: impl FnOnce(&[u8]) -> R) -> R {
        operation(self.0.as_slice())
    }

    pub(crate) fn duplicate(&self) -> Self {
        Self(Zeroizing::new(self.0.to_vec()))
    }

    pub(crate) fn from_zeroizing(value: Zeroizing<Vec<u8>>) -> Result<Self> {
        if value.is_empty() || value.len() > MAX_SECRET_BYTES {
            return Err(BrokerError::InvalidField("secret"));
        }
        Ok(Self(value))
    }
}

#[cfg(test)]
mod tests {
    use zeroize::{ZeroizeOnDrop, Zeroizing};

    use super::{MAX_SECRET_BYTES, SecretValue};
    use crate::BrokerError;

    fn requires_zeroize_on_drop<T: ZeroizeOnDrop>() {}

    #[test]
    fn invalid_inputs_are_rejected_after_entering_zeroizing_storage() {
        requires_zeroize_on_drop::<Zeroizing<Vec<u8>>>();
        assert!(matches!(
            SecretValue::new(Vec::new()),
            Err(BrokerError::InvalidField("secret"))
        ));
        assert!(matches!(
            SecretValue::new(vec![0x5a; MAX_SECRET_BYTES + 1]),
            Err(BrokerError::InvalidField("secret"))
        ));
    }
}
