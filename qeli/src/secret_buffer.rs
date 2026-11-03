//! One finite, zeroizing raw-secret policy for Linux file and command suppliers.
use zeroize::Zeroizing;

pub(crate) const MAX_SECRET_BYTES: usize = 16 * 1024;

#[derive(Debug)]
pub(crate) enum SecretDataError {
    TooLarge,
    InvalidUtf8,
}

// No Debug: raw credentials must never be formatted into a diagnostic.
pub(crate) struct SecretBuffer(Zeroizing<Vec<u8>>);
impl SecretBuffer {
    pub(crate) fn new() -> Self {
        Self(Zeroizing::new(Vec::with_capacity(MAX_SECRET_BYTES)))
    }

    pub(crate) fn append(&mut self, bytes: &[u8]) -> Result<(), SecretDataError> {
        if bytes.len() > MAX_SECRET_BYTES - self.0.len() {
            return Err(SecretDataError::TooLarge);
        }
        // Preallocation and the guard prevent reallocating secret-bearing storage.
        self.0.extend_from_slice(bytes);
        Ok(())
    }

    pub(crate) fn decode(&self) -> Result<Zeroizing<String>, SecretDataError> {
        let text = std::str::from_utf8(&self.0).map_err(|_| SecretDataError::InvalidUtf8)?;
        Ok(Zeroizing::new(text.trim().to_owned()))
    }

    #[cfg(test)]
    pub(crate) fn bytes(&self) -> &[u8] {
        &self.0
    }

    #[cfg(test)]
    pub(crate) fn capacity(&self) -> usize {
        self.0.capacity()
    }
}
