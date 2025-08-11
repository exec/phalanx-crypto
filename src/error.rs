//! Error types for Phalanx Protocol

use thiserror::Error;

/// Result type alias for Phalanx operations
pub type Result<T> = std::result::Result<T, PhalanxError>;

/// Comprehensive error types for all Phalanx operations
#[derive(Error, Debug)]
pub enum PhalanxError {
    /// Cryptographic operation failed
    #[error("Cryptographic error: {0}")]
    Crypto(String),
    
    /// Invalid protocol message or format
    #[error("Protocol error: {0}")]
    Protocol(String),
    
    /// Group operation failed
    #[error("Group error: {0}")]
    Group(String),
    
    /// Authentication or signature verification failed
    #[error("Authentication failed: {0}")]
    Authentication(String),
    
    /// Key exchange or derivation failed
    #[error("Key derivation error: {0}")]
    KeyDerivation(String),
    
    /// Message encryption/decryption failed
    #[error("Encryption error: {0}")]
    Encryption(String),
    
    /// Invalid group membership or permissions
    #[error("Membership error: {0}")]
    Membership(String),
    
    /// Protocol version mismatch or unsupported
    #[error("Version error: {0}")]
    Version(String),
    
    /// Serialization/deserialization failed
    #[cfg(feature = "serde")]
    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
    
    /// Generic I/O error
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
}

impl PhalanxError {
    /// Create a new crypto error
    pub fn crypto(msg: impl Into<String>) -> Self {
        Self::Crypto(msg.into())
    }
    
    /// Create a new protocol error
    pub fn protocol(msg: impl Into<String>) -> Self {
        Self::Protocol(msg.into())
    }
    
    /// Create a new group error
    pub fn group(msg: impl Into<String>) -> Self {
        Self::Group(msg.into())
    }
    
    /// Create a new authentication error
    pub fn auth(msg: impl Into<String>) -> Self {
        Self::Authentication(msg.into())
    }
    
    /// Create a new key derivation error
    pub fn key_derivation(msg: impl Into<String>) -> Self {
        Self::KeyDerivation(msg.into())
    }
    
    /// Create a new encryption error
    pub fn encryption(msg: impl Into<String>) -> Self {
        Self::Encryption(msg.into())
    }
    
    /// Create a new membership error
    pub fn membership(msg: impl Into<String>) -> Self {
        Self::Membership(msg.into())
    }
    
    /// Create a new version error
    pub fn version(msg: impl Into<String>) -> Self {
        Self::Version(msg.into())
    }
}

/// Convert from various cryptographic library errors
impl From<chacha20poly1305::Error> for PhalanxError {
    fn from(err: chacha20poly1305::Error) -> Self {
        PhalanxError::crypto(format!("ChaCha20Poly1305 error: {}", err))
    }
}

impl From<ed25519_dalek::SignatureError> for PhalanxError {
    fn from(err: ed25519_dalek::SignatureError) -> Self {
        PhalanxError::auth(format!("Ed25519 signature error: {}", err))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_error_creation() {
        let err = PhalanxError::crypto("Test crypto error");
        assert_eq!(err.to_string(), "Cryptographic error: Test crypto error");
        
        let err = PhalanxError::protocol("Test protocol error");
        assert_eq!(err.to_string(), "Protocol error: Test protocol error");
    }
}