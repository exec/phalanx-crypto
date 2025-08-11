//! # Phalanx Protocol
//!
//! A general-purpose group E2E encryption protocol designed for maximum security and flexibility.
//!
//! Phalanx provides cryptographically secure group communication with forward secrecy,
//! post-compromise security, and efficient key rotation. While designed for Legion Protocol,
//! it can be used by any communication system requiring group E2E encryption.
//!
//! ## Features
//!
//! - **Double Ratchet** for forward secrecy and post-compromise security
//! - **Group key agreement** using X25519 key exchange
//! - **ChaCha20-Poly1305** for authenticated encryption
//! - **BLAKE3** for key derivation and message authentication
//! - **Ed25519** for digital signatures
//! - **Flexible transport layer** - works over any reliable channel
//! - **Zero-knowledge proofs** for membership verification (planned)
//!
//! ## Security Properties
//!
//! - **End-to-End Encryption**: Only group members can decrypt messages
//! - **Forward Secrecy**: Past messages remain secure even if current keys are compromised
//! - **Post-Compromise Security**: Future messages remain secure after key compromise recovery
//! - **Authentication**: All messages are cryptographically authenticated
//! - **Deniability**: Messages cannot be proven to have been sent by a specific user
//! - **Metadata Protection**: Minimal metadata leakage
//!
//! ## Basic Usage
//!
//! ```rust
//! use phalanx::{PhalanxGroup, Identity, GroupMessage};
//!
//! // Create a new identity
//! let identity = Identity::generate();
//!
//! // Create or join a group
//! let mut group = PhalanxGroup::new(identity);
//!
//! // Encrypt a message
//! let plaintext = b"Hello, secure world!";
//! let encrypted = group.encrypt_message(plaintext)?;
//!
//! // Decrypt a message
//! let decrypted = group.decrypt_message(&encrypted)?;
//! assert_eq!(decrypted, plaintext);
//! # Ok::<(), phalanx::PhalanxError>(())
//! ```

#![warn(missing_docs, rustdoc::missing_crate_level_docs)]
#![deny(unsafe_code)]

pub mod identity;
pub mod group;
pub mod message;
pub mod crypto;
pub mod error;
pub mod protocol;
pub mod key_manager;

#[cfg(feature = "async")]
pub mod async_group;

// Re-export main types for convenience
pub use identity::{Identity, PublicKey, PrivateKey};
pub use group::{PhalanxGroup, GroupConfig, MembershipProof};
pub use message::{GroupMessage, MessageContent, MessageType, EncryptedMessage};
pub use error::{PhalanxError, Result};
pub use protocol::{ProtocolVersion, HandshakeMessage, KeyRotationMessage};
pub use key_manager::{AdvancedKeyManager, KeyBackupStorage, HsmProvider};

#[cfg(feature = "async")]
pub use async_group::AsyncPhalanxGroup;

/// Protocol constants
pub mod constants {
    /// Maximum supported group size
    pub const MAX_GROUP_SIZE: usize = 1000;
    
    /// Key rotation interval in seconds (24 hours by default)
    pub const DEFAULT_KEY_ROTATION_INTERVAL: u64 = 24 * 60 * 60;
    
    /// Maximum message size in bytes (1MB)
    pub const MAX_MESSAGE_SIZE: usize = 1024 * 1024;
    
    /// Current protocol version
    pub const PROTOCOL_VERSION: u8 = 1;
    
    /// Minimum supported protocol version
    pub const MIN_PROTOCOL_VERSION: u8 = 1;
}

/// Cryptographic parameters and algorithms used by Phalanx
pub mod algorithms {
    /// AEAD algorithm used for message encryption
    pub const AEAD: &str = "ChaCha20-Poly1305";
    
    /// Key exchange algorithm
    pub const KEY_EXCHANGE: &str = "X25519";
    
    /// Signature algorithm
    pub const SIGNATURE: &str = "Ed25519";
    
    /// Hash and KDF algorithm
    pub const HASH_KDF: &str = "BLAKE3";
    
    /// Key size in bytes
    pub const KEY_SIZE: usize = 32;
    
    /// Nonce size in bytes
    pub const NONCE_SIZE: usize = 12;
    
    /// Authentication tag size in bytes
    pub const TAG_SIZE: usize = 16;
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_basic_encryption_flow() {
        let identity = Identity::generate();
        let mut group = PhalanxGroup::new(identity);
        
        let content = MessageContent::text("Test message");
        let encrypted = group.encrypt_message(&content).unwrap();
        let decrypted = group.decrypt_message(&encrypted).unwrap();
        
        assert_eq!(decrypted, content);
    }
}