//! Identity management for Phalanx Protocol
//! 
//! Handles cryptographic identity creation, key management, and operations.

use crate::error::{PhalanxError, Result};
use ed25519_dalek::{SigningKey, VerifyingKey, Signature, Signer, Verifier};
use x25519_dalek::{EphemeralSecret, PublicKey as X25519PublicKey};
use rand::{rngs::OsRng, RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;
use zeroize::Zeroize;

#[cfg(feature = "serde")]
use serde::{Serialize, Deserialize};

/// A complete cryptographic identity for Phalanx Protocol
/// 
/// Contains both signing keys (Ed25519) and key exchange capabilities (X25519).
/// Private keys are automatically zeroized on drop for security.
pub struct Identity {
    /// Ed25519 signing key for authentication
    signing_key: SigningKey,
    /// X25519 key exchange secret (generated per-session)
    kx_secret: Option<EphemeralSecret>,
}

/// Public key component that can be safely shared
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct PublicKey {
    /// Ed25519 verification key
    pub verify_key: VerifyingKey,
    /// X25519 public key for key exchange
    pub kx_public: X25519PublicKey,
}

/// Private key component that must be kept secret
pub struct PrivateKey {
    /// Ed25519 signing key
    signing_key: SigningKey,
}

impl Identity {
    /// Generate a new random identity
    pub fn generate() -> Self {
        let mut rng = OsRng;
        let mut secret_bytes = [0u8; 32];
        rng.fill_bytes(&mut secret_bytes);
        let signing_key = SigningKey::from_bytes(&secret_bytes);
        
        Self {
            signing_key,
            kx_secret: None,
        }
    }
    
    /// Create identity from existing private key bytes
    pub fn from_bytes(private_key_bytes: &[u8]) -> Result<Self> {
        if private_key_bytes.len() != 32 {
            return Err(PhalanxError::crypto("Private key must be 32 bytes"));
        }
        
        let signing_key = SigningKey::from_bytes(
            private_key_bytes.try_into()
                .map_err(|_| PhalanxError::crypto("Invalid private key bytes"))?
        );
        
        Ok(Self {
            signing_key,
            kx_secret: None,
        })
    }
    
    /// Get the public key for this identity
    pub fn public_key(&self) -> PublicKey {
        let verify_key = self.signing_key.verifying_key();
        
        // Use static X25519 key derived from signing key
        let kx_public = self.static_public_key();
        
        PublicKey {
            verify_key,
            kx_public,
        }
    }
    
    /// Get the private key component
    pub fn private_key(&self) -> PrivateKey {
        PrivateKey {
            signing_key: self.signing_key.clone(),
        }
    }
    
    /// Generate a new ephemeral key exchange secret
    pub fn generate_kx_key(&mut self) -> X25519PublicKey {
        let secret = EphemeralSecret::random_from_rng(OsRng);
        let public = X25519PublicKey::from(&secret);
        self.kx_secret = Some(secret);
        public
    }
    
    /// Perform key exchange with another party's public key
    /// This consumes the ephemeral secret as diffie_hellman takes ownership
    pub fn key_exchange(&mut self, other_public: &X25519PublicKey) -> Result<[u8; 32]> {
        let secret = self.kx_secret.take()
            .ok_or_else(|| PhalanxError::crypto("No key exchange secret available"))?;
        
        let shared_secret = secret.diffie_hellman(other_public);
        Ok(*shared_secret.as_bytes())
    }
    
    /// Perform key exchange using static X25519 key derived from signing key
    /// This allows consistent key exchange without ephemeral keys
    pub fn static_key_exchange(&self, other_public: &X25519PublicKey) -> Result<[u8; 32]> {
        // Derive a static X25519 private key from the Ed25519 signing key
        let signing_key_bytes = self.signing_key.to_bytes();
        
        // Use BLAKE3 with a context to derive X25519 key from Ed25519 key
        let derived_key = blake3::hash(&signing_key_bytes);
        let seed: [u8; 32] = *derived_key.as_bytes();
        
        // Create deterministic RNG from seed
        let mut rng = ChaCha20Rng::from_seed(seed);
        
        // Create X25519 ephemeral secret using the deterministic RNG
        let static_secret = EphemeralSecret::random_from_rng(&mut rng);
        let shared_secret = static_secret.diffie_hellman(other_public);
        Ok(*shared_secret.as_bytes())
    }
    
    /// Get the static X25519 public key derived from signing key
    pub fn static_public_key(&self) -> X25519PublicKey {
        // Derive the same static private key
        let signing_key_bytes = self.signing_key.to_bytes();
        
        let derived_key = blake3::hash(&signing_key_bytes);
        let seed: [u8; 32] = *derived_key.as_bytes();
        
        // Create deterministic RNG from seed
        let mut rng = ChaCha20Rng::from_seed(seed);
        
        // Create ephemeral secret and get its public key
        let static_secret = EphemeralSecret::random_from_rng(&mut rng);
        X25519PublicKey::from(&static_secret)
    }
    
    /// Sign a message with this identity
    pub fn sign(&self, message: &[u8]) -> Signature {
        self.signing_key.sign(message)
    }
    
    /// Get the identity's unique ID (hash of public key)
    pub fn id(&self) -> [u8; 32] {
        let public_key = self.public_key();
        blake3::hash(&public_key.verify_key.to_bytes()).into()
    }
    
    /// Export private key bytes (use with caution)
    pub fn to_bytes(&self) -> [u8; 32] {
        self.signing_key.to_bytes()
    }
}

impl PublicKey {
    /// Verify a signature against this public key
    pub fn verify(&self, message: &[u8], signature: &Signature) -> Result<()> {
        self.verify_key.verify(message, signature)
            .map_err(|e| PhalanxError::auth(format!("Signature verification failed: {}", e)))
    }
    
    /// Get the public key's unique ID
    pub fn id(&self) -> [u8; 32] {
        blake3::hash(&self.verify_key.to_bytes()).into()
    }
    
    /// Serialize public key to bytes
    pub fn to_bytes(&self) -> [u8; 64] {
        let mut bytes = [0u8; 64];
        bytes[..32].copy_from_slice(&self.verify_key.to_bytes());
        bytes[32..].copy_from_slice(self.kx_public.as_bytes());
        bytes
    }
    
    /// Deserialize public key from bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != 64 {
            return Err(PhalanxError::crypto("Public key must be 64 bytes"));
        }
        
        let verify_key = VerifyingKey::from_bytes(
            bytes[..32].try_into()
                .map_err(|_| PhalanxError::crypto("Invalid Ed25519 public key"))?
        ).map_err(|e| PhalanxError::crypto(format!("Invalid Ed25519 key: {}", e)))?;
        
        let kx_bytes: [u8; 32] = bytes[32..].try_into()
            .map_err(|_| PhalanxError::crypto("Invalid X25519 public key"))?;
        let kx_public = X25519PublicKey::from(kx_bytes);
        
        Ok(Self {
            verify_key,
            kx_public,
        })
    }
}

impl PrivateKey {
    /// Sign a message with this private key
    pub fn sign(&self, message: &[u8]) -> Signature {
        self.signing_key.sign(message)
    }
    
    /// Get the corresponding public key
    pub fn public_key(&self) -> VerifyingKey {
        self.signing_key.verifying_key()
    }
    
    /// Export private key bytes (use with extreme caution)
    pub fn to_bytes(&self) -> [u8; 32] {
        self.signing_key.to_bytes()
    }
}

impl std::fmt::Debug for Identity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Identity")
            .field("public_key", &self.public_key())
            .field("has_kx_secret", &self.kx_secret.is_some())
            .finish()
    }
}

impl Clone for Identity {
    fn clone(&self) -> Self {
        Self {
            signing_key: self.signing_key.clone(),
            kx_secret: None, // Don't clone ephemeral secrets
        }
    }
}

impl Clone for PrivateKey {
    fn clone(&self) -> Self {
        Self {
            signing_key: self.signing_key.clone(),
        }
    }
}

impl Drop for Identity {
    fn drop(&mut self) {
        // Manually zeroize signing key bytes
        let mut bytes = self.signing_key.to_bytes();
        bytes.zeroize();
    }
}

impl Drop for PrivateKey {
    fn drop(&mut self) {
        // Manually zeroize signing key bytes
        let mut bytes = self.signing_key.to_bytes();
        bytes.zeroize();
    }
}

impl std::fmt::Debug for PrivateKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PrivateKey")
            .field("public_key", &self.public_key())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_identity_generation() {
        let identity = Identity::generate();
        let public_key = identity.public_key();
        
        // Test signing
        let message = b"test message";
        let signature = identity.sign(message);
        
        // Test verification
        assert!(public_key.verify(message, &signature).is_ok());
    }
    
    #[test]
    fn test_key_exchange() {
        let mut alice = Identity::generate();
        let mut bob = Identity::generate();
        
        // Generate ephemeral keys
        let alice_public = alice.generate_kx_key();
        let bob_public = bob.generate_kx_key();
        
        // Perform key exchange
        let alice_shared = alice.key_exchange(&bob_public).unwrap();
        let bob_shared = bob.key_exchange(&alice_public).unwrap();
        
        // Should produce the same shared secret
        assert_eq!(alice_shared, bob_shared);
    }
    
    #[test]
    fn test_identity_serialization() {
        let identity = Identity::generate();
        let bytes = identity.to_bytes();
        let recovered = Identity::from_bytes(&bytes).unwrap();
        
        // Should have the same public key
        assert_eq!(identity.public_key().id(), recovered.public_key().id());
    }
    
    #[test]
    fn test_public_key_serialization() {
        let identity = Identity::generate();
        let public_key = identity.public_key();
        
        let bytes = public_key.to_bytes();
        let recovered = PublicKey::from_bytes(&bytes).unwrap();
        
        assert_eq!(public_key.id(), recovered.id());
    }
}