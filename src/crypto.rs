//! Core cryptographic primitives for Phalanx Protocol

use crate::error::{PhalanxError, Result};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce, aead::{Aead, KeyInit}};
use blake3::Hasher;
use hkdf::Hkdf;
use sha2::Sha256;
use rand::{RngCore, rngs::OsRng};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Key derivation context strings
pub mod contexts {
    /// Context for deriving group encryption keys
    pub const GROUP_KEY: &str = "PHALANX_GROUP_KEY_V1";
    /// Context for deriving message keys
    pub const MESSAGE_KEY: &str = "PHALANX_MESSAGE_KEY_V1";
    /// Context for deriving authentication keys
    pub const AUTH_KEY: &str = "PHALANX_AUTH_KEY_V1";
    /// Context for deriving key exchange keys
    pub const KEY_EXCHANGE: &str = "PHALANX_KEY_EXCHANGE_V1";
    /// Context for key derivation
    pub const KEY_DERIVATION: &str = "PHALANX_KEY_DERIVE_V1";
}

/// Symmetric encryption key that is automatically zeroized
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SymmetricKey([u8; 32]);

/// Encrypted data with associated authentication tag
#[derive(Debug, Clone)]
pub struct EncryptedData {
    /// The ciphertext
    pub ciphertext: Vec<u8>,
    /// The nonce used for encryption
    pub nonce: [u8; 12],
    /// Additional authenticated data hash
    pub aad_hash: [u8; 32],
}

impl SymmetricKey {
    /// Generate a new random symmetric key
    pub fn generate() -> Self {
        let mut key = [0u8; 32];
        OsRng.fill_bytes(&mut key);
        Self(key)
    }
    
    /// Create key from bytes
    pub fn from_bytes(bytes: [u8; 32]) -> Result<Self> {
        Ok(Self(bytes))
    }
    
    /// Get key bytes (use with caution)
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
    
    /// Encrypt data with associated authenticated data
    pub fn encrypt(&self, plaintext: &[u8], aad: &[u8]) -> Result<EncryptedData> {
        // Generate random nonce
        let mut nonce_bytes = [0u8; 12];
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);
        
        // Create cipher
        let cipher = ChaCha20Poly1305::new(Key::from_slice(&self.0));
        
        // Encrypt with AAD
        let ciphertext = cipher.encrypt(nonce, aead::Payload {
            msg: plaintext,
            aad,
        })?;
        
        // Hash the AAD for verification
        let aad_hash = blake3::hash(aad).into();
        
        Ok(EncryptedData {
            ciphertext,
            nonce: nonce_bytes,
            aad_hash,
        })
    }
    
    /// Decrypt data and verify associated authenticated data
    pub fn decrypt(&self, data: &EncryptedData, aad: &[u8]) -> Result<Vec<u8>> {
        // Verify AAD hash
        let expected_hash = blake3::hash(aad);
        if data.aad_hash != *expected_hash.as_bytes() {
            return Err(PhalanxError::auth("AAD hash mismatch"));
        }
        
        // Create cipher and decrypt
        let cipher = ChaCha20Poly1305::new(Key::from_slice(&self.0));
        let nonce = Nonce::from_slice(&data.nonce);
        
        let plaintext = cipher.decrypt(nonce, aead::Payload {
            msg: &data.ciphertext,
            aad,
        })?;
        
        Ok(plaintext)
    }
}

/// Key derivation function using BLAKE3
pub fn derive_phalanx_key(ikm: &[u8], _salt: &[u8], info: &str) -> SymmetricKey {
    let derived = blake3::derive_key(info, ikm);
    SymmetricKey(derived)
}

/// Key derivation using HKDF-SHA256
pub fn hkdf_expand(prk: &[u8], info: &[u8], length: usize) -> Result<Vec<u8>> {
    let hk = Hkdf::<Sha256>::from_prk(prk)
        .map_err(|e| PhalanxError::key_derivation(format!("HKDF PRK invalid: {}", e)))?;
    
    let mut output = vec![0u8; length];
    hk.expand(info, &mut output)
        .map_err(|e| PhalanxError::key_derivation(format!("HKDF expand failed: {}", e)))?;
    
    Ok(output)
}

/// Extract key material using HKDF-SHA256
pub fn hkdf_extract(salt: &[u8], ikm: &[u8]) -> [u8; 32] {
    let (prk, _) = Hkdf::<Sha256>::extract(Some(salt), ikm);
    prk.into()
}

/// Secure hash function
pub fn hash(data: &[u8]) -> [u8; 32] {
    blake3::hash(data).into()
}

/// Secure hash of multiple inputs
pub fn hash_multiple(inputs: &[&[u8]]) -> [u8; 32] {
    let mut hasher = Hasher::new();
    for input in inputs {
        hasher.update(input);
    }
    hasher.finalize().into()
}

/// Generate a random nonce
pub fn generate_nonce() -> [u8; 12] {
    let mut nonce = [0u8; 12];
    OsRng.fill_bytes(&mut nonce);
    nonce
}

/// Generate random bytes
pub fn random_bytes(len: usize) -> Vec<u8> {
    let mut bytes = vec![0u8; len];
    OsRng.fill_bytes(&mut bytes);
    bytes
}

/// Constant-time comparison
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    use subtle::ConstantTimeEq;
    a.ct_eq(b).into()
}

impl std::fmt::Debug for SymmetricKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SymmetricKey")
            .field("key", &"[REDACTED]")
            .finish()
    }
}

#[cfg(feature = "serde")]
mod serde_impl {
    use super::*;
    use serde::{Serialize, Deserialize};
    
    impl Serialize for SymmetricKey {
        fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
        where
            S: serde::Serializer,
        {
            serializer.serialize_str(&base64::encode(self.as_bytes()))
        }
    }
    
    impl<'de> Deserialize<'de> for SymmetricKey {
        fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
        where
            D: serde::Deserializer<'de>,
        {
            use serde::de::{self, Visitor};
            
            struct SymmetricKeyVisitor;
            
            impl<'de> Visitor<'de> for SymmetricKeyVisitor {
                type Value = SymmetricKey;
                
                fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                    formatter.write_str("a base64 encoded 32-byte key")
                }
                
                fn visit_str<E>(self, value: &str) -> std::result::Result<SymmetricKey, E>
                where
                    E: de::Error,
                {
                    let decoded = base64::decode(value)
                        .map_err(de::Error::custom)?;
                    if decoded.len() != 32 {
                        return Err(de::Error::custom("Invalid key length"));
                    }
                    let mut key_bytes = [0u8; 32];
                    key_bytes.copy_from_slice(&decoded);
                    SymmetricKey::from_bytes(key_bytes)
                        .map_err(de::Error::custom)
                }
            }
            
            deserializer.deserialize_str(SymmetricKeyVisitor)
        }
    }
    
    impl Serialize for EncryptedData {
        fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
        where
            S: serde::Serializer,
        {
            use serde::ser::SerializeStruct;
            
            let mut state = serializer.serialize_struct("EncryptedData", 3)?;
            state.serialize_field("ciphertext", &base64::encode(&self.ciphertext))?;
            state.serialize_field("nonce", &base64::encode(&self.nonce))?;
            state.serialize_field("aad_hash", &base64::encode(&self.aad_hash))?;
            state.end()
        }
    }
    
    impl<'de> Deserialize<'de> for EncryptedData {
        fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
        where
            D: serde::Deserializer<'de>,
        {
            use serde::de::{self, Visitor, MapAccess};
            
            struct EncryptedDataVisitor;
            
            impl<'de> Visitor<'de> for EncryptedDataVisitor {
                type Value = EncryptedData;
                
                fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                    formatter.write_str("struct EncryptedData")
                }
                
                fn visit_map<V>(self, mut map: V) -> std::result::Result<EncryptedData, V::Error>
                where
                    V: MapAccess<'de>,
                {
                    let mut ciphertext = None;
                    let mut nonce = None;
                    let mut aad_hash = None;
                    
                    while let Some(key) = map.next_key()? {
                        match key {
                            "ciphertext" => {
                                let encoded: String = map.next_value()?;
                                ciphertext = Some(base64::decode(&encoded)
                                    .map_err(de::Error::custom)?);
                            }
                            "nonce" => {
                                let encoded: String = map.next_value()?;
                                let decoded = base64::decode(&encoded)
                                    .map_err(de::Error::custom)?;
                                if decoded.len() != 12 {
                                    return Err(de::Error::custom("Invalid nonce length"));
                                }
                                let mut n = [0u8; 12];
                                n.copy_from_slice(&decoded);
                                nonce = Some(n);
                            }
                            "aad_hash" => {
                                let encoded: String = map.next_value()?;
                                let decoded = base64::decode(&encoded)
                                    .map_err(de::Error::custom)?;
                                if decoded.len() != 32 {
                                    return Err(de::Error::custom("Invalid AAD hash length"));
                                }
                                let mut h = [0u8; 32];
                                h.copy_from_slice(&decoded);
                                aad_hash = Some(h);
                            }
                            _ => {
                                let _: serde::de::IgnoredAny = map.next_value()?;
                            }
                        }
                    }
                    
                    let ciphertext = ciphertext.ok_or_else(|| de::Error::missing_field("ciphertext"))?;
                    let nonce = nonce.ok_or_else(|| de::Error::missing_field("nonce"))?;
                    let aad_hash = aad_hash.ok_or_else(|| de::Error::missing_field("aad_hash"))?;
                    
                    Ok(EncryptedData {
                        ciphertext,
                        nonce,
                        aad_hash,
                    })
                }
            }
            
            deserializer.deserialize_struct("EncryptedData", &["ciphertext", "nonce", "aad_hash"], EncryptedDataVisitor)
        }
    }
}

// Add missing import for aead module
use chacha20poly1305::aead;

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_symmetric_encryption() {
        let key = SymmetricKey::generate();
        let plaintext = b"Hello, world!";
        let aad = b"additional data";
        
        let encrypted = key.encrypt(plaintext, aad).unwrap();
        let decrypted = key.decrypt(&encrypted, aad).unwrap();
        
        assert_eq!(decrypted, plaintext);
    }
    
    #[test]
    fn test_key_derivation() {
        let ikm = b"input key material";
        let salt = b"salt";
        let info = contexts::GROUP_KEY;
        
        let key1 = derive_phalanx_key(ikm, salt, info);
        let key2 = derive_phalanx_key(ikm, salt, info);
        
        // Should be deterministic
        assert_eq!(key1.as_bytes(), key2.as_bytes());
    }
    
    #[test]
    fn test_hkdf() {
        let ikm = b"input key material";
        let salt = b"salt";
        let info = b"info";
        
        let prk = hkdf_extract(salt, ikm);
        let okm = hkdf_expand(&prk, info, 32).unwrap();
        
        assert_eq!(okm.len(), 32);
    }
    
    #[test]
    fn test_hash_functions() {
        let data = b"test data";
        let hash1 = hash(data);
        let hash2 = hash(data);
        
        assert_eq!(hash1, hash2);
        
        let multi_hash = hash_multiple(&[b"part1", b"part2"]);
        let single_hash = hash(b"part1part2");
        
        // These should be the same since hash_multiple just concatenates
        assert_eq!(multi_hash, single_hash);
    }
}