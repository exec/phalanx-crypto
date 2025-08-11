//! Protocol messages and handshake logic for Phalanx

use crate::{
    error::{PhalanxError, Result},
    identity::{Identity, PublicKey},
    crypto::{EncryptedData, derive_phalanx_key, contexts},
};
use ed25519_dalek::Signature;
use x25519_dalek::PublicKey as X25519PublicKey;
use std::time::{SystemTime, UNIX_EPOCH};

#[cfg(feature = "serde")]
use serde::{Serialize, Deserialize};

/// Protocol version enumeration
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum ProtocolVersion {
    /// Version 1 - Initial Phalanx protocol
    V1 = 1,
}

impl ProtocolVersion {
    /// Get the current protocol version
    pub fn current() -> Self {
        Self::V1
    }
    
    /// Check if this version is compatible with another
    pub fn is_compatible_with(self, other: Self) -> bool {
        self == other // For now, exact match required
    }
}

impl TryFrom<u8> for ProtocolVersion {
    type Error = PhalanxError;
    
    fn try_from(value: u8) -> Result<Self> {
        match value {
            1 => Ok(Self::V1),
            _ => Err(PhalanxError::version(format!("Unsupported protocol version: {}", value))),
        }
    }
}

impl From<ProtocolVersion> for u8 {
    fn from(version: ProtocolVersion) -> u8 {
        version as u8
    }
}

/// Initial handshake message for group joining
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct HandshakeMessage {
    /// Protocol version
    pub version: ProtocolVersion,
    /// Sender's public key
    pub sender_key: PublicKey,
    /// Ephemeral key for this handshake
    pub ephemeral_key: X25519PublicKey,
    /// Timestamp of the handshake
    pub timestamp: u64,
    /// Encrypted handshake payload
    pub encrypted_payload: EncryptedData,
    /// Signature of the handshake
    pub signature: Signature,
}

/// Handshake payload content
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct HandshakePayload {
    /// Group ID being joined
    pub group_id: [u8; 32],
    /// Supported capabilities
    pub capabilities: Vec<String>,
    /// Client information
    pub client_info: String,
    /// Proof of membership (if required)
    pub membership_proof: Option<Vec<u8>>,
    /// Encrypted group key for secure key sharing
    pub encrypted_group_key: Option<Vec<u8>>,
}

/// Key rotation message for forward secrecy
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct KeyRotationMessage {
    /// Protocol version
    pub version: ProtocolVersion,
    /// Rotation sequence number
    pub sequence: u64,
    /// Timestamp of rotation
    pub timestamp: u64,
    /// New ephemeral keys for each member
    pub member_keys: Vec<(PublicKey, X25519PublicKey)>,
    /// Signature by group admin
    pub signature: Signature,
}

/// Group membership change notification
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct MembershipChange {
    /// Change type
    pub change_type: MembershipChangeType,
    /// Member's public key
    pub member_key: PublicKey,
    /// Timestamp of change
    pub timestamp: u64,
    /// Admin signature
    pub signature: Signature,
}

/// Types of membership changes
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum MembershipChangeType {
    /// Member joined the group
    Join,
    /// Member left the group
    Leave,
    /// Member was removed from the group
    Remove,
    /// Member role changed
    RoleChange,
}

impl HandshakeMessage {
    /// Create a new handshake message
    pub fn new(
        sender: &Identity,
        group_id: [u8; 32],
        capabilities: Vec<String>,
        client_info: String,
    ) -> Result<Self> {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| PhalanxError::crypto(format!("System time error: {}", e)))?
            .as_secs();
        
        let sender_key = sender.public_key();
        
        // Generate ephemeral key for this handshake
        let mut sender_mut = sender.clone();
        let ephemeral_key = sender_mut.generate_kx_key();
        
        // Create handshake payload
        let payload = HandshakePayload {
            group_id,
            capabilities,
            client_info,
            membership_proof: None,
            encrypted_group_key: None,
        };
        
        // Derive handshake key from sender's identity
        let handshake_key = derive_phalanx_key(
            &sender.id(),
            b"PHALANX_HANDSHAKE",
            contexts::KEY_EXCHANGE,
        );
        
        // Encrypt payload
        let payload_bytes = Self::serialize_payload(&payload)?;
        let aad = Self::create_handshake_aad(&sender_key, &ephemeral_key, timestamp);
        let encrypted_payload = handshake_key.encrypt(&payload_bytes, &aad)?;
        
        // Sign the handshake
        let signature_data = Self::create_signature_data(
            ProtocolVersion::current(),
            &sender_key,
            &ephemeral_key,
            timestamp,
            &encrypted_payload,
        );
        let signature = sender.sign(&signature_data);
        
        Ok(Self {
            version: ProtocolVersion::current(),
            sender_key,
            ephemeral_key,
            timestamp,
            encrypted_payload,
            signature,
        })
    }
    
    /// Create a handshake message with encrypted group key for secure key sharing
    pub fn new_with_group_key(
        sender: &mut Identity,
        recipient_public_key: &PublicKey,
        group_id: [u8; 32],
        capabilities: Vec<String>,
        client_info: String,
        group_key: &crate::crypto::SymmetricKey,
    ) -> Result<Self> {
        use crate::crypto::{derive_phalanx_key, contexts};
        
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| PhalanxError::crypto(format!("System time error: {}", e)))?
            .as_secs();
        
        let sender_key = sender.public_key();
        
        // Generate ephemeral key for this handshake
        let ephemeral_key = sender.generate_kx_key();
        
        // Perform X25519 key exchange to get shared secret
        let shared_secret = sender.key_exchange(&recipient_public_key.kx_public)?;
        
        // Derive encryption key from shared secret
        let encryption_key = derive_phalanx_key(
            &shared_secret,
            b"PHALANX_GROUP_KEY",
            contexts::KEY_EXCHANGE,
        );
        
        // Encrypt the group key
        let group_key_bytes = group_key.as_bytes();
        let aad = b"PHALANX_GROUP_KEY_V1";
        let encrypted_group_key_data = encryption_key.encrypt(group_key_bytes, aad)?;
        let encrypted_group_key_bytes = serde_json::to_vec(&encrypted_group_key_data)
            .map_err(|e| PhalanxError::crypto(format!("Group key encryption serialization failed: {}", e)))?;
        
        // Create handshake payload with encrypted group key
        let payload = HandshakePayload {
            group_id,
            capabilities,
            client_info,
            membership_proof: None,
            encrypted_group_key: Some(encrypted_group_key_bytes),
        };
        
        // Derive handshake key from sender's identity
        let handshake_key = derive_phalanx_key(
            &sender.id(),
            b"PHALANX_HANDSHAKE",
            contexts::KEY_EXCHANGE,
        );
        
        // Encrypt payload
        let payload_bytes = Self::serialize_payload(&payload)?;
        let aad = Self::create_handshake_aad(&sender_key, &ephemeral_key, timestamp);
        let encrypted_payload = handshake_key.encrypt(&payload_bytes, &aad)?;
        
        // Sign the handshake
        let signature_data = Self::create_signature_data(
            ProtocolVersion::current(),
            &sender_key,
            &ephemeral_key,
            timestamp,
            &encrypted_payload,
        );
        let signature = sender.sign(&signature_data);
        
        Ok(Self {
            version: ProtocolVersion::current(),
            sender_key,
            ephemeral_key,
            timestamp,
            encrypted_payload,
            signature,
        })
    }
    
    /// Extract group key from handshake message
    pub fn extract_group_key(&self, recipient: &mut Identity) -> Result<Option<crate::crypto::SymmetricKey>> {
        use crate::crypto::{derive_phalanx_key, contexts};
        
        // First verify and decrypt the handshake payload
        let payload = self.verify_and_decrypt()?;
        
        if let Some(encrypted_group_key_bytes) = payload.encrypted_group_key {
            // Perform key exchange to get shared secret using sender's ephemeral key
            let shared_secret = recipient.static_key_exchange(&self.ephemeral_key)?;
            
            // Derive decryption key from shared secret
            let decryption_key = derive_phalanx_key(
                &shared_secret,
                b"PHALANX_GROUP_KEY",
                contexts::KEY_EXCHANGE,
            );
            
            // Deserialize encrypted data
            let encrypted_group_key_data: crate::crypto::EncryptedData = 
                serde_json::from_slice(&encrypted_group_key_bytes)
                    .map_err(|e| PhalanxError::crypto(format!("Group key decryption deserialization failed: {}", e)))?;
            
            // Decrypt the group key
            let aad = b"PHALANX_GROUP_KEY_V1";
            let group_key_bytes = decryption_key.decrypt(&encrypted_group_key_data, aad)?;
            
            // Convert back to SymmetricKey
            if group_key_bytes.len() != 32 {
                return Err(PhalanxError::crypto("Invalid group key size"));
            }
            let mut key_array = [0u8; 32];
            key_array.copy_from_slice(&group_key_bytes);
            let group_key = crate::crypto::SymmetricKey::from_bytes(key_array)?;
            
            Ok(Some(group_key))
        } else {
            Ok(None)
        }
    }
    
    /// Verify and decrypt a handshake message
    pub fn verify_and_decrypt(&self) -> Result<HandshakePayload> {
        // Verify signature first
        let signature_data = Self::create_signature_data(
            self.version,
            &self.sender_key,
            &self.ephemeral_key,
            self.timestamp,
            &self.encrypted_payload,
        );
        
        self.sender_key.verify(&signature_data, &self.signature)?;
        
        // Derive handshake key
        let handshake_key = derive_phalanx_key(
            &self.sender_key.id(),
            b"PHALANX_HANDSHAKE",
            contexts::KEY_EXCHANGE,
        );
        
        // Decrypt payload
        let aad = Self::create_handshake_aad(&self.sender_key, &self.ephemeral_key, self.timestamp);
        let decrypted_bytes = handshake_key.decrypt(&self.encrypted_payload, &aad)?;
        
        // Deserialize payload
        Self::deserialize_payload(&decrypted_bytes)
    }
    
    /// Check if handshake is recent (within last 5 minutes)
    pub fn is_recent(&self) -> bool {
        if let Ok(now) = SystemTime::now().duration_since(UNIX_EPOCH) {
            let age = now.as_secs().saturating_sub(self.timestamp);
            age <= 300 // 5 minutes
        } else {
            false
        }
    }
    
    fn create_handshake_aad(sender: &PublicKey, ephemeral: &X25519PublicKey, timestamp: u64) -> Vec<u8> {
        let mut aad = Vec::new();
        aad.extend_from_slice(&sender.id());
        aad.extend_from_slice(ephemeral.as_bytes());
        aad.extend_from_slice(&timestamp.to_be_bytes());
        aad.extend_from_slice(b"PHALANX_HANDSHAKE_V1");
        aad
    }
    
    fn create_signature_data(
        version: ProtocolVersion,
        sender: &PublicKey,
        ephemeral: &X25519PublicKey,
        timestamp: u64,
        encrypted_payload: &EncryptedData,
    ) -> Vec<u8> {
        let mut data = Vec::new();
        data.push(version.into());
        data.extend_from_slice(&sender.id());
        data.extend_from_slice(ephemeral.as_bytes());
        data.extend_from_slice(&timestamp.to_be_bytes());
        data.extend_from_slice(&encrypted_payload.ciphertext);
        data.extend_from_slice(&encrypted_payload.nonce);
        data.extend_from_slice(&encrypted_payload.aad_hash);
        data.extend_from_slice(b"PHALANX_HANDSHAKE_SIG_V1");
        data
    }
    
    #[cfg(feature = "serde")]
    fn serialize_payload(payload: &HandshakePayload) -> Result<Vec<u8>> {
        serde_json::to_vec(payload)
            .map_err(|e| PhalanxError::protocol(format!("Handshake payload serialization failed: {}", e)))
    }
    
    #[cfg(not(feature = "serde"))]
    fn serialize_payload(payload: &HandshakePayload) -> Result<Vec<u8>> {
        let mut bytes = Vec::new();
        
        // Group ID
        bytes.extend_from_slice(&payload.group_id);
        
        // Capabilities count and data
        let cap_count = payload.capabilities.len() as u32;
        bytes.extend_from_slice(&cap_count.to_be_bytes());
        for cap in &payload.capabilities {
            let cap_bytes = cap.as_bytes();
            let cap_len = cap_bytes.len() as u32;
            bytes.extend_from_slice(&cap_len.to_be_bytes());
            bytes.extend_from_slice(cap_bytes);
        }
        
        // Client info
        let info_bytes = payload.client_info.as_bytes();
        let info_len = info_bytes.len() as u32;
        bytes.extend_from_slice(&info_len.to_be_bytes());
        bytes.extend_from_slice(info_bytes);
        
        // Membership proof
        if let Some(proof) = &payload.membership_proof {
            bytes.push(1); // Present
            let proof_len = proof.len() as u32;
            bytes.extend_from_slice(&proof_len.to_be_bytes());
            bytes.extend_from_slice(proof);
        } else {
            bytes.push(0); // Not present
        }
        
        // Encrypted group key
        if let Some(encrypted_key) = &payload.encrypted_group_key {
            bytes.push(1); // Present
            let key_len = encrypted_key.len() as u32;
            bytes.extend_from_slice(&key_len.to_be_bytes());
            bytes.extend_from_slice(encrypted_key);
        } else {
            bytes.push(0); // Not present
        }
        
        Ok(bytes)
    }
    
    #[cfg(feature = "serde")]
    fn deserialize_payload(bytes: &[u8]) -> Result<HandshakePayload> {
        serde_json::from_slice(bytes)
            .map_err(|e| PhalanxError::protocol(format!("Handshake payload deserialization failed: {}", e)))
    }
    
    #[cfg(not(feature = "serde"))]
    fn deserialize_payload(bytes: &[u8]) -> Result<HandshakePayload> {
        if bytes.len() < 32 + 4 {
            return Err(PhalanxError::protocol("Invalid handshake payload"));
        }
        
        let mut pos = 0;
        
        // Group ID
        let mut group_id = [0u8; 32];
        group_id.copy_from_slice(&bytes[pos..pos + 32]);
        pos += 32;
        
        // Capabilities
        let cap_count = u32::from_be_bytes([bytes[pos], bytes[pos+1], bytes[pos+2], bytes[pos+3]]) as usize;
        pos += 4;
        
        let mut capabilities = Vec::new();
        for _ in 0..cap_count {
            if pos + 4 > bytes.len() {
                return Err(PhalanxError::protocol("Truncated capability"));
            }
            
            let cap_len = u32::from_be_bytes([bytes[pos], bytes[pos+1], bytes[pos+2], bytes[pos+3]]) as usize;
            pos += 4;
            
            if pos + cap_len > bytes.len() {
                return Err(PhalanxError::protocol("Truncated capability data"));
            }
            
            let cap_str = String::from_utf8(bytes[pos..pos + cap_len].to_vec())
                .map_err(|_| PhalanxError::protocol("Invalid UTF-8 in capability"))?;
            capabilities.push(cap_str);
            pos += cap_len;
        }
        
        // Client info
        if pos + 4 > bytes.len() {
            return Err(PhalanxError::protocol("Truncated client info length"));
        }
        
        let info_len = u32::from_be_bytes([bytes[pos], bytes[pos+1], bytes[pos+2], bytes[pos+3]]) as usize;
        pos += 4;
        
        if pos + info_len > bytes.len() {
            return Err(PhalanxError::protocol("Truncated client info"));
        }
        
        let client_info = String::from_utf8(bytes[pos..pos + info_len].to_vec())
            .map_err(|_| PhalanxError::protocol("Invalid UTF-8 in client info"))?;
        pos += info_len;
        
        // Membership proof
        if pos >= bytes.len() {
            return Err(PhalanxError::protocol("Truncated membership proof marker"));
        }
        
        let membership_proof = if bytes[pos] == 1 {
            pos += 1;
            if pos + 4 > bytes.len() {
                return Err(PhalanxError::protocol("Truncated proof length"));
            }
            
            let proof_len = u32::from_be_bytes([bytes[pos], bytes[pos+1], bytes[pos+2], bytes[pos+3]]) as usize;
            pos += 4;
            
            if pos + proof_len > bytes.len() {
                return Err(PhalanxError::protocol("Truncated proof data"));
            }
            
            Some(bytes[pos..pos + proof_len].to_vec())
        } else {
            pos += 1;
            None
        };
        
        // Encrypted group key
        let encrypted_group_key = if pos < bytes.len() && bytes[pos] == 1 {
            pos += 1;
            if pos + 4 > bytes.len() {
                return Err(PhalanxError::protocol("Truncated encrypted group key length"));
            }
            
            let key_len = u32::from_be_bytes([bytes[pos], bytes[pos+1], bytes[pos+2], bytes[pos+3]]) as usize;
            pos += 4;
            
            if pos + key_len > bytes.len() {
                return Err(PhalanxError::protocol("Truncated encrypted group key data"));
            }
            
            Some(bytes[pos..pos + key_len].to_vec())
        } else {
            None
        };
        
        Ok(HandshakePayload {
            group_id,
            capabilities,
            client_info,
            membership_proof,
            encrypted_group_key,
        })
    }
}

impl KeyRotationMessage {
    /// Create a new key rotation message
    pub fn new(
        admin: &Identity,
        sequence: u64,
        member_keys: Vec<(PublicKey, X25519PublicKey)>,
    ) -> Result<Self> {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| PhalanxError::crypto(format!("System time error: {}", e)))?
            .as_secs();
        
        // Sign the rotation message
        let signature_data = Self::create_signature_data(sequence, timestamp, &member_keys);
        let signature = admin.sign(&signature_data);
        
        Ok(Self {
            version: ProtocolVersion::current(),
            sequence,
            timestamp,
            member_keys,
            signature,
        })
    }
    
    /// Verify key rotation message
    pub fn verify(&self, admin_key: &PublicKey) -> Result<()> {
        let signature_data = Self::create_signature_data(self.sequence, self.timestamp, &self.member_keys);
        admin_key.verify(&signature_data, &self.signature)
    }
    
    fn create_signature_data(
        sequence: u64,
        timestamp: u64,
        member_keys: &[(PublicKey, X25519PublicKey)],
    ) -> Vec<u8> {
        let mut data = Vec::new();
        data.push(ProtocolVersion::current().into());
        data.extend_from_slice(&sequence.to_be_bytes());
        data.extend_from_slice(&timestamp.to_be_bytes());
        
        for (pub_key, ephemeral) in member_keys {
            data.extend_from_slice(&pub_key.id());
            data.extend_from_slice(ephemeral.as_bytes());
        }
        
        data.extend_from_slice(b"PHALANX_KEY_ROTATION_V1");
        data
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_handshake_message() {
        let sender = Identity::generate();
        let group_id = [1u8; 32];
        let capabilities = vec!["phalanx/v1".to_string(), "threading".to_string()];
        let client_info = "test-client/1.0".to_string();
        
        let handshake = HandshakeMessage::new(
            &sender,
            group_id,
            capabilities.clone(),
            client_info.clone(),
        ).unwrap();
        
        let payload = handshake.verify_and_decrypt().unwrap();
        
        assert_eq!(payload.group_id, group_id);
        assert_eq!(payload.capabilities, capabilities);
        assert_eq!(payload.client_info, client_info);
    }
    
    #[test]
    fn test_key_rotation() {
        let admin = Identity::generate();
        let member1 = Identity::generate();
        let member2 = Identity::generate();
        
        let mut member1_clone = member1.clone();
        let mut member2_clone = member2.clone();
        
        let member_keys = vec![
            (member1.public_key(), member1_clone.generate_kx_key()),
            (member2.public_key(), member2_clone.generate_kx_key()),
        ];
        
        let rotation = KeyRotationMessage::new(&admin, 1, member_keys).unwrap();
        
        assert!(rotation.verify(&admin.public_key()).is_ok());
    }
    
    #[test]
    fn test_protocol_version_compatibility() {
        let v1 = ProtocolVersion::V1;
        assert!(v1.is_compatible_with(ProtocolVersion::V1));
        
        let converted: u8 = v1.into();
        let back: ProtocolVersion = converted.try_into().unwrap();
        assert_eq!(v1, back);
    }
}