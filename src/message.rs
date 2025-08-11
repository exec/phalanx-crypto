//! Message types and handling for Phalanx Protocol

use crate::{
    error::{PhalanxError, Result},
    identity::{Identity, PublicKey},
    crypto::{SymmetricKey, EncryptedData, hash_multiple},
};
use ed25519_dalek::Signature;
use bytes::Bytes;
use std::time::{SystemTime, UNIX_EPOCH};

#[cfg(feature = "serde")]
use serde::{Serialize, Deserialize};

/// Message types in the Phalanx protocol
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum MessageType {
    /// Regular text message
    Text,
    /// System/control message
    System,
    /// Key rotation message
    KeyRotation,
    /// Member join notification
    MemberJoin,
    /// Member leave notification
    MemberLeave,
    /// Heartbeat/keepalive message
    Heartbeat,
}

/// Encrypted group message with full cryptographic protection
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct GroupMessage {
    /// Message version for protocol evolution
    pub version: u8,
    /// Sender's public key
    pub sender: PublicKey,
    /// Message type
    pub message_type: MessageType,
    /// Message sequence number
    pub sequence: u64,
    /// Timestamp (Unix epoch seconds)
    pub timestamp: u64,
    /// Encrypted message content
    pub encrypted_content: EncryptedData,
    /// Digital signature of the entire message
    pub signature: Signature,
    /// Message ID (hash of content)
    pub message_id: [u8; 32],
}

/// Plaintext message content before encryption
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct MessageContent {
    /// The actual message text or data
    pub data: Bytes,
    /// Optional reply-to message ID
    pub reply_to: Option<[u8; 32]>,
    /// Optional thread ID for threading support
    pub thread_id: Option<[u8; 32]>,
    /// Message metadata (arbitrary key-value pairs)
    pub metadata: std::collections::HashMap<String, String>,
}

/// Encrypted message envelope for wire transmission
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct EncryptedMessage {
    /// Protocol version
    pub version: u8,
    /// Encrypted group message
    pub encrypted_data: EncryptedData,
    /// Sender identification (not encrypted for routing)
    pub sender_id: [u8; 32],
    /// Message timestamp
    pub timestamp: u64,
    /// Message sequence number
    pub sequence: u64,
}

impl GroupMessage {
    /// Create a new group message
    pub fn new(
        sender: &Identity,
        message_type: MessageType,
        content: &MessageContent,
        sequence: u64,
        group_key: &SymmetricKey,
    ) -> Result<Self> {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| PhalanxError::crypto(format!("System time error: {}", e)))?
            .as_secs();
        
        let sender_public = sender.public_key();
        
        // Serialize message content
        let content_bytes = Self::serialize_content(content)?;
        
        // Create AAD (Additional Authenticated Data)
        let aad = Self::create_aad(&sender_public, message_type.clone(), sequence, timestamp);
        
        // Encrypt the content
        let encrypted_content = group_key.encrypt(&content_bytes, &aad)?;
        
        // Calculate message ID
        let message_id = hash_multiple(&[
            &sender_public.id(),
            &sequence.to_be_bytes(),
            &timestamp.to_be_bytes(),
            &encrypted_content.ciphertext,
        ]);
        
        // Create signature payload
        let signature_data = Self::create_signature_data(
            &sender_public,
            &message_type,
            sequence,
            timestamp,
            &encrypted_content,
            &message_id,
        );
        
        // Sign the message
        let signature = sender.sign(&signature_data);
        
        Ok(Self {
            version: crate::constants::PROTOCOL_VERSION,
            sender: sender_public,
            message_type,
            sequence,
            timestamp,
            encrypted_content,
            signature,
            message_id,
        })
    }
    
    /// Decrypt and verify a group message
    pub fn decrypt(&self, group_key: &SymmetricKey) -> Result<MessageContent> {
        // Verify signature first
        self.verify_signature()?;
        
        // Create AAD for decryption
        let aad = Self::create_aad(&self.sender, self.message_type.clone(), self.sequence, self.timestamp);
        
        // Decrypt content
        let decrypted_bytes = group_key.decrypt(&self.encrypted_content, &aad)?;
        
        // Deserialize content
        Self::deserialize_content(&decrypted_bytes)
    }
    
    /// Verify the message signature
    pub fn verify_signature(&self) -> Result<()> {
        let signature_data = Self::create_signature_data(
            &self.sender,
            &self.message_type,
            self.sequence,
            self.timestamp,
            &self.encrypted_content,
            &self.message_id,
        );
        
        self.sender.verify(&signature_data, &self.signature)
    }
    
    /// Check if this message is from a specific sender
    pub fn is_from(&self, public_key: &PublicKey) -> bool {
        self.sender.id() == public_key.id()
    }
    
    /// Get the age of this message in seconds
    pub fn age_seconds(&self) -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
            .saturating_sub(self.timestamp)
    }
    
    /// Create Additional Authenticated Data for encryption
    fn create_aad(sender: &PublicKey, msg_type: MessageType, sequence: u64, timestamp: u64) -> Vec<u8> {
        let mut aad = Vec::new();
        aad.extend_from_slice(&sender.id());
        aad.push(msg_type as u8);
        aad.extend_from_slice(&sequence.to_be_bytes());
        aad.extend_from_slice(&timestamp.to_be_bytes());
        aad.extend_from_slice(b"PHALANX_MSG_V1");
        aad
    }
    
    /// Create signature data
    fn create_signature_data(
        sender: &PublicKey,
        msg_type: &MessageType,
        sequence: u64,
        timestamp: u64,
        encrypted_content: &EncryptedData,
        message_id: &[u8; 32],
    ) -> Vec<u8> {
        let mut sig_data = Vec::new();
        sig_data.push(crate::constants::PROTOCOL_VERSION);
        sig_data.extend_from_slice(&sender.id());
        sig_data.push(msg_type.clone() as u8);
        sig_data.extend_from_slice(&sequence.to_be_bytes());
        sig_data.extend_from_slice(&timestamp.to_be_bytes());
        sig_data.extend_from_slice(&encrypted_content.ciphertext);
        sig_data.extend_from_slice(&encrypted_content.nonce);
        sig_data.extend_from_slice(&encrypted_content.aad_hash);
        sig_data.extend_from_slice(message_id);
        sig_data.extend_from_slice(b"PHALANX_SIG_V1");
        sig_data
    }
    
    /// Serialize message content to bytes
    #[cfg(feature = "serde")]
    fn serialize_content(content: &MessageContent) -> Result<Vec<u8>> {
        serde_json::to_vec(content)
            .map_err(|e| PhalanxError::protocol(format!("Content serialization failed: {}", e)))
    }
    
    /// Serialize message content to bytes (without serde)
    #[cfg(not(feature = "serde"))]
    fn serialize_content(content: &MessageContent) -> Result<Vec<u8>> {
        // Simple binary format without serde
        let mut bytes = Vec::new();
        
        // Data length and data
        let data_len = content.data.len() as u32;
        bytes.extend_from_slice(&data_len.to_be_bytes());
        bytes.extend_from_slice(&content.data);
        
        // Reply-to (32 bytes if present, or 0 marker)
        if let Some(reply_to) = &content.reply_to {
            bytes.push(1); // Present marker
            bytes.extend_from_slice(reply_to);
        } else {
            bytes.push(0); // Not present marker
        }
        
        // Thread ID (32 bytes if present, or 0 marker)
        if let Some(thread_id) = &content.thread_id {
            bytes.push(1); // Present marker
            bytes.extend_from_slice(thread_id);
        } else {
            bytes.push(0); // Not present marker
        }
        
        // Metadata (simplified - just serialize as JSON-like string)
        let metadata_str = format!("{:?}", content.metadata);
        let metadata_bytes = metadata_str.as_bytes();
        let metadata_len = metadata_bytes.len() as u32;
        bytes.extend_from_slice(&metadata_len.to_be_bytes());
        bytes.extend_from_slice(metadata_bytes);
        
        Ok(bytes)
    }
    
    /// Deserialize message content from bytes
    #[cfg(feature = "serde")]
    fn deserialize_content(bytes: &[u8]) -> Result<MessageContent> {
        serde_json::from_slice(bytes)
            .map_err(|e| PhalanxError::protocol(format!("Content deserialization failed: {}", e)))
    }
    
    /// Deserialize message content from bytes (without serde)
    #[cfg(not(feature = "serde"))]
    fn deserialize_content(bytes: &[u8]) -> Result<MessageContent> {
        if bytes.len() < 4 {
            return Err(PhalanxError::protocol("Invalid content format"));
        }
        
        let mut pos = 0;
        
        // Read data length and data
        let data_len = u32::from_be_bytes([bytes[pos], bytes[pos+1], bytes[pos+2], bytes[pos+3]]) as usize;
        pos += 4;
        
        if pos + data_len > bytes.len() {
            return Err(PhalanxError::protocol("Invalid data length"));
        }
        
        let data = Bytes::copy_from_slice(&bytes[pos..pos + data_len]);
        pos += data_len;
        
        // Read reply-to
        if pos >= bytes.len() {
            return Err(PhalanxError::protocol("Truncated content"));
        }
        
        let reply_to = if bytes[pos] == 1 {
            pos += 1;
            if pos + 32 > bytes.len() {
                return Err(PhalanxError::protocol("Invalid reply-to"));
            }
            let mut reply_bytes = [0u8; 32];
            reply_bytes.copy_from_slice(&bytes[pos..pos + 32]);
            pos += 32;
            Some(reply_bytes)
        } else {
            pos += 1;
            None
        };
        
        // Read thread ID
        if pos >= bytes.len() {
            return Err(PhalanxError::protocol("Truncated content"));
        }
        
        let thread_id = if bytes[pos] == 1 {
            pos += 1;
            if pos + 32 > bytes.len() {
                return Err(PhalanxError::protocol("Invalid thread ID"));
            }
            let mut thread_bytes = [0u8; 32];
            thread_bytes.copy_from_slice(&bytes[pos..pos + 32]);
            pos += 32;
            Some(thread_bytes)
        } else {
            pos += 1;
            None
        };
        
        // Read metadata
        if pos + 4 > bytes.len() {
            return Err(PhalanxError::protocol("Truncated metadata length"));
        }
        
        let metadata_len = u32::from_be_bytes([bytes[pos], bytes[pos+1], bytes[pos+2], bytes[pos+3]]) as usize;
        pos += 4;
        
        if pos + metadata_len > bytes.len() {
            return Err(PhalanxError::protocol("Truncated metadata"));
        }
        
        // For simplicity, just create empty metadata in non-serde mode
        let metadata = std::collections::HashMap::new();
        
        Ok(MessageContent {
            data,
            reply_to,
            thread_id,
            metadata,
        })
    }
}

impl MessageContent {
    /// Create a new text message
    pub fn text(message: impl Into<String>) -> Self {
        Self {
            data: Bytes::from(message.into()),
            reply_to: None,
            thread_id: None,
            metadata: std::collections::HashMap::new(),
        }
    }
    
    /// Create a reply to another message
    pub fn reply(message: impl Into<String>, reply_to: [u8; 32]) -> Self {
        Self {
            data: Bytes::from(message.into()),
            reply_to: Some(reply_to),
            thread_id: None,
            metadata: std::collections::HashMap::new(),
        }
    }
    
    /// Add metadata to the message
    pub fn with_metadata(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.metadata.insert(key.into(), value.into());
        self
    }
    
    /// Set thread ID for threaded conversations
    pub fn with_thread(mut self, thread_id: [u8; 32]) -> Self {
        self.thread_id = Some(thread_id);
        self
    }
    
    /// Get message as UTF-8 string
    pub fn as_string(&self) -> Result<String> {
        String::from_utf8(self.data.to_vec())
            .map_err(|e| PhalanxError::protocol(format!("Invalid UTF-8: {}", e)))
    }
}

// Convert MessageType to u8 for serialization
impl From<MessageType> for u8 {
    fn from(msg_type: MessageType) -> u8 {
        match msg_type {
            MessageType::Text => 0,
            MessageType::System => 1,
            MessageType::KeyRotation => 2,
            MessageType::MemberJoin => 3,
            MessageType::MemberLeave => 4,
            MessageType::Heartbeat => 5,
        }
    }
}

impl TryFrom<u8> for MessageType {
    type Error = PhalanxError;
    
    fn try_from(value: u8) -> Result<Self> {
        match value {
            0 => Ok(MessageType::Text),
            1 => Ok(MessageType::System),
            2 => Ok(MessageType::KeyRotation),
            3 => Ok(MessageType::MemberJoin),
            4 => Ok(MessageType::MemberLeave),
            5 => Ok(MessageType::Heartbeat),
            _ => Err(PhalanxError::protocol(format!("Unknown message type: {}", value))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::SymmetricKey;
    
    #[test]
    fn test_message_creation_and_decryption() {
        let sender = Identity::generate();
        let group_key = SymmetricKey::generate();
        let content = MessageContent::text("Hello, world!");
        
        let message = GroupMessage::new(
            &sender,
            MessageType::Text,
            &content,
            1,
            &group_key,
        ).unwrap();
        
        let decrypted = message.decrypt(&group_key).unwrap();
        assert_eq!(decrypted.as_string().unwrap(), "Hello, world!");
    }
    
    #[test]
    fn test_message_signature_verification() {
        let sender = Identity::generate();
        let group_key = SymmetricKey::generate();
        let content = MessageContent::text("Test message");
        
        let message = GroupMessage::new(
            &sender,
            MessageType::Text,
            &content,
            1,
            &group_key,
        ).unwrap();
        
        assert!(message.verify_signature().is_ok());
    }
    
    #[test]
    fn test_reply_messages() {
        let sender = Identity::generate();
        let group_key = SymmetricKey::generate();
        
        let original_id = [1u8; 32];
        let reply_content = MessageContent::reply("This is a reply", original_id);
        
        let message = GroupMessage::new(
            &sender,
            MessageType::Text,
            &reply_content,
            1,
            &group_key,
        ).unwrap();
        
        let decrypted = message.decrypt(&group_key).unwrap();
        assert_eq!(decrypted.reply_to, Some(original_id));
        assert_eq!(decrypted.as_string().unwrap(), "This is a reply");
    }
}