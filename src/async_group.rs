//! Async support for Phalanx groups
//! 
//! This module provides async/await interfaces for Phalanx groups,
//! useful for network operations and concurrent message handling.

#[cfg(feature = "async")]
use tokio::sync::{RwLock, Mutex};
use crate::{
    group::{PhalanxGroup, GroupConfig, GroupMember, MemberRole},
    identity::Identity,
    message::{GroupMessage, MessageContent},
    protocol::HandshakeMessage,
    crypto::SymmetricKey,
    error::Result,
};
use std::sync::Arc;

/// Async wrapper for PhalanxGroup
#[cfg(feature = "async")]
#[derive(Debug)]
pub struct AsyncPhalanxGroup {
    inner: Arc<RwLock<PhalanxGroup>>,
}

#[cfg(feature = "async")]
impl AsyncPhalanxGroup {
    /// Create a new async Phalanx group
    pub fn new(identity: Identity) -> Self {
        Self {
            inner: Arc::new(RwLock::new(PhalanxGroup::new(identity))),
        }
    }
    
    /// Create a new async group with custom configuration
    pub fn with_config(identity: Identity, config: GroupConfig) -> Self {
        Self {
            inner: Arc::new(RwLock::new(PhalanxGroup::with_config(identity, config))),
        }
    }
    
    /// Join an existing group using a handshake
    pub async fn join(
        identity: Identity,
        handshake: HandshakeMessage,
        group_key: SymmetricKey,
    ) -> Result<Self> {
        let group = PhalanxGroup::join(identity, handshake, group_key)?;
        Ok(Self {
            inner: Arc::new(RwLock::new(group)),
        })
    }
    
    /// Get the group ID
    pub async fn group_id(&self) -> [u8; 32] {
        let group = self.inner.read().await;
        *group.group_id()
    }
    
    /// Check if we're an admin or owner
    pub async fn is_admin(&self) -> bool {
        let group = self.inner.read().await;
        group.is_admin()
    }
    
    /// Add a new member to the group
    pub async fn add_member(&self, member_key: crate::identity::PublicKey, role: MemberRole) -> Result<()> {
        let mut group = self.inner.write().await;
        group.add_member(member_key, role)
    }
    
    /// Remove a member from the group
    pub async fn remove_member(&self, member_id: &[u8; 32]) -> Result<()> {
        let mut group = self.inner.write().await;
        group.remove_member(member_id)
    }
    
    /// Encrypt a message for the group
    pub async fn encrypt_message(&self, content: &MessageContent) -> Result<GroupMessage> {
        let mut group = self.inner.write().await;
        group.encrypt_message(content)
    }
    
    /// Decrypt a group message
    pub async fn decrypt_message(&self, message: &GroupMessage) -> Result<MessageContent> {
        let group = self.inner.read().await;
        group.decrypt_message(message)
    }
    
    /// Rotate group encryption keys
    pub async fn rotate_keys(&self) -> Result<crate::protocol::KeyRotationMessage> {
        let mut group = self.inner.write().await;
        group.rotate_keys()
    }
    
    /// Check if key rotation is needed
    pub async fn needs_key_rotation(&self) -> bool {
        let group = self.inner.read().await;
        group.needs_key_rotation()
    }
    
    /// Update member's last seen timestamp
    pub async fn update_member_activity(&self, member_id: &[u8; 32]) {
        let mut group = self.inner.write().await;
        group.update_member_activity(member_id);
    }
    
    /// Set member nickname
    pub async fn set_member_nickname(&self, member_id: &[u8; 32], nickname: Option<String>) -> Result<()> {
        let mut group = self.inner.write().await;
        group.set_member_nickname(member_id, nickname)
    }
    
    /// Get a copy of all group members
    pub async fn members(&self) -> std::collections::HashMap<[u8; 32], GroupMember> {
        let group = self.inner.read().await;
        group.members().clone()
    }
    
    /// Get group statistics
    pub async fn stats(&self) -> crate::group::GroupStats {
        let group = self.inner.read().await;
        group.stats()
    }
    
    /// Create a handshake for joining this group
    pub async fn create_handshake(&self) -> Result<HandshakeMessage> {
        let group = self.inner.read().await;
        group.create_handshake()
    }
    
    /// Get group configuration
    pub async fn config(&self) -> GroupConfig {
        let group = self.inner.read().await;
        group.config().clone()
    }
}

#[cfg(feature = "async")]
impl Clone for AsyncPhalanxGroup {
    fn clone(&self) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
        }
    }
}

#[cfg(all(test, feature = "async"))]
mod tests {
    use super::*;
    use crate::message::MessageContent;
    
    #[tokio::test]
    async fn test_async_group_creation() {
        let identity = Identity::generate();
        let group = AsyncPhalanxGroup::new(identity.clone());
        
        let members = group.members().await;
        assert_eq!(members.len(), 1);
        assert!(members.contains_key(&identity.id()));
        assert!(group.is_admin().await);
    }
    
    #[tokio::test]
    async fn test_async_message_encryption() {
        let identity = Identity::generate();
        let group = AsyncPhalanxGroup::new(identity);
        
        let content = MessageContent::text("Hello, async world!");
        let encrypted = group.encrypt_message(&content).await.unwrap();
        let decrypted = group.decrypt_message(&encrypted).await.unwrap();
        
        assert_eq!(decrypted.as_string().unwrap(), "Hello, async world!");
    }
    
    #[tokio::test]
    async fn test_async_member_management() {
        let admin = Identity::generate();
        let member = Identity::generate();
        
        let group = AsyncPhalanxGroup::new(admin);
        
        // Add member
        group.add_member(member.public_key(), MemberRole::Member).await.unwrap();
        let members = group.members().await;
        assert_eq!(members.len(), 2);
        
        // Remove member
        group.remove_member(&member.id()).await.unwrap();
        let members = group.members().await;
        assert_eq!(members.len(), 1);
    }
}