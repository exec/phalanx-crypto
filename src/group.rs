//! Group management and encryption for Phalanx Protocol

use crate::{
    error::{PhalanxError, Result},
    identity::{Identity, PublicKey},
    message::{GroupMessage, MessageContent, MessageType},
    protocol::{ProtocolVersion, HandshakeMessage, KeyRotationMessage},
    crypto::{SymmetricKey, hash_multiple},
    key_manager::{AdvancedKeyManager, KeySet, RotationPolicy},
};
use std::collections::{HashMap, HashSet};
use std::time::{SystemTime, UNIX_EPOCH};
use x25519_dalek::PublicKey as X25519PublicKey;

#[cfg(feature = "serde")]
use serde::{Serialize, Deserialize};

/// Configuration for a Phalanx group
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct GroupConfig {
    /// Maximum number of members allowed
    pub max_members: usize,
    /// Key rotation interval in seconds
    pub key_rotation_interval: u64,
    /// Whether messages are stored persistently
    pub persistent_storage: bool,
    /// Group visibility (public/private/invite-only)
    pub visibility: GroupVisibility,
    /// Admin permissions required for certain operations
    pub admin_only_operations: Vec<GroupOperation>,
}

/// Group visibility levels
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum GroupVisibility {
    /// Anyone can discover and join
    Public,
    /// Discoverable but invite required
    Private,
    /// Completely hidden, invite only
    InviteOnly,
}

/// Operations that can be restricted to admins
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum GroupOperation {
    /// Adding new members
    AddMember,
    /// Removing members
    RemoveMember,
    /// Changing group settings
    ChangeSettings,
    /// Rotating encryption keys
    RotateKeys,
    /// Deleting messages
    DeleteMessage,
}

/// Member role in the group
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum MemberRole {
    /// Regular group member
    Member,
    /// Group administrator
    Admin,
    /// Group owner (highest privileges)
    Owner,
    /// Moderator (limited admin privileges)
    Moderator,
    /// Guest (read-only access)
    Guest,
}

/// Member status in the group
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum MemberStatus {
    /// Active member
    Active,
    /// Temporarily muted
    Muted,
    /// Banned from participation
    Banned,
    /// Pending approval to join
    Pending,
    /// Temporarily suspended
    Suspended,
}

/// Fine-grained permissions for group members
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum GroupPermission {
    /// Can send messages
    SendMessages,
    /// Can delete own messages
    DeleteOwnMessages,
    /// Can delete any messages
    DeleteAnyMessages,
    /// Can invite new members
    InviteMembers,
    /// Can remove members
    RemoveMembers,
    /// Can modify group settings
    ModifySettings,
    /// Can manage member roles
    ManageRoles,
    /// Can initiate key rotation
    RotateKeys,
    /// Can view group audit logs
    ViewAuditLogs,
    /// Can manage group bans
    ManageBans,
    /// Can create channels/subgroups
    CreateChannels,
}

/// Member presence information
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum MemberPresence {
    /// Online and active
    Online,
    /// Away but available
    Away,
    /// Do not disturb
    DoNotDisturb,
    /// Offline
    Offline,
    /// Invisible (appears offline to others)
    Invisible,
}

/// Information about a group member
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct GroupMember {
    /// Member's public key
    pub public_key: PublicKey,
    /// Current ephemeral key for key exchange
    pub ephemeral_key: Option<X25519PublicKey>,
    /// Member's role in the group
    pub role: MemberRole,
    /// When the member joined
    pub joined_at: u64,
    /// Last seen timestamp
    pub last_seen: Option<u64>,
    /// Member nickname (optional)
    pub nickname: Option<String>,
    /// Member status
    pub status: MemberStatus,
    /// Custom permissions for this member
    pub permissions: Vec<GroupPermission>,
    /// Member's presence information
    pub presence: MemberPresence,
}

/// Proof of membership for joining restricted groups
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct MembershipProof {
    /// Proof type identifier
    pub proof_type: String,
    /// Proof data (format depends on type)
    pub proof_data: Vec<u8>,
    /// Signature from an admin/inviter
    pub signature: Option<ed25519_dalek::Signature>,
}

/// Audit log entry for group operations
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct AuditLogEntry {
    /// Timestamp of the action
    pub timestamp: u64,
    /// Member who performed the action
    pub actor: [u8; 32],
    /// Type of action performed
    pub action: AuditAction,
    /// Target of the action (if applicable)
    pub target: Option<[u8; 32]>,
    /// Additional context or details
    pub details: Option<String>,
}

/// Types of auditable actions in a group
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum AuditAction {
    /// Member joined the group
    MemberJoined,
    /// Member left the group
    MemberLeft,
    /// Member was removed/kicked
    MemberRemoved,
    /// Member role was changed
    RoleChanged,
    /// Member was banned
    MemberBanned,
    /// Member was unbanned
    MemberUnbanned,
    /// Keys were rotated
    KeysRotated,
    /// Group settings changed
    SettingsChanged,
    /// Channel created
    ChannelCreated,
    /// Channel deleted
    ChannelDeleted,
    /// Message deleted
    MessageDeleted,
}

/// Group channel/subgroup for topic-based organization
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct GroupChannel {
    /// Channel identifier
    pub id: String,
    /// Human-readable channel name
    pub name: String,
    /// Channel description
    pub description: Option<String>,
    /// Members with access to this channel
    pub members: HashSet<[u8; 32]>,
    /// Channel-specific permissions
    pub permissions: HashMap<[u8; 32], Vec<GroupPermission>>,
    /// Whether the channel is archived
    pub archived: bool,
    /// Channel creation timestamp
    pub created_at: u64,
    /// Last activity timestamp
    pub last_activity: Option<u64>,
}

/// Ban entry for banned members
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct BanEntry {
    /// When the ban was issued
    pub banned_at: u64,
    /// Who issued the ban
    pub banned_by: [u8; 32],
    /// Reason for the ban
    pub reason: Option<String>,
    /// Ban expiration (None for permanent)
    pub expires_at: Option<u64>,
    /// Type of ban
    pub ban_type: BanType,
}

/// Types of bans
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum BanType {
    /// Complete ban from group
    Full,
    /// Can view but not participate
    ReadOnly,
    /// Temporary suspension
    Temporary,
}

/// The main Phalanx group for encrypted communication
#[derive(Debug)]
pub struct PhalanxGroup {
    /// Group's unique identifier
    group_id: [u8; 32],
    /// Our identity in this group
    identity: Identity,
    /// Current group encryption key
    group_key: SymmetricKey,
    /// Group configuration
    config: GroupConfig,
    /// All group members
    members: HashMap<[u8; 32], GroupMember>,
    /// Message sequence counter
    message_sequence: u64,
    /// Key rotation sequence
    key_sequence: u64,
    /// Last key rotation time
    last_key_rotation: u64,
    /// Protocol version
    version: ProtocolVersion,
    /// Advanced key management system (temporarily commented out)
    // key_manager: AdvancedKeyManager,
    /// Group audit log
    audit_log: Vec<AuditLogEntry>,
    /// Group channels/subgroups
    channels: HashMap<String, GroupChannel>,
    /// Banned members list
    banned_members: HashMap<[u8; 32], BanEntry>,
}

impl Default for GroupConfig {
    fn default() -> Self {
        Self {
            max_members: 100,
            key_rotation_interval: crate::constants::DEFAULT_KEY_ROTATION_INTERVAL,
            persistent_storage: false,
            visibility: GroupVisibility::Private,
            admin_only_operations: vec![
                GroupOperation::AddMember,
                GroupOperation::RemoveMember,
                GroupOperation::ChangeSettings,
                GroupOperation::RotateKeys,
            ],
        }
    }
}

impl PhalanxGroup {
    /// Create a new Phalanx group
    pub fn new(identity: Identity) -> Self {
        Self::with_config(identity, GroupConfig::default())
    }
    
    /// Get default permissions for a given role
    fn default_permissions_for_role(role: &MemberRole) -> Vec<GroupPermission> {
        use GroupPermission::*;
        match role {
            MemberRole::Owner => vec![
                SendMessages, DeleteOwnMessages, DeleteAnyMessages, InviteMembers, 
                RemoveMembers, ModifySettings, ManageRoles, RotateKeys, ViewAuditLogs,
                ManageBans, CreateChannels
            ],
            MemberRole::Admin => vec![
                SendMessages, DeleteOwnMessages, DeleteAnyMessages, InviteMembers,
                RemoveMembers, ManageRoles, ViewAuditLogs, ManageBans, CreateChannels
            ],
            MemberRole::Moderator => vec![
                SendMessages, DeleteOwnMessages, DeleteAnyMessages, ManageBans, ViewAuditLogs
            ],
            MemberRole::Member => vec![
                SendMessages, DeleteOwnMessages
            ],
            MemberRole::Guest => vec![],
        }
    }
    
    /// Create a new group with custom configuration
    pub fn with_config(identity: Identity, config: GroupConfig) -> Self {
        let group_id = Self::generate_group_id(&identity.public_key());
        let group_key = SymmetricKey::generate();
        
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        
        let mut members = HashMap::new();
        let creator_member = GroupMember {
            public_key: identity.public_key(),
            ephemeral_key: None,
            role: MemberRole::Owner,
            joined_at: timestamp,
            last_seen: Some(timestamp),
            nickname: None,
            status: MemberStatus::Active,
            permissions: Self::default_permissions_for_role(&MemberRole::Owner),
            presence: MemberPresence::Online,
        };
        
        members.insert(identity.id(), creator_member);
        
        // Initialize key manager (simplified for now)
        // let key_manager = AdvancedKeyManager::new().await.unwrap();
        // TODO: Implement async constructor or simplify
        
        // Create initial audit log entry
        let mut audit_log = Vec::new();
        audit_log.push(AuditLogEntry {
            timestamp,
            actor: identity.id(),
            action: AuditAction::MemberJoined,
            target: Some(identity.id()),
            details: Some("Group creator".to_string()),
        });
        
        Self {
            group_id,
            identity,
            group_key,
            config,
            members,
            message_sequence: 0,
            key_sequence: 0,
            last_key_rotation: timestamp,
            version: ProtocolVersion::current(),
            // key_manager, // TODO: Re-enable when async issues are resolved
            audit_log,
            channels: HashMap::new(),
            banned_members: HashMap::new(),
        }
    }
    
    /// Join an existing group using a handshake
    pub fn join(
        identity: Identity,
        handshake: HandshakeMessage,
        group_key: SymmetricKey,
    ) -> Result<Self> {
        let payload = handshake.verify_and_decrypt()?;
        
        let config = GroupConfig::default(); // TODO: Get from group info
        
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        
        let mut members = HashMap::new();
        
        // Add the joining member (self)
        let member = GroupMember {
            public_key: identity.public_key(),
            ephemeral_key: Some(handshake.ephemeral_key),
            role: MemberRole::Member,
            joined_at: timestamp,
            last_seen: Some(timestamp),
            nickname: None,
            status: MemberStatus::Active,
            permissions: Self::default_permissions_for_role(&MemberRole::Member),
            presence: MemberPresence::Online,
        };
        members.insert(identity.id(), member);
        
        // Add the sender of the handshake (group creator/inviter)
        let sender = GroupMember {
            public_key: handshake.sender_key.clone(),
            ephemeral_key: Some(handshake.ephemeral_key),
            role: MemberRole::Owner, // Assume sender is owner/admin
            joined_at: timestamp, // We don't know actual join time
            last_seen: Some(timestamp),
            nickname: None,
            status: MemberStatus::Active,
            permissions: Self::default_permissions_for_role(&MemberRole::Owner),
            presence: MemberPresence::Online,
        };
        members.insert(handshake.sender_key.id(), sender);
        
        Ok(Self {
            group_id: payload.group_id,
            identity,
            group_key,
            config,
            members,
            message_sequence: 0,
            key_sequence: 0,
            last_key_rotation: timestamp,
            version: ProtocolVersion::current(),
            // key_manager, // TODO: Re-enable when async issues are resolved
            audit_log: Vec::new(),
            channels: HashMap::new(),
            banned_members: HashMap::new(),
        })
    }
    
    /// Get the group ID
    pub fn group_id(&self) -> &[u8; 32] {
        &self.group_id
    }
    
    /// Get our identity
    pub fn identity(&self) -> &Identity {
        &self.identity
    }
    
    /// Get group configuration
    pub fn config(&self) -> &GroupConfig {
        &self.config
    }
    
    /// Get all group members
    pub fn members(&self) -> &HashMap<[u8; 32], GroupMember> {
        &self.members
    }
    
    /// Get a specific member by their ID
    pub fn get_member(&self, member_id: &[u8; 32]) -> Option<&GroupMember> {
        self.members.get(member_id)
    }
    
    /// Check if we're an admin or owner
    pub fn is_admin(&self) -> bool {
        if let Some(member) = self.members.get(&self.identity.id()) {
            matches!(member.role, MemberRole::Admin | MemberRole::Owner)
        } else {
            false
        }
    }
    
    /// Check if we have a specific permission
    pub fn has_permission(&self, permission: &GroupPermission) -> bool {
        if let Some(member) = self.members.get(&self.identity.id()) {
            member.permissions.contains(permission)
        } else {
            false
        }
    }
    
    /// Add a new member to the group
    pub fn add_member(&mut self, member_key: PublicKey, role: MemberRole) -> Result<()> {
        // Check permissions
        if !self.has_permission(&GroupPermission::InviteMembers) {
            return Err(PhalanxError::membership("No permission to add members"));
        }
        
        // Check if member is banned
        if self.banned_members.contains_key(&member_key.id()) {
            return Err(PhalanxError::membership("Cannot add banned member"));
        }
        
        // Check group size limit
        if self.members.len() >= self.config.max_members {
            return Err(PhalanxError::group("Group is at maximum capacity"));
        }
        
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        
        let member = GroupMember {
            public_key: member_key.clone(),
            ephemeral_key: None,
            role: role.clone(),
            joined_at: timestamp,
            last_seen: None,
            nickname: None,
            status: MemberStatus::Active,
            permissions: Self::default_permissions_for_role(&role),
            presence: MemberPresence::Online,
        };
        
        let member_id = member_key.id();
        self.members.insert(member_id, member);
        
        // Add to audit log
        self.audit_log.push(AuditLogEntry {
            timestamp,
            actor: self.identity.id(),
            action: AuditAction::MemberJoined,
            target: Some(member_id),
            details: Some(format!("Added with role: {:?}", role)),
        });
        
        Ok(())
    }
    
    /// Remove a member from the group
    pub fn remove_member(&mut self, member_id: &[u8; 32]) -> Result<()> {
        // Check permissions
        if self.config.admin_only_operations.contains(&GroupOperation::RemoveMember) && !self.is_admin() {
            return Err(PhalanxError::membership("Only admins can remove members"));
        }
        
        // Can't remove yourself
        if member_id == &self.identity.id() {
            return Err(PhalanxError::membership("Cannot remove yourself"));
        }
        
        // Can't remove the owner
        if let Some(member) = self.members.get(member_id) {
            if member.role == MemberRole::Owner {
                return Err(PhalanxError::membership("Cannot remove group owner"));
            }
        }
        
        self.members.remove(member_id);
        
        // Trigger key rotation after member removal for security
        self.rotate_keys()?;
        
        Ok(())
    }
    
    /// Ban a member from the group
    pub fn ban_member(&mut self, member_id: &[u8; 32], reason: Option<String>, duration: Option<u64>) -> Result<()> {
        if !self.has_permission(&GroupPermission::ManageBans) {
            return Err(PhalanxError::membership("No permission to ban members"));
        }
        
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        
        // Remove from members if present
        self.members.remove(member_id);
        
        // Add to banned list
        let ban_entry = BanEntry {
            banned_at: timestamp,
            banned_by: self.identity.id(),
            reason: reason.clone(),
            expires_at: duration.map(|d| timestamp + d),
            ban_type: BanType::Full,
        };
        
        self.banned_members.insert(*member_id, ban_entry);
        
        // Add to audit log
        self.audit_log.push(AuditLogEntry {
            timestamp,
            actor: self.identity.id(),
            action: AuditAction::MemberBanned,
            target: Some(*member_id),
            details: reason,
        });
        
        Ok(())
    }
    
    /// Unban a member
    pub fn unban_member(&mut self, member_id: &[u8; 32]) -> Result<()> {
        if !self.has_permission(&GroupPermission::ManageBans) {
            return Err(PhalanxError::membership("No permission to unban members"));
        }
        
        self.banned_members.remove(member_id);
        
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        
        // Add to audit log
        self.audit_log.push(AuditLogEntry {
            timestamp,
            actor: self.identity.id(),
            action: AuditAction::MemberUnbanned,
            target: Some(*member_id),
            details: None,
        });
        
        Ok(())
    }
    
    /// Change a member's role
    pub fn change_member_role(&mut self, member_id: &[u8; 32], new_role: MemberRole) -> Result<()> {
        if !self.has_permission(&GroupPermission::ManageRoles) {
            return Err(PhalanxError::membership("No permission to change member roles"));
        }
        
        let member = self.members.get_mut(member_id)
            .ok_or_else(|| PhalanxError::membership("Member not found"))?;
        
        let old_role = member.role.clone();
        member.role = new_role.clone();
        member.permissions = Self::default_permissions_for_role(&new_role);
        
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        
        // Add to audit log
        self.audit_log.push(AuditLogEntry {
            timestamp,
            actor: self.identity.id(),
            action: AuditAction::RoleChanged,
            target: Some(*member_id),
            details: Some(format!("{:?} -> {:?}", old_role, new_role)),
        });
        
        Ok(())
    }
    
    /// Set custom permissions for a member
    pub fn set_member_permissions(&mut self, member_id: &[u8; 32], permissions: Vec<GroupPermission>) -> Result<()> {
        if !self.has_permission(&GroupPermission::ManageRoles) {
            return Err(PhalanxError::membership("No permission to set member permissions"));
        }
        
        let member = self.members.get_mut(member_id)
            .ok_or_else(|| PhalanxError::membership("Member not found"))?;
        
        member.permissions = permissions;
        
        Ok(())
    }
    
    /// Create a new channel/subgroup
    pub fn create_channel(&mut self, channel_id: String, name: String, description: Option<String>) -> Result<()> {
        if !self.has_permission(&GroupPermission::CreateChannels) {
            return Err(PhalanxError::membership("No permission to create channels"));
        }
        
        if self.channels.contains_key(&channel_id) {
            return Err(PhalanxError::group("Channel already exists"));
        }
        
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        
        let channel = GroupChannel {
            id: channel_id.clone(),
            name,
            description,
            members: HashSet::new(),
            permissions: HashMap::new(),
            archived: false,
            created_at: timestamp,
            last_activity: None,
        };
        
        let channel_id_for_audit = channel_id.clone();
        self.channels.insert(channel_id, channel);
        
        // Add to audit log
        self.audit_log.push(AuditLogEntry {
            timestamp,
            actor: self.identity.id(),
            action: AuditAction::ChannelCreated,
            target: None,
            details: Some(format!("Channel: {}", channel_id_for_audit)),
        });
        
        Ok(())
    }
    
    /// Add member to a channel
    pub fn add_member_to_channel(&mut self, channel_id: &str, member_id: &[u8; 32]) -> Result<()> {
        if !self.has_permission(&GroupPermission::ManageRoles) {
            return Err(PhalanxError::membership("No permission to manage channel membership"));
        }
        
        // Verify member exists in group
        if !self.members.contains_key(member_id) {
            return Err(PhalanxError::membership("Member not found in group"));
        }
        
        let channel = self.channels.get_mut(channel_id)
            .ok_or_else(|| PhalanxError::group("Channel not found"))?;
        
        channel.members.insert(*member_id);
        Ok(())
    }
    
    /// Set member presence
    pub fn set_presence(&mut self, presence: MemberPresence) -> Result<()> {
        let member = self.members.get_mut(&self.identity.id())
            .ok_or_else(|| PhalanxError::membership("Member not found"))?;
        
        member.presence = presence;
        
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        member.last_seen = Some(timestamp);
        
        Ok(())
    }
    
    /// Get audit log entries
    pub fn get_audit_log(&self) -> Result<&Vec<AuditLogEntry>> {
        if !self.has_permission(&GroupPermission::ViewAuditLogs) {
            return Err(PhalanxError::membership("No permission to view audit logs"));
        }
        Ok(&self.audit_log)
    }
    
    /// Advanced key rotation using the key manager
    pub fn advanced_key_rotation(&mut self) -> Result<()> {
        if !self.has_permission(&GroupPermission::RotateKeys) {
            return Err(PhalanxError::membership("No permission to rotate keys"));
        }
        
        // Simplified key rotation for now
        self.group_key = SymmetricKey::generate();
        self.key_sequence += 1;
        
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        self.last_key_rotation = timestamp;
        
        // Add to audit log
        self.audit_log.push(AuditLogEntry {
            timestamp,
            actor: self.identity.id(),
            action: AuditAction::KeysRotated,
            target: None,
            details: Some(format!("Advanced rotation to version {}", self.key_sequence)),
        });
        
        Ok(())
    }
    
    /// Schedule automatic key rotation
    pub fn schedule_key_rotation(&mut self, _policy: RotationPolicy) -> Result<()> {
        if !self.has_permission(&GroupPermission::RotateKeys) {
            return Err(PhalanxError::membership("No permission to schedule key rotation"));
        }
        
        // TODO: Implement when key manager is re-enabled
        Ok(())
    }
    
    /// Get group health metrics
    pub fn get_health_metrics(&self) -> GroupHealthMetrics {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        
        let active_members = self.members.values()
            .filter(|m| {
                if let Some(last_seen) = m.last_seen {
                    timestamp - last_seen < 3600 // Active within last hour
                } else {
                    false
                }
            })
            .count();
        
        let banned_count = self.banned_members.len();
        let channel_count = self.channels.len();
        
        let key_rotation_health = if self.needs_key_rotation() {
            HealthStatus::Warning
        } else {
            HealthStatus::Healthy
        };
        
        GroupHealthMetrics {
            total_members: self.members.len(),
            active_members,
            banned_members: banned_count,
            channels: channel_count,
            key_rotation_health,
            last_activity: timestamp,
        }
    }
    
    /// Encrypt a message for the group
    pub fn encrypt_message(&mut self, content: &MessageContent) -> Result<GroupMessage> {
        self.message_sequence += 1;
        
        GroupMessage::new(
            &self.identity,
            MessageType::Text,
            content,
            self.message_sequence,
            &self.group_key,
        )
    }
    
    /// Decrypt a group message
    pub fn decrypt_message(&self, message: &GroupMessage) -> Result<MessageContent> {
        // Verify sender is a group member
        let sender_id = message.sender.id();
        if !self.members.contains_key(&sender_id) {
            return Err(PhalanxError::membership("Message from non-member"));
        }
        
        message.decrypt(&self.group_key)
    }
    
    /// Rotate group encryption keys
    pub fn rotate_keys(&mut self) -> Result<KeyRotationMessage> {
        // Check permissions
        if self.config.admin_only_operations.contains(&GroupOperation::RotateKeys) && !self.is_admin() {
            return Err(PhalanxError::membership("Only admins can rotate keys"));
        }
        
        // Generate new group key
        self.group_key = SymmetricKey::generate();
        self.key_sequence += 1;
        
        // Update timestamp
        self.last_key_rotation = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        
        // Collect member keys for rotation message
        let mut member_keys = Vec::new();
        for member in self.members.values_mut() {
            if let Some(ephemeral) = &member.ephemeral_key {
                member_keys.push((member.public_key.clone(), *ephemeral));
            }
        }
        
        KeyRotationMessage::new(&self.identity, self.key_sequence, member_keys)
    }
    
    /// Check if key rotation is needed
    pub fn needs_key_rotation(&self) -> bool {
        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        
        current_time - self.last_key_rotation >= self.config.key_rotation_interval
    }
    
    /// Update member's last seen timestamp
    pub fn update_member_activity(&mut self, member_id: &[u8; 32]) {
        if let Some(member) = self.members.get_mut(member_id) {
            let timestamp = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0);
            member.last_seen = Some(timestamp);
        }
    }
    
    /// Set member nickname
    pub fn set_member_nickname(&mut self, member_id: &[u8; 32], nickname: Option<String>) -> Result<()> {
        let member = self.members.get_mut(member_id)
            .ok_or_else(|| PhalanxError::membership("Member not found"))?;
        
        member.nickname = nickname;
        Ok(())
    }
    
    /// Generate a group ID from creator's public key
    fn generate_group_id(creator_key: &PublicKey) -> [u8; 32] {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0)
            .to_be_bytes();
        hash_multiple(&[
            &creator_key.id(),
            &timestamp,
            b"PHALANX_GROUP_V1",
        ])
    }
    
    /// Create a handshake for joining this group
    pub fn create_handshake(&self) -> Result<HandshakeMessage> {
        HandshakeMessage::new(
            &self.identity,
            self.group_id,
            vec!["phalanx/v1".to_string()],
            "phalanx-client/1.0".to_string(),
        )
    }
    
    /// Create a handshake with encrypted group key for secure key sharing
    pub fn create_handshake_with_group_key(&mut self, recipient_public_key: &PublicKey) -> Result<HandshakeMessage> {
        HandshakeMessage::new_with_group_key(
            &mut self.identity,
            recipient_public_key,
            self.group_id,
            vec!["phalanx/v1".to_string()],
            "phalanx-client/1.0".to_string(),
            &self.group_key,
        )
    }
    
    /// Join a group by extracting the group key from a handshake message
    pub fn join_with_handshake(
        mut identity: Identity,
        handshake: HandshakeMessage,
    ) -> Result<Self> {
        // Extract group key from handshake
        let group_key = handshake.extract_group_key(&mut identity)?
            .ok_or_else(|| PhalanxError::protocol("No group key in handshake message"))?;
        
        // Use the existing join method with the extracted key
        Self::join(identity, handshake, group_key)
    }
    
    /// Get group statistics
    pub fn stats(&self) -> GroupStats {
        let active_members = self.members.values()
            .filter(|m| {
                if let Some(last_seen) = m.last_seen {
                    let now = SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .map(|d| d.as_secs())
                        .unwrap_or(0);
                    now - last_seen < 3600 // Active within last hour
                } else {
                    false
                }
            })
            .count();
        
        GroupStats {
            total_members: self.members.len(),
            active_members,
            message_count: self.message_sequence,
            key_rotation_count: self.key_sequence,
            created_at: self.members.get(&self.identity.id())
                .map(|m| m.joined_at)
                .unwrap_or(0),
        }
    }
}

/// Group statistics
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct GroupStats {
    /// Total number of members
    pub total_members: usize,
    /// Number of recently active members
    pub active_members: usize,
    /// Total messages sent
    pub message_count: u64,
    /// Number of key rotations performed
    pub key_rotation_count: u64,
    /// Group creation timestamp
    pub created_at: u64,
}

/// Group health metrics
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct GroupHealthMetrics {
    /// Total number of members
    pub total_members: usize,
    /// Number of recently active members
    pub active_members: usize,
    /// Number of banned members
    pub banned_members: usize,
    /// Number of channels
    pub channels: usize,
    /// Key rotation health status
    pub key_rotation_health: HealthStatus,
    /// Last group activity timestamp
    pub last_activity: u64,
}

/// Health status indicator
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum HealthStatus {
    /// All systems healthy
    Healthy,
    /// Minor issues detected
    Warning,
    /// Critical issues detected
    Critical,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::message::MessageContent;
    
    #[test]
    fn test_group_creation() {
        let identity = Identity::generate();
        let group = PhalanxGroup::new(identity.clone());
        
        assert_eq!(group.members.len(), 1);
        assert!(group.members.contains_key(&identity.id()));
        assert!(group.is_admin()); // Creator is owner/admin
    }
    
    #[test]
    fn test_message_encryption_decryption() {
        let identity = Identity::generate();
        let mut group = PhalanxGroup::new(identity);
        
        let content = MessageContent::text("Hello, group!");
        let encrypted = group.encrypt_message(&content).unwrap();
        let decrypted = group.decrypt_message(&encrypted).unwrap();
        
        assert_eq!(decrypted.as_string().unwrap(), "Hello, group!");
    }
    
    #[test]
    fn test_member_management() {
        let admin = Identity::generate();
        let member = Identity::generate();
        
        let mut group = PhalanxGroup::new(admin);
        
        // Add member
        group.add_member(member.public_key(), MemberRole::Member).unwrap();
        assert_eq!(group.members.len(), 2);
        
        // Remove member
        group.remove_member(&member.id()).unwrap();
        // After removal, key rotation happens, so we just check member count
        assert_eq!(group.members.len(), 1);
    }
    
    #[test]
    fn test_key_rotation() {
        let identity = Identity::generate();
        let mut group = PhalanxGroup::new(identity);
        
        let old_sequence = group.key_sequence;
        let rotation_msg = group.rotate_keys().unwrap();
        
        assert_eq!(group.key_sequence, old_sequence + 1);
        assert!(rotation_msg.verify(&group.identity.public_key()).is_ok());
    }
    
    #[test]
    fn test_permissions() {
        let admin = Identity::generate();
        let member = Identity::generate();
        
        let mut group = PhalanxGroup::new(admin);
        
        // Add a regular member
        group.add_member(member.public_key(), MemberRole::Member).unwrap();
        
        // Change identity to the member (simulate member trying to add another member)
        group.identity = member;
        
        let new_member = Identity::generate();
        let result = group.add_member(new_member.public_key(), MemberRole::Member);
        
        // Should fail because regular members can't add other members
        assert!(result.is_err());
    }
}