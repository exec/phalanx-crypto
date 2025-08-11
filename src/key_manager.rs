//! Advanced key management for Phalanx Protocol
//! 
//! Provides enterprise-grade key lifecycle management, rotation scheduling,
//! backup/recovery, and security compliance features.

use crate::{
    Identity, PublicKey, 
    error::{PhalanxError, Result},
    crypto::{SymmetricKey, derive_phalanx_key, contexts},
    message::{GroupMessage, MessageContent},
};
use std::collections::{HashMap, BTreeMap, HashSet};
use std::time::{SystemTime, Duration, UNIX_EPOCH};
use tokio::sync::{RwLock, Mutex};
use serde::{Serialize, Deserialize};
use tracing::{debug, info, warn, error, instrument};
use async_trait::async_trait;

/// Advanced key manager for Phalanx groups
pub struct AdvancedKeyManager {
    /// Current active keys by group
    active_keys: RwLock<HashMap<[u8; 32], KeySet>>,
    /// Key rotation schedules
    rotation_schedules: RwLock<HashMap<[u8; 32], RotationSchedule>>,
    /// Key backup storage
    backup_storage: RwLock<Box<dyn KeyBackupStorage>>,
    /// Key derivation cache
    derivation_cache: RwLock<HashMap<KeyDerivationRequest, CachedKey>>,
    /// Security policies
    security_policies: RwLock<SecurityPolicies>,
    /// Key usage statistics
    usage_stats: RwLock<HashMap<[u8; 32], KeyUsageStats>>,
    /// Pending key operations
    pending_operations: Mutex<Vec<PendingKeyOperation>>,
    /// HSM integration (if available)
    hsm_provider: Option<Box<dyn HsmProvider>>,
}

/// Complete key set for a group
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeySet {
    /// Current encryption key
    pub current_key: EncryptionKeyInfo,
    /// Previous keys for decryption
    pub previous_keys: BTreeMap<u64, EncryptionKeyInfo>,
    /// Key exchange keys by member
    pub member_keys: HashMap<[u8; 32], MemberKeyInfo>,
    /// Root key for derivation
    pub root_key: RootKeyInfo,
    /// Key metadata
    pub metadata: KeyMetadata,
}

/// Information about an encryption key
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptionKeyInfo {
    /// Key sequence number
    pub sequence: u64,
    /// Symmetric encryption key
    pub key: SymmetricKey,
    /// Key creation timestamp
    pub created_at: SystemTime,
    /// Key expiration timestamp
    pub expires_at: Option<SystemTime>,
    /// Key derivation info
    pub derivation: KeyDerivation,
    /// Usage statistics
    pub usage_count: u64,
    /// Security level
    pub security_level: SecurityLevel,
}

/// Information about a member's keys
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemberKeyInfo {
    /// Member public key
    pub public_key: PublicKey,
    /// Key exchange public key
    pub kx_public_key: [u8; 32],
    /// Shared secrets with this member
    pub shared_secrets: HashMap<u64, [u8; 32]>,
    /// Member key status
    pub status: MemberKeyStatus,
    /// Last key update
    pub last_updated: SystemTime,
}

/// Root key information for key derivation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RootKeyInfo {
    /// Root key identifier
    pub key_id: [u8; 32],
    /// Key derivation parameters
    pub derivation_params: KeyDerivationParams,
    /// Root key creation time
    pub created_at: SystemTime,
    /// Root key version
    pub version: u32,
    /// Security classification
    pub classification: SecurityClassification,
}

/// Key metadata for management
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyMetadata {
    /// Group identifier
    pub group_id: [u8; 32],
    /// Key set version
    pub version: u64,
    /// Creation timestamp
    pub created_at: SystemTime,
    /// Last rotation timestamp
    pub last_rotation: Option<SystemTime>,
    /// Rotation policy
    pub rotation_policy: RotationPolicy,
    /// Backup policy
    pub backup_policy: BackupPolicy,
    /// Compliance tags
    pub compliance_tags: HashSet<String>,
}

/// Key rotation schedule
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RotationSchedule {
    /// Next rotation time
    pub next_rotation: SystemTime,
    /// Rotation interval
    pub interval: Duration,
    /// Automatic rotation enabled
    pub auto_rotate: bool,
    /// Rotation policy
    pub policy: RotationPolicy,
    /// Retry configuration
    pub retry_config: RetryConfig,
}

/// Key rotation policy
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RotationPolicy {
    /// Maximum key age before forced rotation
    pub max_key_age: Duration,
    /// Maximum usage count before rotation
    pub max_usage_count: u64,
    /// Rotation trigger conditions
    pub triggers: HashSet<RotationTrigger>,
    /// Pre-rotation notification time
    pub notification_time: Duration,
    /// Emergency rotation capability
    pub emergency_rotation: bool,
}

/// Key backup policy
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackupPolicy {
    /// Backup enabled
    pub enabled: bool,
    /// Backup frequency
    pub frequency: Duration,
    /// Retention period
    pub retention_period: Duration,
    /// Encryption for backups
    pub backup_encryption: BackupEncryption,
    /// Backup verification
    pub verify_backups: bool,
    /// Geographic distribution
    pub geo_distribution: Option<GeoDistribution>,
}

/// Security policies for key management
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityPolicies {
    /// Minimum key strength
    pub min_key_strength: SecurityLevel,
    /// Required compliance frameworks
    pub compliance_frameworks: HashSet<ComplianceFramework>,
    /// Key escrow requirements
    pub key_escrow: Option<KeyEscrowPolicy>,
    /// Audit requirements
    pub audit_policy: AuditPolicy,
    /// Access control policies
    pub access_control: AccessControlPolicy,
}

/// Key usage statistics
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct KeyUsageStats {
    /// Total operations
    pub total_operations: u64,
    /// Encryption operations
    pub encryption_count: u64,
    /// Decryption operations
    pub decryption_count: u64,
    /// Key derivation operations
    pub derivation_count: u64,
    /// First use timestamp
    pub first_used: Option<SystemTime>,
    /// Last use timestamp
    pub last_used: Option<SystemTime>,
    /// Bytes processed
    pub bytes_processed: u64,
    /// Error count
    pub error_count: u64,
}

/// Pending key operation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PendingKeyOperation {
    /// Operation ID
    pub operation_id: [u8; 32],
    /// Group ID
    pub group_id: [u8; 32],
    /// Operation type
    pub operation: KeyOperation,
    /// Scheduled execution time
    pub scheduled_at: SystemTime,
    /// Operation priority
    pub priority: OperationPriority,
    /// Retry count
    pub retry_count: u32,
    /// Dependencies
    pub dependencies: Vec<[u8; 32]>,
}

/// Key derivation request for caching
#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub struct KeyDerivationRequest {
    /// Base key identifier
    pub base_key_id: [u8; 32],
    /// Derivation context
    pub context: String,
    /// Additional parameters
    pub params: Vec<u8>,
}

/// Cached derived key
#[derive(Debug, Clone)]
pub struct CachedKey {
    /// Derived key
    pub key: SymmetricKey,
    /// Cache timestamp
    pub cached_at: SystemTime,
    /// Cache TTL
    pub ttl: Duration,
    /// Usage count since cached
    pub usage_count: u64,
}

/// Types of key operations
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum KeyOperation {
    /// Rotate group keys
    Rotate {
        /// New key sequence
        sequence: u64,
        /// Rotation reason
        reason: RotationReason,
    },
    /// Generate new keys
    Generate {
        /// Key type
        key_type: KeyType,
        /// Security level
        security_level: SecurityLevel,
    },
    /// Backup keys
    Backup {
        /// Backup destination
        destination: BackupDestination,
        /// Include historical keys
        include_history: bool,
    },
    /// Restore keys
    Restore {
        /// Restore source
        source: BackupSource,
        /// Restore point
        restore_point: SystemTime,
    },
    /// Derive keys
    Derive {
        /// Derivation context
        context: String,
        /// Parameters
        params: HashMap<String, Vec<u8>>,
    },
    /// Clean up old keys
    Cleanup {
        /// Cutoff time
        cutoff_time: SystemTime,
        /// Preserve count
        preserve_count: u32,
    },
}

/// Various enums and supporting types
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum RotationTrigger {
    TimeExpired,
    UsageExceeded,
    SecurityBreach,
    MembershipChange,
    ComplianceRequirement,
    ManualRequest,
    EmergencyRotation,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RotationReason {
    Scheduled,
    Emergency,
    Compromise,
    Compliance,
    MembershipChange,
    Manual,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum KeyType {
    Encryption,
    Authentication,
    KeyExchange,
    Derivation,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum SecurityLevel {
    Standard,
    High,
    Critical,
    TopSecret,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MemberKeyStatus {
    Active,
    Revoked,
    Expired,
    Pending,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SecurityClassification {
    Public,
    Internal,
    Confidential,
    Secret,
    TopSecret,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ComplianceFramework {
    FIPS140_2,
    CommonCriteria,
    NIST,
    ISO27001,
    SOX,
    GDPR,
    HIPAA,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum OperationPriority {
    Low,
    Normal,
    High,
    Emergency,
}

/// Supporting structures
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyDerivation {
    pub method: DerivationMethod,
    pub parameters: HashMap<String, Vec<u8>>,
    pub context: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyDerivationParams {
    pub method: DerivationMethod,
    pub salt: [u8; 32],
    pub iterations: u32,
    pub key_length: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DerivationMethod {
    HKDF,
    PBKDF2,
    Scrypt,
    Argon2,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RetryConfig {
    pub max_retries: u32,
    pub base_delay: Duration,
    pub max_delay: Duration,
    pub backoff_multiplier: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackupEncryption {
    pub enabled: bool,
    pub key_id: Option<[u8; 32]>,
    pub cipher: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeoDistribution {
    pub regions: Vec<String>,
    pub min_replicas: u32,
    pub consistency_level: ConsistencyLevel,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ConsistencyLevel {
    Eventual,
    Strong,
    Linearizable,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyEscrowPolicy {
    pub enabled: bool,
    pub trustees: Vec<String>,
    pub threshold: u32,
    pub escrow_duration: Duration,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditPolicy {
    pub enabled: bool,
    pub log_all_operations: bool,
    pub retention_period: Duration,
    pub compliance_reporting: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessControlPolicy {
    pub require_authentication: bool,
    pub multi_factor_auth: bool,
    pub role_based_access: bool,
    pub audit_access: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum BackupDestination {
    Local { path: String },
    Remote { url: String, credentials: String },
    HSM { module_id: String },
    Cloud { provider: String, config: HashMap<String, String> },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum BackupSource {
    Local { path: String },
    Remote { url: String, credentials: String },
    HSM { module_id: String },
    Cloud { provider: String, config: HashMap<String, String> },
}

/// Trait for key backup storage
#[async_trait]
pub trait KeyBackupStorage: Send + Sync {
    async fn store_backup(&self, group_id: [u8; 32], keyset: &KeySet, metadata: &BackupMetadata) -> Result<BackupId>;
    async fn retrieve_backup(&self, backup_id: BackupId) -> Result<(KeySet, BackupMetadata)>;
    async fn list_backups(&self, group_id: [u8; 32]) -> Result<Vec<BackupInfo>>;
    async fn delete_backup(&self, backup_id: BackupId) -> Result<()>;
    async fn verify_backup(&self, backup_id: BackupId) -> Result<bool>;
}

/// Trait for HSM integration
#[async_trait]
pub trait HsmProvider: Send + Sync {
    async fn generate_key(&self, key_type: KeyType, security_level: SecurityLevel) -> Result<HsmKeyHandle>;
    async fn derive_key(&self, base_key: HsmKeyHandle, context: &str, params: &[u8]) -> Result<HsmKeyHandle>;
    async fn encrypt(&self, key_handle: HsmKeyHandle, plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>>;
    async fn decrypt(&self, key_handle: HsmKeyHandle, ciphertext: &[u8], aad: &[u8]) -> Result<Vec<u8>>;
    async fn export_key(&self, key_handle: HsmKeyHandle) -> Result<Vec<u8>>;
    async fn import_key(&self, key_data: &[u8], key_type: KeyType) -> Result<HsmKeyHandle>;
}

/// Supporting types for backup and HSM
pub type BackupId = [u8; 32];
pub type HsmKeyHandle = String;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackupMetadata {
    pub backup_id: BackupId,
    pub group_id: [u8; 32],
    pub created_at: SystemTime,
    pub version: u64,
    pub encryption: BackupEncryption,
    pub compression: bool,
    pub integrity_hash: [u8; 32],
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackupInfo {
    pub backup_id: BackupId,
    pub created_at: SystemTime,
    pub size: u64,
    pub version: u64,
    pub verified: bool,
}

impl Default for SecurityPolicies {
    fn default() -> Self {
        Self {
            min_key_strength: SecurityLevel::Standard,
            compliance_frameworks: HashSet::new(),
            key_escrow: None,
            audit_policy: AuditPolicy {
                enabled: true,
                log_all_operations: false,
                retention_period: Duration::from_secs(365 * 24 * 3600), // 1 year
                compliance_reporting: false,
            },
            access_control: AccessControlPolicy {
                require_authentication: true,
                multi_factor_auth: false,
                role_based_access: false,
                audit_access: true,
            },
        }
    }
}

impl Default for RotationPolicy {
    fn default() -> Self {
        Self {
            max_key_age: Duration::from_secs(30 * 24 * 3600), // 30 days
            max_usage_count: 1_000_000,
            triggers: {
                let mut triggers = HashSet::new();
                triggers.insert(RotationTrigger::TimeExpired);
                triggers.insert(RotationTrigger::UsageExceeded);
                triggers
            },
            notification_time: Duration::from_secs(24 * 3600), // 24 hours
            emergency_rotation: true,
        }
    }
}

impl Default for BackupPolicy {
    fn default() -> Self {
        Self {
            enabled: true,
            frequency: Duration::from_secs(7 * 24 * 3600), // Weekly
            retention_period: Duration::from_secs(90 * 24 * 3600), // 90 days
            backup_encryption: BackupEncryption {
                enabled: true,
                key_id: None,
                cipher: "ChaCha20-Poly1305".to_string(),
            },
            verify_backups: true,
            geo_distribution: None,
        }
    }
}

impl AdvancedKeyManager {
    /// Create a new advanced key manager
    pub async fn new() -> Result<Self> {
        Ok(Self {
            active_keys: RwLock::new(HashMap::new()),
            rotation_schedules: RwLock::new(HashMap::new()),
            backup_storage: RwLock::new(Box::new(LocalBackupStorage::new("/tmp/phalanx_backups".to_string()).await?)),
            derivation_cache: RwLock::new(HashMap::new()),
            security_policies: RwLock::new(SecurityPolicies::default()),
            usage_stats: RwLock::new(HashMap::new()),
            pending_operations: Mutex::new(Vec::new()),
            hsm_provider: None,
        })
    }
    
    /// Create a new key set for a group
    #[instrument(skip(self, identity))]
    pub async fn create_key_set(&self, group_id: [u8; 32], identity: &Identity) -> Result<KeySet> {
        info!("Creating new key set for group {:?}", hex::encode(group_id));
        
        // Generate root key
        let root_key_id = self.generate_random_bytes(32);
        let root_key = RootKeyInfo {
            key_id: root_key_id,
            derivation_params: KeyDerivationParams {
                method: DerivationMethod::HKDF,
                salt: self.generate_random_bytes(32),
                iterations: 100_000,
                key_length: 32,
            },
            created_at: SystemTime::now(),
            version: 1,
            classification: SecurityClassification::Internal,
        };
        
        // Generate initial encryption key
        let encryption_key = self.generate_encryption_key(1, &root_key).await?;
        
        // Create member key info
        let mut member_keys = HashMap::new();
        let public_key = identity.public_key();
        member_keys.insert(public_key.id(), MemberKeyInfo {
            public_key,
            kx_public_key: self.generate_random_bytes(32),
            shared_secrets: HashMap::new(),
            status: MemberKeyStatus::Active,
            last_updated: SystemTime::now(),
        });
        
        // Create key metadata
        let metadata = KeyMetadata {
            group_id,
            version: 1,
            created_at: SystemTime::now(),
            last_rotation: None,
            rotation_policy: RotationPolicy::default(),
            backup_policy: BackupPolicy::default(),
            compliance_tags: HashSet::new(),
        };
        
        let key_set = KeySet {
            current_key: encryption_key,
            previous_keys: BTreeMap::new(),
            member_keys,
            root_key,
            metadata,
        };
        
        // Store the key set
        let mut active_keys = self.active_keys.write().await;
        active_keys.insert(group_id, key_set.clone());
        
        // Schedule rotation
        self.schedule_rotation(group_id, &key_set.metadata.rotation_policy).await?;
        
        // Initialize usage stats
        let mut usage_stats = self.usage_stats.write().await;
        usage_stats.insert(group_id, KeyUsageStats::default());
        
        info!("Created key set for group {:?}", hex::encode(group_id));
        Ok(key_set)
    }
    
    /// Rotate keys for a group
    #[instrument(skip(self))]
    pub async fn rotate_keys(&self, group_id: [u8; 32], reason: RotationReason) -> Result<u64> {
        info!("Rotating keys for group {:?}, reason: {:?}", hex::encode(group_id), reason);
        
        let mut active_keys = self.active_keys.write().await;
        let key_set = active_keys.get_mut(&group_id)
            .ok_or_else(|| PhalanxError::crypto("Group not found for rotation"))?;
        
        // Move current key to previous keys
        let old_sequence = key_set.current_key.sequence;
        let old_key = key_set.current_key.clone();
        key_set.previous_keys.insert(old_sequence, old_key);
        
        // Generate new current key
        let new_sequence = old_sequence + 1;
        let new_key = self.generate_encryption_key(new_sequence, &key_set.root_key).await?;
        key_set.current_key = new_key;
        
        // Update metadata
        key_set.metadata.version += 1;
        key_set.metadata.last_rotation = Some(SystemTime::now());
        
        // Clean up old keys (keep last 10)
        while key_set.previous_keys.len() > 10 {
            if let Some((oldest_seq, _)) = key_set.previous_keys.iter().next() {
                let oldest_seq = *oldest_seq;
                key_set.previous_keys.remove(&oldest_seq);
            }
        }
        
        // Update usage stats
        let mut usage_stats = self.usage_stats.write().await;
        if let Some(stats) = usage_stats.get_mut(&group_id) {
            stats.total_operations += 1;
        }
        
        // Schedule next rotation
        self.schedule_rotation(group_id, &key_set.metadata.rotation_policy).await?;
        
        // Create backup if enabled
        if key_set.metadata.backup_policy.enabled {
            self.create_backup(group_id).await?;
        }
        
        info!("Rotated keys for group {:?} to sequence {}", hex::encode(group_id), new_sequence);
        Ok(new_sequence)
    }
    
    /// Add a new member to the key set
    #[instrument(skip(self, identity))]
    pub async fn add_member(&self, group_id: [u8; 32], identity: &Identity) -> Result<()> {
        info!("Adding member to group {:?}", hex::encode(group_id));
        
        let mut active_keys = self.active_keys.write().await;
        let key_set = active_keys.get_mut(&group_id)
            .ok_or_else(|| PhalanxError::crypto("Group not found for member addition"))?;
        
        let public_key = identity.public_key();
        let member_id = public_key.id();
        
        if key_set.member_keys.contains_key(&member_id) {
            return Err(PhalanxError::crypto("Member already exists in group"));
        }
        
        // Generate key exchange material for the new member
        let kx_public_key = self.generate_random_bytes(32);
        let member_info = MemberKeyInfo {
            public_key,
            kx_public_key,
            shared_secrets: HashMap::new(),
            status: MemberKeyStatus::Active,
            last_updated: SystemTime::now(),
        };
        
        key_set.member_keys.insert(member_id, member_info);
        key_set.metadata.version += 1;
        
        info!("Added member {:?} to group {:?}", hex::encode(member_id), hex::encode(group_id));
        
        // Trigger key rotation due to membership change
        if key_set.metadata.rotation_policy.triggers.contains(&RotationTrigger::MembershipChange) {
            self.schedule_immediate_operation(group_id, KeyOperation::Rotate {
                sequence: key_set.current_key.sequence + 1,
                reason: RotationReason::MembershipChange,
            }).await?;
        }
        
        Ok(())
    }
    
    /// Remove a member from the key set
    #[instrument(skip(self))]
    pub async fn remove_member(&self, group_id: [u8; 32], member_id: [u8; 32]) -> Result<()> {
        info!("Removing member {:?} from group {:?}", hex::encode(member_id), hex::encode(group_id));
        
        let mut active_keys = self.active_keys.write().await;
        let key_set = active_keys.get_mut(&group_id)
            .ok_or_else(|| PhalanxError::crypto("Group not found for member removal"))?;
        
        if let Some(mut member_info) = key_set.member_keys.remove(&member_id) {
            member_info.status = MemberKeyStatus::Revoked;
            key_set.metadata.version += 1;
            
            info!("Removed member {:?} from group {:?}", hex::encode(member_id), hex::encode(group_id));
            
            // Trigger key rotation due to membership change
            if key_set.metadata.rotation_policy.triggers.contains(&RotationTrigger::MembershipChange) {
                self.schedule_immediate_operation(group_id, KeyOperation::Rotate {
                    sequence: key_set.current_key.sequence + 1,
                    reason: RotationReason::MembershipChange,
                }).await?;
            }
        } else {
            return Err(PhalanxError::crypto("Member not found in group"));
        }
        
        Ok(())
    }
    
    /// Get current encryption key for a group
    #[instrument(skip(self))]
    pub async fn get_encryption_key(&self, group_id: [u8; 32]) -> Result<SymmetricKey> {
        let active_keys = self.active_keys.read().await;
        let key_set = active_keys.get(&group_id)
            .ok_or_else(|| PhalanxError::crypto("Group not found"))?;
        
        // Update usage stats
        let mut usage_stats = self.usage_stats.write().await;
        if let Some(stats) = usage_stats.get_mut(&group_id) {
            stats.encryption_count += 1;
            stats.total_operations += 1;
            stats.last_used = Some(SystemTime::now());
            if stats.first_used.is_none() {
                stats.first_used = Some(SystemTime::now());
            }
        }
        
        Ok(key_set.current_key.key.clone())
    }
    
    /// Get decryption key for a specific sequence
    #[instrument(skip(self))]
    pub async fn get_decryption_key(&self, group_id: [u8; 32], sequence: u64) -> Result<SymmetricKey> {
        let active_keys = self.active_keys.read().await;
        let key_set = active_keys.get(&group_id)
            .ok_or_else(|| PhalanxError::crypto("Group not found"))?;
        
        let key = if sequence == key_set.current_key.sequence {
            key_set.current_key.key.clone()
        } else if let Some(prev_key) = key_set.previous_keys.get(&sequence) {
            prev_key.key.clone()
        } else {
            return Err(PhalanxError::crypto(format!("Key sequence {} not found", sequence)));
        };
        
        // Update usage stats
        let mut usage_stats = self.usage_stats.write().await;
        if let Some(stats) = usage_stats.get_mut(&group_id) {
            stats.decryption_count += 1;
            stats.total_operations += 1;
            stats.last_used = Some(SystemTime::now());
            if stats.first_used.is_none() {
                stats.first_used = Some(SystemTime::now());
            }
        }
        
        Ok(key)
    }
    
    /// Derive a specialized key for a specific context
    #[instrument(skip(self))]
    pub async fn derive_key(&self, group_id: [u8; 32], context: &str, params: &[u8]) -> Result<SymmetricKey> {
        let request = KeyDerivationRequest {
            base_key_id: group_id,
            context: context.to_string(),
            params: params.to_vec(),
        };
        
        // Check cache first
        {
            let cache = self.derivation_cache.read().await;
            if let Some(cached) = cache.get(&request) {
                let age = SystemTime::now().duration_since(cached.cached_at).unwrap_or_default();
                if age < cached.ttl {
                    debug!("Using cached derived key for context: {}", context);
                    return Ok(cached.key.clone());
                }
            }
        }
        
        // Get base key
        let active_keys = self.active_keys.read().await;
        let key_set = active_keys.get(&group_id)
            .ok_or_else(|| PhalanxError::crypto("Group not found"))?;
        
        // Derive new key
        let derived_key = derive_phalanx_key(
            key_set.current_key.key.as_bytes(),
            context.as_bytes(),
            contexts::KEY_DERIVATION,
        );
        
        // Cache the derived key
        {
            let mut cache = self.derivation_cache.write().await;
            cache.insert(request, CachedKey {
                key: derived_key.clone(),
                cached_at: SystemTime::now(),
                ttl: Duration::from_secs(3600), // 1 hour
                usage_count: 0,
            });
            
            // Limit cache size
            if cache.len() > 1000 {
                let cutoff = SystemTime::now() - Duration::from_secs(1800);
                cache.retain(|_, v| v.cached_at > cutoff);
            }
        }
        
        // Update usage stats
        let mut usage_stats = self.usage_stats.write().await;
        if let Some(stats) = usage_stats.get_mut(&group_id) {
            stats.derivation_count += 1;
            stats.total_operations += 1;
        }
        
        debug!("Derived new key for context: {}", context);
        Ok(derived_key)
    }
    
    /// Create a backup of the key set
    #[instrument(skip(self))]
    pub async fn create_backup(&self, group_id: [u8; 32]) -> Result<BackupId> {
        info!("Creating backup for group {:?}", hex::encode(group_id));
        
        let active_keys = self.active_keys.read().await;
        let key_set = active_keys.get(&group_id)
            .ok_or_else(|| PhalanxError::crypto("Group not found for backup"))?;
        
        let backup_id = self.generate_random_bytes(32);
        let metadata = BackupMetadata {
            backup_id,
            group_id,
            created_at: SystemTime::now(),
            version: key_set.metadata.version,
            encryption: key_set.metadata.backup_policy.backup_encryption.clone(),
            compression: true,
            integrity_hash: self.generate_random_bytes(32), // TODO: Calculate actual hash
        };
        
        let backup_storage = self.backup_storage.read().await;
        let stored_id = backup_storage.store_backup(group_id, key_set, &metadata).await?;
        
        info!("Created backup {:?} for group {:?}", hex::encode(stored_id), hex::encode(group_id));
        Ok(stored_id)
    }
    
    /// Process pending operations
    #[instrument(skip(self))]
    pub async fn process_pending_operations(&self) -> Result<usize> {
        let now = SystemTime::now();
        let mut pending = self.pending_operations.lock().await;
        let mut processed = 0;
        
        let mut remaining_operations = Vec::new();
        
        for operation in pending.drain(..) {
            if operation.scheduled_at <= now {
                match self.execute_operation(operation.group_id, operation.operation.clone()).await {
                    Ok(_) => {
                        processed += 1;
                        info!("Executed scheduled operation {:?} for group {:?}", 
                              operation.operation, hex::encode(operation.group_id));
                    },
                    Err(e) => {
                        error!("Failed to execute operation: {}", e);
                        if operation.retry_count < 3 {
                            let mut retried_op = operation;
                            retried_op.retry_count += 1;
                            retried_op.scheduled_at = now + Duration::from_secs(60 * (2u64.pow(retried_op.retry_count)));
                            remaining_operations.push(retried_op);
                        }
                    }
                }
            } else {
                remaining_operations.push(operation);
            }
        }
        
        *pending = remaining_operations;
        Ok(processed)
    }
    
    /// Get key usage statistics
    pub async fn get_usage_stats(&self, group_id: [u8; 32]) -> Result<KeyUsageStats> {
        let usage_stats = self.usage_stats.read().await;
        Ok(usage_stats.get(&group_id).cloned().unwrap_or_default())
    }
    
    /// Helper methods
    async fn generate_encryption_key(&self, sequence: u64, root_key: &RootKeyInfo) -> Result<EncryptionKeyInfo> {
        let key = derive_phalanx_key(
            &root_key.key_id,
            &sequence.to_be_bytes(),
            contexts::KEY_DERIVATION,
        );
        
        Ok(EncryptionKeyInfo {
            sequence,
            key,
            created_at: SystemTime::now(),
            expires_at: None,
            derivation: KeyDerivation {
                method: DerivationMethod::HKDF,
                parameters: HashMap::new(),
                context: "encryption_key".to_string(),
            },
            usage_count: 0,
            security_level: SecurityLevel::Standard,
        })
    }
    
    async fn schedule_rotation(&self, group_id: [u8; 32], policy: &RotationPolicy) -> Result<()> {
        let next_rotation = SystemTime::now() + policy.max_key_age;
        let schedule = RotationSchedule {
            next_rotation,
            interval: policy.max_key_age,
            auto_rotate: true,
            policy: policy.clone(),
            retry_config: RetryConfig {
                max_retries: 3,
                base_delay: Duration::from_secs(60),
                max_delay: Duration::from_secs(3600),
                backoff_multiplier: 2.0,
            },
        };
        
        let mut schedules = self.rotation_schedules.write().await;
        schedules.insert(group_id, schedule);
        
        // Schedule the actual operation
        self.schedule_operation(group_id, KeyOperation::Rotate {
            sequence: 0, // Will be determined at execution time
            reason: RotationReason::Scheduled,
        }, next_rotation, OperationPriority::Normal).await?;
        
        Ok(())
    }
    
    async fn schedule_operation(&self, group_id: [u8; 32], operation: KeyOperation, scheduled_at: SystemTime, priority: OperationPriority) -> Result<()> {
        let operation_id = self.generate_random_bytes(32);
        let pending_op = PendingKeyOperation {
            operation_id,
            group_id,
            operation,
            scheduled_at,
            priority,
            retry_count: 0,
            dependencies: Vec::new(),
        };
        
        let mut pending = self.pending_operations.lock().await;
        pending.push(pending_op);
        pending.sort_by(|a, b| a.scheduled_at.cmp(&b.scheduled_at));
        
        Ok(())
    }
    
    async fn schedule_immediate_operation(&self, group_id: [u8; 32], operation: KeyOperation) -> Result<()> {
        self.schedule_operation(group_id, operation, SystemTime::now(), OperationPriority::High).await
    }
    
    async fn execute_operation(&self, group_id: [u8; 32], operation: KeyOperation) -> Result<()> {
        match operation {
            KeyOperation::Rotate { reason, .. } => {
                self.rotate_keys(group_id, reason).await?;
            },
            KeyOperation::Backup { .. } => {
                self.create_backup(group_id).await?;
            },
            KeyOperation::Cleanup { cutoff_time, preserve_count } => {
                self.cleanup_old_keys(group_id, cutoff_time, preserve_count).await?;
            },
            _ => {
                warn!("Unsupported operation type: {:?}", operation);
            }
        }
        Ok(())
    }
    
    async fn cleanup_old_keys(&self, group_id: [u8; 32], cutoff_time: SystemTime, preserve_count: u32) -> Result<()> {
        let mut active_keys = self.active_keys.write().await;
        let key_set = active_keys.get_mut(&group_id)
            .ok_or_else(|| PhalanxError::crypto("Group not found for cleanup"))?;
        
        let mut old_keys: Vec<_> = key_set.previous_keys.iter()
            .filter(|(_, key)| key.created_at < cutoff_time)
            .map(|(&seq, _)| seq)
            .collect();
        
        old_keys.sort();
        old_keys.reverse();
        
        // Keep the specified number of keys
        let to_remove = old_keys.len().saturating_sub(preserve_count as usize);
        for &seq in old_keys.iter().take(to_remove) {
            key_set.previous_keys.remove(&seq);
        }
        
        info!("Cleaned up {} old keys for group {:?}", to_remove, hex::encode(group_id));
        Ok(())
    }
    
    fn generate_random_bytes(&self, length: usize) -> [u8; 32] {
        use rand::RngCore;
        let mut rng = rand::thread_rng();
        let mut bytes = [0u8; 32];
        rng.fill_bytes(&mut bytes[..length.min(32)]);
        bytes
    }
}

/// Local backup storage implementation
pub struct LocalBackupStorage {
    backup_dir: String,
}

impl LocalBackupStorage {
    pub async fn new(backup_dir: String) -> Result<Self> {
        tokio::fs::create_dir_all(&backup_dir).await
            .map_err(|e| PhalanxError::crypto(format!("Failed to create backup directory: {}", e)))?;
        
        Ok(Self { backup_dir })
    }
}

#[async_trait]
impl KeyBackupStorage for LocalBackupStorage {
    async fn store_backup(&self, group_id: [u8; 32], keyset: &KeySet, metadata: &BackupMetadata) -> Result<BackupId> {
        let backup_path = format!("{}/{}.backup", self.backup_dir, hex::encode(metadata.backup_id));
        
        let backup_data = bincode::serialize(&(keyset, metadata))
            .map_err(|e| PhalanxError::crypto(format!("Serialization failed: {}", e)))?;
        
        tokio::fs::write(&backup_path, backup_data).await
            .map_err(|e| PhalanxError::crypto(format!("Failed to write backup: {}", e)))?;
        
        Ok(metadata.backup_id)
    }
    
    async fn retrieve_backup(&self, backup_id: BackupId) -> Result<(KeySet, BackupMetadata)> {
        let backup_path = format!("{}/{}.backup", self.backup_dir, hex::encode(backup_id));
        
        let backup_data = tokio::fs::read(&backup_path).await
            .map_err(|e| PhalanxError::crypto(format!("Failed to read backup: {}", e)))?;
        
        let (keyset, metadata) = bincode::deserialize(&backup_data)
            .map_err(|e| PhalanxError::crypto(format!("Deserialization failed: {}", e)))?;
        
        Ok((keyset, metadata))
    }
    
    async fn list_backups(&self, _group_id: [u8; 32]) -> Result<Vec<BackupInfo>> {
        // TODO: Implement proper backup listing
        Ok(Vec::new())
    }
    
    async fn delete_backup(&self, backup_id: BackupId) -> Result<()> {
        let backup_path = format!("{}/{}.backup", self.backup_dir, hex::encode(backup_id));
        tokio::fs::remove_file(&backup_path).await
            .map_err(|e| PhalanxError::crypto(format!("Failed to delete backup: {}", e)))?;
        Ok(())
    }
    
    async fn verify_backup(&self, backup_id: BackupId) -> Result<bool> {
        let backup_path = format!("{}/{}.backup", self.backup_dir, hex::encode(backup_id));
        Ok(tokio::fs::metadata(&backup_path).await.is_ok())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[tokio::test]
    async fn test_key_manager_creation() {
        let manager = AdvancedKeyManager::new().await.unwrap();
        assert!(manager.active_keys.read().await.is_empty());
    }
    
    #[tokio::test]
    async fn test_key_set_creation() {
        let manager = AdvancedKeyManager::new().await.unwrap();
        let identity = Identity::generate();
        let group_id = [1u8; 32];
        
        let key_set = manager.create_key_set(group_id, &identity).await.unwrap();
        assert_eq!(key_set.current_key.sequence, 1);
        assert_eq!(key_set.member_keys.len(), 1);
    }
    
    #[tokio::test]
    async fn test_key_rotation() {
        let manager = AdvancedKeyManager::new().await.unwrap();
        let identity = Identity::generate();
        let group_id = [1u8; 32];
        
        manager.create_key_set(group_id, &identity).await.unwrap();
        let new_sequence = manager.rotate_keys(group_id, RotationReason::Manual).await.unwrap();
        
        assert_eq!(new_sequence, 2);
    }
    
    #[tokio::test]
    async fn test_member_management() {
        let manager = AdvancedKeyManager::new().await.unwrap();
        let identity1 = Identity::generate();
        let identity2 = Identity::generate();
        let group_id = [1u8; 32];
        
        manager.create_key_set(group_id, &identity1).await.unwrap();
        manager.add_member(group_id, &identity2).await.unwrap();
        
        let key_set = manager.active_keys.read().await;
        let key_set = key_set.get(&group_id).unwrap();
        assert_eq!(key_set.member_keys.len(), 2);
    }
}