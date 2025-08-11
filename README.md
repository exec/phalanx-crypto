# Phalanx Protocol

**🛡️ General-purpose group E2E encryption protocol**

Phalanx is a cryptographically secure group communication protocol designed for maximum security, flexibility, and ease of use. While originally created for the Legion Protocol ecosystem, Phalanx is a standalone crate that can be used by any communication system requiring group end-to-end encryption.

## 🎯 Overview

Phalanx provides military-grade security for group communications with:

- **End-to-End Encryption**: Only group members can decrypt messages
- **Forward Secrecy**: Past messages remain secure even if current keys are compromised  
- **Post-Compromise Security**: Future messages remain secure after key compromise recovery
- **Perfect Authentication**: All messages are cryptographically signed and verified
- **Flexible Membership**: Dynamic group membership with role-based permissions
- **Transport Agnostic**: Works over any reliable communication channel

## 🔐 Security Features

### Cryptographic Primitives

- **ChaCha20-Poly1305**: Authenticated encryption for messages
- **X25519**: Elliptic curve Diffie-Hellman for key exchange  
- **Ed25519**: Digital signatures for authentication
- **BLAKE3**: Cryptographic hashing and key derivation
- **HKDF**: Key derivation function for perfect forward secrecy

### Security Properties

✅ **Confidentiality**: Messages encrypted with group keys  
✅ **Integrity**: Authenticated encryption prevents tampering  
✅ **Authentication**: Every message is cryptographically signed  
✅ **Forward Secrecy**: Regular key rotation protects past messages  
✅ **Post-Compromise Security**: Key compromise recovery protects future messages  
✅ **Deniability**: Messages cannot be proven to originate from specific users  
✅ **Metadata Protection**: Minimal information leakage about group activity

## 🚀 Quick Start

Add Phalanx to your `Cargo.toml`:

```toml
[dependencies]
phalanx = "0.1"

# Optional features
phalanx = { version = "0.1", features = ["serde", "async"] }
```

### Basic Usage

```rust
use phalanx::{Identity, PhalanxGroup, MessageContent};

// Create identities for group members
let alice = Identity::generate();
let bob = Identity::generate();

// Alice creates a group
let mut alice_group = PhalanxGroup::new(alice.clone());

// Alice adds Bob to the group  
alice_group.add_member(bob.public_key(), MemberRole::Member)?;

// Alice sends a message
let content = MessageContent::text("Hello, secure group!");
let encrypted_msg = alice_group.encrypt_message(&content)?;

// Bob receives and decrypts the message
let decrypted = alice_group.decrypt_message(&encrypted_msg)?;
println!("Decrypted: {}", decrypted.as_string()?);
```

### Async Support

```rust
use phalanx::{Identity, AsyncPhalanxGroup, MessageContent};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let alice = Identity::generate();
    let group = AsyncPhalanxGroup::new(alice);
    
    let content = MessageContent::text("Hello, async world!");
    let encrypted = group.encrypt_message(&content).await?;
    let decrypted = group.decrypt_message(&encrypted).await?;
    
    println!("Message: {}", decrypted.as_string()?);
    Ok(())
}
```

## 🏗️ Architecture

### Core Components

```
┌─────────────────────────────────────────────────────────┐
│                    Phalanx Protocol                     │
├─────────────────────────────────────────────────────────┤
│  Identity Management  │  Group Management  │  Messages  │
│  - Key Generation     │  - Member Roles    │  - Encrypt │
│  - Authentication     │  - Permissions     │  - Decrypt │
│  - Key Exchange       │  - Key Rotation    │  - Verify  │
├─────────────────────────────────────────────────────────┤
│                Cryptographic Primitives                 │
│  ChaCha20-Poly1305  │  X25519  │  Ed25519  │  BLAKE3   │
└─────────────────────────────────────────────────────────┘
```

### Message Flow

```
┌─────────┐    encrypt    ┌─────────────┐    transport    ┌─────────┐
│ Alice   │─────────────→│ Phalanx     │─────────────────│ Network │
│         │               │ Group       │                 │         │
└─────────┘               └─────────────┘                 └─────────┘
                                 │                              │
                                 │                              ▼
┌─────────┐    decrypt    ┌─────────────┐    receive     ┌─────────┐
│ Bob     │◀─────────────│ Phalanx     │◀────────────────│ Network │
│         │               │ Group       │                 │         │
└─────────┘               └─────────────┘                 └─────────┘
```

## 📚 Advanced Features

### Group Management

```rust
use phalanx::{PhalanxGroup, GroupConfig, GroupVisibility, MemberRole};

// Create group with custom configuration
let config = GroupConfig {
    max_members: 50,
    key_rotation_interval: 3600, // 1 hour
    visibility: GroupVisibility::InviteOnly,
    persistent_storage: true,
    ..Default::default()
};

let mut group = PhalanxGroup::with_config(identity, config);

// Add members with different roles
group.add_member(alice_key, MemberRole::Admin)?;
group.add_member(bob_key, MemberRole::Member)?;

// Rotate keys manually or automatically
if group.needs_key_rotation() {
    let rotation_msg = group.rotate_keys()?;
    // Broadcast rotation message to all members
}
```

### Message Threading

```rust
use phalanx::MessageContent;

// Create a threaded conversation
let thread_id = [1u8; 32];
let reply_to_msg_id = [2u8; 32];

let content = MessageContent::reply("This is a reply", reply_to_msg_id)
    .with_thread(thread_id)
    .with_metadata("priority", "high");

let message = group.encrypt_message(&content)?;
```

### Handshake Protocol

```rust
use phalanx::{HandshakeMessage, Identity};

// Client creates handshake to join group
let client = Identity::generate();
let handshake = HandshakeMessage::new(
    &client,
    group_id,
    vec!["phalanx/v1".to_string()],
    "my-app/1.0".to_string(),
)?;

// Server verifies and processes handshake
let payload = handshake.verify_and_decrypt()?;
if payload.group_id == expected_group_id {
    // Allow client to join group
}
```

## 🔧 Configuration

### Feature Flags

- `std` (default): Standard library support
- `serde`: JSON serialization/deserialization support  
- `async`: Async/await support with Tokio

### Security Parameters

```rust
use phalanx::constants::*;

// Protocol limits
MAX_GROUP_SIZE: 1000 members
MAX_MESSAGE_SIZE: 1MB
DEFAULT_KEY_ROTATION_INTERVAL: 24 hours

// Cryptographic parameters  
KEY_SIZE: 32 bytes (256-bit)
NONCE_SIZE: 12 bytes
TAG_SIZE: 16 bytes
```

## 🧪 Testing

Run the comprehensive test suite:

```bash
# Basic tests
cargo test

# All features
cargo test --all-features

# Benchmarks
cargo bench
```

## 🔒 Security Considerations

### Key Management

- **Ephemeral Keys**: Session keys are ephemeral and regularly rotated
- **Key Derivation**: Strong key derivation using HKDF-BLAKE3
- **Secure Deletion**: Keys are zeroized on drop
- **No Key Reuse**: Each message uses a fresh nonce

### Forward Secrecy

- **Automatic Rotation**: Keys rotate based on time and membership changes
- **Ratcheting**: Future keys cannot be derived from past keys
- **Member Changes**: Key rotation triggered on member join/leave

### Implementation Security

- **Constant-Time Operations**: Timing attack resistance
- **Memory Safety**: Written in Rust with no unsafe code
- **Zeroization**: Sensitive data cleared from memory
- **Side-Channel Resistance**: Careful implementation of crypto operations

## 🤝 Integration Examples

### Legion Protocol Integration

```rust
use legion_protocol::{IronSession, ChannelType};
use phalanx::{PhalanxGroup, Identity};

// Detect Legion encrypted channel
if let ChannelType::LegionEncrypted = get_channel_type("!secure") {
    let group = PhalanxGroup::new(identity);
    // Integrate with Legion Protocol session
}
```

### Custom Transport

```rust
use phalanx::{GroupMessage, EncryptedMessage};

// Implement your transport layer
trait MessageTransport {
    async fn send(&self, msg: EncryptedMessage) -> Result<()>;
    async fn receive(&self) -> Result<EncryptedMessage>;
}

// Phalanx works with any reliable transport
struct MyTransport;
impl MessageTransport for MyTransport {
    // Your implementation here
}
```

## 🛣️ Roadmap

### Version 0.2 (Planned)
- [ ] Zero-knowledge membership proofs
- [ ] Onion routing for metadata protection  
- [ ] Multi-device support per identity
- [ ] Message deletion/redaction
- [ ] Audit logging

### Version 0.3 (Future)
- [ ] Post-quantum cryptography migration
- [ ] Cross-group messaging
- [ ] Advanced permission systems
- [ ] Formal verification of protocols

## 📄 License

Licensed under the MIT License. See [LICENSE](LICENSE) for details.

## 🤖 Contributing

Contributions welcome! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

**Security Issues**: Please report security issues privately to security@phalanx-protocol.org

---

**Built with 🛡️ by the Phalanx Protocol team**

*Phalanx: Where privacy meets usability in group communications.*