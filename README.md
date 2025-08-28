# 🛡️ Phalanx Crypto

End-to-end encryption library for secure group communications.

## Features

- **Group E2E Encryption**: Secure messaging for multiple participants
- **Forward Secrecy**: Past messages stay secure even if keys are compromised
- **Modern Cryptography**: ChaCha20-Poly1305, X25519, Ed25519, BLAKE3
- **Dynamic Membership**: Add/remove group members securely
- **Transport Agnostic**: Works over any communication channel
- **Async Support**: Built for modern async Rust applications

## Installation

```bash
cargo add phalanx-crypto
```

## Quick Start

### Create a Group

```rust
use phalanx_crypto::{PhalanxGroup, Identity};

// Generate identity
let identity = Identity::generate();

// Create new group
let mut group = PhalanxGroup::new(identity);

// Add members (in real app, exchange keys securely)
let member_identity = Identity::generate();
group.add_member(member_identity.public_key())?;
```

### Encrypt Messages

```rust
use phalanx_crypto::MessageContent;

// Create message
let content = MessageContent::text("Hello secure world!");

// Encrypt for group
let encrypted = group.encrypt_message(&content)?;

// Send encrypted bytes over network...
```

### Decrypt Messages

```rust
// Receive encrypted message
let decrypted = group.decrypt_message(&encrypted_message)?;

match decrypted.content_type {
    MessageType::Text => {
        println!("Message: {}", String::from_utf8_lossy(&decrypted.data));
    }
    MessageType::Binary => {
        // Handle binary data
    }
}
```

### Async Groups

```rust
use phalanx_crypto::AsyncPhalanxGroup;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let identity = Identity::generate();
    let mut group = AsyncPhalanxGroup::new(identity);
    
    // All operations are async
    let encrypted = group.encrypt_message(&content).await?;
    let decrypted = group.decrypt_message(&encrypted).await?;
    
    Ok(())
}
```

## Security

- **ChaCha20-Poly1305**: Authenticated encryption
- **X25519**: Key exchange and agreement  
- **Ed25519**: Digital signatures
- **BLAKE3**: Hashing and key derivation
- **Perfect Forward Secrecy**: Regular key rotation
- **Post-Compromise Security**: Recovery from key compromise

## Features

- `std` - Standard library support (default)
- `serde` - Serialization support
- `async` - Async group operations

## License

MIT OR Apache-2.0