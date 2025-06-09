# AES-256 Encryption/Decryption in Rust

This repository contains a complete working example of AES-256 encryption and decryption in Rust. The implementation uses AES-256-CBC mode with PKCS7 padding and includes proper IV generation for security.

## Overview

This Rust implementation provides:
- AES-256 encryption (256-bit keys)
- CBC mode with PKCS7 padding
- Random IV generation for each encryption
- Secure key generation
- Base64 encoding for output
- Comprehensive error handling with `Result` types

## Dependencies

Add the following dependencies to your `Cargo.toml`:

```toml
[dependencies]
aes = "0.8"
block-modes = "0.9"
rand = "0.8"
base64 = "0.21"
```

## Usage

**Run the example:**
```bash
cargo run --bin aes256_rust
```

Or compile and run directly:
```bash
rustc aes256_rust.rs
./aes256_rust
```

## Key Features

- **Memory-safe**: Implementation using Rust's type system prevents common cryptographic vulnerabilities
- **Zero-cost abstractions**: Compile-time guarantees with no runtime overhead
- **Comprehensive error handling**: Uses `Result` types for robust error management
- **Modern cryptographic libraries**: Built on well-maintained, audited crates

## Usage Pattern

The implementation follows this pattern:

```rust
1. Create an AES256 instance (with random or provided key)
2. Encrypt plaintext → get base64-encoded result
3. Decrypt base64 data → get original plaintext
4. Verify results match
```

## Example Output

```
Key (base64): rKz8Gme5xR7FC7TzAH9hN2gOb8p4Z3K1vX9sL4qW2Ys=
Original message: Hello, this is a secret message!
Encrypted (base64): kJ9mL7Fh3N2pO5R8qT1vX4Z6Y... (truncated)
Decrypted message: Hello, this is a secret message!
Messages match: true
```

## Security Notes

⚠️ **Important Security Considerations:**

1. **Key Management**: In production, never log or display encryption keys
2. **Key Storage**: Store keys securely using proper key management systems
3. **Random Generation**: The implementation uses cryptographically secure random number generators
4. **IV Uniqueness**: Each encryption operation uses a fresh, random IV
5. **Authenticated Encryption**: Consider using AES-GCM for authenticated encryption in production

## File Structure

```
├── aes256_rust.rs        # Rust implementation
├── Cargo.toml           # Dependencies configuration
└── README.md            # This file
```

## Contributing

Feel free to submit improvements or optimizations to the Rust implementation!

## License

This example is provided for educational purposes. Use appropriate licenses for production code. 