use aes::Aes256;
use base64::{engine::general_purpose, Engine as _};
use cbc::cipher::{BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use cbc::{Decryptor, Encryptor};
use rand::Rng;
use std::io::{self, Write};

// Create type aliases for AES-256-CBC
type Aes256CbcEnc = cbc::Encryptor<Aes256>;
type Aes256CbcDec = cbc::Decryptor<Aes256>;

pub struct AES256 {
    key: [u8; 32],
}

impl AES256 {
    pub fn new() -> Self {
        let mut key = [0u8; 32];
        rand::thread_rng().fill(&mut key);
        Self { key }
    }

    pub fn with_key(key: [u8; 32]) -> Self {
        Self { key }
    }

    pub fn from_base64(base64_key: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let key_bytes = general_purpose::STANDARD
            .decode(base64_key)
            .map_err(|e| format!("Failed to decode base64 key: {}", e))?;

        if key_bytes.len() != 32 {
            return Err("Invalid key length. Must be 32 bytes (256 bits)".into());
        }

        let mut key = [0u8; 32];
        key.copy_from_slice(&key_bytes);
        Ok(Self { key })
    }

    pub fn encrypt(&self, plaintext: &str) -> Result<String, Box<dyn std::error::Error>> {
        // Generate random IV
        let mut iv = [0u8; 16];
        rand::thread_rng().fill(&mut iv);

        // Create encryptor
        let cipher = Aes256CbcEnc::new(&self.key.into(), &iv.into());

        // Prepare buffer for encryption (need space for padding)
        let plaintext_bytes = plaintext.as_bytes();
        let mut buffer = vec![0u8; plaintext_bytes.len() + 16]; // Extra space for padding
        buffer[0..plaintext_bytes.len()].copy_from_slice(plaintext_bytes);

        // Encrypt the data with PKCS7 padding
        let ciphertext = cipher
            .encrypt_padded_mut::<cbc::cipher::block_padding::Pkcs7>(
                &mut buffer,
                plaintext_bytes.len(),
            )
            .map_err(|e| format!("Encryption failed: {:?}", e))?;

        // Combine IV and ciphertext
        let mut result = Vec::new();
        result.extend_from_slice(&iv);
        result.extend_from_slice(ciphertext);

        // Encode to base64
        Ok(general_purpose::STANDARD.encode(&result))
    }

    pub fn decrypt(&self, encrypted_data: &str) -> Result<String, Box<dyn std::error::Error>> {
        // Decode from base64
        let data = general_purpose::STANDARD
            .decode(encrypted_data)
            .map_err(|e| format!("Failed to decode base64: {}", e))?;

        if data.len() < 16 {
            return Err("Invalid encrypted data: too short".into());
        }

        // Extract IV and ciphertext
        let (iv, ciphertext) = data.split_at(16);
        let iv: [u8; 16] = iv.try_into().map_err(|_| "Invalid IV length")?;

        // Create decryptor
        let cipher = Aes256CbcDec::new(&self.key.into(), &iv.into());

        // Prepare buffer for decryption
        let mut buffer = ciphertext.to_vec();

        // Decrypt the data with PKCS7 padding removal
        let plaintext = cipher
            .decrypt_padded_mut::<cbc::cipher::block_padding::Pkcs7>(&mut buffer)
            .map_err(|e| format!("Failed to decrypt: {:?}", e))?;

        // Convert to string
        String::from_utf8(plaintext.to_vec())
            .map_err(|e| format!("Failed to convert to UTF-8: {}", e).into())
    }

    pub fn get_key_base64(&self) -> String {
        general_purpose::STANDARD.encode(&self.key)
    }
}

impl Default for AES256 {
    fn default() -> Self {
        Self::new()
    }
}

fn print_menu() {
    println!("\nAES-256 Encryption Utility");
    println!("-------------------------");
    println!("1. Generate new key");
    println!("2. Input message to encrypt");
    println!("3. Encrypt message (uses 'Hello, World!' if no message set)");
    println!("4. Decrypt message");
    println!("5. Show current key");
    println!("6. Load key from base64");
    println!("0. Exit");
    print!("\nChoice: ");
    io::stdout().flush().unwrap();
}

fn get_input(prompt: &str) -> String {
    print!("{}", prompt);
    io::stdout().flush().unwrap();
    let mut input = String::new();
    io::stdin().read_line(&mut input).unwrap();
    input.trim().to_string()
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut aes = AES256::new();
    let mut current_message = String::new();
    let mut last_encrypted = String::new();

    loop {
        print_menu();

        let choice = get_input("");
        println!();

        match choice.as_str() {
            "1" => {
                aes = AES256::new();
                println!("New key generated!");
                println!("Key (base64): {}", aes.get_key_base64());
            }
            "2" => {
                current_message = get_input("Enter message to encrypt: ");
                println!("Message stored for encryption.");
            }
            "3" => {
                let message = if current_message.is_empty() {
                    "Hello, World!"
                } else {
                    &current_message
                };

                println!("Encrypting: {}", message);
                match aes.encrypt(message) {
                    Ok(encrypted) => {
                        last_encrypted = encrypted.clone();
                        println!("Encrypted (base64): {}", encrypted);
                    }
                    Err(e) => println!("Encryption error: {}", e),
                }
            }
            "4" => {
                let encrypted = if last_encrypted.is_empty() {
                    get_input("Enter encrypted message (base64): ")
                } else {
                    println!("Using last encrypted message: {}", last_encrypted);
                    last_encrypted.clone()
                };

                match aes.decrypt(&encrypted) {
                    Ok(decrypted) => println!("Decrypted message: {}", decrypted),
                    Err(e) => println!("Decryption error: {}", e),
                }
            }
            "5" => {
                println!("Current key (base64): {}", aes.get_key_base64());
            }
            "6" => {
                let key = get_input("Enter key (base64): ");
                match AES256::from_base64(&key) {
                    Ok(new_aes) => {
                        aes = new_aes;
                        println!("Key loaded successfully!");
                    }
                    Err(e) => println!("Error loading key: {}", e),
                }
            }
            "0" => {
                println!("Goodbye!");
                break;
            }
            _ => println!("Invalid choice. Please try again."),
        }

        println!("\nPress Enter to continue...");
        io::stdin().read_line(&mut String::new())?;
    }

    Ok(())
}

// Cargo.toml dependencies:
/*
[dependencies]
aes = "0.8"
block-modes = "0.9"
rand = "0.8"
base64 = "0.21"
*/
