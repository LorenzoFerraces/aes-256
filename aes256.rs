use aes::Aes256;
use base64::{engine::general_purpose, Engine as _};
use cbc::cipher::{BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use rand::Rng;
use std::io::{self, Write, Read};
use std::fs::{OpenOptions, File};
use std::path::Path;

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

    pub fn encrypt_file(&self, mut file: &File, path: String) -> Result<(), Box<dyn std::error::Error>> {
        // Generate random IV
        let mut iv = [0u8; 16];
        let mut file_bytes = Vec::new();
        file.read_to_end(&mut file_bytes)?;
        rand::thread_rng().fill(&mut iv);

        // Create encryptor
        let cipher = Aes256CbcEnc::new(&self.key.into(), &iv.into());

        // Prepare buffer for encryption (need space for padding)
        let mut buffer = vec![0u8; file_bytes.len() + 16]; // Extra space for padding
        buffer[0..file_bytes.len()].copy_from_slice(file_bytes.as_slice());

        // Encrypt the data with PKCS7 padding
        let ciphertext = cipher
            .encrypt_padded_mut::<cbc::cipher::block_padding::Pkcs7>(
                &mut buffer,
                file_bytes.len(),
            )
            .map_err(|e| format!("Encryption failed: {:?}", e))?;

        // Combine IV and ciphertext
        let mut result = Vec::new();
        result.extend_from_slice(&iv);
        result.extend_from_slice(ciphertext);

        // Encode to base64
        let encode = base64::engine::general_purpose::STANDARD.encode(&result);

        // Return the encrypted file
        let mut new_file = File::create(path)?;
        new_file.write_all(encode.as_bytes())?;

        Ok(())
    }

    pub fn decrypt_file(&self, mut encrypted_file: &File, path: String) -> Result<(), Box<dyn std::error::Error>> {
        let mut file_bytes = Vec::new();
        encrypted_file.read_to_end(&mut file_bytes)?;
        // Decode from base64
        let data = base64::engine::general_purpose::STANDARD
            .decode(file_bytes)
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

        // Return the decrypted file
        let mut new_file = File::create(path)?;
        new_file.write_all(plaintext)?;
        
        Ok(())
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
    println!("2. Input path to the file to encrypt");
    println!("3. Encrypt file");
    println!("4. Decrypt file");
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
    let mut current_path = String::new();
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
                current_path = get_input("Enter the path to the file to encrypt: ");
                println!("File stored for encryption.");
            }
            "3" => {
                if current_path.is_empty() {
                    current_path = get_input("Enter the path to the file to encrypt: ")
                };

                let path = Path::new(&current_path);
                if path.exists() && path.is_file() {
                    println!("Encrypting");
                    let file = OpenOptions::new().write(true).read(true).open(&current_path)?;
                    match aes.encrypt_file(&file, current_path.clone()) {
                        Ok(()) => {
                            last_encrypted = current_path.clone();
                            println!("Encrypted (base64)");
                        }
                        Err(e) => println!("Encryption error: {}", e),
                    }
                } else {
                    println!("The file or path does not exist. Try again.");
                    current_path = "".to_string()
                }
                
            }
            "4" => {
                if last_encrypted.is_empty() {
                    last_encrypted = get_input("Enter the path to the encrypted file (base64): ")
                };

                let path = Path::new(&last_encrypted);
                if path.exists() && path.is_file() {
                    let file = OpenOptions::new().write(true).read(true).open(&last_encrypted)?;
                    match aes.decrypt_file(&file, last_encrypted.clone()) {
                        Ok(()) => println!("Decrypted file"),
                        Err(e) => println!("Decryption error: {}", e),
                    }
                } else {
                    println!("The file or path does not exist. Try again.");
                    last_encrypted = "".to_string()
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
