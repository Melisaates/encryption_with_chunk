use aes::{Aes128, Aes256};
use block_modes::{Cbc, BlockMode};
use block_modes::block_padding::Pkcs7;
use rand::Rng;
use std::fs::{File, OpenOptions};
use std::io::{self, Read, Write, Seek, SeekFrom};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use hex::{encode};

// Struct to hold encryption key and initialization vector (IV)
pub struct KeyData {
    pub key: [u8; 16],
    pub iv: [u8; 16],
}

// Function to generate a random key and IV
pub fn generate_key_iv() -> KeyData {
    let mut rng = rand::thread_rng();
    KeyData {
        key: rng.gen(),
        iv: rng.gen(),
    }
}

type Aes128Cbc = Cbc<Aes128, Pkcs7>;

// Function to encrypt a file
pub fn encrypt_file(file_path: &str,
    output_path: &str,
    key: &[u8; 16],
    iv: &[u8; 16]) -> std::io::Result<()> {
    let key_data = generate_key_iv();

    // Encrypt the file
    // For AES-256, the key is 32 bytes and IV is 16 bytes
    let cipher = Aes128Cbc::new_from_slices(&key_data.key, &key_data.iv).unwrap();  // This should work correctly
    let mut file = File::open(file_path)?;
    let mut data = Vec::new();
    file.read_to_end(&mut data)?;

    let encrypted_data = cipher.encrypt_vec(&data);

    // Calculate HMAC
    let mut hmac = Hmac::<Sha256>::new_from_slice(&key_data.key).expect("HMAC can take key of any size");
    hmac.update(&encrypted_data);
    let hmac_result = hmac.finalize().into_bytes();

    // Write the encrypted data and HMAC to the file
    let mut output_file = File::create(output_path)?;
    output_file.write_all(&encrypted_data)?;
    output_file.write_all(&hmac_result)?;

    Ok(())
}

// Function to decrypt a file
pub fn decrypt_file(file_path: &str,
    output_path: &str,
    key: &[u8; 16],
    iv: &[u8; 16]) -> std::io::Result<()> {

    let mut file = File::open(file_path)?;
    let mut encrypted_data = Vec::new();
    file.read_to_end(&mut encrypted_data)?;

    // HMAC check (we assume the HMAC is stored at the end of the file)
    if encrypted_data.len() < 32 {
        return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "Data too short to contain HMAC"));
    }

    let hmac_offset = encrypted_data.len() - 32;
    let hmac_received = &encrypted_data[hmac_offset..];
    let encrypted_data = &encrypted_data[..hmac_offset];

    // Compute HMAC
    let mut hmac = Hmac::<Sha256>::new_from_slice(key).expect("HMAC can take key of any size");
    hmac.update(encrypted_data);
    let hmac_calculated = hmac.finalize().into_bytes();

    // HMAC verification
    if hmac_received != hmac_calculated.as_slice() {
        return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "HMAC mismatch: Data is corrupted"));
    }

    // Decrypt the file data
    let cipher = Aes128Cbc::new_from_slices(key, iv).expect("Error creating cipher");
    let decrypted_data = cipher.decrypt_vec(encrypted_data).map_err(|_| {
        std::io::Error::new(std::io::ErrorKind::InvalidData, "Decryption failed")
    })?;

    // Write the decrypted data to the output file
    let mut output_file = File::create(output_path)?;
    output_file.write_all(&decrypted_data)?;

    Ok(())
}

// Function to encrypt data
pub fn encrypt_data(file_data: &[u8], key: &[u8; 16], iv: &[u8; 16]) -> std::io::Result<Vec<u8>> {

    // Encrypt with AES CBC
    let cipher = Aes128Cbc::new_from_slices(key, iv).expect("Error creating cipher");
    let encrypted_data = cipher.encrypt_vec(&file_data);

    // Calculate HMAC
    let mut hmac = Hmac::<Sha256>::new_from_slice(key).expect("HMAC can take key of any size");
    hmac.update(&encrypted_data);
    let hmac_result = hmac.finalize().into_bytes();

    Ok(encrypted_data)
}

// Function to decrypt data
pub fn decrypt_data(encrypted_data: &[u8], key: &[u8; 16], iv: &[u8; 16]) -> std::io::Result<Vec<u8>> {

    // Check HMAC
    if encrypted_data.len() < 32 {
        return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "Data too short to contain HMAC"));
    }

    let hmac_offset = encrypted_data.len() - 32;
    let hmac_received = &encrypted_data[hmac_offset..];
    let encrypted_data = &encrypted_data[..hmac_offset];

    println!("Received HMAC: {:?}", hmac_received);

    // Compute HMAC
    let mut hmac = Hmac::<Sha256>::new_from_slice(key).expect("HMAC can take key of any size");
    hmac.update(encrypted_data);
    let hmac_calculated = hmac.finalize().into_bytes();

    println!("Calculated HMAC: {:?}", hmac_calculated);

    // HMAC verification
    if hmac_received != hmac_calculated.as_slice() {
        return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "HMAC mismatch: Data is corrupted"));
    }

    // Decrypt the data
    // Decrypt with AES CBC
    let cipher = Aes128Cbc::new_from_slices(key, iv).expect("Error creating cipher");
    let decrypted_data = cipher.decrypt_vec(encrypted_data).map_err(|_| {
        std::io::Error::new(std::io::ErrorKind::InvalidData, "Decryption failed")
    })?;

    Ok(decrypted_data)
}

// Function to split a file into chunks
pub fn split_file(file_path: &str, chunk_size: usize) -> Vec<Vec<u8>> {
    let mut file = File::open(file_path).expect("Failed to open file");
    let mut file_contents = Vec::new();
    file.read_to_end(&mut file_contents).expect("Failed to read file");

    let mut chunks = Vec::new();
    for chunk in file_contents.chunks(chunk_size) {
        chunks.push(chunk.to_vec());
    }
    chunks
}
