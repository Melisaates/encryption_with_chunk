use aes::Aes128;
use block_modes::{BlockMode, Cbc};
use block_modes::block_padding::Pkcs7;
use crypto_mac::Mac;
use hmac::{Hmac, Mac as _};
use rand::Rng;
use sha2::Sha256;
use std::error::Error;
use std::fs::File;
use std::io::{self, BufWriter, Read, Write};

// Define the AES-128 CBC type with PKCS7 padding
type Aes128Cbc = Cbc<Aes128, Pkcs7>;

// Define constants for chunk size and HMAC length
pub const CHUNK_SIZE: usize = 10 * 1024 * 1024; // 10 MB
pub const HMAC_LENGTH: usize = 32;

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

// Encrypt a single chunk of data
fn encrypt_chunk(chunk: &[u8], cipher: &Aes128Cbc) -> Vec<u8> {
    cipher.clone().encrypt_vec(chunk)
}

// Function to encrypt a file in chunks
pub fn encrypt_file_chunked(
    file_path: &str,
    output_path: &str,
    key: &[u8; 16],
    iv: &[u8; 16],
) -> io::Result<()> {
    let mut input_file = File::open(file_path)?;
    let mut output_file = File::create(output_path)?;
    let cipher = Aes128Cbc::new_from_slices(key, iv).expect("Cipher creation failed");
    
    // Create a temporary buffer to store all encrypted data before writing
    let mut encrypted_buffer = Vec::new();
    let mut buffer = vec![0; CHUNK_SIZE];

    loop {
        let bytes_read = input_file.read(&mut buffer)?;
        if bytes_read == 0 {
            break;
        }
        
        let chunk = &buffer[..bytes_read];
        let encrypted_chunk = encrypt_chunk(chunk, &cipher);
        
        // Write chunk length
        let chunk_len = (encrypted_chunk.len() as u32).to_le_bytes();
        encrypted_buffer.extend_from_slice(&chunk_len);
        
        // Write encrypted chunk
        encrypted_buffer.extend_from_slice(&encrypted_chunk);
    }

    // Calculate HMAC for all encrypted data
    let mut hmac = Hmac::<Sha256>::new_from_slice(key).expect("HMAC creation failed");
    hmac.update(&encrypted_buffer);
    let hmac_result = hmac.finalize().into_bytes();

    // Write everything to file
    output_file.write_all(&encrypted_buffer)?;
    output_file.write_all(&hmac_result)?;
    
    Ok(())
}

// Function to decrypt a file in chunks
pub fn decrypt_file_chunked(
    file_path: &str,
    output_path: &str,
    key: &[u8; 16],
    iv: &[u8; 16],
) -> Result<(), Box<dyn Error>> {
    let mut input_file = File::open(file_path)?;
    let mut encrypted_data = Vec::new();
    input_file.read_to_end(&mut encrypted_data)?;

    // Verify file length
    if encrypted_data.len() < HMAC_LENGTH {
        return Err("File too short".into());
    }

    // Split HMAC and encrypted data
    let hmac_offset = encrypted_data.len() - HMAC_LENGTH;
    let hmac_received = &encrypted_data[hmac_offset..];
    let encrypted_data = &encrypted_data[..hmac_offset];

    // Verify HMAC
    let mut hmac = Hmac::<Sha256>::new_from_slice(key)?;
    hmac.update(encrypted_data);
    let hmac_calculated = hmac.finalize().into_bytes();

    if hmac_received != hmac_calculated.as_slice() {
        println!("Expected HMAC: {:?}", hmac_calculated.as_slice());
        println!("Received HMAC: {:?}", hmac_received);
        return Err(Box::new(io::Error::new(io::ErrorKind::InvalidData, "HMAC verification failed")));
    }

    // Prepare for decryption
    let cipher = Aes128Cbc::new_from_slices(key, iv)?;
    let mut writer = BufWriter::new(File::create(output_path)?);
    let mut offset = 0;

    // Process chunks
    while offset + 4 <= encrypted_data.len() {
        // Read chunk length
        let chunk_len = u32::from_le_bytes(
            encrypted_data[offset..offset + 4].try_into().unwrap()
        ) as usize;
        offset += 4;

        // Verify chunk boundaries
        if offset + chunk_len > encrypted_data.len() {
            return Err(Box::new(io::Error::new(io::ErrorKind::InvalidData, "Invalid chunk length")));
        }

        // Decrypt chunk
        let encrypted_chunk = &encrypted_data[offset..offset + chunk_len];
        let decrypted_chunk = cipher.clone().decrypt_vec(encrypted_chunk)?;
        writer.write_all(&decrypted_chunk)?;

        offset += chunk_len;
    }

    writer.flush()?;
    Ok(())
}

// Function to encrypt data in chunks
pub fn encrypt_data_chunked(
    file_data: &[u8],
    key: &[u8; 16],
    iv: &[u8; 16],
) -> std::io::Result<Vec<u8>> {
    let cipher = Aes128Cbc::new_from_slices(key, iv).expect("Cipher creation failed");
    
    let mut encrypted_buffer = Vec::new();
    let mut offset = 0;

    // Process chunks of file data
    while offset < file_data.len() {
        let chunk_end = std::cmp::min(offset + CHUNK_SIZE, file_data.len());
        let chunk = &file_data[offset..chunk_end];
        let encrypted_chunk = encrypt_chunk(chunk, &cipher);

        // Add chunk length
        let chunk_len = (encrypted_chunk.len() as u32).to_le_bytes();
        encrypted_buffer.extend_from_slice(&chunk_len);
        
        // Add encrypted chunk
        encrypted_buffer.extend_from_slice(&encrypted_chunk);

        offset = chunk_end;
    }

    // Calculate HMAC for the encrypted data
    let mut hmac = Hmac::<Sha256>::new_from_slice(key).expect("HMAC creation failed");
    hmac.update(&encrypted_buffer);
    let hmac_result = hmac.finalize().into_bytes();

    // Append HMAC to the encrypted buffer
    encrypted_buffer.extend_from_slice(&hmac_result);

    Ok(encrypted_buffer)
}

// Function to decrypt data in chunks
pub fn decrypt_data_chunked(
    encrypted_data: &[u8],
    key: &[u8; 16],
    iv: &[u8; 16],
) -> std::io::Result<Vec<u8>> {
    // Verify the HMAC
    if encrypted_data.len() < HMAC_LENGTH {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "Encrypted data too short"));
    }

    let hmac_offset = encrypted_data.len() - HMAC_LENGTH;
    let hmac_received = &encrypted_data[hmac_offset..];
    let encrypted_data = &encrypted_data[..hmac_offset];

    let mut hmac = Hmac::<Sha256>::new_from_slice(key).expect("HMAC creation failed");
    hmac.update(encrypted_data);
    let hmac_calculated = hmac.finalize().into_bytes();

    if hmac_received != hmac_calculated.as_slice() {
        println!("Expected HMAC: {:?}", hmac_calculated.as_slice());
        println!("Received HMAC: {:?}", hmac_received);
        return Err(io::Error::new(io::ErrorKind::InvalidData, "HMAC verification failed"));
    }

    // Decrypt the data
    let cipher = Aes128Cbc::new_from_slices(key, iv).expect("Cipher creation failed");
    let mut decrypted_buffer = Vec::new();
    let mut offset = 0;

    while offset + 4 <= encrypted_data.len() {
        // Read the chunk length
        let chunk_len = u32::from_le_bytes(
            encrypted_data[offset..offset + 4].try_into().unwrap()
        ) as usize;
        offset += 4;

        // Validate chunk boundaries
        if offset + chunk_len > encrypted_data.len() {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "Invalid chunk length"));
        }

        // Decrypt the chunk
        let encrypted_chunk = &encrypted_data[offset..offset + chunk_len];
        let decrypted_chunk = cipher.clone().decrypt_vec(encrypted_chunk).expect("Decryption failed");
        decrypted_buffer.extend_from_slice(&decrypted_chunk);

        offset += chunk_len;
    }

    Ok(decrypted_buffer)
}
