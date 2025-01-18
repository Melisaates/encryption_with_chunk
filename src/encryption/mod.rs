use aes::Aes128;
use block_modes::{BlockMode, Cbc};
use block_modes::block_padding::Pkcs7;
use cipher::{BlockEncrypt, BlockDecrypt};
use rand::Rng;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::error::Error;
use std::fs::File;
use std::io::{self, BufReader, BufWriter, Read, Write};

type Aes128Cbc = Cbc<Aes128, Pkcs7>;

pub const CHUNK_SIZE: usize = 10 * 1024 * 1024; // 10 MB
pub const HMAC_LENGTH: usize = 32;

pub struct KeyData {
    pub key: [u8; 16],
    pub iv: [u8; 16],
}

// Anahtar ve IV üretimi
pub fn generate_key_iv() -> KeyData {
    let mut rng = rand::thread_rng();
    KeyData {
        key: rng.gen(),
        iv: rng.gen(),
    }
}

// Dosyayı parçalara ayır
pub fn split_file(file_path: &str, chunk_size: usize) -> Vec<Vec<u8>> {
    let mut file = File::open(file_path).expect("Dosya açılamadı");
    let mut file_contents = Vec::new();
    file.read_to_end(&mut file_contents).expect("Dosya okunamadı");

    file_contents
        .chunks(chunk_size)
        .map(|chunk| chunk.to_vec())
        .collect()
}

// Dosyayı şifrele
pub fn encrypt_file_path_with_chunk(
    file_path: &str,
    output_path: &str,
    key: &[u8; 16],
    iv: &[u8; 16],
) -> io::Result<()> {
    let chunks = split_file(file_path, CHUNK_SIZE);
    let cipher = Aes128Cbc::new_from_slices(key, iv).expect("Cipher oluşturulamadı");
    let mut output_file = File::create(output_path)?;
    let mut hmac = Hmac::<Sha256>::new_from_slice(key).expect("HMAC oluşturulamadı");

    for chunk in chunks {
        let encrypted_data = cipher.clone().encrypt_vec(&chunk);
        hmac.update(&encrypted_data);
        output_file.write_all(&encrypted_data)?;
    }

    let hmac_result = hmac.finalize().into_bytes();
    output_file.write_all(&hmac_result)?;

    Ok(())
}

pub fn decrypt_file_chunked(
    file_path: &str,
    output_path: &str,
    key: &[u8; 16],
    iv: &[u8; 16],
) -> Result<(), Box<dyn Error>> {
    let input_file = File::open(file_path)?;
    let mut reader = BufReader::new(input_file);
    let mut encrypted_data = Vec::new();
    reader.read_to_end(&mut encrypted_data)?;

    if encrypted_data.len() < HMAC_LENGTH {
        return Err(Box::new(io::Error::new(
            io::ErrorKind::InvalidData,
            "HMAC eksik",
        )));
    }

    let hmac_offset = encrypted_data.len() - HMAC_LENGTH;
    let hmac_received = &encrypted_data[hmac_offset..];
    let encrypted_data = &encrypted_data[..hmac_offset];

    let mut hmac = Hmac::<Sha256>::new_from_slice(key)?;
    hmac.update(encrypted_data);
    let hmac_calculated = hmac.finalize().into_bytes();

    if hmac_received != hmac_calculated.as_slice() {
        return Err(Box::new(io::Error::new(
            io::ErrorKind::InvalidData,
            "HMAC uyuşmuyor",
        )));
    }

    let mut writer = BufWriter::new(File::create(output_path)?);
    let cipher = Aes128Cbc::new_from_slices(key, iv)?;

    let mut count = 0;
    for chunk in encrypted_data.chunks(CHUNK_SIZE) {
        count += 1;
        println!("Chunk: {}", count);

        // Debug: Veriyi ve HMAC'i kontrol et
        println!("Encrypted chunk: {:?}", chunk);

        let decrypted_chunk = cipher.clone().decrypt_vec(chunk).map_err(|e| {
            println!("Decrypt error details: {:?}", e); // Hata detaylarını yazdır
            Box::new(io::Error::new(io::ErrorKind::InvalidData, format!("Decrypt error: {:?}", e)))
        })?;
        
        // Debug: Çözülmüş veriyi kontrol et
        println!("Decrypted chunk: {:?}", decrypted_chunk);

        writer.write_all(&decrypted_chunk)?;
    }

    writer.flush()?;
    Ok(())
}







pub fn encrypt_file_with_chunk(file_data: &[u8], key: &[u8; 16], iv: &[u8; 16]) -> std::io::Result<Vec<u8>> {
    let cipher = Aes128Cbc::new_from_slices(key, iv).expect("Error creating cipher");
    
    // Veriyi parçalar halinde işleyin
    let mut encrypted_result = Vec::new();
    for chunk in file_data.chunks(CHUNK_SIZE) {
        let encrypted_chunk = cipher.clone().encrypt_vec(chunk);
        encrypted_result.extend(encrypted_chunk);
    }

    // HMAC hesaplama
    let mut hmac = Hmac::<Sha256>::new_from_slice(key).expect("HMAC can take key of any size");
    hmac.update(&encrypted_result);
    let hmac_result = hmac.finalize().into_bytes();

    // Şifrelenmiş veri ile HMAC birleştirme
    encrypted_result.extend_from_slice(&hmac_result);

    Ok(encrypted_result)
}


pub fn decrypt_file_with_chunk(encrypted_data: &[u8], key: &[u8; 16], iv: &[u8; 16]) -> std::io::Result<Vec<u8>> {
    //let mut file = File::open(file_path)?;
  //  let mut encrypted_data = Vec::new();
  //  file.read_to_end(&mut encrypted_data)?;

    // HMAC'ı kontrol etme
    if encrypted_data.len() < 32 {
        return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "Data too short to contain HMAC"));
    }

    // HMAC'ı ve şifreli veriyi ayırma
    // HMAC, verinin son 32 byte'ıdır
    // Veri, HMAC'den önceki kısımdır
    let hmac_offset = encrypted_data.len() - 32;
    let hmac_received = &encrypted_data[hmac_offset..];
    let encrypted_data = &encrypted_data[..hmac_offset];

    println!("Received HMAC: {:?}", hmac_received);

    // HMAC'ı hesaplama
    let mut hmac = Hmac::<Sha256>::new_from_slice(key).expect("HMAC can take key of any size");
    hmac.update(encrypted_data);
    let hmac_calculated = hmac.finalize().into_bytes();

    println!("Calculated HMAC: {:?}", hmac_calculated);

    // HMAC doğrulama
    if hmac_received != hmac_calculated.as_slice() {
        return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "HMAC mismatch: Data is corrupted"));
    }

    // Şifreyi çözme
    let cipher = Aes128Cbc::new_from_slices(key, iv).expect("Error creating cipher");
    let decrypted_data = cipher.clone().decrypt_vec(encrypted_data).map_err(|_| {
        std::io::Error::new(std::io::ErrorKind::InvalidData, "Decryption failed")
    })?;

    Ok(decrypted_data)
}



































//use openssl::symm::{Cipher, Crypter, Mode};

// pub fn encrypt_decrypt_test() {
//     let key = b"verysecretkey123";  // 16-byte key for AES-128
//     let iv = b"initialvector123";  // 16-byte IV
//     let data = b"Hello, world!";  // Known data to test

//     // Encrypt the data
//     let cipher = Cipher::aes_128_cbc();
//     let mut encrypter = Crypter::new(cipher, Mode::Encrypt, key, Some(iv)).unwrap();
//     let mut encrypted_data = vec![0; data.len() + cipher.block_size()];
//     let count = encrypter.update(data, &mut encrypted_data).unwrap();
//     let rest = encrypter.finalize(&mut encrypted_data[count..]).unwrap();
//     encrypted_data.truncate(count + rest);

//     println!("Encrypted data: {:?}", encrypted_data);

//     // Decrypt the data
//     let mut decrypter = Crypter::new(cipher, Mode::Decrypt, key, Some(iv)).unwrap();
//     let mut decrypted_data = vec![0; encrypted_data.len()];
//     let count = decrypter.update(&encrypted_data, &mut decrypted_data).unwrap();
//     let rest = decrypter.finalize(&mut decrypted_data[count..]).unwrap();
//     decrypted_data.truncate(count + rest);

//     println!("Decrypted data: {:?}", String::from_utf8(decrypted_data).unwrap());
// }