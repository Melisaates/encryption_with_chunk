use aes::{Aes128, Aes256};
use block_modes::{Cbc, BlockMode};
use block_modes::block_padding::Pkcs7;
use std::fs::{File, OpenOptions};
use std::io::{self, Read, Write, Seek, SeekFrom};
use hmac::{Hmac, Mac, NewMac};
use rand::Rng;
use sha2::Sha256;
use hex::{encode};
const CHUNK_SIZE: usize = 10 * 1024 * 1024; // 5 MB
const HMAC_LENGTH: usize = 32;  // HMAC length (in bytes)

type Aes128Cbc = Cbc<Aes128, Pkcs7>;

pub struct KeyData {
   pub key: [u8; 16],
    pub iv: [u8; 16],
}   

// Generate key and IV for encryption
pub fn generate_key_iv() -> KeyData {
    let mut rng = rand::thread_rng();
    let key: [u8; 16] = rng.gen();
    let iv: [u8; 16] = rng.gen();
    KeyData { key, iv }
}



pub fn split_file(file_path: &str, chunk_size: usize) -> Vec<Vec<u8>> {
    let mut file = File::open(file_path).expect("Dosya açılamadı");
    let mut file_contents = Vec::new();
    file.read_to_end(&mut file_contents).expect("Dosya okunamadı");

    let mut chunks = Vec::new();
    for chunk in file_contents.chunks(chunk_size) {
        chunks.push(chunk.to_vec());
    }
    chunks
}


// HMAC hesaplama ve doğrulama işlemi
pub fn encrypt_file_path_with_chunk(file_path: &str, output_path: &str, key: &[u8; 16], iv: &[u8; 16]) -> std::io::Result<()> {
    // Dosyayı parçalara böl

    println!("key: {:?}", key);
    println!("iv: {:?}", iv);
    let chunks = split_file(file_path, CHUNK_SIZE);
    let cipher = Aes128Cbc::new_from_slices(key, iv).expect("Error creating cipher");
    let mut output_file = File::create(output_path)?;

    // HMAC oluştur
    let mut hmac = Hmac::<Sha256>::new_from_slice(key).expect("HMAC can take key of any size");

    // Her parçayı şifrele ve yaz
    for chunk in chunks {
        let encrypted_data = cipher.clone().encrypt_vec(&chunk);
        hmac.update(&encrypted_data);
        output_file.write_all(&encrypted_data)?;
    }

    // Son olarak HMAC'i dosyaya yaz
    let hmac_result = hmac.finalize().into_bytes();
    output_file.write_all(&hmac_result)?;

    Ok(())
}



// decrypt file path fonksiyonu oluşturuldu   
// Chunk size ve HMAC length sabitleri tanımlandı
pub fn decrypt_file_path_with_chunk(file_path: &str, output_path: &str, key: &[u8; 16], iv: &[u8; 16]) -> io::Result<()> {
    let mut file = File::open(file_path)?;
    let mut output_file = File::create(output_path)?;
    


    let file_metadata = file.metadata()?;
    let file_size = file_metadata.len() as usize;

    if file_size < HMAC_LENGTH {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "Data too short to contain HMAC"));
    }

    file.seek(SeekFrom::End(-(HMAC_LENGTH as i64)))?;
    let mut hmac_received = vec![0u8; HMAC_LENGTH];
    file.read_exact(&mut hmac_received)?;

    file.seek(SeekFrom::Start(0))?;

    let mut hmac_calculator = Hmac::<Sha256>::new_from_slice(key).expect("HMAC can take key of any size");
    let mut buffer = vec![0u8; CHUNK_SIZE];
    let mut total_read = 0;

    while total_read + CHUNK_SIZE < file_size - HMAC_LENGTH {
        let read_bytes = file.read(&mut buffer)?;
        if read_bytes == 0 {
            break;
        }
        // Log the encrypted data chunk before decryption
        println!("Encrypted chunk: {:?}", &buffer[..read_bytes]);
    
        // HMAC update
        hmac_calculator.update(&buffer[..read_bytes]);
    
        let cipher = Cbc::<Aes128, Pkcs7>::new_from_slices(key, iv).expect("Error creating cipher");
        let decrypted_chunk = cipher.decrypt_vec(&buffer[..read_bytes]).map_err(|e| {
            eprintln!("Decryption error: {:?}", e);
            io::Error::new(io::ErrorKind::InvalidData, "Decryption failed")
        })?;
    
        // Log the decrypted chunk
        println!("Decrypted chunk: {:?}", decrypted_chunk);
        output_file.write_all(&decrypted_chunk)?;
    
        total_read += read_bytes;
    }
    
    // HMAC doğrulaması
    let hmac_calculated = hmac_calculator.finalize().into_bytes();
    println!("Calculated HMAC: {:?}", hmac_calculated);
println!("Received HMAC: {:?}", hmac_received);
    if hmac_received != hmac_calculated.as_slice() {
        eprintln!("HMAC mismatch: expected {:?}, got {:?}", hmac_received, hmac_calculated);
        return Err(io::Error::new(io::ErrorKind::InvalidData, "HMAC mismatch: Data is corrupted"));
    }

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
    let decrypted_data = cipher.decrypt_vec(encrypted_data).map_err(|_| {
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