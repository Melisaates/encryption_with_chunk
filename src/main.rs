mod encryption;
use encryption::{decrypt_file_chunked, encrypt_file_chunked, generate_key_iv};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let file_path = "input.mp4";
    let encrypted_file_path = "encrypted.mp4";
    let decrypted_file_path = "decrypted.mp4";
    
    let key_data = generate_key_iv();
    println!("Key: {:?}", key_data.key);
    println!("IV: {:?}", key_data.iv);
    
    encrypt_file_chunked(file_path, encrypted_file_path, &key_data.key, &key_data.iv)?;
    println!("File encrypted successfully: {}", encrypted_file_path);
    
    decrypt_file_chunked(encrypted_file_path, decrypted_file_path, &key_data.key, &key_data.iv)?;
    println!("File decrypted successfully: {}", decrypted_file_path);
    
    Ok(())
}