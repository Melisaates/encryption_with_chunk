mod encryption;
use encryption::{decrypt_file_chunked, encrypt_file_path_with_chunk, generate_key_iv};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let file_path = "C:/Users/melisates/Documents/WhatsApp Video 2024-11-03 at 18.47.50_f9c56fbd.mp4";
    //WhatsApp Image 2024-12-01 at 14.40.49_48a551a2.jpg
    //1. Algorithms and Computation.mp4
    //Documents/WhatsApp Video 2024-11-03 at 18.47.50_f9c56fbd.mp4
    let encrypted_file_path = "C:/Users/melisates/development/encryption_with_chunk/files/encrypteered.mp4";
    let decrypted_file_path = "C:/Users/melisates/Documents/decryptereed.mp4";

    let key_data = generate_key_iv();
    println!("Key: {:?}", key_data.key);
    println!("IV: {:?}", key_data.iv);

    encrypt_file_path_with_chunk(file_path, encrypted_file_path, &key_data.key, &key_data.iv)?;
    println!("Dosya başarıyla şifrelendi: {}", encrypted_file_path);

    

    decrypt_file_chunked(encrypted_file_path, decrypted_file_path, &key_data.key, &key_data.iv)?;
    println!("Dosya başarıyla çözüldü: {}", decrypted_file_path);

    Ok(())
}

