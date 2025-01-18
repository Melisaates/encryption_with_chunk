mod encryption;
use encryption::{decrypt_file_path_with_chunk, encrypt_file_path_with_chunk, generate_key_iv};
fn main()  -> Result<(), Box<dyn std::error::Error>> {
    //try to encrypt and decrypt a file
    let file_path = "C:/Users/melisates/Downloads/1. Algorithms and Computation.mp4";
    //"C:\Users\melisates\Downloads\1. Algorithms and Computation.mp4"
    //Documents/WhatsApp Video 2024-11-03 at 18.47.50_f9c56fbd.mp4
    //WhatsApp Image 2024-12-01 at 14.40.49_48a551a2.jpg
    let encrypted_file_path = "C:/Users/melisates/Documents/encrypted_fileeee.mp4";
    let decrypted_file_path = "C:/Users/melisates/Documents/decrypted_fileee.mp4";


    println!("Encrypted file size: {}", std::fs::metadata(encrypted_file_path)?.len());
println!("File size before decryption: {}", std::fs::metadata(decrypted_file_path)?.len());

    // 1. Generate key and IV
    let key_data = generate_key_iv();
    println!("Key_: {:?}", key_data.key);
println!("IV_: {:?}", key_data.iv);

    // 3. Encrypt the file
    encrypt_file_path_with_chunk(file_path, encrypted_file_path, &key_data.key, &key_data.iv)?;
    println!("File encrypted successfully: {}", encrypted_file_path);

    // 4. Decrypt the file
    decrypt_file_path_with_chunk(
        encrypted_file_path,
        decrypted_file_path,
        &key_data.key,
        &key_data.iv,
    )?;
    println!("File decrypted successfully: {}", decrypted_file_path);

    println!("Decrypted file size: {}", std::fs::metadata(decrypted_file_path)?.len());

Ok(())
}
