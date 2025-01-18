use aes::Aes128;
use block_modes::{BlockMode, Cbc};
use block_modes::block_padding::Pkcs7;

type Aes128Cbc = Cbc<Aes128, Pkcs7>;

fn main() {
    let key = [231, 255, 228, 63, 249, 150, 245, 179, 192, 67, 20, 229, 134, 107, 193, 192];
    let iv = [241, 235, 204, 54, 176, 81, 234, 78, 53, 96, 104, 217, 33, 158, 41, 231];

    let cipher = Aes128Cbc::new_from_slices(&key, &iv).expect("Cipher creation failed");

    // Test encryption
    let plaintext = b"Hello, world!";
    let encrypted = cipher.clone().encrypt_vec(plaintext);
    println!("Encrypted: {:?}", encrypted);

    // Test decryption
    let decrypted = cipher.clone().decrypt_vec(&encrypted).expect("Decryption failed");
    println!("Decrypted: {:?}", decrypted);
}
