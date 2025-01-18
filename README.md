# encryption_with_chunk

# File Encryption/Decryption with AES-128-CBC and HMAC

This project provides functions to encrypt and decrypt files or data chunks using the AES-128-CBC encryption algorithm, alongside HMAC-SHA256 for data integrity verification.

## Features
- **AES-128-CBC encryption** for file or data chunks.
- **HMAC-SHA256** for verifying the integrity of encrypted data.
- Support for **chunked encryption** and **non-chunked encryption**.
- Secure encryption/decryption of both files and raw byte data.

## Functions

### `encrypt_file_chunked`
Encrypts a file in chunks, using AES-128-CBC. It saves the encrypted data to an output file, appending an HMAC for integrity verification.

### `decrypt_file_chunked`
Decrypts a chunked encrypted file. It verifies the HMAC and restores the original file.

### `encrypt_data_chunked`
Encrypts raw byte data (not from a file) in chunks, using AES-128-CBC. It returns the encrypted data along with the HMAC.

### `decrypt_data_chunked`
Decrypts raw byte data encrypted in chunks. It verifies the HMAC and returns the decrypted data.

### `encrypt_data` (Non-chunked encryption)
Encrypts raw byte data without chunking. It uses AES-128-CBC for encryption and appends the HMAC.

### `decrypt_data` (Non-chunked decryption)
Decrypts raw byte data encrypted without chunking. It verifies the HMAC and returns the decrypted data.

## Usage

### Dependencies
- `aes` (AES encryption library)
- `block-modes` (Block cipher modes such as CBC)
- `crypto-mac` (For HMAC-SHA256)
- `hmac` (HMAC functionality)
- `rand` (For generating random keys/IVs)
- `sha2` (For SHA256 hashing)

You can install these dependencies using `cargo`:

```bash
cargo add aes block-modes crypto-mac hmac rand sha2

```
## Example Usage

### `Encrypt File (Chunked)`
```bash
mod encryption_chunked;
use encryption_chunked::{encrypt_file_chunked, generate_key_iv};
use std::io::Result;

fn main() -> Result<()> {
    let key_iv = generate_key_iv();
    encrypt_file_chunked("input.txt", "output.enc", &key_iv.key, &key_iv.iv)
}
```


### `Decrypt File (Chunked)`
```bash
mod encryption_chunked;
use encryption_chunked::{decrypt_file_chunked, generate_key_iv};
use std::error::Error;

fn main() -> Result<(), Box<dyn Error>> {
    let key_iv = generate_key_iv();
    decrypt_file_chunked("output.enc", "decrypted.txt", &key_iv.key, &key_iv.iv)
}

```


### `Encrypt Data (Non-chunked)`

```bash
mod encryption;
use encryption::{encrypt_data, generate_key_iv};

fn main() -> std::io::Result<()> {
    let key_iv = generate_key_iv();
    let encrypted_data = encrypt_data(b"some data", &key_iv.key, &key_iv.iv)?;
    // Process the encrypted data...
    Ok(())
}
```


### `Decrypt Data (Non-chunked)`

```bash
mod encryption;
use encryption::{decrypt_data, generate_key_iv};

fn main() -> std::io::Result<()> {
    let key_iv = generate_key_iv();
    let decrypted_data = decrypt_data(&encrypted_data, &key_iv.key, &key_iv.iv)?;
    // Process the decrypted data...
    Ok(())
}

```
## Installation
Clone the repository:
```bash

git clone https://github.com/Melisaates/encryption_with_chunk.git
```
Install the dependencies and build the project:

```bash
cargo build
```

## License

This project is licensed under the MIT License - see the LICENSE file for details.


---

### Push Instructions

1. **Navigate to your project folder** in the terminal:
```bash
   cd /path/to/your/project
```
2. Stage all changes:
```bash
  git add .
```
3. Commit your changes with a meaningful message:
```bash
  git commit -m "Added AES encryption/decryption functions with chunked support"
```
4. Push the changes to your GitHub repository:
```bash
  git push origin main
```






