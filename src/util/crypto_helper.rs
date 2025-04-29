use aes_gcm::aead::rand_core::RngCore;
use aes_gcm::aead::{Aead, OsRng};
use aes_gcm::{Aes256Gcm, Key, KeyInit};
use base64::prelude::BASE64_URL_SAFE_NO_PAD;
use base64::Engine;
use nanoid::nanoid;

/// Encrypts the given plaintext using AES-256-GCM encryption.
///
/// # Arguments
///
/// * `key_byte` - A 32-byte array representing the encryption key. The key must be exactly 32 bytes long.
/// * `plaintext` - A byte slice containing the plaintext data to be encrypted.
///
/// # Returns
///
/// A `Result` containing a tuple with two `String` values:
/// - The first `String` is the Base64 URL-safe encoded nonce.
/// - The second `String` is the Base64 URL-safe encoded ciphertext with the authentication tag appended.
///
/// # Errors
///
/// Returns a `Box<dyn std::error::Error>` if:
/// - The key is not 32 bytes long.
/// - Encryption fails.
///
/// # Example
///
/// ```rust
/// let key: [u8; 32] = [0; 32];
/// let plaintext = b"Hello, world!";
/// let result = aes_gcm_encrypt(&key, plaintext).await;
/// match result {
///     Ok((nonce, ciphertext)) => {
///         println!("Nonce: {}", nonce);
///         println!("Ciphertext: {}", ciphertext);
///     }
///     Err(e) => eprintln!("Encryption failed: {}", e),
/// }
/// ```
pub async fn aes_gcm_encrypt(
    key_byte: &[u8; 32],
    plaintext: &[u8],
) -> Result<(String, String), Box<dyn std::error::Error>> {
    if key_byte.len() != 32 {
        return Err("Key must be exactly 32 bytes long".into());
    }

    let key = Key::<Aes256Gcm>::from_slice(key_byte);
    let cipher = Aes256Gcm::new(key);

    let mut nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = aes_gcm::Nonce::from_slice(&nonce_bytes);

    let ciphertext_with_tag = cipher
        .encrypt(nonce, plaintext.as_ref())
        .map_err(|e| format!("Decryption failed: {}", e))?;

    Ok((
        BASE64_URL_SAFE_NO_PAD.encode(&nonce_bytes),
        BASE64_URL_SAFE_NO_PAD.encode(ciphertext_with_tag),
    ))
}

/// Decrypts the given ciphertext using AES-256-GCM decryption.
///
/// # Arguments
///
/// * `key_byte` - A 32-byte array representing the decryption key. The key must be exactly 32 bytes long.
/// * `nonce` - A `String` containing the Base64 URL-safe encoded nonce. The nonce must be exactly 12 bytes long after decoding.
/// * `ciphertext_with_tag` - A `String` containing the Base64 URL-safe encoded ciphertext with the authentication tag appended.
///
/// # Returns
///
/// A `Result` containing a `Vec<u8>` with the decrypted plaintext data.
///
/// # Errors
///
/// Returns a `Box<dyn std::error::Error>` if:
/// - The key is not 32 bytes long.
/// - The nonce is not 12 bytes long after decoding.
/// - Decoding the nonce or ciphertext fails.
/// - Decryption fails.
///
/// # Example
///
/// ```rust
/// let key: [u8; 32] = [0; 32];
/// let nonce = "Base64EncodedNonce".to_string();
/// let ciphertext = "Base64EncodedCiphertext".to_string();
/// let result = aes_gcm_decrypt(&key, &nonce, &ciphertext).await;
/// match result {
///     Ok(plaintext) => println!("Decrypted plaintext: {:?}", plaintext),
///     Err(e) => eprintln!("Decryption failed: {}", e),
/// }
/// ```
pub async fn aes_gcm_decrypt(
    key_byte: &[u8; 32],
    nonce: &String,
    ciphertext_with_tag: &String,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    if key_byte.len() != 32 {
        return Err("Key must be exactly 32 bytes long".into());
    }

    let decoded_nonce = BASE64_URL_SAFE_NO_PAD.decode(nonce)?;
    if decoded_nonce.len() != 12 {
        return Err("Nonce must be exactly 12 bytes long".into());
    }

    let decoded_ciphertext = BASE64_URL_SAFE_NO_PAD.decode(ciphertext_with_tag)?;

    let key = Key::<Aes256Gcm>::from_slice(key_byte);
    let cipher = Aes256Gcm::new(key);

    let nonce = aes_gcm::Nonce::from_slice(&decoded_nonce);

    let plaintext = cipher
        .decrypt(nonce, decoded_ciphertext.as_ref())
        .map_err(|e| format!("Decryption failed: {}", e))?;

    Ok(plaintext)
}

/// Generates a list of backup codes with the specified size and length.
///
/// # Arguments
///
/// * `size` - The number of backup codes to generate.
/// * `length` - The length of each backup code.
///
/// # Returns
///
/// A `Vec<String>` containing the generated backup codes. Each code is a string
/// composed of characters from a predefined alphabet.
///
/// # Example
///
/// ```rust
/// let codes = generate_backup_codes(5, 10).await;
/// for code in codes {
///     println!("{}", code);
/// }
/// ```
pub async fn generate_backup_codes(size: usize, length: usize) -> Vec<String> {
    let alphabet: [char; 52] = [
        'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'J', 'K', 'M', 'N', 'P', 'R', 'S', 'T', 'U', 'V',
        'W', 'X', 'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'j', 'k', 'm', 'n', 'p', 'r',
        's', 't', 'u', 'v', 'w', 'x', 'y', 'z', '2', '3', '4', '5', '6', '7', '8', '9',
    ];
    let mut codes = Vec::new();
    for _ in 0..size {
        let code = nanoid!(length, &alphabet);
        codes.push(code);
    }
    codes
}
