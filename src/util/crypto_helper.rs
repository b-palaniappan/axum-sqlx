use crate::config::app_config::AppState;
use crate::db::repo::auth_repository;
use crate::error::error_model::{AppError, ErrorType};
use aes_gcm::aead::rand_core::RngCore;
use aes_gcm::aead::{Aead, OsRng};
use aes_gcm::{Aes256Gcm, Key, KeyInit};
use argon2::password_hash::SaltString;
use argon2::{Argon2, Params, PasswordHash, PasswordHasher, PasswordVerifier, Version};
use axum::response::Response;
use base64::Engine;
use base64::prelude::BASE64_URL_SAFE_NO_PAD;
use hmac::{Hmac, Mac};
use nanoid::nanoid;
use secrecy::ExposeSecret;
use sha2::Sha512;
use sqlx::PgPool;
use std::sync::Arc;
use tracing::error;

/// Hashes a password and generates an HMAC signature for it.
///
/// This function uses the Argon2id algorithm to hash the provided password with a randomly
/// generated salt. It also generates an HMAC signature for the hashed password to ensure
/// tamper detection.
///
/// # Arguments
///
/// * `state` - A reference to the application state containing the Argon2 pepper and HMAC key.
/// * `password` - A reference to the password string to be hashed.
///
/// # Returns
///
/// A `Result` containing:
/// - A `String` representing the hashed password.
/// - A `Vec<u8>` containing the HMAC signature of the hashed password.
///
/// If an error occurs during the hashing or HMAC generation process, a boxed `std::error::Error`
/// is returned.
///
/// # Errors
///
/// This function may return an error if:
/// - The Argon2 hashing process fails.
/// - The HMAC key is invalid.
///
/// # Example
///
/// ```rust,no_run
/// # use axum_sqlx::config::app_config::AppState;
/// # use axum_sqlx::util::crypto_helper::hash_password_sign_with_hmac;
/// # use std::sync::Arc;
/// #
/// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
/// // Create a test state
/// let encryption_key: [u8; 32] = [0; 32]; // Simplified for example
/// let state = Arc::new(AppState {
///     pg_pool: sqlx::postgres::PgPool::connect("postgres://localhost").await?,
///     redis_pool: bb8_redis::bb8::Pool::builder().build(bb8_redis::RedisConnectionManager::new("redis://localhost")?).await?,
///     webauthn: webauthn_rs::WebauthnBuilder::new("localhost", &webauthn_rs::prelude::Url::parse("http://localhost").unwrap()).unwrap().build().unwrap(),
///     argon_pepper: "some_pepper".to_string().into(),
///     hmac_key: "some_hmac_key".to_string().into(),
///     jwt_private_key: "key".to_string().into(),
///     jwt_public_key: "key".to_string().into(),
///     jwt_expiration: 3600,
///     jwt_issuer: "test".to_string(),
///     dummy_hashed_password: "test".to_string().into(),
///     encryption_key,
/// });
///
/// let password = "my_secure_password".to_string();
/// let result = hash_password_sign_with_hmac(&state, &password).await;
/// match result {
///     Ok((hash, hmac)) => {
///         println!("Password Hash: {}", hash);
///         println!("HMAC: {:?}", hmac);
///     }
///     Err(e) => eprintln!("Error: {}", e),
/// }
/// # Ok(())
/// # }
/// ```
pub async fn hash_password_sign_with_hmac(
    state: &Arc<AppState>,
    password: &String,
) -> Result<(String, Vec<u8>), Box<dyn std::error::Error>> {
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::new_with_secret(
        state.argon_pepper.expose_secret().as_bytes(),
        argon2::Algorithm::Argon2id,
        Version::V0x13,
        Params::default(),
    )
    .unwrap();
    let password_hash = argon2
        .hash_password_customized(
            password.as_bytes(),
            Some(argon2::Algorithm::Argon2id.ident()),
            Some(19),
            Params::new(65536, 4, 5, Some(64)).unwrap(),
            &salt,
        )
        .map_err(|e| format!("Decryption failed: {}", e))?
        .to_string();

    // Generate HMAC for password hash to detect tampering
    type HmacSha512 = Hmac<Sha512>;
    let mut mac =
        <HmacSha512 as Mac>::new_from_slice(state.hmac_key.expose_secret().as_bytes()).unwrap();
    mac.update(password_hash.as_bytes());
    let password_hmac = mac.finalize().into_bytes().to_vec();
    Ok((password_hash, password_hmac))
}

/// Performs a fake password hash verification to mitigate timing attacks.
///
/// This function triggers a fake password hash verification process to ensure that
/// the response time remains consistent, even if the user ID is invalid. This helps
/// prevent attackers from inferring the validity of a user ID based on response time.
///
/// # Arguments
///
/// * `state` - A reference to the application state containing the Argon2 pepper
///   and a dummy hashed password for the fake verification process.
///
/// # Returns
///
/// Always returns an `Err` with an `AppError` indicating unauthorized access.
///
/// # Errors
///
/// This function always returns an `AppError` with the `UnauthorizedError` type.
///
/// # Example
///
/// ```rust,no_run
/// # use axum_sqlx::config::app_config::AppState;
/// # use axum_sqlx::util::crypto_helper::run_fake_password_hash_check;
/// # use std::sync::Arc;
/// #
/// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
/// // Create a test state
/// let encryption_key: [u8; 32] = [0; 32]; // Simplified for example
/// let state = Arc::new(AppState {
///     pg_pool: sqlx::postgres::PgPool::connect("postgres://localhost").await?,
///     redis_pool: bb8_redis::bb8::Pool::builder().build(bb8_redis::RedisConnectionManager::new("redis://localhost")?).await?,
///     webauthn: webauthn_rs::WebauthnBuilder::new("localhost", &webauthn_rs::prelude::Url::parse("http://localhost").unwrap()).unwrap().build().unwrap(),
///     argon_pepper: "some_pepper".to_string().into(),
///     hmac_key: "test_key".to_string().into(),
///     jwt_private_key: "key".to_string().into(),
///     jwt_public_key: "key".to_string().into(),
///     jwt_expiration: 3600,
///     jwt_issuer: "test".to_string(),
///     dummy_hashed_password: "$argon2id$v=19$m=65536,t=2,p=1$...".to_string().into(),
///     encryption_key,
/// });
///
/// let result = run_fake_password_hash_check(&state).await;
/// assert!(result.is_err());
/// # Ok(())
/// # }
/// ```
pub async fn run_fake_password_hash_check(state: &Arc<AppState>) -> Result<Response, AppError> {
    let argon2 = Argon2::new_with_secret(
        state.argon_pepper.expose_secret().as_bytes(),
        argon2::Algorithm::Argon2id,
        Version::V0x13,
        Params::default(),
    )
    .unwrap();

    // Trigger a fake check to avoid returning immediately.
    // Which can be used by hacker to figure out user id is not valid.
    let dummy_password_hash = state.dummy_hashed_password.expose_secret();
    let password_hash = PasswordHash::new(dummy_password_hash).unwrap();
    let _ = argon2.verify_password("dummy".as_bytes(), &password_hash);
    Err(AppError::new(
        ErrorType::UnauthorizedError,
        "Invalid credentials. Check email and password.",
    ))
}

/// Verifies a password hash and its HMAC signature.
///
/// This function checks if the user-entered password matches the stored password hash
/// using the Argon2id algorithm. It also verifies the HMAC signature of the password hash
/// to ensure data integrity and authenticity.
///
/// # Arguments
///
/// * `state` - A reference to the application state containing the Argon2 pepper, HMAC key, and database connection pool.
/// * `user_entered_password` - A reference to the password string entered by the user.
/// * `password_hash` - A reference to the stored password hash string.
/// * `password_hmac` - A byte slice containing the stored HMAC signature of the password hash.
/// * `user_id` - A reference to the user ID for logging and authentication failure handling.
///
/// # Returns
///
/// A `Result`:
/// - `Ok(())` if the password and HMAC verification succeed.
/// - `Err(AppError)` if the verification fails or an error occurs during the process.
///
/// # Errors
///
/// This function returns an `AppError` in the following cases:
/// - Password verification fails.
/// - HMAC verification fails.
/// - An error occurs while handling authentication failure (e.g., updating failed login attempts).
///
/// # Example
///
/// ```rust,no_run
/// # use axum_sqlx::config::app_config::AppState;
/// # use axum_sqlx::util::crypto_helper::verify_password_hash_hmac;
/// # use std::sync::Arc;
/// #
/// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
/// // Create a test state
/// let encryption_key: [u8; 32] = [0; 32]; // Simplified for example
/// let state = Arc::new(AppState {
///     pg_pool: sqlx::postgres::PgPool::connect("postgres://localhost").await?,
///     redis_pool: bb8_redis::bb8::Pool::builder().build(bb8_redis::RedisConnectionManager::new("redis://localhost")?).await?,
///     webauthn: webauthn_rs::WebauthnBuilder::new("localhost", &webauthn_rs::prelude::Url::parse("http://localhost").unwrap()).unwrap().build().unwrap(),
///     argon_pepper: "some_pepper".to_string().into(),
///     hmac_key: "test_key".to_string().into(),
///     jwt_private_key: "key".to_string().into(),
///     jwt_public_key: "key".to_string().into(),
///     jwt_expiration: 3600,
///     jwt_issuer: "test".to_string(),
///     dummy_hashed_password: "test".to_string().into(),
///     encryption_key,
/// });
///
/// let user_id = 123;
/// let stored_hmac = vec![1, 2, 3, 4]; // Example HMAC
///
/// let result = verify_password_hash_hmac(
///     &state,
///     &"user_password".to_string(),
///     &"stored_password_hash".to_string(),
///     &stored_hmac,
///     &user_id,
/// ).await;
///
/// match result {
///     Ok(_) => println!("Password and HMAC verified successfully."),
///     Err(e) => eprintln!("Verification failed: {:?}", e),
/// }
/// # Ok(())
/// # }
/// ```
pub async fn verify_password_hash_hmac(
    state: &Arc<AppState>,
    user_entered_password: &String,
    password_hash: &String,
    password_hmac: &[u8],
    user_id: &i64,
) -> Result<(), AppError> {
    let pg_pool = &state.pg_pool;
    let parsed_hash = PasswordHash::new(password_hash).unwrap();
    let argon2 = Argon2::new_with_secret(
        state.argon_pepper.expose_secret().as_bytes(),
        argon2::Algorithm::Argon2id,
        Version::V0x13,
        Params::default(),
    )
    .unwrap();

    if argon2
        .verify_password(user_entered_password.as_bytes(), &parsed_hash)
        .is_err()
    {
        error!("Password verification failed for user ID: {}", user_id);
        handle_user_authentication_failed(pg_pool, user_id)
            .await
            .map_err(|e| {
                error!("Error handling user authentication failed: {:?}", e);
                AppError::new(
                    ErrorType::InternalServerError,
                    "Something went wrong. Please try again later.",
                )
            })?;
        return Err(AppError::new(
            ErrorType::UnauthorizedError,
            "Invalid credentials. Check email and password.",
        ));
    }

    type HmacSha512 = Hmac<Sha512>;
    let mut mac =
        <HmacSha512 as Mac>::new_from_slice(state.hmac_key.expose_secret().as_bytes()).unwrap();
    mac.update(password_hash.as_bytes());
    if mac.verify_slice(password_hmac).is_err() {
        error!("HMAC verification failed for user ID: {}", user_id);
        handle_user_authentication_failed(pg_pool, user_id)
            .await
            .map_err(|e| {
                error!("Error handling user authentication failed: {:?}", e);
                AppError::new(
                    ErrorType::InternalServerError,
                    "Something went wrong. Please try again later.",
                )
            })?;
        return Err(AppError::new(
            ErrorType::UnauthorizedError,
            "Invalid credentials. Check email and password.",
        ));
    }
    Ok(())
}

/// Handles failed user authentication attempts.
///
/// This function increments the failed login attempts for a user in the database.
/// If the number of failed attempts exceeds a predefined threshold (5), the user's
/// account is locked to prevent further login attempts.
///
/// # Arguments
///
/// * `pg_pool` - A reference to the PostgreSQL connection pool used for database operations.
/// * `user_id` - A reference to the ID of the user whose authentication failed.
///
/// # Returns
///
/// A `Result`:
/// - `Ok(())` if the operation completes successfully.
/// - `Err(AppError)` if the user's account is locked due to too many failed login attempts.
///
/// # Errors
///
/// This function will return an `AppError` with the `UnauthorizedError` type if the user's
/// account is locked after exceeding the allowed number of failed login attempts.
///
/// # Example
///
/// ```rust,no_run
/// # use axum_sqlx::util::crypto_helper::handle_user_authentication_failed;
/// # use sqlx::PgPool;
/// #
/// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
/// // Get a connection pool
/// let pg_pool = PgPool::connect("postgres://localhost").await?;
/// let user_id = 123;
///
/// let result = handle_user_authentication_failed(&pg_pool, &user_id).await;
/// match result {
///     Ok(_) => println!("Failed login attempt recorded."),
///     Err(e) => eprintln!("Error: {:?}", e),
/// }
/// # Ok(())
/// # }
/// ```
pub async fn handle_user_authentication_failed(
    pg_pool: &PgPool,
    user_id: &i64,
) -> Result<(), AppError> {
    auth_repository::increase_failed_login_attempts(pg_pool, user_id)
        .await
        .unwrap();

    let user = auth_repository::get_user_by_id(pg_pool, user_id)
        .await
        .unwrap();

    // Lock user account if failed login attempts are more than 5.
    if user.failed_login_attempts.unwrap_or(0) >= 5 {
        auth_repository::lock_user_account(pg_pool, user_id)
            .await
            .unwrap();
        return Err(AppError::new(
            ErrorType::UnauthorizedError,
            "User account is locked. Contact support.",
        ));
    }
    Ok(())
}

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
/// ```rust,no_run
/// # use axum_sqlx::util::crypto_helper::aes_gcm_encrypt;
/// #
/// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
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
/// # Ok(())
/// # }
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
/// ```rust,no_run
/// # use axum_sqlx::util::crypto_helper::aes_gcm_decrypt;
/// #
/// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
/// let key: [u8; 32] = [0; 32];
/// let nonce = "Base64EncodedNonce".to_string();
/// let ciphertext = "Base64EncodedCiphertext".to_string();
/// let result = aes_gcm_decrypt(&key, &nonce, &ciphertext).await;
/// match result {
///     Ok(plaintext) => println!("Decrypted plaintext: {:?}", plaintext),
///     Err(e) => eprintln!("Decryption failed: {}", e),
/// }
/// # Ok(())
/// # }
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
/// ```rust,no_run
/// # use axum_sqlx::util::crypto_helper::generate_backup_codes;
/// #
/// # async fn example() {
/// let codes = generate_backup_codes(5, 10).await;
/// for code in codes {
///     println!("{}", code);
/// }
/// # }
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
