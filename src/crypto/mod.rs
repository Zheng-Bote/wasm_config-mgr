use aes_gcm::{
    Aes256Gcm, KeyInit, Nonce,
    aead::{Aead, Payload},
};
use argon2::{Algorithm, Argon2, Params, Version};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use curve25519_dalek::{
    constants::ED25519_BASEPOINT_POINT, edwards::CompressedEdwardsY, scalar::Scalar,
};
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256, Sha512};
use thiserror::Error;
use zeroize::Zeroizing;

type HmacSha256 = Hmac<Sha256>;

pub const CONTAINER_MAGIC: &[u8; 4] = b"WCFG";
pub const CONTAINER_VERSION: u8 = 0x01;
pub const KDF_RAW: u8 = 0x00;
pub const KDF_ARGON2ID: u8 = 0x01;
pub const SALT_LEN: usize = 16;
pub const NONCE_LEN: usize = 12;
pub const HEADER_LEN: usize = 4 + 1 + 1 + SALT_LEN + NONCE_LEN; // 34 bytes
pub const TAG_LEN: usize = 16;
pub const SEALED_PREFIX_HMAC: &str = "wcfg-sealed:v1:hmac:";
pub const SEALED_PREFIX_ED25519: &str = "wcfg-sealed:v1:ed25519:";

#[derive(Debug, Error, PartialEq, Eq)]
pub enum CryptoError {
    #[error("invalid master key format: {0}")]
    InvalidKey(String),
    #[error("container file is too short or truncated")]
    TruncatedContainer,
    #[error("invalid container magic header (expected WCFG)")]
    InvalidMagic,
    #[error("unsupported container version: {0}")]
    UnsupportedVersion(u8),
    #[error("unsupported KDF algorithm identifier: {0}")]
    UnsupportedKdf(u8),
    #[error("key derivation failed: {0}")]
    KdfFailure(String),
    #[error("random number generation failed")]
    RngFailure,
    #[error("AES-256-GCM authentication or decryption failed (tampered data or wrong key)")]
    AuthenticationFailed,
    #[error("decrypted payload is not valid UTF-8")]
    InvalidUtf8,
    #[error("invalid sealed response format: {0}")]
    InvalidSealedFormat(String),
}

#[derive(Clone)]
pub enum KeyMaterial {
    /// Direct 256-bit (32-byte) master key.
    RawKey(Zeroizing<[u8; 32]>),
    /// Passphrase to be derived via Argon2id.
    Passphrase(Zeroizing<String>),
}

impl std::fmt::Debug for KeyMaterial {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::RawKey(_) => f.write_str("KeyMaterial::RawKey([REDACTED])"),
            Self::Passphrase(_) => f.write_str("KeyMaterial::Passphrase([REDACTED])"),
        }
    }
}

impl KeyMaterial {
    /// Parses a raw 256-bit key from hex (64 chars), Base64 (44 chars), or exact 32 raw bytes.
    pub fn from_raw_str(raw: &str) -> Result<Self, CryptoError> {
        let trimmed = raw.trim();
        if trimmed.len() == 64 {
            if let Ok(bytes) = hex::decode(trimmed) {
                let arr: [u8; 32] = bytes
                    .try_into()
                    .map_err(|_| CryptoError::InvalidKey("expected 32 bytes".to_string()))?;
                return Ok(Self::RawKey(Zeroizing::new(arr)));
            }
        }
        if let Ok(bytes) = BASE64.decode(trimmed) {
            if bytes.len() == 32 {
                let arr: [u8; 32] = bytes.try_into().unwrap();
                return Ok(Self::RawKey(Zeroizing::new(arr)));
            }
        }
        if trimmed.as_bytes().len() == 32 {
            let arr: [u8; 32] = trimmed.as_bytes().try_into().unwrap();
            return Ok(Self::RawKey(Zeroizing::new(arr)));
        }
        Err(CryptoError::InvalidKey(
            "raw master key must be 32 bytes (64 hex chars, 44 base64 chars, or 32 ASCII bytes)"
                .to_string(),
        ))
    }

    pub fn from_passphrase(passphrase: impl Into<String>) -> Result<Self, CryptoError> {
        let p = Zeroizing::new(passphrase.into());
        if p.is_empty() {
            return Err(CryptoError::InvalidKey(
                "passphrase must not be empty".to_string(),
            ));
        }
        Ok(Self::Passphrase(p))
    }
}

fn derive_argon2id_key(
    passphrase: &str,
    salt: &[u8; SALT_LEN],
) -> Result<Zeroizing<[u8; 32]>, CryptoError> {
    let params = Params::new(19 * 1024, 2, 1, Some(32))
        .map_err(|e| CryptoError::KdfFailure(e.to_string()))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut output = Zeroizing::new([0u8; 32]);
    argon2
        .hash_password_into(passphrase.as_bytes(), salt, &mut *output)
        .map_err(|e| CryptoError::KdfFailure(e.to_string()))?;
    Ok(output)
}

/// Encrypts a plaintext INI string using AES-256-GCM and binds the 34-byte container header as AAD.
pub fn encrypt_ini(plaintext: &str, key_material: &KeyMaterial) -> Result<Vec<u8>, CryptoError> {
    let mut salt = [0u8; SALT_LEN];
    let mut nonce_bytes = [0u8; NONCE_LEN];
    getrandom::getrandom(&mut nonce_bytes).map_err(|_| CryptoError::RngFailure)?;

    let (kdf_id, derived_key) = match key_material {
        KeyMaterial::RawKey(k) => (KDF_RAW, k.clone()),
        KeyMaterial::Passphrase(pass) => {
            getrandom::getrandom(&mut salt).map_err(|_| CryptoError::RngFailure)?;
            let dk = derive_argon2id_key(pass, &salt)?;
            (KDF_ARGON2ID, dk)
        }
    };

    let mut header = Vec::with_capacity(HEADER_LEN);
    header.extend_from_slice(CONTAINER_MAGIC);
    header.push(CONTAINER_VERSION);
    header.push(kdf_id);
    header.extend_from_slice(&salt);
    header.extend_from_slice(&nonce_bytes);
    debug_assert_eq!(header.len(), HEADER_LEN);

    let cipher = Aes256Gcm::new_from_slice(&*derived_key)
        .map_err(|_| CryptoError::InvalidKey("invalid key length".to_string()))?;
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(
            nonce,
            Payload {
                msg: plaintext.as_bytes(),
                aad: &header,
            },
        )
        .map_err(|_| CryptoError::AuthenticationFailed)?;

    let mut container = Vec::with_capacity(HEADER_LEN + ciphertext.len());
    container.extend_from_slice(&header);
    container.extend_from_slice(&ciphertext);
    Ok(container)
}

/// Decrypts and authenticates a `WCFG` AES-256-GCM container back into an INI plaintext string.
pub fn decrypt_ini(
    container: &[u8],
    key_material: &KeyMaterial,
) -> Result<Zeroizing<String>, CryptoError> {
    if container.len() < HEADER_LEN + TAG_LEN {
        return Err(CryptoError::TruncatedContainer);
    }

    if &container[0..4] != CONTAINER_MAGIC {
        return Err(CryptoError::InvalidMagic);
    }

    let version = container[4];
    if version != CONTAINER_VERSION {
        return Err(CryptoError::UnsupportedVersion(version));
    }

    let kdf_id = container[5];
    let salt: [u8; SALT_LEN] = container[6..22].try_into().unwrap();
    let nonce_bytes: [u8; NONCE_LEN] = container[22..34].try_into().unwrap();
    let header_aad = &container[0..HEADER_LEN];
    let ciphertext = &container[HEADER_LEN..];

    let derived_key = match (kdf_id, key_material) {
        (KDF_RAW, KeyMaterial::RawKey(k)) => k.clone(),
        (KDF_ARGON2ID, KeyMaterial::Passphrase(pass)) => derive_argon2id_key(pass, &salt)?,
        (KDF_RAW, KeyMaterial::Passphrase(_)) | (KDF_ARGON2ID, KeyMaterial::RawKey(_)) => {
            return Err(CryptoError::AuthenticationFailed);
        }
        (other, _) => return Err(CryptoError::UnsupportedKdf(other)),
    };

    let cipher = Aes256Gcm::new_from_slice(&*derived_key)
        .map_err(|_| CryptoError::InvalidKey("invalid key length".to_string()))?;
    let nonce = Nonce::from_slice(&nonce_bytes);

    let plaintext_bytes = Zeroizing::new(
        cipher
            .decrypt(
                nonce,
                Payload {
                    msg: ciphertext,
                    aad: header_aad,
                },
            )
            .map_err(|_| CryptoError::AuthenticationFailed)?,
    );

    let text = std::str::from_utf8(&plaintext_bytes).map_err(|_| CryptoError::InvalidUtf8)?;
    Ok(Zeroizing::new(text.to_string()))
}

fn build_seal_aad(client_id: &str, section: &str, key: &str, env_name: &str) -> String {
    format!("wasm-config-mgr:seal-aad:v1:{client_id}:{section}:{key}:{env_name}")
}

fn derive_hmac_seal_key(
    client_secret: &[u8],
    client_id: &str,
    section: &str,
    key: &str,
    env_name: &str,
) -> Zeroizing<[u8; 32]> {
    let info = format!("wasm-config-mgr:seal-key:v1:{client_id}:{section}:{key}:{env_name}");
    let mut mac =
        <HmacSha256 as Mac>::new_from_slice(client_secret).expect("HMAC key valid");
    mac.update(info.as_bytes());
    let result = mac.finalize().into_bytes();
    let mut key_out = Zeroizing::new([0u8; 32]);
    key_out.copy_from_slice(&result);
    key_out
}

/// Seals a configuration value for an HMAC-authenticated client using AES-256-GCM so no plaintext appears on stdout.
pub fn seal_value_hmac(
    plaintext_value: &str,
    client_secret: &[u8],
    client_id: &str,
    section: &str,
    key: &str,
    env_name: &str,
) -> Result<String, CryptoError> {
    let seal_key = derive_hmac_seal_key(client_secret, client_id, section, key, env_name);
    let aad = build_seal_aad(client_id, section, key, env_name);

    let mut nonce_bytes = [0u8; NONCE_LEN];
    getrandom::getrandom(&mut nonce_bytes).map_err(|_| CryptoError::RngFailure)?;

    let cipher = Aes256Gcm::new_from_slice(&*seal_key)
        .map_err(|_| CryptoError::InvalidKey("invalid seal key".into()))?;
    let ciphertext = cipher
        .encrypt(
            Nonce::from_slice(&nonce_bytes),
            Payload {
                msg: plaintext_value.as_bytes(),
                aad: aad.as_bytes(),
            },
        )
        .map_err(|_| CryptoError::AuthenticationFailed)?;

    Ok(format!(
        "{SEALED_PREFIX_HMAC}{}:{}",
        hex::encode(nonce_bytes),
        hex::encode(ciphertext)
    ))
}

/// Unseals a `wcfg-sealed:v1:hmac:...` value using the client's HMAC secret and context.
pub fn unseal_value_hmac(
    sealed_token: &str,
    client_secret: &[u8],
    client_id: &str,
    section: &str,
    key: &str,
    env_name: &str,
) -> Result<Zeroizing<String>, CryptoError> {
    let rest = sealed_token
        .trim()
        .strip_prefix(SEALED_PREFIX_HMAC)
        .ok_or_else(|| {
            CryptoError::InvalidSealedFormat("missing wcfg-sealed:v1:hmac: prefix".into())
        })?;
    let (nonce_hex, cipher_hex) = rest.split_once(':').ok_or_else(|| {
        CryptoError::InvalidSealedFormat("expected <nonce_hex>:<ciphertext_hex>".into())
    })?;

    let nonce_vec = hex::decode(nonce_hex)
        .map_err(|_| CryptoError::InvalidSealedFormat("invalid nonce hex".into()))?;
    let nonce_bytes: [u8; NONCE_LEN] = nonce_vec
        .try_into()
        .map_err(|_| CryptoError::InvalidSealedFormat("nonce must be 12 bytes".into()))?;
    let ciphertext = hex::decode(cipher_hex)
        .map_err(|_| CryptoError::InvalidSealedFormat("invalid ciphertext hex".into()))?;

    let seal_key = derive_hmac_seal_key(client_secret, client_id, section, key, env_name);
    let aad = build_seal_aad(client_id, section, key, env_name);

    let cipher = Aes256Gcm::new_from_slice(&*seal_key)
        .map_err(|_| CryptoError::InvalidKey("invalid seal key".into()))?;
    let plain_bytes = Zeroizing::new(
        cipher
            .decrypt(
                Nonce::from_slice(&nonce_bytes),
                Payload {
                    msg: &ciphertext,
                    aad: aad.as_bytes(),
                },
            )
            .map_err(|_| CryptoError::AuthenticationFailed)?,
    );

    let text = std::str::from_utf8(&plain_bytes).map_err(|_| CryptoError::InvalidUtf8)?;
    Ok(Zeroizing::new(text.to_string()))
}

fn derive_ed25519_shared_seal_key(
    shared_point_bytes: &[u8; 32],
    ephemeral_r_bytes: &[u8; 32],
    client_pubkey_bytes: &[u8; 32],
    client_id: &str,
    section: &str,
    key: &str,
    env_name: &str,
) -> Zeroizing<[u8; 32]> {
    let mut hasher = Sha256::new();
    hasher.update(b"wasm-config-mgr:ed25519-seal-key:v1:");
    hasher.update(shared_point_bytes);
    hasher.update(ephemeral_r_bytes);
    hasher.update(client_pubkey_bytes);
    hasher.update(format!("{client_id}:{section}:{key}:{env_name}").as_bytes());
    let digest = hasher.finalize();
    let mut out = Zeroizing::new([0u8; 32]);
    out.copy_from_slice(&digest);
    out
}

/// Seals a configuration value for an Ed25519 client using ephemeral Edwards/Curve25519 ECDH + AES-256-GCM.
pub fn seal_value_ed25519(
    plaintext_value: &str,
    client_pubkey_bytes: &[u8; 32],
    client_id: &str,
    section: &str,
    key: &str,
    env_name: &str,
) -> Result<String, CryptoError> {
    let client_point = CompressedEdwardsY(*client_pubkey_bytes)
        .decompress()
        .ok_or_else(|| CryptoError::InvalidKey("invalid Ed25519 public key point".into()))?;

    let mut random_scalar_bytes = Zeroizing::new([0u8; 64]);
    getrandom::getrandom(&mut *random_scalar_bytes).map_err(|_| CryptoError::RngFailure)?;
    let r = Scalar::from_bytes_mod_order_wide(&random_scalar_bytes);

    // Ephemeral public point R = r * B, Shared secret point S = (8 * r) * A (cofactor-cleared)
    let r_clear = r * Scalar::from(8u8);
    let ephemeral_r = (&ED25519_BASEPOINT_POINT * &r_clear).compress().to_bytes();
    let shared_s = Zeroizing::new((&client_point * &r_clear).compress().to_bytes());

    let seal_key = derive_ed25519_shared_seal_key(
        &shared_s,
        &ephemeral_r,
        client_pubkey_bytes,
        client_id,
        section,
        key,
        env_name,
    );
    let aad = build_seal_aad(client_id, section, key, env_name);

    let mut nonce_bytes = [0u8; NONCE_LEN];
    getrandom::getrandom(&mut nonce_bytes).map_err(|_| CryptoError::RngFailure)?;

    let cipher = Aes256Gcm::new_from_slice(&*seal_key)
        .map_err(|_| CryptoError::InvalidKey("invalid seal key".into()))?;
    let ciphertext = cipher
        .encrypt(
            Nonce::from_slice(&nonce_bytes),
            Payload {
                msg: plaintext_value.as_bytes(),
                aad: aad.as_bytes(),
            },
        )
        .map_err(|_| CryptoError::AuthenticationFailed)?;

    Ok(format!(
        "{SEALED_PREFIX_ED25519}{}:{}:{}",
        hex::encode(ephemeral_r),
        hex::encode(nonce_bytes),
        hex::encode(ciphertext)
    ))
}

/// Unseals a `wcfg-sealed:v1:ed25519:...` value using the client's 32-byte Ed25519 secret seed.
pub fn unseal_value_ed25519(
    sealed_token: &str,
    client_secret_seed: &[u8; 32],
    client_id: &str,
    section: &str,
    key: &str,
    env_name: &str,
) -> Result<Zeroizing<String>, CryptoError> {
    let rest = sealed_token
        .trim()
        .strip_prefix(SEALED_PREFIX_ED25519)
        .ok_or_else(|| {
            CryptoError::InvalidSealedFormat("missing wcfg-sealed:v1:ed25519: prefix".into())
        })?;
    let parts: Vec<&str> = rest.split(':').collect();
    if parts.len() != 3 {
        return Err(CryptoError::InvalidSealedFormat(
            "expected <ephemeral_r_hex>:<nonce_hex>:<ciphertext_hex>".into(),
        ));
    }

    let ephemeral_r_vec = hex::decode(parts[0])
        .map_err(|_| CryptoError::InvalidSealedFormat("invalid ephemeral R hex".into()))?;
    let ephemeral_r_bytes: [u8; 32] = ephemeral_r_vec
        .try_into()
        .map_err(|_| CryptoError::InvalidSealedFormat("ephemeral R must be 32 bytes".into()))?;
    let ephemeral_point = CompressedEdwardsY(ephemeral_r_bytes)
        .decompress()
        .ok_or_else(|| CryptoError::InvalidSealedFormat("invalid ephemeral Edwards point".into()))?;

    let nonce_vec = hex::decode(parts[1])
        .map_err(|_| CryptoError::InvalidSealedFormat("invalid nonce hex".into()))?;
    let nonce_bytes: [u8; NONCE_LEN] = nonce_vec
        .try_into()
        .map_err(|_| CryptoError::InvalidSealedFormat("nonce must be 12 bytes".into()))?;
    let ciphertext = hex::decode(parts[2])
        .map_err(|_| CryptoError::InvalidSealedFormat("invalid ciphertext hex".into()))?;

    // Standard RFC 8032 clamping of Ed25519 32-byte seed into secret scalar `a`
    let mut h = Sha512::new();
    h.update(client_secret_seed);
    let digest = h.finalize();
    let mut clamped = Zeroizing::new([0u8; 32]);
    clamped.copy_from_slice(&digest[0..32]);
    clamped[0] &= 248;
    clamped[31] &= 127;
    clamped[31] |= 64;
    let a = Scalar::from_bytes_mod_order(*clamped);

    let client_pubkey_bytes = (&ED25519_BASEPOINT_POINT * &a).compress().to_bytes();
    let shared_s = Zeroizing::new((&ephemeral_point * &a).compress().to_bytes());

    let seal_key = derive_ed25519_shared_seal_key(
        &shared_s,
        &ephemeral_r_bytes,
        &client_pubkey_bytes,
        client_id,
        section,
        key,
        env_name,
    );
    let aad = build_seal_aad(client_id, section, key, env_name);

    let cipher = Aes256Gcm::new_from_slice(&*seal_key)
        .map_err(|_| CryptoError::InvalidKey("invalid seal key".into()))?;
    let plain_bytes = Zeroizing::new(
        cipher
            .decrypt(
                Nonce::from_slice(&nonce_bytes),
                Payload {
                    msg: &ciphertext,
                    aad: aad.as_bytes(),
                },
            )
            .map_err(|_| CryptoError::AuthenticationFailed)?,
    );

    let text = std::str::from_utf8(&plain_bytes).map_err(|_| CryptoError::InvalidUtf8)?;
    Ok(Zeroizing::new(text.to_string()))
}
