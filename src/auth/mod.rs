use crate::ini::{ClientPolicy, IniDocument, POLICY_SECTION, PolicyManifest};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use subtle::ConstantTimeEq;
use thiserror::Error;

type HmacSha256 = Hmac<Sha256>;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum AuthError {
    #[error("access to reserved section `[__policy__]` is strictly forbidden")]
    ReservedPolicySection,
    #[error("malformed authorization token (expected `<scheme>:<client_id>:<hex_signature>`)")]
    MalformedToken,
    #[error("unsupported token scheme `{0}` (expected `hmac` or `ed25519`)")]
    UnsupportedScheme(String),
    #[error("unknown or unauthorized client `{0}`")]
    UnknownClient(String),
    #[error("cryptographic token verification failed for client `{0}`")]
    InvalidSignature(String),
    #[error("client `{client}` is not permitted to access `{section}.{key}`")]
    AccessDenied {
        client: String,
        section: String,
        key: String,
    },
    #[error("requested entry `{section}.{key}` does not exist")]
    EntryNotFound { section: String, key: String },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AccessToken {
    Hmac {
        client_id: String,
        signature: Vec<u8>,
    },
    Ed25519 {
        client_id: String,
        signature: [u8; 64],
    },
}

/// Verified result of an authorization check, including the caller's token type and client policy for response sealing.
#[derive(Debug)]
pub struct AuthorizedEntry<'a> {
    pub value: &'a str,
    pub client_policy: &'a ClientPolicy,
    pub token: AccessToken,
}

/// Builds the canonical message signed by a client requesting `(section, key)`.
pub fn canonical_request_message(client_id: &str, section: &str, key: &str) -> String {
    format!("wasm-config-mgr:v1:{client_id}:{section}:{key}")
}

/// Generates an HMAC-SHA256 authorization token for `(client_id, section, key)`.
pub fn generate_hmac_token(client_id: &str, section: &str, key: &str, secret: &[u8]) -> String {
    let msg = canonical_request_message(client_id, section, key);
    let mut mac = HmacSha256::new_from_slice(secret).expect("HMAC accepts any key size");
    mac.update(msg.as_bytes());
    let sig = mac.finalize().into_bytes();
    format!("hmac:{client_id}:{}", hex::encode(sig))
}

/// Generates an Ed25519 authorization token for `(client_id, section, key)` from a 32-byte secret seed.
pub fn generate_ed25519_token(
    client_id: &str,
    section: &str,
    key: &str,
    secret_key_bytes: &[u8; 32],
) -> String {
    let signing_key = SigningKey::from_bytes(secret_key_bytes);
    let msg = canonical_request_message(client_id, section, key);
    let sig: Signature = signing_key.sign(msg.as_bytes());
    format!("ed25519:{client_id}:{}", hex::encode(sig.to_bytes()))
}

impl AccessToken {
    pub fn parse(token_str: &str) -> Result<Self, AuthError> {
        let parts: Vec<&str> = token_str.trim().split(':').collect();
        if parts.len() != 3 {
            return Err(AuthError::MalformedToken);
        }
        let scheme = parts[0];
        let client_id = parts[1];
        let sig_hex = parts[2];

        if client_id.is_empty() {
            return Err(AuthError::MalformedToken);
        }

        let sig_bytes = hex::decode(sig_hex).map_err(|_| AuthError::MalformedToken)?;

        match scheme {
            "hmac" => {
                if sig_bytes.len() != 32 {
                    return Err(AuthError::MalformedToken);
                }
                Ok(Self::Hmac {
                    client_id: client_id.to_string(),
                    signature: sig_bytes,
                })
            }
            "ed25519" => {
                let sig_arr: [u8; 64] = sig_bytes
                    .try_into()
                    .map_err(|_| AuthError::MalformedToken)?;
                Ok(Self::Ed25519 {
                    client_id: client_id.to_string(),
                    signature: sig_arr,
                })
            }
            other => Err(AuthError::UnsupportedScheme(other.to_string())),
        }
    }

    pub fn client_id(&self) -> &str {
        match self {
            Self::Hmac { client_id, .. } | Self::Ed25519 { client_id, .. } => client_id,
        }
    }
}

fn pattern_matches(pattern: &str, section: &str, key: &str) -> bool {
    if pattern == "*" || pattern == "*.*" {
        return true;
    }
    let Some((pat_sec, pat_key)) = pattern.split_once('.') else {
        return false;
    };
    let sec_ok = pat_sec == "*" || pat_sec == section;
    let key_ok = pat_key == "*" || pat_key == key;
    sec_ok && key_ok
}

/// Verifies the caller's token and policy permissions, returning the requested configuration entry and client context.
pub fn authorize_entry<'a>(
    doc: &'a IniDocument,
    manifest: &'a PolicyManifest,
    token_str: &str,
    section: &str,
    key: &str,
) -> Result<AuthorizedEntry<'a>, AuthError> {
    if section == POLICY_SECTION {
        return Err(AuthError::ReservedPolicySection);
    }

    let token = AccessToken::parse(token_str)?;
    let client_id = token.client_id();

    let Some(client_policy) = manifest.clients.get(client_id) else {
        return Err(AuthError::UnknownClient(client_id.to_string()));
    };

    let msg = canonical_request_message(client_id, section, key);

    // 1. Verify cryptographic signature / MAC
    match &token {
        AccessToken::Hmac { signature, .. } => {
            let Some(secret) = client_policy.hmac_secret.as_ref() else {
                return Err(AuthError::InvalidSignature(client_id.to_string()));
            };
            let mut mac = HmacSha256::new_from_slice(secret).expect("HMAC key size valid");
            mac.update(msg.as_bytes());
            let expected = mac.finalize().into_bytes();
            if expected.as_slice().ct_eq(signature.as_slice()).unwrap_u8() != 1 {
                return Err(AuthError::InvalidSignature(client_id.to_string()));
            }
        }
        AccessToken::Ed25519 { signature, .. } => {
            let Some(pubkey_bytes) = client_policy.ed25519_pubkey.as_ref() else {
                return Err(AuthError::InvalidSignature(client_id.to_string()));
            };
            let verifying_key = VerifyingKey::from_bytes(pubkey_bytes)
                .map_err(|_| AuthError::InvalidSignature(client_id.to_string()))?;
            let sig = Signature::from_bytes(signature);
            verifying_key
                .verify(msg.as_bytes(), &sig)
                .map_err(|_| AuthError::InvalidSignature(client_id.to_string()))?;
        }
    }

    // 2. Check policy allowlist
    let allowed = client_policy
        .allowed_patterns
        .iter()
        .any(|pat| pattern_matches(pat, section, key));

    if !allowed {
        return Err(AuthError::AccessDenied {
            client: client_id.to_string(),
            section: section.to_string(),
            key: key.to_string(),
        });
    }

    // 3. Retrieve value
    let value = doc
        .get(section, key)
        .ok_or_else(|| AuthError::EntryNotFound {
            section: section.to_string(),
            key: key.to_string(),
        })?;

    Ok(AuthorizedEntry {
        value,
        client_policy,
        token,
    })
}

/// Verifies the caller's token and policy permissions, returning the requested configuration entry string slice.
pub fn authorize_and_get<'a>(
    doc: &'a IniDocument,
    manifest: &'a PolicyManifest,
    token_str: &str,
    section: &str,
    key: &str,
) -> Result<&'a str, AuthError> {
    Ok(authorize_entry(doc, manifest, token_str, section, key)?.value)
}
