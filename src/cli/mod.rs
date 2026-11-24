use crate::{
    auth::{
        AccessToken, AuthError, authorize_entry, generate_ed25519_token, generate_hmac_token,
    },
    crypto::{
        CryptoError, KeyMaterial, decrypt_ini, encrypt_ini, seal_value_ed25519, seal_value_hmac,
        unseal_value_ed25519, unseal_value_hmac,
    },
    ini::{IniDocument, IniError},
};
use std::{env, fs, path::PathBuf};
use thiserror::Error;
use zeroize::Zeroizing;

pub const DEFAULT_MASTER_KEY_ENV: &str = "WASM_CONFIG_MASTER_KEY";
pub const DEFAULT_PASSPHRASE_ENV: &str = "WASM_CONFIG_PASSPHRASE";

#[derive(Debug, Error)]
pub enum CliError {
    #[error("invalid arguments: {0}")]
    InvalidArgs(String),
    #[error("invalid environment variable name `{0}` (must match ^[A-Z0-9_]+$)")]
    InvalidEnvName(String),
    #[error("configuration value contains illegal control characters or newlines for ENV output")]
    UnsafeEnvValue,
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("INI error: {0}")]
    Ini(#[from] IniError),
    #[error("crypto error: {0}")]
    Crypto(#[from] CryptoError),
    #[error("authorization error: {0}")]
    Auth(#[from] AuthError),
}

/// Validates that an environment variable identifier consists solely of ASCII uppercase letters, digits, and underscores, and does not start with a digit.
pub fn validate_env_name(name: &str) -> Result<(), CliError> {
    if name.is_empty()
        || name.chars().next().unwrap().is_ascii_digit()
        || !name
            .chars()
            .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_')
    {
        return Err(CliError::InvalidEnvName(name.to_string()));
    }
    Ok(())
}

/// Derives a default environment variable name from `section` and `key` (e.g. `database`, `db_pass` -> `DATABASE_DB_PASS`).
pub fn derive_env_name(section: &str, key: &str) -> Result<String, CliError> {
    let normalize = |s: &str| -> String {
        s.chars()
            .map(|c| {
                if c.is_ascii_alphanumeric() {
                    c.to_ascii_uppercase()
                } else {
                    '_'
                }
            })
            .collect()
    };
    let candidate = format!("{}_{}", normalize(section), normalize(key));
    validate_env_name(&candidate)?;
    Ok(candidate)
}

/// Formats a verified configuration entry as `KEY=VALUE` (or `export KEY='VALUE'` when `export_prefix` is true).
pub fn format_env_output(
    env_name: &str,
    value: &str,
    export_prefix: bool,
) -> Result<String, CliError> {
    validate_env_name(env_name)?;
    if value.contains('\n') || value.contains('\r') || value.contains('\0') {
        return Err(CliError::UnsafeEnvValue);
    }
    if export_prefix {
        let escaped = value.replace('\'', "'\"'\"'");
        Ok(format!("export {env_name}='{escaped}'"))
    } else {
        Ok(format!("{env_name}={value}"))
    }
}

/// Decrypts an encrypted container, verifies caller authorization, and returns an end-to-end sealed ENV assignment (`ENV_NAME=wcfg-sealed:v1:...`) so no plaintext ever appears on stdout.
pub fn query_sealed_env(
    encrypted_container: &[u8],
    key_material: &KeyMaterial,
    token_str: &str,
    section: &str,
    key: &str,
    custom_env_name: Option<&str>,
    export_prefix: bool,
) -> Result<String, CliError> {
    let env_name = match custom_env_name {
        Some(custom) => {
            validate_env_name(custom)?;
            custom.to_string()
        }
        None => derive_env_name(section, key)?,
    };

    let decrypted_ini = decrypt_ini(encrypted_container, key_material)?;
    let doc = IniDocument::parse(&decrypted_ini)?;
    let manifest = doc.extract_policy()?;
    let auth_entry = authorize_entry(&doc, &manifest, token_str, section, key)?;

    if auth_entry.value.contains('\n')
        || auth_entry.value.contains('\r')
        || auth_entry.value.contains('\0')
    {
        return Err(CliError::UnsafeEnvValue);
    }

    let sealed_value = match &auth_entry.token {
        AccessToken::Hmac { client_id, .. } => {
            let secret = auth_entry
                .client_policy
                .hmac_secret
                .as_ref()
                .ok_or_else(|| AuthError::InvalidSignature(client_id.clone()))?;
            seal_value_hmac(auth_entry.value, secret, client_id, section, key, &env_name)?
        }
        AccessToken::Ed25519 { client_id, .. } => {
            let pubkey = auth_entry
                .client_policy
                .ed25519_pubkey
                .as_ref()
                .ok_or_else(|| AuthError::InvalidSignature(client_id.clone()))?;
            seal_value_ed25519(auth_entry.value, pubkey, client_id, section, key, &env_name)?
        }
    };

    format_env_output(&env_name, &sealed_value, export_prefix)
}

/// Unseals a sealed ENV value (`wcfg-sealed:v1:...` or full `ENV_NAME=wcfg-sealed:v1:...`) in the authorized client's memory.
pub fn unseal_env_value(
    sealed_input: &str,
    client_id: &str,
    section: &str,
    key: &str,
    custom_env_name: Option<&str>,
    client_key: &TokenKeySpec,
) -> Result<Zeroizing<String>, CliError> {
    let env_name = match custom_env_name {
        Some(custom) => {
            validate_env_name(custom)?;
            custom.to_string()
        }
        None => derive_env_name(section, key)?,
    };

    // Accept either raw `wcfg-sealed:v1:...`, `ENV=wcfg-sealed:v1:...`, or `export ENV='wcfg-sealed:v1:...'`
    let trimmed = sealed_input.trim();
    let without_export = trimmed.strip_prefix("export ").unwrap_or(trimmed).trim();
    let token_part = if let Some((lhs, rhs)) = without_export.split_once('=') {
        if lhs.trim() != env_name {
            return Err(CliError::Crypto(CryptoError::AuthenticationFailed));
        }
        rhs.trim().trim_matches('\'').trim_matches('"')
    } else {
        without_export
    };

    let unsealed = match client_key {
        TokenKeySpec::HmacSecret(secret) => {
            unseal_value_hmac(token_part, secret, client_id, section, key, &env_name)?
        }
        TokenKeySpec::Ed25519Seed(seed) => {
            unseal_value_ed25519(token_part, seed, client_id, section, key, &env_name)?
        }
    };
    Ok(unsealed)
}

/// Legacy/testing helper when raw unsealed output is explicitly needed in unit tests.
pub fn query_encrypted_env(
    encrypted_container: &[u8],
    key_material: &KeyMaterial,
    token_str: &str,
    section: &str,
    key: &str,
    custom_env_name: Option<&str>,
    export_prefix: bool,
) -> Result<String, CliError> {
    query_sealed_env(
        encrypted_container,
        key_material,
        token_str,
        section,
        key,
        custom_env_name,
        export_prefix,
    )
}

#[derive(Debug)]
pub enum Command {
    Encrypt {
        input: PathBuf,
        output: PathBuf,
        key: KeyMaterial,
    },
    Decrypt {
        input: PathBuf,
        output: Option<PathBuf>,
        key: KeyMaterial,
    },
    Get {
        input: PathBuf,
        section: String,
        key_name: String,
        token: String,
        env_name: Option<String>,
        export_prefix: bool,
        key: KeyMaterial,
    },
    Unseal {
        sealed: String,
        client_id: String,
        section: String,
        key_name: String,
        env_name: Option<String>,
        scheme_key: TokenKeySpec,
    },
    Token {
        client_id: String,
        section: String,
        key_name: String,
        scheme_key: TokenKeySpec,
    },
}

#[derive(Debug, Clone)]
pub enum TokenKeySpec {
    HmacSecret(Vec<u8>),
    Ed25519Seed([u8; 32]),
}

fn resolve_key_material(
    raw_key: Option<String>,
    passphrase: Option<String>,
    key_file: Option<PathBuf>,
    key_env: Option<String>,
    passphrase_env: Option<String>,
) -> Result<KeyMaterial, CliError> {
    if let Some(k) = raw_key {
        return Ok(KeyMaterial::from_raw_str(&k)?);
    }
    if let Some(p) = passphrase {
        return Ok(KeyMaterial::from_passphrase(p)?);
    }
    if let Some(path) = key_file {
        let content = fs::read_to_string(path)?;
        return Ok(KeyMaterial::from_raw_str(content.trim())?);
    }
    let k_env_name = key_env.as_deref().unwrap_or(DEFAULT_MASTER_KEY_ENV);
    if let Ok(val) = env::var(k_env_name) {
        if !val.trim().is_empty() {
            return Ok(KeyMaterial::from_raw_str(&val)?);
        }
    }
    let p_env_name = passphrase_env.as_deref().unwrap_or(DEFAULT_PASSPHRASE_ENV);
    if let Ok(val) = env::var(p_env_name) {
        if !val.is_empty() {
            return Ok(KeyMaterial::from_passphrase(val)?);
        }
    }

    Err(CliError::InvalidArgs(format!(
        "no encryption key provided (set {DEFAULT_MASTER_KEY_ENV}, {DEFAULT_PASSPHRASE_ENV}, or pass --raw-key / --passphrase / --key-file)"
    )))
}

fn resolve_token_key_spec(
    hmac_secret: Option<String>,
    ed25519_seed: Option<String>,
) -> Result<TokenKeySpec, CliError> {
    if let Some(sec) = hmac_secret {
        let bytes = hex::decode(&sec).unwrap_or_else(|_| sec.into_bytes());
        Ok(TokenKeySpec::HmacSecret(bytes))
    } else if let Some(seed_hex) = ed25519_seed {
        let bytes = hex::decode(&seed_hex).map_err(|_| {
            CliError::InvalidArgs("--ed25519-privkey must be 64 hex chars".into())
        })?;
        let arr: [u8; 32] = bytes.try_into().map_err(|_| {
            CliError::InvalidArgs("--ed25519-privkey must be 32 bytes".into())
        })?;
        Ok(TokenKeySpec::Ed25519Seed(arr))
    } else {
        Err(CliError::InvalidArgs(
            "either --hmac-secret or --ed25519-privkey is required".into(),
        ))
    }
}

pub fn parse_cli_args(args: &[String]) -> Result<Command, CliError> {
    if args.len() < 2 {
        return Err(CliError::InvalidArgs(usage()));
    }
    let subcmd = args[1].as_str();
    if subcmd == "--help" || subcmd == "-h" || subcmd == "help" {
        return Err(CliError::InvalidArgs(usage()));
    }

    let mut input: Option<PathBuf> = None;
    let mut output: Option<PathBuf> = None;
    let mut section: Option<String> = None;
    let mut key_name: Option<String> = None;
    let mut token: Option<String> = None;
    let mut sealed: Option<String> = None;
    let mut env_name: Option<String> = None;
    let mut export_prefix = false;
    let mut raw_key: Option<String> = None;
    let mut passphrase: Option<String> = None;
    let mut key_file: Option<PathBuf> = None;
    let mut key_env: Option<String> = None;
    let mut passphrase_env: Option<String> = None;
    let mut client_id: Option<String> = None;
    let mut hmac_secret: Option<String> = None;
    let mut ed25519_seed: Option<String> = None;

    let mut i = 2;
    while i < args.len() {
        let flag = args[i].as_str();
        let next_val = |idx: &mut usize, name: &str| -> Result<String, CliError> {
            *idx += 1;
            args.get(*idx)
                .cloned()
                .ok_or_else(|| CliError::InvalidArgs(format!("missing value for {name}")))
        };

        match flag {
            "--input" | "-i" => input = Some(PathBuf::from(next_val(&mut i, flag)?)),
            "--output" | "-o" => output = Some(PathBuf::from(next_val(&mut i, flag)?)),
            "--section" | "-s" => section = Some(next_val(&mut i, flag)?),
            "--key" | "-k" => key_name = Some(next_val(&mut i, flag)?),
            "--token" | "-t" => token = Some(next_val(&mut i, flag)?),
            "--sealed" => sealed = Some(next_val(&mut i, flag)?),
            "--env-name" | "-e" => env_name = Some(next_val(&mut i, flag)?),
            "--export" => {
                export_prefix = true;
            }
            "--raw-key" => raw_key = Some(next_val(&mut i, flag)?),
            "--passphrase" => passphrase = Some(next_val(&mut i, flag)?),
            "--key-file" => key_file = Some(PathBuf::from(next_val(&mut i, flag)?)),
            "--key-env" => key_env = Some(next_val(&mut i, flag)?),
            "--passphrase-env" => passphrase_env = Some(next_val(&mut i, flag)?),
            "--client" | "-c" => client_id = Some(next_val(&mut i, flag)?),
            "--hmac-secret" => hmac_secret = Some(next_val(&mut i, flag)?),
            "--ed25519-privkey" => ed25519_seed = Some(next_val(&mut i, flag)?),
            other => {
                return Err(CliError::InvalidArgs(format!(
                    "unknown argument `{other}`\n\n{}",
                    usage()
                )));
            }
        }
        i += 1;
    }

    match subcmd {
        "encrypt" => {
            let input = input.ok_or_else(|| CliError::InvalidArgs("--input is required".into()))?;
            let output =
                output.ok_or_else(|| CliError::InvalidArgs("--output is required".into()))?;
            let key = resolve_key_material(raw_key, passphrase, key_file, key_env, passphrase_env)?;
            Ok(Command::Encrypt { input, output, key })
        }
        "decrypt" => {
            let input = input.ok_or_else(|| CliError::InvalidArgs("--input is required".into()))?;
            let key = resolve_key_material(raw_key, passphrase, key_file, key_env, passphrase_env)?;
            Ok(Command::Decrypt { input, output, key })
        }
        "get" => {
            let input = input.ok_or_else(|| CliError::InvalidArgs("--input is required".into()))?;
            let section =
                section.ok_or_else(|| CliError::InvalidArgs("--section is required".into()))?;
            let key_name =
                key_name.ok_or_else(|| CliError::InvalidArgs("--key is required".into()))?;
            let token = token
                .or_else(|| env::var("WASM_CONFIG_TOKEN").ok())
                .ok_or_else(|| {
                    CliError::InvalidArgs("--token (or WASM_CONFIG_TOKEN env) is required".into())
                })?;
            let key = resolve_key_material(raw_key, passphrase, key_file, key_env, passphrase_env)?;
            Ok(Command::Get {
                input,
                section,
                key_name,
                token,
                env_name,
                export_prefix,
                key,
            })
        }
        "unseal" => {
            let client_id =
                client_id.ok_or_else(|| CliError::InvalidArgs("--client is required".into()))?;
            let section =
                section.ok_or_else(|| CliError::InvalidArgs("--section is required".into()))?;
            let key_name =
                key_name.ok_or_else(|| CliError::InvalidArgs("--key is required".into()))?;
            let target_env = match &env_name {
                Some(custom) => custom.clone(),
                None => derive_env_name(&section, &key_name)?,
            };
            let sealed = sealed
                .or_else(|| env::var(&target_env).ok())
                .ok_or_else(|| {
                    CliError::InvalidArgs(format!(
                        "--sealed (or environment variable {target_env}) is required"
                    ))
                })?;
            let scheme_key = resolve_token_key_spec(hmac_secret, ed25519_seed)?;
            Ok(Command::Unseal {
                sealed,
                client_id,
                section,
                key_name,
                env_name,
                scheme_key,
            })
        }
        "token" => {
            let client_id =
                client_id.ok_or_else(|| CliError::InvalidArgs("--client is required".into()))?;
            let section =
                section.ok_or_else(|| CliError::InvalidArgs("--section is required".into()))?;
            let key_name =
                key_name.ok_or_else(|| CliError::InvalidArgs("--key is required".into()))?;
            let scheme_key = resolve_token_key_spec(hmac_secret, ed25519_seed)?;

            Ok(Command::Token {
                client_id,
                section,
                key_name,
                scheme_key,
            })
        }
        other => Err(CliError::InvalidArgs(format!(
            "unknown subcommand `{other}`\n\n{}",
            usage()
        ))),
    }
}

pub fn execute_command(cmd: Command) -> Result<Option<String>, CliError> {
    match cmd {
        Command::Encrypt { input, output, key } => {
            let plaintext = fs::read_to_string(&input)?;
            let doc = IniDocument::parse(&plaintext)?;
            let _ = doc.extract_policy()?;
            let encrypted = encrypt_ini(&plaintext, &key)?;
            fs::write(&output, encrypted)?;
            Ok(None)
        }
        Command::Decrypt { input, output, key } => {
            let container = fs::read(&input)?;
            let plaintext = decrypt_ini(&container, &key)?;
            if let Some(out_path) = output {
                fs::write(out_path, plaintext.as_bytes())?;
                Ok(None)
            } else {
                Ok(Some((*plaintext).clone()))
            }
        }
        Command::Get {
            input,
            section,
            key_name,
            token,
            env_name,
            export_prefix,
            key,
        } => {
            let container = fs::read(&input)?;
            let env_line = query_sealed_env(
                &container,
                &key,
                &token,
                &section,
                &key_name,
                env_name.as_deref(),
                export_prefix,
            )?;
            Ok(Some(env_line))
        }
        Command::Unseal {
            sealed,
            client_id,
            section,
            key_name,
            env_name,
            scheme_key,
        } => {
            let unsealed = unseal_env_value(
                &sealed,
                &client_id,
                &section,
                &key_name,
                env_name.as_deref(),
                &scheme_key,
            )?;
            Ok(Some((*unsealed).clone()))
        }
        Command::Token {
            client_id,
            section,
            key_name,
            scheme_key,
        } => {
            let tok = match scheme_key {
                TokenKeySpec::HmacSecret(sec) => {
                    generate_hmac_token(&client_id, &section, &key_name, &sec)
                }
                TokenKeySpec::Ed25519Seed(seed) => {
                    generate_ed25519_token(&client_id, &section, &key_name, &seed)
                }
            };
            Ok(Some(tok))
        }
    }
}

pub fn usage() -> String {
    concat!(
        "wasm_config-mgr — WASI Preview 2 AES-256-GCM INI Configuration Manager\n\n",
        "USAGE:\n",
        "  wasm_config-mgr encrypt --input <file.ini> --output <file.wcfg> [KEY_OPTIONS]\n",
        "  wasm_config-mgr decrypt --input <file.wcfg> [--output <file.ini>] [KEY_OPTIONS]\n",
        "  wasm_config-mgr get     --input <file.wcfg> --section <sec> --key <k> --token <tok> [--env-name <ENV>] [--export] [KEY_OPTIONS]\n",
        "  wasm_config-mgr unseal  [--sealed <val>] --client <id> --section <sec> --key <k> [--env-name <ENV>] (--hmac-secret <sec> | --ed25519-privkey <hex>)\n",
        "  wasm_config-mgr token   --client <id> --section <sec> --key <k> (--hmac-secret <sec> | --ed25519-privkey <hex>)\n\n",
        "KEY_OPTIONS:\n",
        "  --raw-key <hex|base64>        Direct 256-bit AES master key\n",
        "  --passphrase <str>            Passphrase derived with Argon2id\n",
        "  --key-file <path>             Path to file containing 256-bit key\n",
        "  --key-env <ENV>               Env var with 256-bit key (default: WASM_CONFIG_MASTER_KEY)\n",
        "  --passphrase-env <ENV>        Env var with passphrase (default: WASM_CONFIG_PASSPHRASE)\n"
    )
    .to_string()
}
