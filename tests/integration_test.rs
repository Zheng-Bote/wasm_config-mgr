use ed25519_dalek::SigningKey;
use wasm_config_mgr::{
    auth::{AuthError, generate_ed25519_token, generate_hmac_token},
    cli::{
        CliError, TokenKeySpec, format_env_output, query_encrypted_env, query_sealed_env,
        unseal_env_value, validate_env_name,
    },
    crypto::{CryptoError, HEADER_LEN, KeyMaterial, decrypt_ini, encrypt_ini},
    ini::{IniDocument, IniError},
};

fn sample_ini_with_policy(ed25519_pub_hex: &str) -> String {
    format!(
        r#"
# Sample Application Configuration
; Managed by wasm_config-mgr

[__policy__]
client.billing_service.hmac_secret = 00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff
client.billing_service.allow = database.password, database.host, stripe.*
client.audit_worker.ed25519_pubkey = {ed25519_pub_hex}
client.audit_worker.allow = logging.endpoint

[database]
host = "db.internal.example.com"
port = 5432 ; default postgres port
password = "s3cr3t_db_p@ssw0rd!"

[stripe]
api_key = sk_live_987654321

[logging]
endpoint = https://logs.internal.example.com/ingest
"#
    )
}

// wasm-config-mgr AC-1: The program parses valid INI files with sections, key-value pairs, comments, and quoting without errors and rejects syntactically invalid INI files.
#[test]
fn test_ac1_ini_parsing_and_validation() {
    let valid_ini = sample_ini_with_policy(&"aa".repeat(32));
    let doc = IniDocument::parse(&valid_ini).expect("valid INI should parse");

    assert_eq!(doc.get("database", "host"), Some("db.internal.example.com"));
    assert_eq!(doc.get("database", "port"), Some("5432"));
    assert_eq!(doc.get("database", "password"), Some("s3cr3t_db_p@ssw0rd!"));
    assert_eq!(doc.get("stripe", "api_key"), Some("sk_live_987654321"));

    let serialized = doc.serialize();
    let reparsed = IniDocument::parse(&serialized).expect("serialized INI should re-parse");
    assert_eq!(doc, reparsed);

    // Reject orphan keys outside sections
    let err_orphan = IniDocument::parse("orphan_key = 123\n[sec]\na = b");
    assert!(matches!(err_orphan, Err(IniError::OrphanKey { line: 1 })));

    // Reject unclosed section brackets
    let err_unclosed = IniDocument::parse("[broken_section\nkey = value");
    assert!(matches!(
        err_unclosed,
        Err(IniError::SyntaxError { line: 1, .. })
    ));

    // Reject missing equals sign
    let err_no_eq = IniDocument::parse("[sec]\njust_a_key_without_value");
    assert!(matches!(
        err_no_eq,
        Err(IniError::SyntaxError { line: 2, .. })
    ));
}

// wasm-config-mgr AC-2: The program encrypts an INI file using AES-256-GCM (optionally using a 256-bit raw key or an Argon2id passphrase) and decrypts it without data loss.
#[test]
fn test_ac2_aes256_gcm_roundtrip_raw_and_argon2id() {
    let ini_text = sample_ini_with_policy(&"11".repeat(32));

    // 1. Direct 256-bit Raw Key (64 hex chars)
    let raw_key_hex = "cafebabecafebabecafebabecafebabecafebabecafebabecafebabecafebabe";
    let raw_key = KeyMaterial::from_raw_str(raw_key_hex).expect("valid raw key");
    let encrypted_raw = encrypt_ini(&ini_text, &raw_key).expect("AES-256-GCM encrypt with raw key");
    assert_eq!(&encrypted_raw[0..4], b"WCFG");

    let decrypted_raw =
        decrypt_ini(&encrypted_raw, &raw_key).expect("AES-256-GCM decrypt with raw key");
    assert_eq!(decrypted_raw.as_str(), ini_text);

    // 2. Argon2id Passphrase derivation
    let pass_key =
        KeyMaterial::from_passphrase("correct-horse-battery-staple-2026!").expect("valid pass");
    let encrypted_argon =
        encrypt_ini(&ini_text, &pass_key).expect("AES-256-GCM encrypt with Argon2id");
    assert_eq!(&encrypted_argon[0..4], b"WCFG");

    let decrypted_argon =
        decrypt_ini(&encrypted_argon, &pass_key).expect("AES-256-GCM decrypt with Argon2id");
    assert_eq!(decrypted_argon.as_str(), ini_text);
}

// wasm-config-mgr AC-3: Tampered ciphertexts, altered header bytes, or incorrect decryption keys are reliably detected by AES-256-GCM.
#[test]
fn test_ac3_tamper_and_wrong_key_detection() {
    let ini_text = sample_ini_with_policy(&"22".repeat(32));
    let key1 = KeyMaterial::from_raw_str(
        "0101010101010101010101010101010101010101010101010101010101010101",
    )
    .unwrap();
    let key2 = KeyMaterial::from_raw_str(
        "0202020202020202020202020202020202020202020202020202020202020202",
    )
    .unwrap();

    let container = encrypt_ini(&ini_text, &key1).unwrap();

    // Wrong key fails authentication
    let res_wrong_key = decrypt_ini(&container, &key2);
    assert_eq!(res_wrong_key, Err(CryptoError::AuthenticationFailed));

    // Tampered ciphertext byte fails authentication
    let mut tampered_cipher = container.clone();
    let last_idx = tampered_cipher.len() - 1;
    tampered_cipher[last_idx] ^= 0xFF;
    assert_eq!(
        decrypt_ini(&tampered_cipher, &key1),
        Err(CryptoError::AuthenticationFailed)
    );

    // Tampered AAD header byte (e.g., salt byte in header) fails authentication
    let mut tampered_header = container.clone();
    tampered_header[10] ^= 0x01;
    assert!(HEADER_LEN > 10);
    assert_eq!(
        decrypt_ini(&tampered_header, &key1),
        Err(CryptoError::AuthenticationFailed)
    );
}

// wasm-config-mgr AC-4: An authorized program with a valid cryptographic token (HMAC-SHA256 or Ed25519) and matching policy permissions in [__policy__] receives the ENV entry (ENV_KEY=...).
#[test]
fn test_ac4_authorized_env_retrieval_hmac_and_ed25519() {
    let ed_seed = [42u8; 32];
    let signing_key = SigningKey::from_bytes(&ed_seed);
    let pubkey_hex = hex::encode(signing_key.verifying_key().to_bytes());

    let ini_text = sample_ini_with_policy(&pubkey_hex);
    let master_key = KeyMaterial::from_raw_str(
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    )
    .unwrap();
    let container = encrypt_ini(&ini_text, &master_key).unwrap();

    // 1. Authorized HMAC-SHA256 request for `database.password`
    let client_secret =
        hex::decode("00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff").unwrap();
    let hmac_token =
        generate_hmac_token("billing_service", "database", "password", &client_secret);

    let env_out = query_sealed_env(
        &container,
        &master_key,
        &hmac_token,
        "database",
        "password",
        None,
        false,
    )
    .expect("authorized HMAC query should succeed");
    assert!(env_out.starts_with("DATABASE_PASSWORD=wcfg-sealed:v1:hmac:"));
    assert!(!env_out.contains("s3cr3t_db_p@ssw0rd!"));

    let unsealed_db = unseal_env_value(
        &env_out,
        "billing_service",
        "database",
        "password",
        None,
        &TokenKeySpec::HmacSecret(client_secret.clone()),
    )
    .expect("authorized client can unseal its response");
    assert_eq!(unsealed_db.as_str(), "s3cr3t_db_p@ssw0rd!");

    // Wildcard rule `stripe.*` with custom env name and `--export`
    let stripe_token = generate_hmac_token("billing_service", "stripe", "api_key", &client_secret);
    let env_export = query_sealed_env(
        &container,
        &master_key,
        &stripe_token,
        "stripe",
        "api_key",
        Some("STRIPE_SECRET_KEY"),
        true,
    )
    .expect("authorized wildcard HMAC query should succeed");
    assert!(env_export.starts_with("export STRIPE_SECRET_KEY='wcfg-sealed:v1:hmac:"));
    assert!(!env_export.contains("sk_live_987654321"));

    let unsealed_stripe = unseal_env_value(
        &env_export,
        "billing_service",
        "stripe",
        "api_key",
        Some("STRIPE_SECRET_KEY"),
        &TokenKeySpec::HmacSecret(client_secret),
    )
    .expect("client can unseal exported stripe secret");
    assert_eq!(unsealed_stripe.as_str(), "sk_live_987654321");

    // 2. Authorized Ed25519 request for `logging.endpoint`
    let ed_token = generate_ed25519_token("audit_worker", "logging", "endpoint", &ed_seed);
    let ed_env_out = query_sealed_env(
        &container,
        &master_key,
        &ed_token,
        "logging",
        "endpoint",
        Some("LOG_URL"),
        false,
    )
    .expect("authorized Ed25519 query should succeed");
    assert!(ed_env_out.starts_with("LOG_URL=wcfg-sealed:v1:ed25519:"));
    assert!(!ed_env_out.contains("https://logs.internal.example.com/ingest"));

    let unsealed_ed = unseal_env_value(
        &ed_env_out,
        "audit_worker",
        "logging",
        "endpoint",
        Some("LOG_URL"),
        &TokenKeySpec::Ed25519Seed(ed_seed),
    )
    .expect("Ed25519 client can unseal its response");
    assert_eq!(
        unsealed_ed.as_str(),
        "https://logs.internal.example.com/ingest"
    );
}

// wasm-config-mgr AC-5: Requests with invalid/forged tokens, unknown client IDs, or for section.key entries not permitted by [__policy__] are strictly rejected.
#[test]
fn test_ac5_unauthorized_client_or_forged_token_rejected() {
    let ed_seed = [7u8; 32];
    let signing_key = SigningKey::from_bytes(&ed_seed);
    let pubkey_hex = hex::encode(signing_key.verifying_key().to_bytes());

    let ini_text = sample_ini_with_policy(&pubkey_hex);
    let master_key = KeyMaterial::from_raw_str(
        "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
    )
    .unwrap();
    let container = encrypt_ini(&ini_text, &master_key).unwrap();

    // 1. Forged HMAC secret
    let wrong_secret = b"wrong_secret_key_for_billing_svc";
    let forged_token = generate_hmac_token("billing_service", "database", "password", wrong_secret);
    let res_forged = query_encrypted_env(
        &container,
        &master_key,
        &forged_token,
        "database",
        "password",
        None,
        false,
    );
    assert!(matches!(
        res_forged,
        Err(CliError::Auth(AuthError::InvalidSignature(_)))
    ));

    // 2. Token valid for `database.host` replayed for `database.password`
    let client_secret =
        hex::decode("00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff").unwrap();
    let host_token = generate_hmac_token("billing_service", "database", "host", &client_secret);
    let res_replay = query_encrypted_env(
        &container,
        &master_key,
        &host_token,
        "database",
        "password",
        None,
        false,
    );
    assert!(matches!(
        res_replay,
        Err(CliError::Auth(AuthError::InvalidSignature(_)))
    ));

    // 3. Valid Ed25519 signature from `audit_worker`, but requesting `database.password` (not in allowlist)
    let unauthorized_key_token =
        generate_ed25519_token("audit_worker", "database", "password", &ed_seed);
    let res_denied = query_encrypted_env(
        &container,
        &master_key,
        &unauthorized_key_token,
        "database",
        "password",
        None,
        false,
    );
    assert!(matches!(
        res_denied,
        Err(CliError::Auth(AuthError::AccessDenied { .. }))
    ));

    // 4. Unknown client ID
    let unknown_token = generate_hmac_token("rogue_app", "database", "host", &client_secret);
    let res_unknown = query_encrypted_env(
        &container,
        &master_key,
        &unknown_token,
        "database",
        "host",
        None,
        false,
    );
    assert!(matches!(
        res_unknown,
        Err(CliError::Auth(AuthError::UnknownClient(_)))
    ));
}

// wasm-config-mgr AC-6: The program prevents direct retrieval of internal entries from the [__policy__] section and strictly validates the target environment variable name against [A-Z0-9_]+.
#[test]
fn test_ac6_policy_section_protection_and_env_name_validation() {
    let ini_text = sample_ini_with_policy(&"33".repeat(32));
    let master_key = KeyMaterial::from_raw_str(
        "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
    )
    .unwrap();
    let container = encrypt_ini(&ini_text, &master_key).unwrap();

    let client_secret =
        hex::decode("00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff").unwrap();
    let policy_token = generate_hmac_token(
        "billing_service",
        "__policy__",
        "client.billing_service.hmac_secret",
        &client_secret,
    );

    let res_policy = query_encrypted_env(
        &container,
        &master_key,
        &policy_token,
        "__policy__",
        "client.billing_service.hmac_secret",
        Some("LEAKED_SECRET"),
        false,
    );
    assert!(matches!(
        res_policy,
        Err(CliError::Auth(AuthError::ReservedPolicySection))
    ));

    // Validate environment variable names
    assert!(validate_env_name("VALID_ENV_123").is_ok());
    assert!(validate_env_name("123_INVALID_START").is_err());
    assert!(validate_env_name("lowercase_not_allowed").is_err());
    assert!(validate_env_name("BAD;INJECTION").is_err());
    assert!(validate_env_name("").is_err());

    // Reject multiline values in raw ENV output
    assert!(matches!(
        format_env_output("VALID_NAME", "line1\nline2", false),
        Err(CliError::UnsafeEnvValue)
    ));
}

// wasm-config-mgr AC-7: The get command provides the requested configuration value end-to-end sealed (ENV_KEY=wcfg-sealed:v1:...) by default, ensuring no plaintext appears on stdout and only the authorized client can unseal it.
#[test]
fn test_ac7_end_to_end_response_sealing_no_plaintext_on_stdout() {
    let ed_seed = [99u8; 32];
    let signing_key = SigningKey::from_bytes(&ed_seed);
    let pubkey_hex = hex::encode(signing_key.verifying_key().to_bytes());

    let ini_text = sample_ini_with_policy(&pubkey_hex);
    let raw_key_str = "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd";
    let client_secret_hex = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";
    let client_secret = hex::decode(client_secret_hex).unwrap();
    let hmac_token =
        generate_hmac_token("billing_service", "database", "password", &client_secret);

    let tmp_dir = std::env::temp_dir().join("wasm_config_mgr_test_ac7");
    let _ = std::fs::create_dir_all(&tmp_dir);
    let ini_path = tmp_dir.join("test.ini");
    let wcfg_path = tmp_dir.join("test.wcfg");
    std::fs::write(&ini_path, &ini_text).unwrap();

    // 1. Encrypt via CLI
    let enc_cmd = wasm_config_mgr::cli::parse_cli_args(&[
        "wasm_config-mgr".into(),
        "encrypt".into(),
        "--input".into(),
        ini_path.to_string_lossy().into_owned(),
        "--output".into(),
        wcfg_path.to_string_lossy().into_owned(),
        "--raw-key".into(),
        raw_key_str.into(),
    ])
    .expect("valid encrypt CLI args");
    wasm_config_mgr::cli::execute_command(enc_cmd).expect("CLI encrypt succeeds");

    // 2. Get via CLI -> must return sealed value, never plaintext
    let get_cmd = wasm_config_mgr::cli::parse_cli_args(&[
        "wasm_config-mgr".into(),
        "get".into(),
        "--input".into(),
        wcfg_path.to_string_lossy().into_owned(),
        "--section".into(),
        "database".into(),
        "--key".into(),
        "password".into(),
        "--token".into(),
        hmac_token,
        "--env-name".into(),
        "DB_PASSWORD".into(),
        "--raw-key".into(),
        raw_key_str.into(),
    ])
    .expect("valid get CLI args");
    let sealed_stdout = wasm_config_mgr::cli::execute_command(get_cmd)
        .expect("CLI get succeeds")
        .unwrap();

    assert!(sealed_stdout.starts_with("DB_PASSWORD=wcfg-sealed:v1:hmac:"));
    assert!(!sealed_stdout.contains("s3cr3t_db_p@ssw0rd!"));

    // 3. Unseal via CLI with correct client credentials and context
    let unseal_cmd = wasm_config_mgr::cli::parse_cli_args(&[
        "wasm_config-mgr".into(),
        "unseal".into(),
        "--sealed".into(),
        sealed_stdout.clone(),
        "--client".into(),
        "billing_service".into(),
        "--section".into(),
        "database".into(),
        "--key".into(),
        "password".into(),
        "--env-name".into(),
        "DB_PASSWORD".into(),
        "--hmac-secret".into(),
        client_secret_hex.into(),
    ])
    .expect("valid unseal CLI args");
    let unsealed_plain = wasm_config_mgr::cli::execute_command(unseal_cmd)
        .expect("CLI unseal succeeds")
        .unwrap();
    assert_eq!(unsealed_plain, "s3cr3t_db_p@ssw0rd!");

    // 4. Context tampering (e.g. different env_name or wrong client secret) MUST fail authentication
    let wrong_env_unseal = unseal_env_value(
        &sealed_stdout,
        "billing_service",
        "database",
        "password",
        Some("OTHER_ENV_NAME"),
        &TokenKeySpec::HmacSecret(client_secret.clone()),
    );
    assert!(matches!(
        wrong_env_unseal,
        Err(CliError::Crypto(CryptoError::AuthenticationFailed))
    ));

    let wrong_secret_unseal = unseal_env_value(
        &sealed_stdout,
        "billing_service",
        "database",
        "password",
        Some("DB_PASSWORD"),
        &TokenKeySpec::HmacSecret(b"wrong_secret".to_vec()),
    );
    assert!(matches!(
        wrong_secret_unseal,
        Err(CliError::Crypto(CryptoError::AuthenticationFailed))
    ));

    let _ = std::fs::remove_dir_all(&tmp_dir);
}
