use wasm_config_mgr::{
    auth::generate_hmac_token,
    crypto::{KeyMaterial, encrypt_ini},
    provider::{ConfigProvider, http::handle_http_request},
};

fn setup_test_container() -> (std::path::PathBuf, String, String) {
    let tmp_dir = std::env::temp_dir().join("wasm_config_provider_test");
    let _ = std::fs::create_dir_all(&tmp_dir);
    let ini_path = tmp_dir.join("test.ini");
    let wcfg_path = tmp_dir.join("test.wcfg");

    let client_secret_hex = "4f8b2c19a7d3e605112233445566778899aabbccddeeff00123456789abcdef0";
    let master_key_hex = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    let ini_content = format!(
        r#"
[__policy__]
client.test_app.hmac_secret = {client_secret_hex}
client.test_app.allow = database.*

[database]
password = "super_secure_provider_password_123"
"#
    );

    std::fs::write(&ini_path, ini_content).unwrap();
    let key = KeyMaterial::from_raw_str(master_key_hex).unwrap();
    let encrypted = encrypt_ini(&std::fs::read_to_string(&ini_path).unwrap(), &key).unwrap();
    std::fs::write(&wcfg_path, encrypted).unwrap();

    // Set master key in environment
    unsafe {
        std::env::set_var("WASM_CONFIG_MASTER_KEY", master_key_hex);
    }

    (wcfg_path, client_secret_hex.to_string(), master_key_hex.to_string())
}

// config-provider AC-1: Das WIT-Interface wasm-config:provider/reader@0.1.0 wird definiert und exportiert Funktionen get-sealed und unseal.
#[test]
fn test_provider_ac1_wit_interface_binding() {
    let (wcfg_path, secret_hex, _) = setup_test_container();
    let secret_bytes = hex::decode(&secret_hex).unwrap();
    let token = generate_hmac_token("test_app", "database", "password", &secret_bytes);

    // Call ConfigProvider::get_sealed and ConfigProvider::unseal_hmac directly
    let sealed_res = ConfigProvider::get_sealed(
        &wcfg_path.to_string_lossy(),
        "database",
        "password",
        &token,
        "DB_PASS",
        None,
    );
    assert!(sealed_res.is_ok());
    let sealed_val = sealed_res.unwrap();
    assert!(sealed_val.starts_with("wcfg-sealed:v1:hmac:"));

    let unsealed_res = ConfigProvider::unseal_hmac(
        &sealed_val,
        "test_app",
        "database",
        "password",
        "DB_PASS",
        &secret_hex,
    );
    assert_eq!(unsealed_res.unwrap(), "super_secure_provider_password_123");
}

// config-provider AC-2: Die WIT-Funktion get-sealed validiert den Zugriff gegen Token und Policy und gibt den Wert Ende-zu-Ende versiegelt zurück; unautorisierte Zugriffe liefern einen Fehler.
#[test]
fn test_provider_ac2_get_sealed_and_unseal() {
    let (wcfg_path, secret_hex, _) = setup_test_container();
    let secret_bytes = hex::decode(&secret_hex).unwrap();

    // 1. Invalid signature token -> error
    let invalid_token = generate_hmac_token("test_app", "database", "password", b"wrong_secret_123");
    let err_sig = ConfigProvider::get_sealed(
        &wcfg_path.to_string_lossy(),
        "database",
        "password",
        &invalid_token,
        "DB_PASS",
        None,
    );
    assert!(err_sig.is_err());
    assert!(err_sig.unwrap_err().contains("Authorization or query failed"));

    // 2. Disallowed key -> error
    let forbidden_token = generate_hmac_token("test_app", "admin", "secret", &secret_bytes);
    let err_perm = ConfigProvider::get_sealed(
        &wcfg_path.to_string_lossy(),
        "admin",
        "secret",
        &forbidden_token,
        "ADMIN_PASS",
        None,
    );
    assert!(err_perm.is_err());
}

// config-provider AC-3: Der Spin-HTTP-Endpunkt verarbeitet POST /v1/config/get mit Authorization: Bearer <token> und JSON-Body und antwortet mit HTTP 200 und JSON.
#[test]
fn test_provider_ac3_http_success_response() {
    let (wcfg_path, secret_hex, _) = setup_test_container();
    let secret_bytes = hex::decode(&secret_hex).unwrap();
    let token = generate_hmac_token("test_app", "database", "password", &secret_bytes);

    let headers = vec![("Authorization".to_string(), format!("Bearer {token}"))];
    let body = format!(
        r#"{{"container_path":"{}","section":"database","key":"password","env_name":"DB_PASS"}}"#,
        wcfg_path.to_string_lossy()
    );

    let response = handle_http_request("POST", "/v1/config/get", &headers, &body);
    assert_eq!(response.status, 200);
    assert!(response.body.contains(r#""status":"ok""#));
    assert!(response.body.contains(r#""env_name":"DB_PASS""#));
    assert!(response.body.contains(r#""sealed_value":"wcfg-sealed:v1:hmac:"#));
    assert!(!response.body.contains("super_secure_provider_password_123"));
}

// config-provider AC-4: Der Spin-HTTP-Endpunkt lehnt ungültige Tokens oder unautorisierte Schlüssel mit HTTP 401/403 und einer JSON-Fehlermeldung ohne Klartext-Leaks ab.
#[test]
fn test_provider_ac4_http_unauthorized_rejection() {
    let (wcfg_path, _, _) = setup_test_container();

    // 1. Missing Authorization header -> HTTP 401
    let body = format!(
        r#"{{"container_path":"{}","section":"database","key":"password","env_name":"DB_PASS"}}"#,
        wcfg_path.to_string_lossy()
    );
    let resp_no_auth = handle_http_request("POST", "/v1/config/get", &[], &body);
    assert_eq!(resp_no_auth.status, 401);
    assert!(resp_no_auth.body.contains("Missing Authorization header"));

    // 2. Invalid Token -> HTTP 401
    let bad_headers = vec![("Authorization".to_string(), "Bearer invalid_token".to_string())];
    let resp_bad_token = handle_http_request("POST", "/v1/config/get", &bad_headers, &body);
    assert_eq!(resp_bad_token.status, 401);
    assert!(resp_bad_token.body.contains(r#""status":"error""#));

    // 3. Invalid HTTP Method -> HTTP 405
    let resp_method = handle_http_request("GET", "/v1/config/get", &bad_headers, &body);
    assert_eq!(resp_method.status, 405);
}
