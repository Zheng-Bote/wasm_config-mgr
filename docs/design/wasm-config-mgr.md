---
feature: wasm-config-mgr
status: approved
archive-after: 2027-01-01
touches:
  - src/**
  - tests/**
  - Cargo.toml
  - Example/**
  - README_de.md
---

# Tech Spec — WASI AES-256 INI Config Manager (`wasm-config-mgr`)

Setzt das PRD `docs/prd/wasm-config-mgr.md` um. Die Verfassung hat Vorrang; diese Tech Spec darf sie präzisieren, nie lockern.

## Architektur

Das System besteht aus einer Bibliothek (`src/lib.rs`) mit vier Schichten und einem WASI-Preview-2-kompatiblen CLI-Einstiegspunkt (`src/main.rs`):

1. **`src/ini`**:
   - Parst INI-Text in eine strukturierte `IniDocument`-Repräsentation (`BTreeMap<String, BTreeMap<String, String>>`).
   - Extrahiert aus der reservierten Sektion `[__policy__]` das `PolicyManifest` mit Client-Definitionen (`client.<id>.hmac_secret`, `client.<id>.ed25519_pubkey`, `client.<id>.allow`).
2. **`src/crypto`**:
   - Implementiert das Containerformat `WCFG` (Version 1) mit 34-Byte Header als AAD und AES-256-GCM.
   - Implementiert **Response Sealing (`seal_value_hmac`, `unseal_value_hmac`, `seal_value_ed25519`, `unseal_value_ed25519`)**:
     - Bindet `wasm-config-mgr:seal-aad:v1:<client_id>:<section>:<key>:<env_name>` als Associated Data (AAD) in den AES-256-GCM-Tag ein.
     - Für HMAC-Clients (`wcfg-sealed:v1:hmac:<nonce_hex>:<ciphertext_hex>`) wird der 256-Bit-Sealing-Key per HMAC-SHA256 aus dem Client-Secret und dem Anfragekontext abgeleitet.
     - Für Ed25519-Clients (`wcfg-sealed:v1:ed25519:<ephemeral_R_hex>:<nonce_hex>:<ciphertext_hex>`) wird ein asymmetrischer Curve25519/Edwards-Diffie-Hellman-Schlüsselaustausch ($R = r \cdot B$, $S = r \cdot A$) durchgeführt, sodass nur der Besitzer des privaten Ed25519-Seeds das Geheimnis entsiegeln kann.
3. **`src/auth`**:
   - Verifiziert HMAC-SHA256- und Ed25519-Tokens und prüft die `client.<id>.allow`-Regeln.
   - Gibt neben dem Konfigurationswert auch das verifizierte `ClientPolicy`-Material an die Sealing-Schicht zurück.
4. **`src/cli`**:
   - Verarbeitet CLI-Kommandos (`encrypt`, `decrypt`, `get`, `unseal`, `token`) und gibt bei `get` standardmäßig `<ENV_NAME>=wcfg-sealed:v1:...` (bzw. mit `--export` `export <ENV_NAME>='wcfg-sealed:v1:...'`) auf `stdout` aus.

## Schnittstellen

### CLI-Kommandos

```text
# 1. INI-Datei mit AES-256-GCM verschlüsseln
wasm_config-mgr encrypt --input <config.ini> --output <config.wcfg> [KEY_OPTIONS]

# 2. Verschlüsselte INI-Datei vollständig entschlüsseln (Admin)
wasm_config-mgr decrypt --input <config.wcfg> [--output <config.ini>] [KEY_OPTIONS]

# 3. Autorisierten Eintrag Ende-zu-Ende versiegelt als ENV abrufen (kein Klartext auf stdout!)
wasm_config-mgr get --input <config.wcfg> --section <sec> --key <k> --token <token> [--env-name <CUSTOM_ENV>] [--export] [KEY_OPTIONS]

# 4. Versiegelten ENV-Wert durch den autorisierten Client entsiegeln
wasm_config-mgr unseal --sealed <wcfg-sealed:v1:...> --client <id> --section <sec> --key <k> [--env-name <CUSTOM_ENV>] (--hmac-secret <sec> | --ed25519-privkey <hex>)

# 5. Zugriffs-Token für einen autorisierten Client generieren
wasm_config-mgr token --client <client_id> --section <sec> --key <k> (--hmac-secret <secret> | --ed25519-privkey <hex_seed>)
```

## Datenmodell

- `IniDocument`: Map von normalisierten Sektionsnamen auf Schlüssel-Wert-Maps.
- `EncryptedContainer`: Binärrepräsentation (`Header` 34 Bytes + `Ciphertext` + `Tag` 16 Bytes).
- `ClientPolicy`: `{ client_id: String, hmac_secret: Option<Zeroizing<Vec<u8>>>, ed25519_pubkey: Option<[u8; 32]>, allowed_patterns: Vec<String> }`.

## Umsetzung der Akzeptanzkriterien

| AC | Umsetzung | Test |
|---|---|---|
| AC-1 | `src/ini/mod.rs` (`IniDocument::parse`, `serialize`) | `tests/integration_test.rs::test_ac1_ini_parsing_and_validation` |
| AC-2 | `src/crypto/mod.rs` (`encrypt_ini`, `decrypt_ini`) | `tests/integration_test.rs::test_ac2_aes256_gcm_roundtrip_raw_and_argon2id` |
| AC-3 | `src/crypto/mod.rs` (GCM Tag & Header-AAD Integritätsprüfung) | `tests/integration_test.rs::test_ac3_tamper_and_wrong_key_detection` |
| AC-4 | `src/auth/mod.rs` & `src/cli/mod.rs` (`authorize_and_get`, ENV-Formatierung) | `tests/integration_test.rs::test_ac4_authorized_env_retrieval_hmac_and_ed25519` |
| AC-5 | `src/auth/mod.rs` (Token-Signaturprüfung & Policy-Allowlist) | `tests/integration_test.rs::test_ac5_unauthorized_client_or_forged_token_rejected` |
| AC-6 | `src/auth/mod.rs` & `src/cli/mod.rs` (`__policy__`-Sperre & ENV-Namen-Validierung) | `tests/integration_test.rs::test_ac6_policy_section_protection_and_env_name_validation` |
| AC-7 | `src/crypto/mod.rs` & `src/cli/mod.rs` (Response Sealing `wcfg-sealed:v1:...` & `unseal`) | `tests/integration_test.rs::test_ac7_end_to_end_response_sealing_no_plaintext_on_stdout` |

## Sicherheit

- Erfüllt Security-Regel 1–4 der Verfassung inkl. ADR 0002 (Ende-zu-Ende Response Sealing gegen Klartext-Exposition auf `stdout` oder in Prozess-Umgebungen).

## Offene Punkte

- Keine offenen Punkte.
