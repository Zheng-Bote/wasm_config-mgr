---
feature: config-provider
status: approved
archive-after: 2027-01-01
touches:
  - wit/**
  - spin/**
  - src/**
  - tests/**
  - Cargo.toml
  - Cargo.lock
  - Example/**
  - README.md
  - README_de.md
  - CHANGELOG.md
  - .github/**
---

# Tech Spec — WASI Component Model Interface and Spin HTTP Service (`config-provider`)

Setzt das PRD `docs/prd/config-provider.md` um.

## Architektur

1. **WIT-Definition (`wit/config-provider.wit`):**
   ```wit
   package wasm-config:provider@0.1.0;

   interface reader {
       get-sealed: func(container-path: string, section: string, key: string, token: string, env-name: string) -> result<string, string>;
       unseal-hmac: func(sealed-value: string, client-id: string, section: string, key: string, env-name: string, secret-hex: string) -> result<string, string>;
   }

   world config-provider {
       export reader;
   }
   ```
2. **Provider-Modul (`src/provider/mod.rs`):**
   Implementiert die von `wit_bindgen::generate!` erzeugten Traits und bindet die Kernfunktionen `query_sealed_env` und `unseal_env_value` an.
3. **Spin-HTTP-Handler (`spin/`):**
   Bietet den HTTP-Endpunkt `POST /v1/config/get`:
   - Extrahiert Token aus `Authorization: Bearer <token>` oder dem JSON-Payload.
   - Extrahiert `section`, `key`, `env_name` aus dem JSON-Body.
   - Ruft die Krypto-/Auth-Engine auf und liefert JSON zurück.

## Schnittstellen & Formate

### HTTP POST /v1/config/get
```json
// Request
{
  "container_path": "Example/db_config.wcfg",
  "section": "database",
  "key": "password",
  "env_name": "DB_PASSWORD"
}
```

```json
// Response HTTP 200
{
  "status": "ok",
  "env_name": "DB_PASSWORD",
  "sealed_value": "wcfg-sealed:v1:hmac:..."
}
```

## Umsetzung der Akzeptanzkriterien

| AC | Umsetzung | Test |
|---|---|---|
| AC-1 | `wit/config-provider.wit` & `src/provider/mod.rs` | `tests/provider_test.rs::test_provider_ac1_wit_interface_binding` |
| AC-2 | `src/provider/mod.rs` (`get_sealed`, `unseal_hmac`) | `tests/provider_test.rs::test_provider_ac2_get_sealed_and_unseal` |
| AC-3 | `spin/src/lib.rs` (`handle_http_request`) | `tests/provider_test.rs::test_provider_ac3_http_success_response` |
| AC-4 | `spin/src/lib.rs` (Fehlerbehandlung 401/403) | `tests/provider_test.rs::test_provider_ac4_http_unauthorized_rejection` |

## Sicherheit

- Verfassung Security-Regeln 1–4 gelten uneingeschränkt. Kein Klartext im HTTP-Body oder in WIT-Rückgabewerten für `get-sealed`.
