---
title: "Feature: WASI Component Model (WIT) Export & Fermyon Spin HTTP Micro-Vault Service"
labels: "feature, spec-kit, wasi"
---

## Feature Intent

Extend `wasm_config-mgr` beyond a standalone CLI utility by introducing:
1. A typed WASI Preview 2 Component Model (`wit`) interface for direct in-process consumption by other WebAssembly components.
2. A serverless Fermyon Spin HTTP micro-vault service (`wasi:http`) allowing microservices and containers to query sealed secrets via authenticated REST calls.

## Requirements (EARS Syntax)

1. **WHEN** a client component calls `get-sealed` over the WIT reader interface with a valid token and authorized policy, **THE SYSTEM SHALL** return the end-to-end sealed value (`wcfg-sealed:v1:...`).
2. **WHEN** an HTTP client sends `POST /v1/config/get` with header `Authorization: Bearer <token>` and valid JSON payload, **THE SYSTEM SHALL** respond with HTTP 200 OK and a JSON object containing the sealed value.
3. **IF** an unauthorized client token or forbidden key is requested via WIT or HTTP, **THEN THE SYSTEM SHALL** reject the request with an error (HTTP 401/403) and emit no plaintext secrets.
4. **THE SYSTEM SHALL** ensure all outgoing secrets remain end-to-end sealed and bound to the client and context via AAD.

## Scope

- **WASI Component Model (WIT Export):** `wit/config-provider.wit`, `src/provider/mod.rs`
- **HTTP / Micro-Vault Service (Spin):** `spin/spin.toml`, `src/provider/http.rs`, `src/bin/wasm_config_provider_spin.rs`
- **Tests & Verification:** `tests/provider_test.rs`
- **Documentation & Examples:** `Example/SPIN_HTTP_EXAMPLE.md`, `Example/SPIN_HTTP_EXAMPLE_de.md`, `README.md`, `README_de.md`

### Open Decisions

- None. Both in-process WIT bindings and standalone Spin HTTP component run on WASI Preview 2 (`wasm32-wasip2`).

## SpecDD Architecture Alignment (Drift Control)

Please confirm that this feature respects the constraints defined in `constitution.md`:

- [x] **Layering:** The 4-layer architecture is maintained (`src/ini`, `src/crypto`, `src/auth`, `src/cli` / `src/provider`). Crypto does not depend on Auth or CLI.
- [x] **Security (Encryption at Rest):** All configuration containers at rest remain authenticated and encrypted using AES-256-GCM (96-bit nonce, 128-bit tag, 34-byte header AAD).
- [x] **Security (Access Control):** No configuration entry is disclosed without prior cryptographic token and policy verification (`[__policy__]`).
- [x] **Security (No Plaintext Secrets):** Outgoing secrets are never exposed as plaintext on stdout or HTTP responses; end-to-end response sealing (`wcfg-sealed:v1:...`) remains enforced.
- [x] **Memory Safety:** Sensitive key material and decrypted secrets in RAM are zeroed after use (`zeroize`).
- [x] **WASI Compatibility:** Compiles cleanly for `wasm32-wasip2` and native targets without warnings.
- [x] **Standards:** License (MIT / Apache-2.0), `NOTICE`, and English source code documentation are maintained.

## Acceptance Criteria

- [x] **AC-1:** The WIT interface `wasm-config:provider/reader@0.1.0` is defined and exports `get-sealed` and `unseal-hmac`.
- [x] **AC-2:** The WIT function `get-sealed` validates access against token and policy and returns the sealed value; unauthorized calls fail.
- [x] **AC-3:** The Spin HTTP endpoint processes `POST /v1/config/get` with `Authorization: Bearer <token>` and JSON body, responding with HTTP 200 and sealed JSON payload.
- [x] **AC-4:** The Spin HTTP endpoint rejects invalid tokens or unauthorized keys with HTTP 401/403 without plaintext leaks.
- [x] Tests added/updated: `cargo test` passes 11 tests (including `tests/provider_test.rs`), and SDD gates pass (`sdd lint`, `sdd gate pre-merge`, `sdd gate pre-release`).
- [x] Documentation updated: `README.md`, `README_de.md`, and practical examples in `Example/` are up to date.
