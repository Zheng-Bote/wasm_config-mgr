# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-11-24

### Added
- **Core WASI AES-256-GCM INI Manager:**
  - Robust INI parser supporting sections, key-value pairs, inline comments (`#`, `;`), and quoting in `src/ini/`.
  - Binary container format (`WCFG` v1) with 34-byte authenticated header (AAD) and AES-256-GCM encryption in `src/crypto/`.
  - Master key support via 256-bit raw key (hex, base64, raw bytes) or Argon2id passphrase key derivation.
  - Policy manifest parser for embedded `[__policy__]` sections defining client access allowlists.
  - Cryptographic token authorization using HMAC-SHA256 and Ed25519 signatures.
  - End-to-end **Response Sealing** (`wcfg-sealed:v1:...`): configuration values are never exposed in plaintext on stdout, shell environments, or logs.
  - In-memory unsealing APIs (`unseal_env_value`) with memory zeroing (`zeroize`).
- **WASI Preview 2 Component Model (`wit`):**
  - Exported WIT interface `wasm-config:provider/reader@0.1.0` in `wit/config-provider.wit` for typed in-process composition.
  - Provider module implementation (`src/provider/mod.rs`) via `wit-bindgen`.
- **Fermyon Spin HTTP Micro-Vault Service:**
  - Spin manifest `spin/spin.toml` configuring route `/v1/config/...`.
  - HTTP request handler in `src/provider/http.rs` serving `POST /v1/config/get` with Bearer token authentication and JSON response.
  - WASI binary `wasm_config_provider_spin.wasm`.
- **Examples & Tooling:**
  - Complete Python practical example (`Example/db_config.ini`, `Example/query_db_config.py`).
  - German and English guides for Spin HTTP micro-vault (`Example/SPIN_HTTP_EXAMPLE_de.md`, `Example/SPIN_HTTP_EXAMPLE.md`).
  - Comprehensive documentation in `README.md` and `README_de.md`.
  - Issue templates and GitHub workflows in `.github/`.
  - Apache-2.0 `NOTICE` file.
  - Full Spec-Driven Development (`sdd`) specification suite (ADRs 0001–0003, PRDs, designs, plans).

## [0.0.1] - 2026-11-24

### Added
- Initial project structure (`init`).
