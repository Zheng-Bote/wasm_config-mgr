---
name: Feature Specification (Spec Kit)
about: Propose a new feature, interface or security rule for wasm_config-mgr.
title: "Feature: "
labels: "feature, spec-kit, wasi"
assignees: ""
---

## Feature Intent

_Describe what the feature does and why it is needed. Keep it concise. Reference current architecture (WASI CLI, WIT component, Crypto, Policy) where relevant._

## Requirements (EARS Syntax)

_Use EARS patterns: `THE SYSTEM SHALL …` (ubiquitous), `WHEN <trigger>, THE SYSTEM SHALL …` (event), `WHILE <state>, …` (state), `WHERE <feature/option>, …` (optional), `IF <condition>, THEN THE SYSTEM SHALL …` (unwanted behaviour)._

1. **WHEN** _trigger_, **THE SYSTEM SHALL** _response_.
2. **IF** _condition_, **THEN THE SYSTEM SHALL** _response_.
3. **THE SYSTEM SHALL** _response_.

## Scope

_Which layers and files are affected? Delete lines that do not apply._

- **INI Parser & Policy Engine:** `src/ini/`
- **Crypto & Response Sealing (AES-256-GCM / Argon2id / Curve25519):** `src/crypto/`
- **Token Auth & Permissions (HMAC / Ed25519):** `src/auth/`
- **CLI & Output Formatting:** `src/cli/`, `src/main.rs`
- **WASI Component Model (WIT Export):** `wit/`, `src/provider/`
- **HTTP / Micro-Vault Service (Spin):** `spin/`, `src/bin/`
- **Documentation & Examples:** `Example/`, `README.md`, `README_de.md`

### Open Decisions

_Questions that must be answered before or during implementation (delete if none)._

## SpecDD Architecture Alignment (Drift Control)

Please confirm that this feature respects the constraints defined in `constitution.md`:

- [ ] **Layering:** The 4-layer architecture is maintained (`src/ini`, `src/crypto`, `src/auth`, `src/cli` / `provider`). Crypto does not depend on Auth or CLI.
- [ ] **Security (Encryption at Rest):** All configuration containers at rest remain authenticated and encrypted using AES-256-GCM (96-bit nonce, 128-bit tag, 34-byte header AAD).
- [ ] **Security (Access Control):** No configuration entry is disclosed without prior cryptographic token and policy verification (`[__policy__]`).
- [ ] **Security (No Plaintext Secrets):** Outgoing secrets are never exposed as plaintext on stdout or HTTP responses; end-to-end response sealing (`wcfg-sealed:v1:...`) remains enforced.
- [ ] **Memory Safety:** Sensitive key material and decrypted secrets in RAM are zeroed after use (`zeroize`).
- [ ] **WASI Compatibility:** Compiles cleanly for `wasm32-wasip2` and native targets without warnings.
- [ ] **Standards:** License (MIT / Apache-2.0), `NOTICE`, and English source code documentation are maintained.

## Acceptance Criteria

- [ ] Criterion 1
- [ ] Criterion 2
- [ ] Tests added/updated: `cargo test` and SDD gates pass (`sdd lint`, `sdd gate pre-merge`).
- [ ] Documentation updated: `README.md` and `README_de.md` are up to date.
