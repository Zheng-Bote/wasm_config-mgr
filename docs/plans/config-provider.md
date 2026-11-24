---
feature: config-provider
status: approved
archive-after: 2027-01-01
---

# Plan — WASI Component Model Interface and Spin HTTP Service (`config-provider`)

Reihenfolge der Umsetzung.

## Tasks

- [x] AC-1 WIT-Interface in `wit/config-provider.wit` definieren und `wit-bindgen` in `Cargo.toml` einbinden.
- [x] AC-2 Provider-Export in `src/provider/mod.rs` implementieren (`get-sealed`, `unseal-hmac`).
- [x] AC-3 Spin HTTP Service Core-Handler in `spin/` bzw. `src/provider/http.rs` implementieren (`POST /v1/config/get`).
- [x] AC-4 Fehlerbehandlung (HTTP 401/403, JSON-Fehler, Fail-Closed) und Integrations-Tests für AC-1 bis AC-4 umsetzen.
