---
feature: wasm-config-mgr
status: approved
archive-after: 2027-01-01
---

# Plan — WASI AES-256 INI Config Manager (`wasm-config-mgr`)

Reihenfolge der Umsetzung. Jede Task nennt das Akzeptanzkriterium, auf das sie einzahlt.

## Tasks

- [x] AC-1 INI-Parser, Serialisierer und `[__policy__]`-Extraktor in `src/ini/mod.rs` implementieren.
- [x] AC-2 AES-256-GCM Container-Verschlüsselung (`WCFG`-Format) mit Raw-256-Bit-Key und Argon2id-KDF in `src/crypto/mod.rs` implementieren.
- [x] AC-3 Header-AAD-Authentifizierung und Manipulationserkennung in `src/crypto/mod.rs` sicherstellen.
- [x] AC-4 Kryptografische Token-Erzeugung und -Verifikation (HMAC-SHA256 & Ed25519) sowie ENV-Ausgabe in `src/auth/mod.rs` und `src/cli/mod.rs` umsetzen.
- [x] AC-5 Policy-Manifest-Auswertung (Wildcards, Client-Isolation, Fail-Closed bei fehlender Berechtigung) in `src/auth/mod.rs` implementieren.
- [x] AC-6 Schutz der reservierten `[__policy__]`-Sektion vor `get`-Abfragen sowie Validierung der ENV-Variablennamen in `src/cli/mod.rs` umsetzen.
- [x] AC-7 Ende-zu-Ende Response Sealing (`wcfg-sealed:v1:...`) und Client-seitiges Entschlüsseln (`unseal`) für HMAC- und Ed25519-Clients implementieren und testen.
