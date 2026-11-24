---
status: accepted
date: 2026-11-24
supersedes: []
references:
  - constitution.md
  - docs/adr/0001-wasi-aes256-architecture.md
  - docs/adr/0002-response-sealing-no-plaintext-stdout.md
---

# ADR 0003 — WIT Component Model Export und Spin HTTP Provider Service

## Kontext

Mit ADR 0001 und ADR 0002 wurde `wasm_config-mgr` als WASI CLI Command realisiert, das verschlüsselte INI-Dateien verwaltet und Werte Ende-zu-Ende versiegelt (`wcfg-sealed:v1:...`) bereitstellt. 

Ziel ist es nun, zwei weitere Interaktionsmodi bereitzustellen:
1. **WASI Preview 2 Component Model (`wit`):** Andere WASI-Komponenten sollen Konfigurationen direkt per typisiertem Funktionsaufruf (In-Process) anfordern können, ohne den Overhead von CLI-Subprozessen oder Serialisierung über CLI-Flags.
2. **Fermyon Spin HTTP Service (`wasi:http`):** Bereitstellung als serverloser Micro-Vault-Endpunkt, über den Zielprogramme (z. B. Container, Cloud-Dienste oder lokale Worker) per HTTP-POST Konfigurationen versiegelt abrufen können.

## Entscheidung

1. **WIT-Interface Definition (`wit/config-provider.wit`):**
   Es wird ein WIT World `config-provider` mit dem Interface `wasm-config:provider/reader@0.1.0` definiert:
   - `get-sealed(container-path, section, key, token, env-name) -> result<string, string>`
   - `unseal(sealed-value, client-id, section, key, env-name, client-secret) -> result<string, string>`
2. **Architektur-Trennung:**
   - Der Kern (`wasm_config-mgr`) bleibt das Herzstück für Krypto, INI-Parsing, Autorisierung und Sealing.
   - Die WIT-Bindings werden über `wit-bindgen` exportiert.
   - Der Spin-HTTP-Dienst wird als dedizierter Provider unter `spin/` (oder Workspace-Crate) bereitgestellt und nutzt denselben Kern.
3. **HTTP API Schema:**
   - `POST /v1/config/get`: Nimmt JSON (`section`, `key`, `env_name`, optional `container_path`) mit HTTP Header `Authorization: Bearer <token>` entgegen und antwortet mit JSON (`{ "env_name": "...", "sealed_value": "wcfg-sealed:v1:..." }`).
   - Keine Plaintext-Übertragung: Auch über HTTP wird der Wert stets mit Response Sealing geschützt.

## Konsequenzen

- **Positiv:** Direkte In-Process-Komposition mit anderen WASI-Komponenten via Wasmtime/Component-Model.
- **Positiv:** Standardisiertes HTTP-Interface für Microservice- und Cloud-Architekturen ohne Host-Sicherheitsrisiken.
