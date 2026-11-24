---
status: active
---

# Verfassung — wasm_config-mgr

Diese Verfassung enthält die systemweiten, dauerhaften Regeln des Projekts. Feature-Inhalte (User Stories, Tasklisten, Planung) gehören in PRD, Tech Spec und Plan. Jede Änderung einer Regel verweist auf ein ADR unter `docs/adr`.

## Architektur/Layering

1. Das System ist in vier klar getrennte Schichten unterteilt (`docs/adr/0001-wasi-aes256-architecture.md`, `docs/adr/0003-wit-component-and-spin-http-provider.md`):
   - `src/ini`: Reines Parsing, Validierung und Serialisierung von INI-Konfigurationsdaten und Policy-Sektionen ohne I/O- oder Krypto-Abhängigkeiten.
   - `src/crypto`: Authentifizierte Verschlüsselung (AES-256-GCM), Schlüsselableitung (Argon2id / Raw-256-Bit-Key) für Container-Dateien sowie Ende-zu-Ende Response Sealing (`docs/adr/0002-response-sealing-no-plaintext-stdout.md`). Darf nicht von `src/auth` oder `src/cli` abhängen.
   - `src/auth`: Verifikation von Zugriffs-Tokens (HMAC-SHA256 / Ed25519) und Auswertung des in der verschlüsselten Datei eingebetteten Policy-Manifests (`[__policy__]`).
   - `src/cli`, `src/provider`, `spin`: Bereitstellungsschichten (WASI-CLI-Interface, WIT Component Model Export und Spin HTTP Endpunkt).

## Security

1. Alle Konfigurationsdateien im Ruhezustand müssen mit AES-256-GCM (96-Bit Nonce, 128-Bit Authentication Tag) verschlüsselt und integritätsgeschützt sein (`docs/adr/0001-wasi-aes256-architecture.md`).
2. Kein Konfigurationswert darf ohne vorherige kryptografische Prüfung des Aufrufer-Tokens gegen das in der verschlüsselten Datei enthaltene Policy-Manifest ausgegeben werden (Fail-Closed-Prinzip).
3. Sensible Schlüsselmaterialien im Arbeitsspeicher sind nach Gebrauch zu nullen (`zeroize`), und Fehlermeldungen dürfen niemals Klartext-Geheimnisse oder kryptografische Schlüssel enthalten.
4. Ausgegebene Umgebungsvariablen (`KEY=VALUE`) müssen strikt gegen Zeilenumbrüche und Shell-Injection-Zeichen im Schlüsselnamen validiert werden (`^[A-Z0-9_]+$`) und ihre Werte standardmäßig mit dem Schlüssel des anfragenden Clients Ende-zu-Ende versiegelt (`wcfg-sealed:v1:...`) ausgeben, sodass kein Klartext auf `stdout` oder im HTTP-Body erscheint (`docs/adr/0002-response-sealing-no-plaintext-stdout.md`, `docs/adr/0003-wit-component-and-spin-http-provider.md`).

## Strikte Regeln

1. Jedes Akzeptanzkriterium (`AC-n`) im PRD muss durch mindestens einen automatisierten Test (`// <slug> AC-<n>: ...`) abgedeckt und verifiziert sein.
2. Der Code muss sowohl nativ (`cargo test`) als auch für WASI Preview 2 (`wasm32-wasip2` / `wasm32-wasip1`) warnungsfrei kompilieren.
