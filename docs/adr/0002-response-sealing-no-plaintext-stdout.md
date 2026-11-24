---
status: accepted
date: 2026-11-24
supersedes: []
references:
  - constitution.md
  - docs/adr/0001-wasi-aes256-architecture.md
---

# ADR 0002 — Ende-zu-Ende Response Sealing gegen Klartext auf stdout

## Kontext

In ADR 0001 wurde festgelegt, dass `wasm_config-mgr` nach erfolgreicher Autorisierung den angeforderten Konfigurationseintrag als `ENV_KEY=VALUE` auf `stdout` ausgibt. Wenn `VALUE` jedoch im Klartext auf `stdout` erscheint (z. B. `DATABASE_PASSWORD=s3cr3t_db_p@ssw0rd!`), besteht das Risiko, dass das Geheimnis in Terminal-Logs, CI/CD-Konsolenausgaben, Shell-Histories oder Prozess-Traces im Klartext mitgelesen wird.

## Entscheidung

1. **Kein Klartext auf `stdout` (Response Sealing als Standard):**
   Der `get`-Befehl verschlüsselt den angeforderten Konfigurationswert standardmäßig Ende-zu-Ende für das anfragende Client-Programm mittels **AES-256-GCM** (*Response Sealing*). Auf `stdout` wird ausschließlich das versiegelte Token ausgegeben:
   ```text
   ENV_NAME=wcfg-sealed:v1:<nonce_hex>:<ciphertext_and_tag_hex>
   ```
   bzw. bei asymmetrischen Ed25519-Clients mit ephemerem Diffie-Hellman (Curve25519):
   ```text
   ENV_NAME=wcfg-sealed:v1:ed25519:<ephemeral_R_hex>:<nonce_hex>:<ciphertext_and_tag_hex>
   ```
2. **Schlüsselableitung & AAD-Bindung:**
   - **HMAC-Clients:** Der 256-Bit-Response-Key wird per `HMAC-SHA256(client_hmac_secret, "wasm-config-mgr:seal-key:v1:" || client_id || ":" || section || ":" || key || ":" || env_name)` abgeleitet.
   - **Ed25519-Clients:** Aus dem hinterlegten `ed25519_pubkey` des Clients (Edwards-Punkt $A$) und einem zufälligen ephemeren Skalar $r$ berechnet `wasm_config-mgr` den ephemeren Punkt $R = r \cdot B$ sowie das gemeinsame Geheimnis $S = r \cdot A$. Der Client berechnet mit seinem aus dem Ed25519-Seed abgeleiteten geheimen Skalar $a$ denselben Punkt $S = a \cdot R$. Daraus wird über SHA-256 der 256-Bit-AES-GCM-Schlüssel abgeleitet.
   - **Associated Data (AAD):** Als AAD wird `wasm-config-mgr:seal-aad:v1:<client_id>:<section>:<key>:<env_name>` in den AES-256-GCM-Tag gebunden, sodass ein versiegelter Wert weder einem anderen Client noch einer anderen Umgebungsvariable untergeschoben werden kann.
3. **Entsiegelung im Zielprogramm (`unseal_env_value`):**
   Das autorisierte Zielprogramm liest die versiegelte Umgebungsvariable `ENV_NAME` aus seiner Prozessumgebung und entschlüsselt sie erst direkt in seinem eigenen Arbeitsspeicher (`Zeroizing<String>`) mit seinem Client-Secret bzw. Ed25519-Private-Key.

## Konsequenzen

- **Positiv:** Auf `stdout`, in Shell-Pipelines (`eval`, `env`) und selbst in `ps e` / `/proc/<pid>/environ` steht ausschließlich der AES-256-GCM-versiegelte Wert (`wcfg-sealed:v1:...`). Kein Dritter ohne das Client-Secret bzw. den privaten Ed25519-Schlüssel des Clients kann den Wert entschlüsseln.
- **Positiv:** Aktualisiert Security-Regel 4 der Verfassung (`constitution.md`), sodass `get` standardmäßig niemals Klartext-Geheimnisse auf `stdout` ausgibt.
