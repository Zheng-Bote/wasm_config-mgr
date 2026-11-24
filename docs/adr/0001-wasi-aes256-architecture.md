---
status: accepted
date: 2026-11-24
supersedes: []
references:
  - constitution.md
---

# ADR 0001 — WASI Preview 2 und AES-256-GCM Architektur

## Kontext

Konfigurationsdateien im INI-Format enthalten häufig sensible Zugangsdaten (API-Keys, Datenbank-URLs, Secrets). Wenn mehrere Programme auf dieselbe Konfiguration zugreifen, fehlen bei klassischen Klartext-INI-Dateien oder einfachen `.env`-Dateien sowohl Verschlüsselung im Ruhezustand (Encryption at Rest) als auch eine feingranulare, kryptografisch gesicherte Zugriffskontrolle pro anfragendem Programm. Zudem soll die Lösung portabel und nach dem Capability-Security-Modell in einer WebAssembly System Interface (WASI Preview 2) Sandbox ausführbar sein.

## Entscheidung

1. **Laufzeit & Zielplattform:** Das Programm wird in Rust für WASI Preview 2 entwickelt und nutzt ausschließlich WASI-kompatible Standard-Schnittstellen (CLI-Argumente, Umgebungsvariablen, explizit gemountete Dateisystem-Pfade, `stdout`/`stderr`).
2. **Verschlüsselung & Container-Format:** INI-Dateien werden vollständig mit **AES-256-GCM** (Authenticated Encryption with Associated Data) verschlüsselt. Der 256-Bit-Schlüssel wird entweder direkt als 32-Byte-Schlüssel (Hex/Base64 über ENV oder Keyfile) übergeben oder mittels **Argon2id** und einem zufälligen 128-Bit-Salt aus einer Passphrase abgeleitet. Der Datei-Header (`WCFG` Magic + Version + KDF-Flag + Salt + 96-Bit Nonce) wird als Associated Data (AAD) in den GCM-Tag einbezogen, um Header-Manipulationen auszuschließen.
3. **Autorisierung via Policy-Manifest + Token:** Die verschlüsselte INI-Datei enthält eine reservierte Sektion `[__policy__]`, die für jede Client-ID (`client.<id>.secret` bzw. `client.<id>.pubkey` und `client.<id>.allow`) festlegt, welche `section.key`-Einträge dieser Client abfragen darf. Anfragende Programme authentifizieren sich mit einem kryptografischen Token (`HMAC-SHA256` über `client_id:section:key[:nonce]` oder `Ed25519`-Signatur).
4. **ENV-Bereitstellung:** Nach erfolgreicher Entschlüsselung, Token-Verifikation und Policy-Prüfung gibt das WASI-Modul den angeforderten Eintrag validiert als `ENV_KEY=VALUE` auf `stdout` aus, sodass der aufrufende Prozess oder Host-Wrapper den Wert direkt als Umgebungsvariable importieren kann.

## Konsequenzen

- **Positiv:** Vollständige Vertraulichkeit und Integrität der INI-Datei inkl. der Zugriffsregeln (`[__policy__]`), da das Policy-Manifest selbst im AES-256-GCM-Ciphertext geschützt ist.
- **Positiv:** Keine Hintergrund-Daemons oder Netzwerk-Sockets im WASI-Gast erforderlich; deterministischer CLI-Aufruf nach dem WASI-Capability-Modell.
- **Negativ:** Bei jeder Abfrage muss der Container entschlüsselt werden; bei Verwendung von Argon2id entsteht eine gewollte KDF-Latenz (daher wird für hochfrequente automatisierte Abfragen der direkte 256-Bit-Master-Key unterstützt).
