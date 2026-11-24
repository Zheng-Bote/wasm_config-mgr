---
feature: wasm-config-mgr
status: approved
archive-after: 2027-01-01
touches:
  - src/**
  - tests/**
  - Cargo.toml
  - Example/**
  - README_de.md
---

# PRD — WASI AES-256 INI Config Manager (`wasm-config-mgr`)

## Problem

Anwendungen benötigen häufig einzelne Konfigurationswerte oder Geheimnisse aus zentralen INI-Dateien. Liegen diese INI-Dateien unverschlüsselt im Dateisystem oder werden komplett in die Umgebung geladen, erhält jedes Programm Zugriff auf sämtliche Einträge (Verletzung des Least-Privilege-Prinzips). Zudem dürfen Geheimnisse bei der Übergabe über `stdout` oder Umgebungsvariablen nicht im Klartext in Logs, Terminals oder Prozesslisten (`ps e`) exponiert werden. Es fehlt ein leichtgewichtiges, sandboxfähiges WASI-Werkzeug, das INI-Dateien mit AES-256 verschlüsselt und einzelne Einträge nur nach kryptografischer Autorisierung gezielt und Ende-zu-Ende versiegelt (`wcfg-sealed:v1:...`) als Umgebungsvariable herausgibt.

## Ziel

Ein in Rust geschriebenes WASI-Preview-2-Programm (`wasm_config-mgr`), das:
1. Klartext-INI-Dateien inklusive eingebettetem Policy-Manifest (`[__policy__]`) mittels AES-256-GCM verschlüsselt (`encrypt`) und bei Bedarf vollständig entschlüsselt (`decrypt`).
2. Kryptografische Zugriffs-Tokens für autorisierte Client-Programme erzeugt (`token`) und verifiziert.
3. Auf Anfrage (`get`) eines anderen Programms dessen Zugriffs-Token und Berechtigung für `section.key` prüft und bei Erfolg den Eintrag standardmäßig Ende-zu-Ende für diesen Client mit AES-256-GCM versiegelt (`ENV_KEY=wcfg-sealed:v1:...`) auf `stdout` ausgibt, sodass niemals Klartext auf `stdout` erscheint.
4. Dem empfangenden Programm das Entschlüsseln (`unseal`) des versiegelten ENV-Werts in dessen eigenem Speicher ermöglicht.

## Nutzer

- **DevSecOps / Plattform-Ingenieure**, die Konfigurationsdateien samt Zugriffsregeln sicher verschlüsseln und verteilen.
- **Autorisierte Zielprogramme / WASI-Hosts**, die zur Laufzeit einzelne Konfigurationswerte über ein Zugriffs-Token anfordern und als versiegelte ENV-Variable konsumieren und im eigenen Speicher entsiegeln.

## Umfang

- INI-Parser mit Unterstützung für Sektionen (`[section]`), Schlüssel-Wert-Paare (`key = value`), Kommentare (`#`, `;`) und die reservierte Sektion `[__policy__]`.
- AES-256-GCM-Verschlüsselung und -Entschlüsselung mit Authentifizierung des Binärheaders (AAD) sowie Schlüsselableitung über Argon2id (Passphrase) oder direktem 256-Bit-Master-Key (Hex/Base64 via ENV `WASM_CONFIG_MASTER_KEY` oder Keyfile).
- Autorisierungssystem auf Basis von Client-Policies in `[__policy__]` (erlaubte `section.key`-Muster inkl. Wildcards wie `database.*`) und kryptografischen Tokens (SHA-256-basiertes Message Authentication Verfahren sowie Ed25519).
- Ende-zu-Ende Response Sealing (`wcfg-sealed:v1:...`) des angeforderten Eintrags als `ENV_NAME=wcfg-sealed:v1:...` auf `stdout` mit Validierung des Variablennamens und kontextgebundenem AAD (`client_id`, `section`, `key`, `env_name`).

## Nicht-Ziele

- Kein dauerhaft laufender Netzwerk-Server oder HTTP-Daemon (reines WASI-CLI-/Command-Modell).
- Keine Verwaltung externer KMS-/HSM-Clouddienste innerhalb des WASI-Moduls.

## Akzeptanzkriterien

- **AC-1** Das Programm parst valide INI-Dateien mit Sektionen, Schlüssel-Wert-Paaren, Kommentaren (`#`, `;`) und Quotings fehlerfrei und lehnt syntaktisch ungültige INI-Dateien mit einem Fehlercode ab.
- **AC-2** Das Programm verschlüsselt eine INI-Datei mit AES-256-GCM (wahlweise mit 256-Bit-Raw-Key oder Argon2id-Passphrase) in ein binäres Containerformat mit authentifiziertem Header (AAD) und kann sie mit dem korrekten Schlüssel verlustfrei wieder entschlüsseln.
- **AC-3** Manipulierte Ciphertexte, veränderte Header-Bytes oder falsche Entschlüsselungsschlüssel werden durch AES-256-GCM zuverlässig erkannt und führen zum sofortigen Abbruch ohne Klartextausgabe.
- **AC-4** Ein autorisiertes Programm mit gültigem kryptografischem Token (HMAC-SHA256 oder Ed25519) und passender Freigabe im `[__policy__]`-Manifest erhält bei einer `get`-Anfrage für `section` und `key` den Umgebungsvariablen-Eintrag (`ENV_KEY=...`) auf `stdout`, während der Klartextwert standardmäßig nicht auf `stdout` im Klartext erscheint.
- **AC-5** Anfragen mit ungültigem/gefälschtem Token, unbekannter Client-ID oder für einen laut `[__policy__]` nicht freigegebenen `section.key`-Eintrag werden strikt abgewiesen (Exit-Code != 0, keine Ausgabe auf `stdout`).
- **AC-6** Das Programm verhindert den direkten Abruf von internen Einträgen aus der `[__policy__]`-Sektion über den `get`-Befehl und validiert den Ziel-Umgebungsvariablennamen strikt auf `[A-Z0-9_]+`.
- **AC-7** Der `get`-Befehl gibt den angeforderten Konfigurationswert standardmäßig Ende-zu-Ende versiegelt (`ENV_KEY=wcfg-sealed:v1:...`) aus, sodass auf `stdout` kein Klartext steht und nur der autorisierte Client (mit seinem HMAC-Secret oder Ed25519-Private-Key und passendem Kontext) den Wert entsiegeln (`unseal`) kann.
