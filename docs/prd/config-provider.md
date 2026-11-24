---
feature: config-provider
status: approved
archive-after: 2027-01-01
touches:
  - wit/**
  - spin/**
  - src/**
  - tests/**
  - Cargo.toml
  - Cargo.lock
  - Example/**
  - README.md
  - README_de.md
  - .github/**
---

# PRD — WASI Component Model Interface and Spin HTTP Service (`config-provider`)

## Problem

Bislang kann `wasm_config-mgr` nur als eigenständiges CLI-Kommando (Subprozess über CLI-Argumente und `stdout`) aufgerufen werden. Wenn andere WebAssembly-Komponenten Konfigurationswerte benötigen, erzeugt ein CLI-Subprozess unnötigen Overhead und erfordert Host-seitiges Prozess-Spawning. Ebenso fehlt für Web-Services und Microservice-Architekturen eine standardisierte HTTP-Schnittstelle, über die autorisierte Clients versiegelte Konfigurationswerte per REST/JSON abfragen können.

## Ziel

1. **WIT Component Model Export (Schritt 1):** Bereitstellung einer standardisierten WIT-Schnittstelle (`wasm-config:provider/reader@0.1.0`), sodass jede WASI Preview 2 Komponente (In-Process) versiegelte Konfigurationseinträge typisiert abrufen und entsiegeln kann.
2. **Fermyon Spin HTTP Service (Schritt 2):** Bereitstellung eines Spin-kompatiblen Micro-Vault-HTTP-Dienstes (`wasi:http`), der unter `/v1/config/get` autorisierte Anfragen entgegennimmt und versiegelte Antworten im JSON-Format ausliefert.

## Nutzer

- **WASI Component Developer**, die in Rust, Go, Python oder JavaScript modulare WASI Preview 2 Komponenten bauen und In-Process Konfigurationswerte beziehen wollen.
- **Microservice- & Cloud-Entwickler**, die Spin-Services oder Container betreiben und Secrets sicher über lokale HTTP-Endpunkte beziehen möchten.

## Umfang

- WIT-Definition unter `wit/config-provider.wit`.
- Rust-Export des WIT-Interfaces in `src/provider/mod.rs` via `wit-bindgen`.
- Spin-HTTP-Komponente unter `spin/` mit `spin.toml` und HTTP-Request-Handler für `POST /v1/config/get`.
- Automatisierte Tests für WIT-Provider und HTTP-Handler.

## Nicht-Ziele

- Keine Ablösung des bestehenden CLI-Tools (CLI bleibt vollständig erhalten).
- Keine Speicherung von Zuständen im HTTP-Service (stateless per Request).

## Akzeptanzkriterien

- **AC-1** Das WIT-Interface `wasm-config:provider/reader@0.1.0` wird definiert und exportiert Funktionen `get-sealed` und `unseal`.
- **AC-2** Die WIT-Funktion `get-sealed` validiert den Zugriff gegen Token und Policy und gibt den Wert Ende-zu-Ende versiegelt (`wcfg-sealed:v1:...`) zurück; unautorisierte Zugriffe liefern einen Fehler.
- **AC-3** Der Spin-HTTP-Endpunkt verarbeitet `POST /v1/config/get` mit `Authorization: Bearer <token>` und JSON-Body und antwortet mit HTTP 200 und JSON `{ "env_name": "...", "sealed_value": "..." }`.
- **AC-4** Der Spin-HTTP-Endpunkt lehnt ungültige Tokens oder unautorisierte Schlüssel mit HTTP 401/403 und einer JSON-Fehlermeldung ohne Klartext-Leaks ab.
