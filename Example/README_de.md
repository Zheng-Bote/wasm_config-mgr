# Praxisbeispiel: Datenbank-Konfiguration mit Python & `wasm_config-mgr`

Dieses Verzeichnis ([`./Example`](.)) enthält ein vollständiges, ausführbares Beispiel für das Zusammenspiel zwischen einer AES-256-GCM-verschlüsselten INI-Datei, dem WASI-Modul `wasm_config-mgr` und einem autorisierten Python-Programm.

---

## Enthaltene Dateien

| Datei | Beschreibung |
| :--- | :--- |
| [`db_config.ini`](db_config.ini) | Beispiel-Konfigurationsdatei mit `[__policy__]`-Manifest, `[database]`-Zugangsdaten und einer gesperrten `[admin]`-Sektion. |
| [`query_db_config.py`](query_db_config.py) | Autorisiertes Python-Client-Skript (`client_id = python_db_app`), das die INI-Datei verschlüsselt, die DB-Einträge Ende-zu-Ende versiegelt abruft und direkt im Python-RAM entsiegelt. |

---

## Sicherheitsablauf im Beispiel

```mermaid
sequenceDiagram
    participant Py as query_db_config.py<br/>(Client: python_db_app)
    participant WASI as wasm_config-mgr<br/>(WASI / Native)
    participant FS as db_config.wcfg<br/>(AES-256-GCM Container)

    Note over Py,FS: 1. Initiale Verschlüsselung
    Py->>WASI: encrypt --input db_config.ini --output db_config.wcfg
    WASI->>FS: Schreibt Header (AAD) + AES-256-GCM Ciphertext

    Note over Py,WASI: 2. Autorisierte Abfrage (für host, port, name, user, password, ssl_mode)
    Py->>Py: Berechnet Request-Token:<br/>HMAC-SHA256(client_secret, "wasm-config-mgr:v1:python_db_app:database:password")
    Py->>WASI: get --section database --key password --token hmac:python_db_app:<sig> --env-name DB_PASSWORD
    WASI->>FS: Liest & entschlüsselt db_config.wcfg
    WASI->>WASI: Prüft HMAC-Signatur & Policy (allow = database.*)
    WASI->>WASI: Versiegelt Antwort mit Client-Key + AAD (DB_PASSWORD)
    WASI-->>Py: stdout: DB_PASSWORD=wcfg-sealed:v1:hmac:<nonce>:<ciphertext_tag>

    Note over Py: 3. Speicherung & In-Memory-Entsiegelung
    Py->>Py: os.environ["DB_PASSWORD"] = "wcfg-sealed:v1:hmac:..." (Kein Klartext in ENV!)
    Py->>Py: unseal_in_memory_python("DB_PASSWORD", "database", "password")<br/>Leitet Seal-Key ab, prüft AAD und entschlüsselt direkt im RAM
```

---

## 1. Die Beispiel-INI (`db_config.ini`)

In [`db_config.ini`](db_config.ini) sind zwei Clients mit unterschiedlichen Rechten definiert:

- **`python_db_app`**: Darf über die Wildcard-Regel `database.*` alle Schlüssel der Sektion `[database]` abfragen, hat aber **keinen** Zugriff auf `[admin]`.
- **`reporting_worker`**: Darf ausschließlich `database.host` und `database.port` lesen (kein Zugriff auf `database.password`).

```ini
[__policy__]
client.python_db_app.hmac_secret = 4f8b2c19a7d3e605112233445566778899aabbccddeeff00123456789abcdef0
client.python_db_app.allow = database.*

client.reporting_worker.hmac_secret = 99887766554433221100ffeeddccbbaa99887766554433221100ffeeddccbbaa
client.reporting_worker.allow = database.host, database.port

[database]
host = "pg-prod.internal.example.org"
port = 5432
name = "orders_production"
user = "app_orders_rw"
password = "DB_S3cr3t_P@ssw0rd_2026!#99"
ssl_mode = "verify-full"

[admin]
root_api_token = "adm_live_top_secret_token_do_not_expose"
```

---

## 2. Ausführung des Python-Skripts

Starte das Skript aus dem Hauptverzeichnis des Projekts:

```bash
python3 Example/query_db_config.py
```

> [!TIP]
> Falls `wasmtime` installiert ist und `target/wasm32-wasip2/release/wasm_config-mgr.wasm` gebaut wurde, führt das Skript das WASI-Preview-2-Modul automatisch in der `wasmtime`-Sandbox (mit `--dir=Example`) aus. Andernfalls nutzt es automatisch das kompilierte native Rust-Binary.

### Beispielausgabe

```text
[*] Verwende Runner: /.../target/debug/wasm_config-mgr
[*] 1. Verschlüssele db_config.ini -> db_config.wcfg (AES-256-GCM)...
    Container erzeugt (1703 Bytes, Header-Magic: b'WCFG')

[*] 2. Frage Datenbank-Konfiguration als Client 'python_db_app' ab (Ende-zu-Ende versiegelt):
    stdout -> DB_HOST=wcfg-sealed:v1:hmac:4ed3b13b046a25795645c979:f3104ae82320f0756f77002f2b032031f8162d5e3d7d9654ec97851554279a74d158a7b97baca0e3ef91a8f9
    stdout -> DB_PORT=wcfg-sealed:v1:hmac:14f803f8f12a4649e19de417:771a49109abaad36205f754c83468b28d6734473
    stdout -> DB_NAME=wcfg-sealed:v1:hmac:b6a5ccb0c2f545022d7bc503:de179d84be3bf41c581e48e588bebd87ba7a7be179e5359a09d5b4597f287991fc
    stdout -> DB_USER=wcfg-sealed:v1:hmac:8baaf96a55884bfb6422e5be:65fc421b3e7b14e7d9b2452c6d33882be9e33a9e45c6eba0ef47200eee
    stdout -> DB_PASSWORD=wcfg-sealed:v1:hmac:7684ef10d3b789271a435d92:7522b2673a0d91df9ffa491207232dc677cdc884acc7c7665f4cf8bf504556768febb2bcf650a487b7dfa7
    stdout -> DB_SSL_MODE=wcfg-sealed:v1:hmac:dcada0b964969b5029b411c4:bea57d346ceffe943dd7e15fc1522c7947e5d9f61ce2d7b3322414

[*] 3. Prüfe Prozess-Umgebung (os.environ['DB_PASSWORD']):
    os.environ['DB_PASSWORD'] = wcfg-sealed:v1:hmac:7684ef10d3b789271a435d92:7522b2673a0d91df9ffa491207232dc677cdc884acc7c7665f4cf8bf504556768febb2bcf650a487b7dfa7  (Kein Klartext in ENV!)

[*] 4. Entsiegle Datenbank-Konfiguration direkt im Python-RAM (AES-256-GCM In-Memory):
    Host     : pg-prod.internal.example.org
    Port     : 5432
    Database : orders_production
    User     : app_orders_rw
    Password : DB_S*********************** (erfolgreich im Speicher entsiegelt)
    DSN      : postgresql://app_orders_rw:***MASKED***@pg-prod.internal.example.org:5432/orders_production?sslmode=verify-full

[*] 5. Negativ-Test: Client 'python_db_app' versucht unberechtigt [admin] root_api_token abzufragen...
    Erwartetermaßen abgelehnt (Exit-Code 1): error: authorization error: client `python_db_app` is not permitted to access `admin.root_api_token`
```

---

## 3. Wie die In-Memory-Entsiegelung in Python funktioniert

In [`query_db_config.py`](query_db_config.py) zeigt die Funktion `unseal_in_memory_python()`, wie ein Zielprogramm das versiegelte Format `wcfg-sealed:v1:hmac:<nonce_hex>:<ciphertext_hex>` ohne zusätzlichen Subprozess direkt im Arbeitsspeicher entschlüsselt:

1. **Sealing-Key ableiten (256 Bit):**
   ```python
   key_info = f"wasm-config-mgr:seal-key:v1:{client_id}:{section}:{key}:{env_name}".encode("utf-8")
   seal_key = hmac.new(secret_bytes, key_info, hashlib.sha256).digest()
   ```
2. **Associated Data (AAD) zur Kontext-Verifikation konstruieren:**
   ```python
   aad = f"wasm-config-mgr:seal-aad:v1:{client_id}:{section}:{key}:{env_name}".encode("utf-8")
   ```
3. **AES-256-GCM im Speicher entschlüsseln:**
   ```python
   plaintext = AESGCM(seal_key).decrypt(nonce, ciphertext, aad).decode("utf-8")
   ```

Dadurch ist sichergestellt, dass das Klartext-Passwort zu keinem Zeitpunkt über `stdout`, eine Shell oder `os.environ` übertragen wird.
