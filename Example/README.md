# Practical Example: Database Configuration with Python & `wasm_config-mgr`

This directory ([`./Example`](.)) contains a complete, runnable example demonstrating the interaction between an AES-256-GCM encrypted INI file, the `wasm_config-mgr` WASI module, and an authorized Python application.

---

## Included Files

| File | Description |
| :--- | :--- |
| [`db_config.ini`](db_config.ini) | Example configuration file containing the `[__policy__]` manifest, `[database]` credentials, and a restricted `[admin]` section. |
| [`query_db_config.py`](query_db_config.py) | Authorized Python client script (`client_id = python_db_app`) that encrypts the INI file, retrieves DB entries end-to-end sealed, and unseals them directly in Python process memory. |

---

## Security Sequence in this Example

```mermaid
sequenceDiagram
    participant Py as query_db_config.py<br/>(Client: python_db_app)
    participant WASI as wasm_config-mgr<br/>(WASI / Native)
    participant FS as db_config.wcfg<br/>(AES-256-GCM Container)

    Note over Py,FS: 1. Initial Encryption
    Py->>WASI: encrypt --input db_config.ini --output db_config.wcfg
    WASI->>FS: Writes header (AAD) + AES-256-GCM ciphertext

    Note over Py,WASI: 2. Authorized Query (for host, port, name, user, password, ssl_mode)
    Py->>Py: Computes Request Token:<br/>HMAC-SHA256(client_secret, "wasm-config-mgr:v1:python_db_app:database:password")
    Py->>WASI: get --section database --key password --token hmac:python_db_app:<sig> --env-name DB_PASSWORD
    WASI->>FS: Reads & decrypts db_config.wcfg
    WASI->>WASI: Verifies HMAC signature & policy (allow = database.*)
    WASI->>WASI: Seals response using client key + AAD (DB_PASSWORD)
    WASI-->>Py: stdout: DB_PASSWORD=wcfg-sealed:v1:hmac:<nonce>:<ciphertext_tag>

    Note over Py: 3. Storage & In-Memory Unsealing
    Py->>Py: os.environ["DB_PASSWORD"] = "wcfg-sealed:v1:hmac:..." (No plaintext in ENV!)
    Py->>Py: unseal_in_memory_python("DB_PASSWORD", "database", "password")<br/>Derives seal key, verifies AAD, and decrypts directly in RAM
```

---

## 1. The Example INI (`db_config.ini`)

In [`db_config.ini`](db_config.ini), two clients with different access privileges are configured:

- **`python_db_app`**: Granted full access to all keys under `[database]` via `allow = database.*`, but has **no** access to `[admin]`.
- **`reporting_worker`**: Granted read access only to `database.host` and `database.port` (cannot read `database.password`).

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

## 2. Running the Python Script

Execute the script from the project root:

```bash
python3 Example/query_db_config.py
```

> [!TIP]
> If `wasmtime` is installed and `target/wasm32-wasip2/release/wasm_config-mgr.wasm` is built, the script automatically executes the WASI Preview 2 module inside the `wasmtime` sandbox (with `--dir=Example`). Otherwise, it seamlessly falls back to the compiled native binary.

### Example Output

```text
[*] Using runner: /.../target/debug/wasm_config-mgr
[*] 1. Encrypting db_config.ini -> db_config.wcfg (AES-256-GCM)...
    Container created (1703 bytes, Header Magic: b'WCFG')

[*] 2. Querying database configuration as client 'python_db_app' (end-to-end sealed):
    stdout -> DB_HOST=wcfg-sealed:v1:hmac:4ed3b13b046a25795645c979:f3104ae82320f0756f77002f2b032031f8162d5e3d7d9654ec97851554279a74d158a7b97baca0e3ef91a8f9
    stdout -> DB_PORT=wcfg-sealed:v1:hmac:14f803f8f12a4649e19de417:771a49109abaad36205f754c83468b28d6734473
    stdout -> DB_NAME=wcfg-sealed:v1:hmac:b6a5ccb0c2f545022d7bc503:de179d84be3bf41c581e48e588bebd87ba7a7be179e5359a09d5b4597f287991fc
    stdout -> DB_USER=wcfg-sealed:v1:hmac:8baaf96a55884bfb6422e5be:65fc421b3e7b14e7d9b2452c6d33882be9e33a9e45c6eba0ef47200eee
    stdout -> DB_PASSWORD=wcfg-sealed:v1:hmac:7684ef10d3b789271a435d92:7522b2673a0d91df9ffa491207232dc677cdc884acc7c7665f4cf8bf504556768febb2bcf650a487b7dfa7
    stdout -> DB_SSL_MODE=wcfg-sealed:v1:hmac:dcada0b964969b5029b411c4:bea57d346ceffe943dd7e15fc1522c7947e5d9f61ce2d7b3322414

[*] 3. Inspecting process environment (os.environ['DB_PASSWORD']):
    os.environ['DB_PASSWORD'] = wcfg-sealed:v1:hmac:7684ef10d3b789271a435d92:7522b2673a0d91df9ffa491207232dc677cdc884acc7c7665f4cf8bf504556768febb2bcf650a487b7dfa7  (No plaintext in ENV!)

[*] 4. Unsealing database configuration directly in Python RAM (AES-256-GCM in-memory):
    Host     : pg-prod.internal.example.org
    Port     : 5432
    Database : orders_production
    User     : app_orders_rw
    Password : DB_S*********************** (successfully unsealed in memory)
    DSN      : postgresql://app_orders_rw:***MASKED***@pg-prod.internal.example.org:5432/orders_production?sslmode=verify-full

[*] 5. Negative test: Client 'python_db_app' unauthorized attempt to read [admin] root_api_token...
    Expectedly rejected (Exit Code 1): error: authorization error: client `python_db_app` is not permitted to access `admin.root_api_token`
```

---

## 3. How In-Memory Unsealing Works in Python

In [`query_db_config.py`](query_db_config.py), the function `unseal_in_memory_python()` shows how a target program decrypts the sealed format `wcfg-sealed:v1:hmac:<nonce_hex>:<ciphertext_hex>` directly in RAM without a subprocess:

1. **Derive Response Sealing Key (256-bit):**
   ```python
   key_info = f"wasm-config-mgr:seal-key:v1:{client_id}:{section}:{key}:{env_name}".encode("utf-8")
   seal_key = hmac.new(secret_bytes, key_info, hashlib.sha256).digest()
   ```
2. **Construct Associated Data (AAD) for Context Verification:**
   ```python
   aad = f"wasm-config-mgr:seal-aad:v1:{client_id}:{section}:{key}:{env_name}".encode("utf-8")
   ```
3. **Decrypt AES-256-GCM in Memory:**
   ```python
   plaintext = AESGCM(seal_key).decrypt(nonce, ciphertext, aad).decode("utf-8")
   ```

This guarantees that plaintext secrets never travel through `stdout`, shells, or `os.environ`.
