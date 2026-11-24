#!/usr/bin/env python3
"""
Example script: Authorized retrieval of an AES-256-GCM encrypted
database configuration from `Example/db_config.ini` via `wasm_config-mgr`.

Flow:
1. Encrypts `Example/db_config.ini` -> `Example/db_config.wcfg` using a 256-bit master key.
2. The Python script acts as the authorized client `python_db_app` (with its own HMAC secret).
3. For each requested DB parameter (`host`, `port`, `name`, `user`, `password`, `ssl_mode`),
   the script calculates the HMAC-SHA256 request token locally in Python:
       HMAC-SHA256(client_secret, "wasm-config-mgr:v1:<client_id>:<section>:<key>")
4. It invokes `wasm_config-mgr get`. Plaintext NEVER appears on stdout; instead,
   only the end-to-end sealed ENV assignment (`DB_PASSWORD=wcfg-sealed:v1:hmac:...`) is emitted.
5. The script sets the sealed ENV variable in `os.environ` and unseals the value
   only when needed directly in working memory.
6. In addition, an unauthorized query for `[admin] root_api_token` (not in
   `client.python_db_app.allow`) is demonstrated to be strictly rejected.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import shutil
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

EXAMPLE_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = EXAMPLE_DIR.parent
INI_FILE = EXAMPLE_DIR / "db_config.ini"
WCFG_FILE = EXAMPLE_DIR / "db_config.wcfg"

# 256-bit AES-GCM master key for the container (64 hex characters = 32 bytes)
MASTER_KEY_HEX = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

# Client identity and secret 256-bit HMAC key (matches [__policy__] in db_config.ini)
CLIENT_ID = "python_db_app"
CLIENT_HMAC_SECRET_HEX = "4f8b2c19a7d3e605112233445566778899aabbccddeeff00123456789abcdef0"


@dataclass(frozen=True)
class DatabaseConfig:
    host: str
    port: int
    name: str
    user: str
    password: str
    ssl_mode: str

    def masked_dsn(self) -> str:
        return (
            f"postgresql://{self.user}:***MASKED***@"
            f"{self.host}:{self.port}/{self.name}?sslmode={self.ssl_mode}"
        )


def resolve_runner_cmd() -> list[str]:
    """
    Uses `wasmtime` with the compiled WASI Preview 2 module (`wasm32-wasip2`)
    if `wasmtime` is installed; otherwise falls back to the compiled Rust binary.
    """
    wasm_path = PROJECT_ROOT / "target" / "wasm32-wasip2" / "release" / "wasm_config-mgr.wasm"
    if shutil.which("wasmtime") and wasm_path.exists():
        return [
            "wasmtime",
            "run",
            f"--dir={EXAMPLE_DIR}",
            "--env",
            "WASM_CONFIG_MASTER_KEY",
            str(wasm_path),
        ]

    for profile in ("release", "debug"):
        native_bin = PROJECT_ROOT / "target" / profile / "wasm_config-mgr"
        if native_bin.exists():
            return [str(native_bin)]

    return ["cargo", "run", "--quiet", "--manifest-path", str(PROJECT_ROOT / "Cargo.toml"), "--"]


def create_hmac_request_token(client_id: str, section: str, key: str, secret_hex: str) -> str:
    """
    Generates the cryptographic access token directly using Python standard library:
    `hmac:<client_id>:<hex_signature>` over `wasm-config-mgr:v1:<client_id>:<section>:<key>`.
    """
    secret_bytes = bytes.fromhex(secret_hex)
    canonical_msg = f"wasm-config-mgr:v1:{client_id}:{section}:{key}".encode("utf-8")
    signature = hmac.new(secret_bytes, canonical_msg, hashlib.sha256).hexdigest()
    return f"hmac:{client_id}:{signature}"


def encrypt_ini_container(runner: list[str], env: dict[str, str]) -> None:
    """Encrypts `Example/db_config.ini` to `Example/db_config.wcfg` (AES-256-GCM)."""
    cmd = [
        *runner,
        "encrypt",
        "--input",
        str(INI_FILE),
        "--output",
        str(WCFG_FILE),
    ]
    subprocess.run(cmd, env=env, check=True, text=True, capture_output=True)


def fetch_sealed_env_entry(
    runner: list[str],
    env: dict[str, str],
    section: str,
    key: str,
    env_name: str,
) -> str:
    """
    Queries an entry with a signed HMAC token.
    Returns the sealed assignment `<ENV_NAME>=wcfg-sealed:v1:hmac:...`.
    """
    token = create_hmac_request_token(CLIENT_ID, section, key, CLIENT_HMAC_SECRET_HEX)
    cmd = [
        *runner,
        "get",
        "--input",
        str(WCFG_FILE),
        "--section",
        section,
        "--key",
        key,
        "--token",
        token,
        "--env-name",
        env_name,
    ]
    result = subprocess.run(cmd, env=env, check=True, text=True, capture_output=True)
    stdout_line = result.stdout.strip()

    # Store sealed value in process environment (os.environ contains no plaintext!)
    var_name, sealed_val = stdout_line.split("=", 1)
    os.environ[var_name] = sealed_val
    return stdout_line


def unseal_in_memory_python(
    env_name: str,
    section: str,
    key: str,
    client_id: str = CLIENT_ID,
    secret_hex: str = CLIENT_HMAC_SECRET_HEX,
) -> str:
    """
    Unseals the `wcfg-sealed:v1:hmac:...` value stored in `os.environ[env_name]`
    completely in Python process memory (without subprocess and without stdout!).
    """
    sealed_val = os.environ[env_name]
    prefix = "wcfg-sealed:v1:hmac:"
    if not sealed_val.startswith(prefix):
        raise ValueError(f"Invalid sealed format for {env_name}")

    nonce_hex, cipher_hex = sealed_val[len(prefix) :].split(":", 1)
    nonce = bytes.fromhex(nonce_hex)
    ciphertext = bytes.fromhex(cipher_hex)

    # 1. Derive 256-bit response sealing key via HMAC-SHA256
    secret_bytes = bytes.fromhex(secret_hex)
    key_info = f"wasm-config-mgr:seal-key:v1:{client_id}:{section}:{key}:{env_name}".encode("utf-8")
    seal_key = hmac.new(secret_bytes, key_info, hashlib.sha256).digest()

    # 2. Verify AAD (context binding) and decrypt AES-256-GCM in RAM
    aad = f"wasm-config-mgr:seal-aad:v1:{client_id}:{section}:{key}:{env_name}".encode("utf-8")
    plaintext_bytes = AESGCM(seal_key).decrypt(nonce, ciphertext, aad)
    return plaintext_bytes.decode("utf-8")


def main() -> int:
    runner = resolve_runner_cmd()
    base_env = os.environ.copy()
    base_env["WASM_CONFIG_MASTER_KEY"] = MASTER_KEY_HEX

    print(f"[*] Using runner: {' '.join(runner)}")
    print(f"[*] 1. Encrypting {INI_FILE.name} -> {WCFG_FILE.name} (AES-256-GCM)...")
    encrypt_ini_container(runner, base_env)
    print(f"    Container created ({WCFG_FILE.stat().st_size} bytes, Header Magic: {WCFG_FILE.read_bytes()[:4]!r})\n")

    print(f"[*] 2. Querying database configuration as client '{CLIENT_ID}' (end-to-end sealed):")
    requested_fields = [
        ("host", "DB_HOST"),
        ("port", "DB_PORT"),
        ("name", "DB_NAME"),
        ("user", "DB_USER"),
        ("password", "DB_PASSWORD"),
        ("ssl_mode", "DB_SSL_MODE"),
    ]

    for key, env_name in requested_fields:
        sealed_line = fetch_sealed_env_entry(runner, base_env, "database", key, env_name)
        print(f"    stdout -> {sealed_line}")

    print("\n[*] 3. Inspecting process environment (os.environ['DB_PASSWORD']):")
    print(f"    os.environ['DB_PASSWORD'] = {os.environ['DB_PASSWORD']}  (No plaintext in ENV!)")

    print("\n[*] 4. Unsealing database configuration directly in Python RAM (AES-256-GCM in-memory):")
    db_cfg = DatabaseConfig(
        host=unseal_in_memory_python("DB_HOST", "database", "host"),
        port=int(unseal_in_memory_python("DB_PORT", "database", "port")),
        name=unseal_in_memory_python("DB_NAME", "database", "name"),
        user=unseal_in_memory_python("DB_USER", "database", "user"),
        password=unseal_in_memory_python("DB_PASSWORD", "database", "password"),
        ssl_mode=unseal_in_memory_python("DB_SSL_MODE", "database", "ssl_mode"),
    )
    print(f"    Host     : {db_cfg.host}")
    print(f"    Port     : {db_cfg.port}")
    print(f"    Database : {db_cfg.name}")
    print(f"    User     : {db_cfg.user}")
    print(f"    Password : {db_cfg.password[:4]}{'*' * (len(db_cfg.password) - 4)} (successfully unsealed in memory)")
    print(f"    DSN      : {db_cfg.masked_dsn()}")

    print("\n[*] 5. Negative test: Client 'python_db_app' unauthorized attempt to read [admin] root_api_token...")
    try:
        fetch_sealed_env_entry(runner, base_env, "admin", "root_api_token", "ADMIN_TOKEN")
    except subprocess.CalledProcessError as exc:
        print(f"    Expectedly rejected (Exit Code {exc.returncode}): {exc.stderr.strip()}")

    return 0
    print(f"    Host     : {db_cfg.host}")
    print(f"    Port     : {db_cfg.port}")
    print(f"    Database : {db_cfg.name}")
    print(f"    User     : {db_cfg.user}")
    print(f"    Password : {db_cfg.password[:4]}{'*' * (len(db_cfg.password) - 4)} (erfolgreich im Speicher entsiegelt)")
    print(f"    DSN      : {db_cfg.masked_dsn()}")

    print("\n[*] 5. Negativ-Test: Client 'python_db_app' versucht unberechtigt [admin] root_api_token abzufragen...")
    try:
        fetch_sealed_env_entry(runner, base_env, "admin", "root_api_token", "ADMIN_TOKEN")
    except subprocess.CalledProcessError as exc:
        print(f"    Erwartetermaßen abgelehnt (Exit-Code {exc.returncode}): {exc.stderr.strip()}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
