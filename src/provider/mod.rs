pub mod http;

use crate::{
    cli::{TokenKeySpec, query_sealed_env, unseal_env_value},
    crypto::KeyMaterial,
};
use std::fs;

#[cfg(feature = "wit-bindgen")]
wit_bindgen::generate!({
    world: "config-provider",
    path: "wit/config-provider.wit",
    generate_all
});

pub struct ConfigProvider;

impl ConfigProvider {
    /// In-memory or component-level retrieval of a sealed configuration value.
    pub fn get_sealed(
        container_path: &str,
        section: &str,
        key: &str,
        token: &str,
        env_name: &str,
        master_key_env: Option<&str>,
    ) -> Result<String, String> {
        let container_bytes = fs::read(container_path)
            .map_err(|e| format!("Failed to read container `{container_path}`: {e}"))?;

        let key_env = master_key_env.unwrap_or(crate::cli::DEFAULT_MASTER_KEY_ENV);
        let master_key_str = std::env::var(key_env)
            .map_err(|_| format!("Environment variable `{key_env}` not set"))?;
        let key_material = KeyMaterial::from_raw_str(&master_key_str)
            .map_err(|e| format!("Invalid master key: {e}"))?;

        let assignment = query_sealed_env(
            &container_bytes,
            &key_material,
            token,
            section,
            key,
            Some(env_name),
            false,
        )
        .map_err(|e| format!("Authorization or query failed: {e}"))?;

        // Extract value part from `ENV_NAME=VALUE`
        let val = assignment
            .split_once('=')
            .map(|(_, rhs)| rhs.to_string())
            .unwrap_or(assignment);
        Ok(val)
    }

    /// In-memory unsealing of an HMAC-sealed value using the client's secret hex.
    pub fn unseal_hmac(
        sealed_value: &str,
        client_id: &str,
        section: &str,
        key: &str,
        env_name: &str,
        secret_hex: &str,
    ) -> Result<String, String> {
        let secret_bytes = hex::decode(secret_hex)
            .map_err(|e| format!("Invalid secret hex: {e}"))?;
        let unsealed = unseal_env_value(
            sealed_value,
            client_id,
            section,
            key,
            Some(env_name),
            &TokenKeySpec::HmacSecret(secret_bytes),
        )
        .map_err(|e| format!("Failed to unseal value: {e}"))?;

        Ok((*unsealed).clone())
    }
}

#[cfg(feature = "wit-bindgen")]
impl exports::wasm_config::provider::reader::Guest for ConfigProvider {
    fn get_sealed(
        container_path: String,
        section: String,
        key: String,
        token: String,
        env_name: String,
    ) -> Result<String, String> {
        Self::get_sealed(&container_path, &section, &key, &token, &env_name, None)
    }

    fn unseal_hmac(
        sealed_value: String,
        client_id: String,
        section: String,
        key: String,
        env_name: String,
        secret_hex: String,
    ) -> Result<String, String> {
        Self::unseal_hmac(&sealed_value, &client_id, &section, &key, &env_name, &secret_hex)
    }
}

#[cfg(feature = "wit-bindgen")]
export!(ConfigProvider);
