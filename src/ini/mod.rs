use std::collections::BTreeMap;
use thiserror::Error;
use zeroize::Zeroizing;

pub const POLICY_SECTION: &str = "__policy__";

#[derive(Debug, Error, PartialEq, Eq)]
pub enum IniError {
    #[error("syntax error on line {line}: {message}")]
    SyntaxError { line: usize, message: String },
    #[error("key-value pair outside of any section on line {line}")]
    OrphanKey { line: usize },
    #[error("empty section name on line {line}")]
    EmptySectionName { line: usize },
    #[error("empty key name on line {line}")]
    EmptyKeyName { line: usize },
    #[error("invalid policy entry `{key}`: {reason}")]
    InvalidPolicy { key: String, reason: String },
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct IniDocument {
    sections: BTreeMap<String, BTreeMap<String, String>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ClientPolicy {
    pub client_id: String,
    pub hmac_secret: Option<Zeroizing<Vec<u8>>>,
    pub ed25519_pubkey: Option<[u8; 32]>,
    pub allowed_patterns: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct PolicyManifest {
    pub clients: BTreeMap<String, ClientPolicy>,
}

impl IniDocument {
    pub fn new() -> Self {
        Self::default()
    }

    /// Parses an INI string into a structured `IniDocument`.
    pub fn parse(input: &str) -> Result<Self, IniError> {
        let mut sections: BTreeMap<String, BTreeMap<String, String>> = BTreeMap::new();
        let mut current_section: Option<String> = None;

        for (idx, raw_line) in input.lines().enumerate() {
            let line_num = idx + 1;
            let trimmed = raw_line.trim();

            if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with(';') {
                continue;
            }

            if trimmed.starts_with('[') {
                if !trimmed.ends_with(']') {
                    return Err(IniError::SyntaxError {
                        line: line_num,
                        message: "unclosed section header".to_string(),
                    });
                }
                let sec_name = trimmed[1..trimmed.len() - 1].trim();
                if sec_name.is_empty() {
                    return Err(IniError::EmptySectionName { line: line_num });
                }
                if sec_name.contains('[') || sec_name.contains(']') {
                    return Err(IniError::SyntaxError {
                        line: line_num,
                        message: "nested brackets in section header".to_string(),
                    });
                }
                current_section = Some(sec_name.to_string());
                sections.entry(sec_name.to_string()).or_default();
                continue;
            }

            let Some(sec) = current_section.as_ref() else {
                return Err(IniError::OrphanKey { line: line_num });
            };

            let Some((raw_key, raw_val)) = trimmed.split_once('=') else {
                return Err(IniError::SyntaxError {
                    line: line_num,
                    message: "expected `key = value`".to_string(),
                });
            };

            let key = raw_key.trim();
            if key.is_empty() {
                return Err(IniError::EmptyKeyName { line: line_num });
            }
            if key.chars().any(|c| c.is_control() || c == '=') {
                return Err(IniError::SyntaxError {
                    line: line_num,
                    message: "invalid characters in key".to_string(),
                });
            }

            let value = Self::parse_value(raw_val.trim(), line_num)?;
            sections
                .entry(sec.clone())
                .or_default()
                .insert(key.to_string(), value);
        }

        Ok(Self { sections })
    }

    fn parse_value(val: &str, line_num: usize) -> Result<String, IniError> {
        if (val.starts_with('"') && val.len() >= 2 && val.ends_with('"'))
            || (val.starts_with('\'') && val.len() >= 2 && val.ends_with('\''))
        {
            let quote = val.chars().next().unwrap();
            let inner = &val[1..val.len() - 1];
            if quote == '"' {
                let mut out = String::with_capacity(inner.len());
                let mut chars = inner.chars();
                while let Some(c) = chars.next() {
                    if c == '\\' {
                        match chars.next() {
                            Some('n') => out.push('\n'),
                            Some('r') => out.push('\r'),
                            Some('t') => out.push('\t'),
                            Some('\\') => out.push('\\'),
                            Some('"') => out.push('"'),
                            Some(other) => {
                                return Err(IniError::SyntaxError {
                                    line: line_num,
                                    message: format!("unsupported escape sequence \\{other}"),
                                });
                            }
                            None => {
                                return Err(IniError::SyntaxError {
                                    line: line_num,
                                    message: "trailing backslash in quoted value".to_string(),
                                });
                            }
                        }
                    } else {
                        out.push(c);
                    }
                }
                return Ok(out);
            }
            return Ok(inner.to_string());
        }

        if val.starts_with('"') || val.starts_with('\'') {
            return Err(IniError::SyntaxError {
                line: line_num,
                message: "unclosed quote in value".to_string(),
            });
        }

        // Strip inline comments (# or ;) if preceded by whitespace
        let mut clean = val;
        for (i, c) in val.char_indices() {
            if (c == '#' || c == ';') && i > 0 && val[..i].ends_with(char::is_whitespace) {
                clean = val[..i].trim_end();
                break;
            }
        }
        Ok(clean.to_string())
    }

    pub fn get(&self, section: &str, key: &str) -> Option<&str> {
        self.sections
            .get(section)
            .and_then(|sec| sec.get(key))
            .map(String::as_str)
    }

    pub fn sections(&self) -> &BTreeMap<String, BTreeMap<String, String>> {
        &self.sections
    }

    pub fn serialize(&self) -> String {
        let mut out = String::new();
        for (section, entries) in &self.sections {
            out.push('[');
            out.push_str(section);
            out.push_str("]\n");
            for (k, v) in entries {
                out.push_str(k);
                out.push_str(" = ");
                if v.contains('#')
                    || v.contains(';')
                    || v.starts_with(' ')
                    || v.ends_with(' ')
                    || v.contains('"')
                {
                    let escaped = v.replace('\\', "\\\\").replace('"', "\\\"");
                    out.push('"');
                    out.push_str(&escaped);
                    out.push_str("\"\n");
                } else {
                    out.push_str(v);
                    out.push('\n');
                }
            }
            out.push('\n');
        }
        out
    }

    /// Extracts and validates the `[__policy__]` section from the INI document.
    pub fn extract_policy(&self) -> Result<PolicyManifest, IniError> {
        let mut manifest = PolicyManifest::default();
        let Some(policy_sec) = self.sections.get(POLICY_SECTION) else {
            return Ok(manifest);
        };

        for (key, value) in policy_sec {
            let parts: Vec<&str> = key.split('.').collect();
            if parts.len() != 3 || parts[0] != "client" {
                return Err(IniError::InvalidPolicy {
                    key: key.clone(),
                    reason: "expected format `client.<client_id>.<hmac_secret|ed25519_pubkey|allow>`".to_string(),
                });
            }
            let client_id = parts[1];
            let attr = parts[2];

            if client_id.is_empty()
                || !client_id
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
            {
                return Err(IniError::InvalidPolicy {
                    key: key.clone(),
                    reason: "invalid client_id characters".to_string(),
                });
            }

            let entry = manifest
                .clients
                .entry(client_id.to_string())
                .or_insert_with(|| ClientPolicy {
                    client_id: client_id.to_string(),
                    ..Default::default()
                });

            match attr {
                "hmac_secret" => {
                    if value.is_empty() {
                        return Err(IniError::InvalidPolicy {
                            key: key.clone(),
                            reason: "hmac_secret cannot be empty".to_string(),
                        });
                    }
                    let secret_bytes = hex::decode(value).unwrap_or_else(|_| value.as_bytes().to_vec());
                    entry.hmac_secret = Some(Zeroizing::new(secret_bytes));
                }
                "ed25519_pubkey" => {
                    let decoded = hex::decode(value).map_err(|_| IniError::InvalidPolicy {
                        key: key.clone(),
                        reason: "ed25519_pubkey must be valid 64-character hex".to_string(),
                    })?;
                    let pubkey: [u8; 32] =
                        decoded.try_into().map_err(|_| IniError::InvalidPolicy {
                            key: key.clone(),
                            reason: "ed25519_pubkey must be exactly 32 bytes (64 hex chars)"
                                .to_string(),
                        })?;
                    entry.ed25519_pubkey = Some(pubkey);
                }
                "allow" => {
                    let patterns: Vec<String> = value
                        .split(',')
                        .map(str::trim)
                        .filter(|s| !s.is_empty())
                        .map(String::from)
                        .collect();
                    if patterns.is_empty() {
                        return Err(IniError::InvalidPolicy {
                            key: key.clone(),
                            reason: "allow list cannot be empty".to_string(),
                        });
                    }
                    entry.allowed_patterns = patterns;
                }
                other => {
                    return Err(IniError::InvalidPolicy {
                        key: key.clone(),
                        reason: format!("unknown policy attribute `{other}`"),
                    });
                }
            }
        }

        Ok(manifest)
    }
}
