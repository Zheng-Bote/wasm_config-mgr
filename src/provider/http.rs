use crate::provider::ConfigProvider;

/// Request payload for `POST /v1/config/get`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigGetRequest {
    pub container_path: String,
    pub section: String,
    pub key: String,
    pub env_name: String,
}

/// Success response payload for `POST /v1/config/get`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigGetResponse {
    pub env_name: String,
    pub sealed_value: String,
}

/// Generic HTTP Response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpResponse {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: String,
}

impl HttpResponse {
    pub fn ok_json(body: String) -> Self {
        Self {
            status: 200,
            headers: vec![("Content-Type".into(), "application/json".into())],
            body,
        }
    }

    pub fn error_json(status: u16, message: &str) -> Self {
        let escaped = message.replace('"', "\\\"").replace('\n', " ");
        let body = format!(r#"{{"status":"error","code":{status},"message":"{escaped}"}}"#);
        Self {
            status,
            headers: vec![("Content-Type".into(), "application/json".into())],
            body,
        }
    }
}

/// Helper to parse a basic JSON string without heavy external dependencies.
pub fn parse_get_request_json(json_str: &str) -> Result<ConfigGetRequest, String> {
    let mut container_path = "Example/db_config.wcfg".to_string();
    let mut section: Option<String> = None;
    let mut key: Option<String> = None;
    let mut env_name: Option<String> = None;

    // Quick key-value extraction for JSON object
    let trimmed = json_str.trim().trim_start_matches('{').trim_end_matches('}');
    for part in trimmed.split(',') {
        let Some((raw_k, raw_v)) = part.split_once(':') else {
            continue;
        };
        let k = raw_k.trim().trim_matches('"');
        let v = raw_v.trim().trim_matches('"');
        match k {
            "container_path" => container_path = v.to_string(),
            "section" => section = Some(v.to_string()),
            "key" => key = Some(v.to_string()),
            "env_name" => env_name = Some(v.to_string()),
            _ => {}
        }
    }

    let section = section.ok_or_else(|| "Missing required field `section`".to_string())?;
    let key = key.ok_or_else(|| "Missing required field `key`".to_string())?;
    let env_name = env_name.unwrap_or_else(|| format!("{}_{}", section.to_uppercase(), key.to_uppercase()));

    Ok(ConfigGetRequest {
        container_path,
        section,
        key,
        env_name,
    })
}

/// Core handler for Spin / WASI HTTP incoming requests.
pub fn handle_http_request(
    method: &str,
    uri: &str,
    headers: &[(String, String)],
    body: &str,
) -> HttpResponse {
    if method != "POST" {
        return HttpResponse::error_json(405, "Method Not Allowed (expected POST)");
    }

    let path = uri.split('?').next().unwrap_or(uri);
    if path != "/v1/config/get" {
        return HttpResponse::error_json(404, "Endpoint not found (expected /v1/config/get)");
    }

    // Extract Bearer token from headers
    let auth_header = headers.iter().find(|(k, _)| k.eq_ignore_ascii_case("Authorization"));
    let Some((_, val)) = auth_header else {
        return HttpResponse::error_json(401, "Missing Authorization header");
    };

    let token = val.trim().strip_prefix("Bearer ").map(str::trim).unwrap_or(val.trim());
    if token.is_empty() {
        return HttpResponse::error_json(401, "Empty bearer token");
    }

    let req = match parse_get_request_json(body) {
        Ok(r) => r,
        Err(e) => return HttpResponse::error_json(400, &format!("Invalid JSON request: {e}")),
    };

    match ConfigProvider::get_sealed(&req.container_path, &req.section, &req.key, token, &req.env_name, None) {
        Ok(sealed_value) => {
            let json_body = format!(
                r#"{{"status":"ok","env_name":"{}","sealed_value":"{}"}}"#,
                req.env_name, sealed_value
            );
            HttpResponse::ok_json(json_body)
        }
        Err(err) => {
            let status = if err.contains("denied") || err.contains("permitted") {
                403
            } else if err.contains("Authorization") || err.contains("token") || err.contains("signature") {
                401
            } else {
                500
            };
            HttpResponse::error_json(status, &err)
        }
    }
}
