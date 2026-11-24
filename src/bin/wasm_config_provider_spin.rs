use std::io::{Read, Write};
use wasm_config_mgr::provider::http::handle_http_request;

fn main() {
    let method = std::env::var("REQUEST_METHOD").unwrap_or_else(|_| "POST".into());
    let uri = std::env::var("PATH_INFO").unwrap_or_else(|_| "/v1/config/get".into());
    let auth = std::env::var("HTTP_AUTHORIZATION").unwrap_or_default();

    let mut body = String::new();
    let _ = std::io::stdin().read_to_string(&mut body);

    let headers = vec![("Authorization".to_string(), auth)];
    let response = handle_http_request(&method, &uri, &headers, &body);

    print!("Status: {}\r\n", response.status);
    for (k, v) in &response.headers {
        print!("{k}: {v}\r\n");
    }
    print!("\r\n");
    print!("{}", response.body);
    let _ = std::io::stdout().flush();
}
