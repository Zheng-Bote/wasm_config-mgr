use std::{env, process::ExitCode};
use wasm_config_mgr::cli::{execute_command, parse_cli_args};

fn main() -> ExitCode {
    let args: Vec<String> = env::args().collect();
    match parse_cli_args(&args).and_then(execute_command) {
        Ok(Some(output)) => {
            println!("{output}");
            ExitCode::SUCCESS
        }
        Ok(None) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("error: {err}");
            ExitCode::FAILURE
        }
    }
}
