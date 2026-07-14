use std::path::PathBuf;
use std::process::ExitCode;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Result, bail};
use clap::{Parser, Subcommand};
use palmodctl::{ControlClient, ControlRequest, default_socket_path};

#[derive(Debug, Parser)]
#[command(version, about)]
struct Cli {
    #[arg(long, env = "PALMOD_CONTROL_SOCKET")]
    socket: Option<PathBuf>,
    #[arg(long, default_value_t = 5_000)]
    timeout_ms: u64,
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Report loader, build, hook, and plugin status.
    Status,
    /// Reload all plugins or one plugin by ID.
    Reload { plugin: Option<String> },
    /// Invoke a registered command through the authenticated local surface.
    Invoke {
        command: String,
        #[arg(trailing_var_arg = true)]
        args: Vec<String>,
    },
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("palmodctl: {error:#}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<()> {
    let cli = Cli::parse();
    let id = request_id()?;
    let request = match cli.command {
        Command::Status => ControlRequest::status(id),
        Command::Reload { plugin } => ControlRequest::reload(id, plugin),
        Command::Invoke { command, args } => ControlRequest::invoke(id, command, args),
    };
    let socket = cli.socket.map_or_else(default_socket_path, Ok)?;
    let client = ControlClient::connect(&socket, Duration::from_millis(cli.timeout_ms))?;
    let response = client.call(&request)?;
    if !response.ok {
        let error = response
            .error
            .expect("validated failed response has an error");
        bail!("{}: {}", error.code, error.message);
    }
    println!(
        "{}",
        serde_json::to_string_pretty(&response.result.unwrap_or(serde_json::Value::Null))?
    );
    Ok(())
}

fn request_id() -> Result<u64> {
    let nanos = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
    Ok(u64::try_from(nanos).unwrap_or_else(|_| {
        let low = nanos & u128::from(u64::MAX);
        u64::try_from(low).expect("masked timestamp fits u64")
    }))
}
