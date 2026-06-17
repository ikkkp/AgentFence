use std::env;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::thread;
use std::time::Duration;

#[cfg(windows)]
use std::os::windows::process::CommandExt;

const DAEMON_AUTHORITY: &str = "127.0.0.1:37421";
#[cfg(windows)]
const DETACHED_PROCESS: u32 = 0x00000008;
#[cfg(windows)]
const CREATE_NEW_PROCESS_GROUP: u32 = 0x00000200;
#[cfg(windows)]
const CREATE_NO_WINDOW: u32 = 0x08000000;

#[tauri::command]
fn daemon_status() -> Result<String, String> {
    daemon_request("GET", "/health").map(|_| "ready".to_string())
}

#[tauri::command]
fn start_daemon() -> Result<String, String> {
    if daemon_request("GET", "/health").is_ok() {
        return Ok("daemon already running".to_string());
    }

    let executable = agentfenced_executable();
    let mut command = Command::new(&executable);
    command
        .arg("--listen")
        .arg(DAEMON_AUTHORITY)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    configure_background_process(&mut command);

    let child = command
        .spawn()
        .map_err(|error| format!("failed to start {}: {error}", executable.display()))?;

    for _ in 0..10 {
        thread::sleep(Duration::from_millis(150));
        if daemon_request("GET", "/health").is_ok() {
            return Ok(format!("started agentfenced pid={}", child.id()));
        }
    }

    Ok(format!(
        "started agentfenced pid={}, waiting for health",
        child.id()
    ))
}

#[tauri::command]
fn stop_daemon() -> Result<String, String> {
    daemon_request("POST", "/shutdown").map(|_| "daemon shutdown requested".to_string())
}

fn daemon_request(method: &str, path: &str) -> Result<String, String> {
    let mut stream = TcpStream::connect(DAEMON_AUTHORITY)
        .map_err(|error| format!("failed to connect to daemon at {DAEMON_AUTHORITY}: {error}"))?;
    let request = format!(
        "{method} {path} HTTP/1.1\r\nHost: {DAEMON_AUTHORITY}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
    );
    stream
        .write_all(request.as_bytes())
        .map_err(|error| format!("failed to write daemon request: {error}"))?;

    let mut response = String::new();
    stream
        .read_to_string(&mut response)
        .map_err(|error| format!("failed to read daemon response: {error}"))?;
    let (head, body) = response
        .split_once("\r\n\r\n")
        .ok_or_else(|| "invalid daemon HTTP response".to_string())?;
    if !head.contains(" 200 ") {
        return Err(format!("daemon returned non-200 response: {head}"));
    }
    Ok(body.to_string())
}

fn configure_background_process(command: &mut Command) {
    #[cfg(windows)]
    {
        command.creation_flags(DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP | CREATE_NO_WINDOW);
    }
}

fn agentfenced_executable() -> PathBuf {
    let executable_name = if cfg!(windows) {
        "agentfenced.exe"
    } else {
        "agentfenced"
    };
    if let Ok(current_exe) = env::current_exe() {
        if let Some(parent) = current_exe.parent() {
            let candidate = parent.join(executable_name);
            if candidate.exists() {
                return candidate;
            }
        }
    }
    PathBuf::from(executable_name)
}

fn main() {
    tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![
            daemon_status,
            start_daemon,
            stop_daemon
        ])
        .run(tauri::generate_context!())
        .expect("failed to run AgentFence desktop app");
}
