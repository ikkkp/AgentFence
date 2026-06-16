#[tauri::command]
fn daemon_status() -> &'static str {
    "ready"
}

fn main() {
    tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![daemon_status])
        .run(tauri::generate_context!())
        .expect("failed to run AgentFence desktop app");
}
