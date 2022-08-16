#![cfg_attr(
  all(not(debug_assertions), target_os = "windows"),
  windows_subsystem = "windows"
)]

mod file_encryption;

pub use crate::file_encryption::read_file;

fn main() {
  tauri::Builder::default()
    .invoke_handler(tauri::generate_handler![read_file])
    .run(tauri::generate_context!())
    .expect("error while running tauri application");
}
