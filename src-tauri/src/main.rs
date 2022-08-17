#![cfg_attr(
  all(not(debug_assertions), target_os = "windows"),
  windows_subsystem = "windows"
)]

mod file_encryption;

pub use crate::file_encryption::read_file;
pub use crate::file_encryption::password_exists;
pub use crate::file_encryption::GlobalState;

fn main() {
  tauri::Builder::default()
    .manage(GlobalState{ password: Default::default(), file_password: Default::default(), file_json: Default::default()})
    .invoke_handler(tauri::generate_handler![read_file, password_exists])
    .run(tauri::generate_context!())
    .expect("error while running tauri application");
}
