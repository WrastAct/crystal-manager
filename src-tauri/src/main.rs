#![cfg_attr(
  all(not(debug_assertions), target_os = "windows"),
  windows_subsystem = "windows"
)]

mod file_encryption;
mod json_encryption;

pub use crate::file_encryption::read_file;
pub use crate::file_encryption::password_exists;
pub use crate::file_encryption::enter_password;
pub use crate::file_encryption::GlobalState;
pub use crate::json_encryption::encrypt_json;
pub use crate::json_encryption::decrypt_json;

fn main() {
  tauri::Builder::default()
    .manage(GlobalState{ password: Default::default(), file_password: Default::default(), file_json: Default::default()})
    .invoke_handler(tauri::generate_handler![read_file, password_exists, enter_password, encrypt_json, decrypt_json])
    .run(tauri::generate_context!())
    .expect("error while running tauri application");
}
