#![cfg_attr(
  all(not(debug_assertions), target_os = "windows"),
  windows_subsystem = "windows"
)]

mod file_encryption;
mod json_encryption;

pub use crate::file_encryption::GlobalState;
pub use crate::file_encryption::{
  fetch_data,
  save_data,
  data_exists,
  authenticate
};


fn main() {
  tauri::Builder::default()
    .manage(GlobalState{ password: Default::default(), file_password: Default::default(), file_json: Default::default()})
    .invoke_handler(tauri::generate_handler![
      fetch_data,
      save_data,
      data_exists,
      authenticate
    ])
    .run(tauri::generate_context!())
    .expect("error while running tauri application");
}
