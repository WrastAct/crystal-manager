use base64::{encode, decode};
use hmac::{Hmac, Mac, digest::MacError};
use sha2::Sha256;
use std::fs::File;
use std::io::BufReader;
use std::io::prelude::*;
use std::io::ErrorKind;
use std::sync::Mutex;
use std::{env, ops::Deref};
use tauri::State;

type HmacSha256 = Hmac<Sha256>;

use crate::json_encryption::{
    encrypt_json, decrypt_json
};

static FILE_NAME: &str = "data.txt";

#[derive(Default)]
pub struct GlobalState {
    pub password: Mutex<Option<String>>, //unencrypted password input
    pub file_password: Mutex<Option<String>>, //encrypted, base64 representation of password, extracted from file, unless file is empty
    pub file_json: Mutex<Option<String>>, //encrypted json
}

enum DataFile {
    FileExisted(File),
    FileCreated(File),
    FileEmpty(File),
}

// This function tests if user has already used the app or deleted binary with data
// It MUST be started at the start of program 
// Side effects include fetching data from file to GlobalState
// UNLESS there is no file, in this case it is created
// TODO: Optimize function and use events to invoke at start of program
#[tauri::command]
pub fn data_exists(global_state: State<GlobalState>) -> bool {
    match &*global_state.file_password.lock().unwrap() {
        Some(pass) if !pass.is_empty() => return true,
        _ => {},
    }
    let file = file_exists(&global_state);
    match file {
        DataFile::FileCreated(_) | DataFile::FileEmpty(_) => false,
        DataFile::FileExisted(_) => true,
    }
}

fn verify_password(password: &str, key: &str, base64_password: &str) -> bool {
    let key = key.as_bytes();

    let mut mac = HmacSha256::new_from_slice(key)
        .expect("HMAC can take key of any siz&e");
    
    mac.update(password.as_bytes());

    let base64_password = decode(base64_password).unwrap();
    let base64_password: &[u8] = &base64_password;

    match mac.verify_slice(base64_password) {
        Ok(()) => true,
        Err(MacError) => false,
    }
}

fn encrypt_password(password: &str, key: &str) -> String {
    let key = key.as_bytes();

    let mut mac = HmacSha256::new_from_slice(key)
        .expect("HMAC can take key of any size");
    
    mac.update(password.as_bytes());
    let result = mac.finalize();
    let code_bytes = result.into_bytes();
    let code_bytes = code_bytes.deref();
    let base64_password: String = encode(code_bytes);

    base64_password
}



fn extract_data(file: &File) -> (Option<String>, Option<String>) {
    let mut buf_reader = BufReader::new(file);
    let mut contents = String::new();
    match buf_reader.read_to_string(&mut contents) {
        Ok(_) => {},
        Err(e) => println!("{:?}", e),
    };

    let split = contents.split(":");
    let split = split.collect::<Vec<&str>>();

    let mut password: String = String::new();
    let json: String;

    match split.get(0) {
        Some(pass) if !password.is_empty() => {
            password = (*pass).to_owned();
        },
        _ => return (None, None),
    }

    match split.get(1) {
        Some(js) => {
            json = (*js).to_owned();
        },
        None => return (Some(password), None),
    }

    (Some(password), Some(json))
}


fn file_exists(global_state: &State<GlobalState>) -> DataFile {
    let f = File::open(FILE_NAME);
    
    match f {
        Ok(file) => {
            (*global_state.file_password.lock().unwrap(), 
            *global_state.file_json.lock().unwrap()) = extract_data(&file);

            match &*global_state.file_password.lock().unwrap() {
                Some(_) => return DataFile::FileExisted(file),
                None => return DataFile::FileEmpty(file),
            }
        },
        Err(error) => match error.kind() {
            ErrorKind::NotFound => match File::create(FILE_NAME) {
                Ok(fc) => return DataFile::FileCreated(fc),
                Err(e) => panic!("Problem creating the file: {:?}", e),
            },
            other_error => panic!("Problem opening the file: {:?}", other_error),
        },
    };
}


fn get_env_key() -> String {
    match env::var("SECRET_KEY") {
        Ok(k) => k,
        Err(_) => String::from("secret_key_for_all_those_things"),
    }
}


// Function for writing data in file in specified format
// BASE64_CIPHERED_PASSWORD:BASE64_ENCRYPTED_JSON_DATA
// Takes as arguments BASE-64 encrypted values
fn base64_write(password: &str, json: &str) {
    let f = File::options().write(true).truncate(true).open(FILE_NAME);    

    let mut f = match f {
        Ok(file) => file,
        Err(error) =>  {
            panic!("Problem opening the file: {:?}", error)
        },
    };

    let data = format!("{}:{}", password, json);
    match f.write_all(data.as_bytes()) {
        Ok(_) => println!("writing successfull!"),
        Err(err) => println!("Error! {:?}", err),
    };
}

#[tauri::command]
pub fn save_data(json: String, global_state: State<GlobalState>) {
    let password = match &*global_state.password.lock().unwrap() {
        Some(pass) if !pass.is_empty() => (*pass).clone(),
        _ => return,
    };

    let base64_json = encrypt_json(&json[..], &password[..]);
    let base64_password = match &*global_state.file_password.lock().unwrap() {
        Some(pass) if !pass.is_empty() => (*pass).clone(),
        _ => "".to_owned(), 
    };

    base64_write(&base64_password[..], &base64_json[..]);
}

#[tauri::command]
pub fn fetch_data(global_state: State<GlobalState>) -> String {
    let encrypted_json = match &*global_state.file_json.lock().unwrap() {
        Some(js) => (*js).clone(),
        None => String::new(),
    };

    let password = match &*global_state.password.lock().unwrap() {
        Some(pass) => (*pass).clone(),
        None => String::new(),
    };

    decrypt_json(&encrypted_json[..], &password[..])
}

#[tauri::command]
pub fn authenticate(password: String, global_state: State<GlobalState>) -> bool {
    let key: String = get_env_key();
    let base64_password: String = match &*global_state.file_password.lock().unwrap() {
        Some(pass) => (*pass).clone(),
        None => String::new(), // TODO: If there is no password, we should accept this as new
    };

    if verify_password(&password[..], &key[..], &base64_password[..]) {
        *global_state.password.lock().unwrap() = Some(password);
        
        return true
    }
    false
}