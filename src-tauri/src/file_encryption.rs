use std::io::BufReader;
use std::fs::File;
use std::io::prelude::*;
use std::io::ErrorKind;
use std::{env, ops::Deref};
use sha2::Sha256;
use hmac::{Hmac, Mac, digest::MacError};
use base64::{encode, decode};

// use aes_gcm::{
//     aead::{Aead, KeyInit, OsRng},
//     Aes256Gcm, Nonce
// };

type HmacSha256 = Hmac<Sha256>;

pub struct FileContent {
    password: Option<String>,
    json: Option<String>,
}


fn verify_password(password: &str, key: &[u8], cipher_password: &[u8]) -> bool {
    let mut mac = HmacSha256::new_from_slice(key)
        .expect("HMAC can take key of any size");
    
    mac.update(password.as_bytes());

    match mac.verify_slice(cipher_password) {
        Ok(()) => true,
        Err(MacError) => false,
    }
}

fn create_password(password: &str, key: &[u8]) -> String {
    let mut mac = HmacSha256::new_from_slice(key)
        .expect("HMAC can take key of any size");
    
    mac.update(password.as_bytes());
    let result = mac.finalize();
    let code_bytes = result.into_bytes();
    let code_bytes = code_bytes.deref();
    let base64_password: String = encode(code_bytes);

    base64_password
}


#[tauri::command]
pub fn read_file(password: String) -> String {
    let key: String = match env::var("LALA") {
        Ok(k) => k,
        Err(_) => String::from("secret_key_for_all_those_things"),
    };

    let key: &[u8] = key.as_bytes();
    let base64_password = create_password(&password[..], key);
    
    

    let f = File::open("hello.txt");
    let f = match f {
        Ok(file) => {


            file
        },
        Err(error) => match error.kind() {
            ErrorKind::NotFound => match File::create("hello.txt") {
                Ok(mut fc) => {
                    fc.write_all(base64_password.as_bytes());
                    fc
                },
                Err(e) => panic!("Problem creating the file: {:?}", e),
            },
            other_error => panic!("Problem opening the file: {:?}", other_error),
        },
    };

    

    password
}

fn extract_data(file: &File) -> Option<(String, String)> {
    let mut buf_reader = BufReader::new(file);
    let mut contents = String::new();
    buf_reader.read_to_string(&mut contents);

    let mut split = contents.split(":");
    let split = split.collect::<Vec<&str>>();

    let mut password: String = String::new();
    let mut json: String = String::new();

    match split.get(0) {
        Some(pass) => {
            password = (*pass).to_owned();
        },
        None => return None,
    }

    match split.get(1) {
        Some(js) => {
            json = (*js).to_owned();
        },
        None => {},
    }

    Some((password, json))
}