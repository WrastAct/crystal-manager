use std::io::BufReader;
use std::fs::File;
use std::io::prelude::*;
use std::io::ErrorKind;
use std::{env, ops::Deref};
use sha2::Sha256;
use hmac::{Hmac, Mac, digest::MacError};
use base64::{encode, decode};

use tauri::State;
use std::sync::Mutex;

// use aes_gcm::{
//     aead::{Aead, KeyInit, OsRng},
//     Aes256Gcm, Nonce
// };

type HmacSha256 = Hmac<Sha256>;

#[derive(Default)]
pub struct GlobalState {
    pub password: Mutex<Option<String>>, //unencrypted password input
    pub file_password: Mutex<Option<String>>, //encrypted, base64 representation of password, extracted from file, unless file is empty
    pub file_json: Mutex<Option<String>>, //encrypted json
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


// #[tauri::command]
// pub fn read_file(password: String) -> String {
//     let key: String = match env::var("LALA") {
//         Ok(k) => k,
//         Err(_) => String::from("secret_key_for_all_those_things"),
//     };

//     let key: &[u8] = key.as_bytes();
//     let base64_password = encrypt_password(&password[..], key);

//     let f = File::open("hello.txt");
//     let f = match f {
//         Ok(file) => {
//             file
//         },
//         Err(error) => match error.kind() {
//             ErrorKind::NotFound => match File::create("hello.txt") {
//                 Ok(mut fc) => {
//                     fc.write_all(base64_password.as_bytes());
//                     fc
//                 },
//                 Err(e) => panic!("Problem creating the file: {:?}", e),
//             },
//             other_error => panic!("Problem opening the file: {:?}", other_error),
//         },
//     };

//     password
// }

#[tauri::command]
pub fn read_file(password: String, global_state: State<GlobalState>) -> String {
    *global_state.password.lock().unwrap() = Some(password.clone());

    let key: String = match env::var("SECRET_KEY") {
        Ok(k) => k,
        Err(_) => String::from("secret_key_for_all_those_things"),
    };

    let base64_password = encrypt_password(&password[..], &key[..]);

    //TODO: change this code!!
    let f = File::open("data.txt");
    let mut f = match f {
        Ok(file) => {
            (*global_state.file_password.lock().unwrap(), 
             *global_state.file_json.lock().unwrap()) = extract_data(&file);

            file
        },
        Err(error) => match error.kind() {
            ErrorKind::NotFound => match File::create("data.txt") {
                Ok(mut fc) => fc,
                Err(e) => panic!("Problem creating the file: {:?}", e),
            },
            other_error => panic!("Problem opening the file: {:?}", other_error),
        },
    };
    

    // println!("{:?}", global_state.file_password.lock().unwrap());

    // match &*global_state.file_password.lock().unwrap() {
    //     Some(str) => println!("{str}"),
    //     None => println!("File password none("),
    // }

    match &*global_state.file_password.lock().unwrap() {
        Some(pass) => {
            if let Some(unencrypted) = &*global_state.password.lock().unwrap() {
                if verify_password(&unencrypted[..], &key[..], &pass[..]) {
                    println!("Password Verified");
                } else {
                    println!("Incorrect Password");
                }
            }
        },
        None => {},
    }

    f.write_all(base64_password.as_bytes());

    let mut json: String = String::from("No password"); 

    match &*global_state.password.lock().unwrap() {
        Some(pass) => json = pass.to_owned(),
        None => {},
    };

    json
}

#[tauri::command]


fn extract_data(file: &File) -> (Option<String>, Option<String>) {
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
        None => return (None, None),
    }

    match split.get(1) {
        Some(js) => {
            json = (*js).to_owned();
        },
        None => return (Some(password), None),
    }

    (Some(password), Some(json))
}

//TODO: Implement writing JSON to file
// fn write_data() {}

//TODO: Implement ecnrypting JSON
// fn encrypt_data() {}

//TODO: Implement decrypting JSON
// fn decrypt_data() {}