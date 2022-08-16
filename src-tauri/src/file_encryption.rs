use std::io::BufReader;
use std::fs::File;
use std::io::prelude::*;
use std::io::ErrorKind;
use std::{env, ops::Deref};
use sha2::Sha256;
use hmac::{Hmac, Mac, digest::MacError};


type HmacSha256 = Hmac<Sha256>;

// pub fn read_file(password: String) -> bool {
//     let key: String = match env::var("LALA") {
//         Ok(k) => k,
//         Err(_) => String::from("secret_key_for_all_those_things"),
//     };

//     let key: &[u8] = key.as_bytes();


//     let mut mac = HmacSha256::new_from_slice(key)
//         .expect("HMAC can take key of any size");

//     mac.update(password.as_bytes());

//     let result = mac.finalize();
//     let code_bytes = result.into_bytes();

//     true
// }

fn verify_password(password: &str, key: &[u8], cipher_password: &[u8]) -> bool {
    let mut mac = HmacSha256::new_from_slice(key)
        .expect("HMAC can take key of any size");
    
    mac.update(password.as_bytes());

    // let result = mac.finalize();
    // let code_bytes = result.into_bytes();
    // let code_bytes = code_bytes.deref().to_vec();

    // for value in code_bytes {
    //     print!("{} ", value);
    // }

    match mac.verify_slice(cipher_password) {
        Ok(()) => true,
        Err(MacError) => false,
    }
}

fn create_password(password: &str, key: &[u8]) -> Vec<u8> {
    let mut mac = HmacSha256::new_from_slice(key)
        .expect("HMAC can take key of any size");
    
    mac.update(password.as_bytes());
    let result = mac.finalize();
    let code_bytes = result.into_bytes();
    let code_bytes = code_bytes.deref().to_vec();

    code_bytes
}


#[tauri::command]
pub fn read_file(password: String) -> String {
    let key: String = match env::var("LALA") {
        Ok(k) => k,
        Err(_) => String::from("secret_key_for_all_those_things"),
    };

    let key: &[u8] = key.as_bytes();


    let f = File::open("hello.txt");
    let mut f = match f {
        Ok(mut file) => file,
        Err(error) => match error.kind() {
            ErrorKind::NotFound => match File::create("hello.txt") {
                Ok(mut fc) => {
                    let hash_password = create_password(&password[..], key);
                    let hash_password: &[u8] = &hash_password; 
                    fc.write_all(hash_password);
                    fc
                },
                Err(e) => panic!("Problem creating the file: {:?}", e),
            },
            other_error => panic!("Problem opening the file: {:?}", other_error),
        },
    };

    let mut reader = BufReader::new(f);
    let mut buffer = Vec::new();
    reader.read_to_end(&mut buffer);

    if verify_password(&password[..], key, &buffer) {
        println!("Password is correct");
    } else {
        println!("Wrong password");
    }

    password
}