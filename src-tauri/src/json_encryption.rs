use aes_gcm::{
    aead::{
        Aead, 
        consts::U32,
        Error,
        generic_array::GenericArray, 
        KeyInit, 
        Payload
    },
    Aes256Gcm, Nonce
};
use base64::{encode, decode};
use core::result::Result;
use sha2::{Sha256, Digest};
use std::str;


// TODO: Implement ecnrypting JSON
pub fn encrypt_json(json: &str, password: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(password.as_bytes());

    let key = hasher.finalize();
    let cipher_text = encryptor_json(json, key);
    let cipher_text = match cipher_text {
        Ok(vec) => vec,
        Err(_) => Vec::<u8>::new(),
    };

    let base64_json = encode(cipher_text);
    base64_json
}

fn encryptor_json(json: &str, key: GenericArray<u8, U32>) -> Result<Vec<u8>, Error> {
    let cipher = Aes256Gcm::new(&key);
    let nonce = Nonce::from_slice(b"unique nonce"); //96-bits
    let message: Payload = Payload { msg: (json.as_bytes().as_ref()), aad: (b"somerandomaad") };
    let ciphertext = cipher.encrypt(nonce, message);

    ciphertext
}

pub fn decrypt_json(encrypted_json: &str, password: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(password.as_bytes());

    let key = hasher.finalize();
    let decoded_json = decode(encrypted_json);
    let decoded_json = match decoded_json {
        Ok(vec) => vec,
        Err(_) => Vec::<u8>::new(),
    };

    let decrypted_json = decryptor_json(decoded_json, key);
    let decrypted_json = match decrypted_json {
        Ok(vec) => {
            match str::from_utf8(&vec) {
                Ok(s) => s.to_owned(),
                Err(_) => "".to_owned(),
            }
        },
        Err(_) => "".to_owned(),
    };

    decrypted_json
}

// TODO: Implement decrypting JSON
fn decryptor_json(encrypted_json: Vec<u8>, key: GenericArray<u8, U32>) -> Result<Vec<u8>, Error> {
    let cipher = Aes256Gcm::new(&key);
    let nonce = Nonce::from_slice(b"unique nonce"); //96-bits
    let message: Payload = Payload { msg: (encrypted_json.as_ref()), aad: (b"somerandomaad") };
    let plaintext = cipher.decrypt(nonce, message);

    plaintext
}
