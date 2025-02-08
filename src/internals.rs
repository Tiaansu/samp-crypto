use bcrypt::{ hash as bcrypt_hash, verify as bcrypt_verify };
use argon2::{
    hash_encoded as argon2_hash_encoded,
    verify_encoded as argon2_verify_encoded,
    Config,
};
use log::error;
use regex::Regex;
use std::sync::mpsc::Sender;

#[derive(Debug)]
pub enum ArgumentTypes {
    Primitive(i32),
    String(Vec<u8>),
}

#[derive(Debug, Clone)]
pub enum HashAlgorithms {
    Bcrypt = 0,
    Argon2 = 1,
}

// bcrypt
pub type VerifyParams = (HashAlgorithms, i32, String, bool, Vec<ArgumentTypes>);
pub type HashParams = (HashAlgorithms, i32, String, String, Vec<ArgumentTypes>);

pub fn bcrypt_hash_verify(
    verify_sender: Option<Sender<VerifyParams>>,
    playerid: i32,
    input: String,
    hash: String,
    callback: String,
    optional_args: Vec<ArgumentTypes>
) {
    match bcrypt_verify(&input, &hash) {
        Ok(success) => {
            let _ = verify_sender
                .as_ref()
                .unwrap()
                .send((
                    HashAlgorithms::Bcrypt,
                    playerid,
                    callback,
                    success,
                    optional_args,
                ));
        }
        Err(err) => {
            error!("[bcrypt] {} => {:?}", callback, err);
        }
    }
}

pub fn bcrypt_hash_start(
    hash_sender: Option<Sender<HashParams>>,
    playerid: i32,
    input: String,
    callback: String,
    cost: u32,
    optional_args: Vec<ArgumentTypes>
) {
    match bcrypt_hash(&input, cost) {
        Ok(hash) => {
            let _ = hash_sender
                .as_ref()
                .unwrap()
                .send((
                    HashAlgorithms::Bcrypt,
                    playerid,
                    callback,
                    hash,
                    optional_args,
                ));
        }
        Err(err) => {
            error!("[bcrypt] {} => {:?}", callback, err);
        }
    }
}

// argon2
pub fn argon2_hash_start(
    hash_sender: Option<Sender<HashParams>>,
    playerid: i32,
    password: String,
    salt: String,
    callback: String,
    config: Config,
    optional_args: Vec<ArgumentTypes>
) {
    match argon2_hash_encoded(password.as_bytes(), salt.as_bytes(), &config) {
        Ok(hash) => {
            let _ = hash_sender
                .as_ref()
                .unwrap()
                .send((
                    HashAlgorithms::Argon2,
                    playerid,
                    callback,
                    hash,
                    optional_args,
                ));
        }
        Err(err) => {
            error!("[argon2] {} => {:?}", callback, err);
        }
    }
}

pub fn argon2_hash_verify(
    verify_sender: Option<Sender<VerifyParams>>,
    playerid: i32,
    input: String,
    hash: String,
    callback: String,
    optional_args: Vec<ArgumentTypes>
) {
    match argon2_verify_encoded(&hash, input.as_bytes()) {
        Ok(success) => {
            let _ = verify_sender
                .as_ref()
                .unwrap()
                .send((
                    HashAlgorithms::Argon2,
                    playerid,
                    callback,
                    success,
                    optional_args,
                ));
        }
        Err(err) => {
            error!("[argon2] {} => {:?}", callback, err);
        }
    }
}

// extras
pub fn is_argon2_hash(input: &str) -> bool {
    let re = Regex::new(
        r"^\$argon2(i|d|id)\$v=\d+\$m=\d+,t=\d+,p=\d+\$[a-zA-Z0-9/+]+(\$[a-zA-Z0-9/+]+)?$"
    ).unwrap();
    re.is_match(input)
}
