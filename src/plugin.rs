use std::{ collections::LinkedList, sync::mpsc::{ channel, Receiver, Sender } };

use log::{ error, info };
use samp::{
    amx::{ Amx, AmxExt, AmxIdent },
    cell::AmxString,
    plugin::SampPlugin,
};
use threadpool::ThreadPool;

use crate::internals::{
    ArgumentTypes,
    HashAlgorithms,
    HashParams,
    VerifyParams,
};

fn is_valid_hash_algorithm(algorithm: HashAlgorithms) -> bool {
    match algorithm {
        HashAlgorithms::Bcrypt | HashAlgorithms::Argon2 => true,
    }
}

pub struct SampCrypto {
    pub hashes: LinkedList<String>,
    pub pool: ThreadPool,
    pub hash_sender: Option<Sender<HashParams>>,
    pub hash_receiver: Option<Receiver<HashParams>>,
    pub verify_sender: Option<Sender<VerifyParams>>,
    pub verify_receiver: Option<Receiver<VerifyParams>>,
    pub amx_list: Vec<AmxIdent>,
}

impl SampPlugin for SampCrypto {
    fn on_load(&mut self) {
        info!("Version: 0.0.1");

        let (verify_sender, verify_receiver) = channel();
        self.verify_sender = Some(verify_sender);
        self.verify_receiver = Some(verify_receiver);

        let (hash_sender, hash_receiver) = channel();
        self.hash_sender = Some(hash_sender);
        self.hash_receiver = Some(hash_receiver);
    }

    fn on_amx_load(&mut self, amx: &Amx) {
        self.amx_list.push(amx.ident())
    }

    fn on_amx_unload(&mut self, amx: &Amx) {
        let raw = amx.ident();
        let index = self.amx_list
            .iter()
            .position(|x| *x == raw)
            .unwrap();
        self.amx_list.remove(index);
    }

    fn process_tick(&mut self) {
        for (
            hash_algorithm,
            playerid,
            callback,
            hash,
            optional_args,
        ) in self.hash_receiver.as_ref().unwrap().try_iter() {
            self.hashes.push_front(hash);

            if !is_valid_hash_algorithm(hash_algorithm.clone()) {
                error!("Unknown algorithm {}", hash_algorithm as i32);
                return;
            }

            let algorithm = match hash_algorithm {
                HashAlgorithms::Bcrypt => "bcrypt",
                HashAlgorithms::Argon2 => "argon2",
            };

            let mut executed = false;
            for amx in &self.amx_list {
                if let Some(amx) = samp::amx::get(*amx) {
                    let allocator = amx.allocator();

                    for param in optional_args.iter().rev() {
                        match param {
                            ArgumentTypes::Primitive(x) => {
                                if amx.push(x).is_err() {
                                    error!(
                                        "[{}] Cannot execute callback {:?}",
                                        algorithm,
                                        callback
                                    );
                                }
                            }
                            ArgumentTypes::String(data) => {
                                let buf = allocator
                                    .allot_buffer(data.len() + 1)
                                    .unwrap();
                                let amx_str = unsafe {
                                    AmxString::new(buf, &data)
                                };
                                if amx.push(amx_str).is_err() {
                                    error!(
                                        "[{}] Cannot execute callback {:?}",
                                        algorithm,
                                        callback
                                    );
                                }
                            }
                        }
                    }
                    if amx.push(playerid).is_err() {
                        error!(
                            "[{}] Cannot execute callback {:?}",
                            algorithm,
                            callback
                        );
                    }
                    if let Ok(index) = amx.find_public(&callback) {
                        if amx.exec(index).is_ok() {
                            executed = true;
                            break;
                        }
                    }
                }
            }
            if !executed {
                error!(
                    "[{}] Cannot execute callback {:?}",
                    algorithm,
                    callback
                );
            }
        }

        for (
            hash_algorithm,
            playerid,
            callback,
            success,
            optional_args,
        ) in self.verify_receiver.as_ref().unwrap().try_iter() {
            if !is_valid_hash_algorithm(hash_algorithm.clone()) {
                error!("Unknown algorithm {}", hash_algorithm as i32);
                return;
            }

            let algorithm = match hash_algorithm {
                HashAlgorithms::Bcrypt => "bcrypt",
                HashAlgorithms::Argon2 => "argon2",
            };

            let mut executed = false;
            for amx in &self.amx_list {
                if let Some(amx) = samp::amx::get(*amx) {
                    let allocator = amx.allocator();

                    for param in optional_args.iter().rev() {
                        match param {
                            ArgumentTypes::Primitive(x) => {
                                if amx.push(x).is_err() {
                                    error!(
                                        "[{}] Cannot execute callback {:?}",
                                        algorithm,
                                        callback
                                    );
                                }
                            }
                            ArgumentTypes::String(data) => {
                                let buf = allocator
                                    .allot_buffer(data.len() + 1)
                                    .unwrap();
                                let amx_str = unsafe {
                                    AmxString::new(buf, &data)
                                };
                                if amx.push(amx_str).is_err() {
                                    error!(
                                        "[{}] Cannot execute callback {:?}",
                                        algorithm,
                                        callback
                                    );
                                }
                            }
                        }
                    }
                    if amx.push(success).is_err() {
                        error!(
                            "[{}] Cannot execute callback {:?}",
                            algorithm,
                            callback
                        );
                    }
                    if amx.push(playerid).is_err() {
                        error!(
                            "[{}] Cannot execute callback {:?}",
                            algorithm,
                            callback
                        );
                    }
                    if let Ok(index) = amx.find_public(&callback) {
                        if amx.exec(index).is_ok() {
                            executed = true;
                            break;
                        }
                    }
                }
            }
            if !executed {
                error!(
                    "[{}] Cannot execute callback {:?}",
                    algorithm,
                    callback
                );
            }
        }

        self.hashes.clear();
    }
}
