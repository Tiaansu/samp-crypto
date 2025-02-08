use argon2::{ Config, Variant, Version };
use log::error;
use samp::{
    amx::Amx,
    cell::{ AmxCell, AmxString, Ref, UnsizedBuffer },
    error::{ AmxError, AmxResult },
    native,
};

use crate::internals::{
    argon2_hash_start,
    argon2_hash_verify,
    bcrypt_hash_start,
    bcrypt_hash_verify,
    is_argon2_hash,
    ArgumentTypes,
};

impl super::SampCrypto {
    // bcrypt
    #[native(raw, name = "bcrypt_hash")]
    pub fn bcrypt_hash(
        &mut self,
        amx: &Amx,
        mut args: samp::args::Args
    ) -> AmxResult<bool> {
        let playerid = args.next::<i32>().ok_or(AmxError::Params)?;
        let callback = args
            .next::<AmxString>()
            .ok_or(AmxError::Params)?
            .to_string();
        let input = args
            .next::<AmxString>()
            .ok_or(AmxError::Params)?
            .to_string();
        let cost = args.next::<u32>().ok_or(AmxError::Params)?;
        let mut format: Vec<u8> = Vec::new();

        if args.count() > 4 {
            if let Some(specifiers) = args.next::<AmxString>() {
                format = specifiers.to_bytes();
            }
        }

        if !format.is_empty() && format.len() != args.count() - 5 {
            error!(
                "The argument count mismatch expected: {} provided: {}.",
                format.len(),
                args.count() - 5
            );
            return Ok(false);
        }

        let sender = self.hash_sender.clone();
        let mut optional_args: Vec<ArgumentTypes> = Vec::new();

        for specifiers in format {
            match specifiers {
                b'd' | b'i' | b'f' => {
                    optional_args.push(
                        ArgumentTypes::Primitive(
                            *args.next::<Ref<i32>>().ok_or(AmxError::Params)?
                        )
                    );
                }
                b's' => {
                    let argument: Ref<i32> = args
                        .next()
                        .ok_or(AmxError::Params)?;
                    let amx_str = AmxString::from_raw(amx, argument.address())?;
                    optional_args.push(
                        ArgumentTypes::String(amx_str.to_bytes())
                    );
                }
                _ => {
                    error!("Unknown specifier type {}", specifiers);
                    return Ok(false);
                }
            }
        }

        self.pool.execute(move || {
            bcrypt_hash_start(
                sender,
                playerid,
                input,
                callback,
                cost,
                optional_args
            );
        });

        Ok(true)
    }

    #[native(raw, name = "bcrypt_verify")]
    pub fn bcrypt_verify(
        &mut self,
        amx: &Amx,
        mut args: samp::args::Args
    ) -> AmxResult<bool> {
        let playerid = args.next::<i32>().ok_or(AmxError::Params)?;
        let callback = args
            .next::<AmxString>()
            .ok_or(AmxError::Params)?
            .to_string();
        let input = args
            .next::<AmxString>()
            .ok_or(AmxError::Params)?
            .to_string();
        let hash = args
            .next::<AmxString>()
            .ok_or(AmxError::Params)?
            .to_string();

        let mut format: Vec<u8> = Vec::new();

        if args.count() > 4 {
            if let Some(specifiers) = args.next::<AmxString>() {
                format = specifiers.to_bytes();
            }
        }

        if !format.is_empty() && format.len() != args.count() - 5 {
            error!(
                "The argument count mismatch expected: {} provided: {}.",
                format.len(),
                args.count() - 5
            );
            return Ok(false);
        }

        let sender = self.verify_sender.clone();
        let mut optional_args: Vec<ArgumentTypes> = Vec::new();

        for specifiers in format {
            match specifiers {
                b'd' | b'i' | b'f' => {
                    optional_args.push(
                        ArgumentTypes::Primitive(
                            *args.next::<Ref<i32>>().ok_or(AmxError::Params)?
                        )
                    );
                }
                b's' => {
                    let argument: Ref<i32> = args
                        .next()
                        .ok_or(AmxError::Params)?;
                    let amx_str = AmxString::from_raw(amx, argument.address())?;
                    optional_args.push(
                        ArgumentTypes::String(amx_str.to_bytes())
                    );
                }
                _ => {
                    error!("Unknown specifier type {}", specifiers);
                    return Ok(false);
                }
            }
        }

        self.pool.execute(move || {
            bcrypt_hash_verify(
                sender,
                playerid,
                input,
                hash,
                callback,
                optional_args
            );
        });

        Ok(true)
    }

    // argon2
    #[native(raw, name = "argon2_hash")]
    pub fn argon2_hash(
        &mut self,
        amx: &Amx,
        mut args: samp::args::Args
    ) -> AmxResult<bool> {
        let playerid = args.next::<i32>().ok_or(AmxError::Params)?;
        let callback = args
            .next::<AmxString>()
            .ok_or(AmxError::Params)?
            .to_string();
        let password = args
            .next::<AmxString>()
            .ok_or(AmxError::Params)?
            .to_string();
        let salt = args
            .next::<AmxString>()
            .ok_or(AmxError::Params)?
            .to_string();
        let variant = args.next::<u32>().ok_or(AmxError::Params)?;
        let mem_cost = args.next::<u32>().ok_or(AmxError::Params)?;
        let time_cost = args.next::<u32>().ok_or(AmxError::Params)?;
        let lanes = args.next::<u32>().ok_or(AmxError::Params)?;
        let hash_length = args.next::<u32>().ok_or(AmxError::Params)?;

        let mut format: Vec<u8> = Vec::new();

        if args.count() > 9 {
            if let Some(specifiers) = args.next::<AmxString>() {
                format = specifiers.to_bytes();
            }
        }

        if !format.is_empty() && format.len() != args.count() - 10 {
            error!(
                "The argument count mismatch expected: {} provided: {}.",
                format.len(),
                args.count() - 10
            );
            return Ok(false);
        }

        let sender = self.hash_sender.clone();
        let mut optional_args: Vec<ArgumentTypes> = Vec::new();

        for specifiers in format {
            match specifiers {
                b'd' | b'i' | b'f' => {
                    optional_args.push(
                        ArgumentTypes::Primitive(
                            *args.next::<Ref<i32>>().ok_or(AmxError::Params)?
                        )
                    );
                }
                b's' => {
                    let argument: Ref<i32> = args
                        .next()
                        .ok_or(AmxError::Params)?;
                    let amx_str = AmxString::from_raw(amx, argument.address())?;
                    optional_args.push(
                        ArgumentTypes::String(amx_str.to_bytes())
                    );
                }
                _ => {
                    error!("Unknown specifier type {}", specifiers);
                    return Ok(false);
                }
            }
        }

        let config = Config {
            ad: &[],
            hash_length,
            lanes,
            mem_cost,
            secret: &[],
            time_cost,
            variant: Variant::from_u32(variant).unwrap(),
            version: Version::Version13,
        };

        self.pool.execute(move || {
            argon2_hash_start(
                sender,
                playerid,
                password,
                salt,
                callback,
                config.clone(),
                optional_args
            );
        });

        Ok(true)
    }

    #[native(raw, name = "argon2_verify")]
    pub fn argon2_verify(
        &mut self,
        amx: &Amx,
        mut args: samp::args::Args
    ) -> AmxResult<bool> {
        let playerid = args.next::<i32>().ok_or(AmxError::Params)?;
        let callback = args
            .next::<AmxString>()
            .ok_or(AmxError::Params)?
            .to_string();
        let input = args
            .next::<AmxString>()
            .ok_or(AmxError::Params)?
            .to_string();
        let hash = args
            .next::<AmxString>()
            .ok_or(AmxError::Params)?
            .to_string();

        let mut format: Vec<u8> = Vec::new();

        if args.count() > 4 {
            if let Some(specifiers) = args.next::<AmxString>() {
                format = specifiers.to_bytes();
            }
        }

        if !format.is_empty() && format.len() != args.count() - 5 {
            error!(
                "The argument count mismatch expected: {} provided: {}.",
                format.len(),
                args.count() - 5
            );
            return Ok(false);
        }

        let sender = self.verify_sender.clone();
        let mut optional_args: Vec<ArgumentTypes> = Vec::new();

        for specifiers in format {
            match specifiers {
                b'd' | b'i' | b'f' => {
                    optional_args.push(
                        ArgumentTypes::Primitive(
                            *args.next::<Ref<i32>>().ok_or(AmxError::Params)?
                        )
                    );
                }
                b's' => {
                    let argument: Ref<i32> = args
                        .next()
                        .ok_or(AmxError::Params)?;
                    let amx_str = AmxString::from_raw(amx, argument.address())?;
                    optional_args.push(
                        ArgumentTypes::String(amx_str.to_bytes())
                    );
                }
                _ => {
                    error!("Unknown specifier type {}", specifiers);
                    return Ok(false);
                }
            }
        }

        self.pool.execute(move || {
            argon2_hash_verify(
                sender,
                playerid,
                input,
                hash,
                callback,
                optional_args
            );
        });

        Ok(true)
    }

    // extra
    #[native(name = "crypto_get_hash")]
    pub fn crypto_get_hash(
        &mut self,
        _: &Amx,
        dest: UnsizedBuffer,
        size: usize
    ) -> AmxResult<bool> {
        match self.hashes.front() {
            Some(hash) => {
                let mut dest = dest.into_sized_buffer(size);
                let result = samp::cell::string::put_in_buffer(
                    &mut dest,
                    &hash
                );

                let is_argon2 = if is_argon2_hash(&hash) {
                    "argon2"
                } else {
                    "bcrypt"
                };

                if result.is_err() {
                    match result.err().unwrap() {
                        AmxError::General => {
                            error!(
                                "[{}] The hash buffer is too small. Expected: {} provided: {}.",
                                is_argon2,
                                hash.len() + 1,
                                size
                            );
                            return Ok(false);
                        }
                        _ => {
                            return Ok(false);
                        }
                    }
                }

                Ok(true)
            }
            None => Ok(false),
        }
    }

    #[native(name = "crypto_set_thread_limit")]
    pub fn crypto_set_thread_limit(
        &mut self,
        _: &Amx,
        value: i32
    ) -> AmxResult<bool> {
        if value < 1 {
            error!("Number of threads must be at least 1.");
            return Ok(false);
        }
        self.pool.set_num_threads(value as usize);
        Ok(true)
    }
}
