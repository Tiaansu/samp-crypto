use std::collections::LinkedList;

use plugin::SampCrypto;
use samp::initialize_plugin;
use threadpool::ThreadPool;

mod internals;
mod natives;
mod plugin;

initialize_plugin!(
    natives: [
        SampCrypto::bcrypt_hash,
        SampCrypto::bcrypt_verify,
        SampCrypto::argon2_hash,
        SampCrypto::argon2_verify,
        SampCrypto::crypto_get_hash,
        SampCrypto::crypto_set_thread_limit,
    ],
    {
        samp::plugin::enable_process_tick();
        let samp_logger = samp::plugin::logger()
            .level(log::LevelFilter::Info);

        let _ = fern::Dispatch::new()
            .format(|callback, message, record| {
                callback.finish(format_args!("[SampCrypto] [{}]: {}", record.level().to_string().to_lowercase(), message))
            })
            .chain(samp_logger)
            .apply();

        SampCrypto {
            hashes: LinkedList::new(),
            pool: ThreadPool::new(3),
            hash_receiver: None,
            hash_sender: None,
            verify_receiver: None,
            verify_sender: None,
            amx_list: Vec::new()
        }
    }
);
