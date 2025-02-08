# SampCrypto
![Build](https://github.com/tiaansu/samp-crypto/actions/workflows/build.yml/badge.svg)
[![GitHub issues](https://img.shields.io/github/issues/Sreyas-Sreelal/samp-bcrypt.svg)](https://github.com/Sreyas-Sreelal/samp-bcrypt/issues) [![GitHub pull requests](https://img.shields.io/github/issues-pr-raw/sreyas-sreelal/samp-bcrypt.svg)](https://github.com/Sreyas-Sreelal/samp-bcrypt/pulls) [![GitHub pull license](https://img.shields.io/github/license/sreyas-sreelal/samp-bcrypt.svg)](LICENSE)

A crypto plugin for samp in Rust.

## Installation
* Download suitable binary files from releases for your operating system
* Add it to your `plugins` folder
* Add `samp_crypto` to server.cfg or `samp_crypto.so` (for linux)
* Add [samp_crypto.inc](include/samp_crypto.inc) and [samp_crypto_inline.inc](include/samp_crypto_inline.inc) in includes folder

## Building
* Clone the repo   
    `git clone https://github.com/tiaansu/samp-crypto.git`

* Build   
    `cargo build --release`

## API
### BCrypt
* #### bcrypt_hash(playerid, const callback[], const input[], cost = BCRYPT_COST, const args[] = "", {Float, _}:...)
    **Params**   
        `playerid` - id of the player   
        `callback[]` - callback to execute after hashing   
        `input[]` - strign to hash   
        `cost` - work factor (4 - 31)   
        `args` - custom arguments   

    **Example**   
    ```pwn
    main()
    {
        bcrypt_hash(0, "OnPassswordHash", "text", BCRYPT_COST);
    }

    forward OnPassswordHash(playerid);
    public OnPassswordHash(playerid)
    {
        // get the hash
    }
    ```

* #### bcrypt_verify(playerid, const callback[], const input[], const hash[], const args[] = "", {Float, _}:...)
    **Params**    
        `playerid` - id of the player   
        `callback[]` - callback to execute after verifying   
        `input[]` - text to compare with hash    
        `hash[]` - hash to compare with text   
        `args` - custom arguments   

    **Example**
    ```pwn
    main()
    {
        bcrypt_verify(0, "OnPassswordVerify", "text", "$2y$12$lSzxFYNULh7weMGb8tf0beY1Lkb429nF.umuO/n0O.Q3U6wb1h5x.");
    }
    
    forward OnPassswordVerify(playerid, bool:success);
    public OnPassswordVerify(playerid, bool:success)
    {
        printf("%s", success ? "success" : "failed");
    }
    ```

### Argon2
* #### argon2_hash(playerid, const callback[], const password[], const salt[], E_ARGON2_VARIANT:variant = ARGON2ID, mem_cost = ARGON2_MEM_COST, time_cost = ARGON2_TIME_COST, lanes = ARGON2_LANES, hash_length = ARGON2_HASH_LENGTH, const args[] = "", { Float, _}:...)
    **Params**   
        `playerid` - id of the player   
        `callback[]` - callback to execute after hashing   
        `password[]` - password to hash   
        `salt[]` - salt   
        `variant` - variant   
        `mem_cost` - memory cost   
        `time_cost` - time cost   
        `lanes` - number of lanes   
        `hash_length` - hash length   
        `args` - custom arguments   

    **Example**
    ```pwn
    main()
    {
        argon2_hash(0, "OnPassswordHash", "text", "SALT@123@salt");
    }

    forward OnPassswordHash(playerid);
    public OnPassswordHash(playerid)
    {
        // get the hash
    }
    ```

* #### argon2_verify(playerid, const callback[], const input[], const hash[], const args[] = "", {Float, _}: ...)
    **Params**   
        `playerid` - id of the player   
        `callback[]` - callback to execute after verifying   
        `input[]` - text to compare with hash   
        `hash[]` - hash to compare with text   
        `args` - custom arguments   

    **Example**
    ```pwn
    main()
    {
        argon2_verify(0, "OnPassswordVerify", "text", "$argon2id$v=19$m=32768,t=3,p=4$U0FMVEAxMjNAc2FsdA$12BH1JyWdygQP+fhLLl98V42+ucH6gnBHUluSIeBBQkLgzQA2JKmmK2tvHw21O5Z5XCFssKPl4CL39VrXHYm8g");
    }
    
    forward OnPassswordVerify(playerid, bool:success);
    public OnPassswordVerify(playerid, bool:success)
    {
        printf("%s", success ? "success" : "failed");
    }
    ```

### Config & Extra
* #### crypto_set_thread_limit(value)
    **Params**
        `value` - number of worker threads at a time.

    **Example**
    ```pwn
    main()
    {
        crypto_set_thread_limit(3);
        // other crypto functions
    }
    ```

    > [!IMPORTANT]   
    > - You must call it before other crypto functions
    > - You must set a lower value if you don't want to experience high CPU usage

* #### crypto_get_hash(hash[], size = sizeof hash)
    **Params**   
        `hash[]` - string to store hashed data   
        `size` - max size of hash   

    **Example**
    ```pwn
    main()
    {
        bcrypt_hash(0, "OnPasswordHash", "text", BCRYPT_COST);
    }

    forward OnPasswordHash(playerid);
    public OnPasswordHash(playerid)
    {
        new dest[BCRYPT_HASH_LENGTH];
        // this if check isn't a must but it's recommended
        // to ensure that you get a valid hash
        if (crypto_get_hash(dest))
        {
            printf("hash: %s", dest);
        }
    }
    ```