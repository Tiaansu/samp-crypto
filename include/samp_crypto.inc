#if defined _samp_bcrypt_included
    #error samp_bcrypt is already included. If you want to use samp_crypto, remove the samp_bcrypt first in the include and in the plugins.
#endif

#if defined _inc_samp_crypto
    #undef _inc_samp_crypto
#endif

#if defined _samp_crypto_included
    #endinput
#endif
#define _samp_crypto_included

#if !defined BCRYPT_HASH_LENGTH
    #define BCRYPT_HASH_LENGTH (61)
#endif

#if !defined BCRYPT_COST
    #define BCRYPT_COST (12)
#endif

#if !defined ARGON2_MEM_COST
    #define ARGON2_MEM_COST (32768) // 32MB
#endif

#if !defined ARGON2_TIME_COST
    #define ARGON2_TIME_COST 3
#endif

#if !defined ARGON2_LANES
    #define ARGON2_LANES 4
#endif

#if !defined ARGON2_HASH_LENGTH
    #define ARGON2_HASH_LENGTH (64)
#endif

enum E_ARGON2_VARIANT
{
    ARGON2D = 0,
    ARGON2I,
    ARGON2ID,
}

// bcrypt
/*
bcrypt_hash(playerid, const callback[], const input[], cost = BCRYPT_COST, const args[] = "", {Float, _}:...)
    Params
        `playerid` - id of the player
        `callback[]` - callback to execute after hashing
        `input[]` - strign to hash
        `cost` - work factor (4 - 31)
        `args` - custom arguments

    Example
        ```
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
 */
native bcrypt_hash(playerid, const callback[], const input[], cost = BCRYPT_COST, const args[] = "", {Float, _}:...);

/*
bcrypt_verify(playerid, const callback[], const input[], const hash[], const args[] = "", {Float, _}:...)
    Params
        `playerid` - id of the player
        `callback[]` - callback to execute after verifying
        `input[]` - text to compare with hash
        `hash[]` - hash to compare with text
        `args` - custom arguments

    Example
        ```
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
 */
native bcrypt_verify(playerid, const callback[], const input[], const hash[], const args[] = "", {Float, _}: ...);

// argon2
/*
argon2_hash(playerid, const callback[], const password[], const salt[], E_ARGON2_VARIANT:variant = ARGON2ID, mem_cost = ARGON2_MEM_COST, time_cost = ARGON2_TIME_COST, lanes = ARGON2_LANES, hash_length = ARGON2_HASH_LENGTH, const args[] = "", { Float, _}:...)
    Params
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

    Example
        ```
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
 */
native argon2_hash(playerid, const callback[], const password[], const salt[], E_ARGON2_VARIANT:variant = ARGON2ID, mem_cost = ARGON2_MEM_COST, time_cost = ARGON2_TIME_COST, lanes = ARGON2_LANES, hash_length = ARGON2_HASH_LENGTH, const args[] = "", { Float, _}:...);

/*
argon2_verify(playerid, const callback[], const input[], const hash[], const args[] = "", {Float, _}: ...)
    Params
        `playerid` - id of the player
        `callback[]` - callback to execute after verifying
        `input[]` - text to compare with hash
        `hash[]` - hash to compare with text
        `args` - custom arguments

    Example
        ```
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
 */
native argon2_verify(playerid, const callback[], const input[], const hash[], const args[] = "", {Float, _}: ...);

/*
crypto_set_thread_limit(value)
    Params
        `value` - number of worker threads at a time.

    Example
        ```
        main()
        {
            crypto_set_thread_limit(3);
            // other crypto functions
        }
        ```

    Note
        - You must call it before other crypto functions
        - You must set a lower value if you don't want to experience high CPU usage
 */
native crypto_set_thread_limit(value);

/*
crypto_get_hash(hash[], size = sizeof hash)
    Params
        `hash[]` - string to store hashed data
        `size` - max size of hash

    Example
        ```
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
 */
native crypto_get_hash(hash[], size = sizeof hash);
