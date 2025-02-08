#if defined _samp_bcrypt_included
    #error samp_bcrypt is already included. If you want to use samp_crypto, remove the samp_bcrypt first in the include and in the plugins.
#endif

#if defined _INC_y_bcrypt
    #error y_bcrypt is already included. Remove it first if you want to use samp_crypto_inline.
#endif

#if defined _INC_y_inline_bcrypt
    #error y_inline_bcrypt is already included. Remove it first if you want to use samp_crypto_inline.
#endif

#if defined _inc_samp_crypto_inline
    #undef _inc_samp_crypto_inline
#endif

#if defined _samp_crypto_inline_included
    #endinput
#endif
#define _samp_crypto_inline_included

#if !defined _INC_y_inline
	#tryinclude "..\YSI_Coding\y_inline\y_inline_entry"
#endif
#if !defined _INC_y_inline
	#tryinclude "YSI_Coding\y_inline\y_inline_entry"
#endif
#if !defined _INC_y_inline
	#tryinclude "YSI\YSI_Coding\y_inline\y_inline_entry"
#endif
#if !defined _INC_y_inline
	#tryinclude <YSI_Coding\y_inline\y_inline_entry>
#endif
#if !defined _INC_y_inline
	#tryinclude <YSI\YSI_Coding\y_inline\y_inline_entry>
#endif
#if !defined _INC_y_inline
	#error Could not find y_inline
#endif

#if !defined _samp_crypto_included
    #tryinclude <samp_crypto>
#endif
#if !defined _samp_crypto_included
    #error Could not find samp_crypto
#endif

enum E_CRYPTO_INLINE
{
    E_CRYPTO_INLINE_BCRYPT,
    E_CRYPTO_INLINE_ARGON2,
}

// Internal
forward _Inline_CryptoCheckDone(Func:cb<>, bool:success, E_CRYPTO_INLINE:type);
forward _Inline_CryptoHashDone(Func:cb<s>, E_CRYPTO_INLINE:type);

public _Inline_CryptoCheckDone(Func:cb<>, bool:success, E_CRYPTO_INLINE:type)
{
    new ret = @.cb(success);
    Indirect_Release(cb);
    return ret;
}

public _Inline_CryptoHashDone(Func:cb<s>, E_CRYPTO_INLINE:type)
{
    new ret = false;

    switch (type)
    {
        case E_CRYPTO_INLINE_BCRYPT:
        {
            new hash[BCRYPT_HASH_LENGTH];
            if (crypto_get_hash(hash))
            {
                ret = @.cb(hash);
            }
        }
        case E_CRYPTO_INLINE_ARGON2:
        {
            new hash[256];
            if (crypto_get_hash(hash))
            {
                ret = @.cb(hash);
            }
        }
        default:
        {
            printf("[samp_crypto_inline] Unknown crypto type: %i", _:type);
        }
    }

    Indirect_Release(cb);
    return ret;
}

// API
stock bool:BCrypt_CheckInline(const password[], const hash[], Func:cb<i>)
{
    if (bcrypt_verify(_:cb, __nameof(_Inline_CryptoCheckDone), password, hash, "i", _:E_CRYPTO_INLINE_BCRYPT))
    {
        Indirect_Claim(cb);
        return true;
    }
    return false;
}

stock BCrypt_HashInline(const password[], cost = BCRYPT_COST, {F@_@s, F@_@si}:cb)
{
    if (bcrypt_hash(_:cb, __nameof(_Inline_CryptoHashDone), password, cost))
    {
        Indirect_Claim(cb);
        return true;
    }
    return false;
}

stock bool:Argon2_CheckInline(const password[], const hash[], Func:cb<i>)
{
    if (argon2_verify(_:cb, __nameof(_Inline_CryptoCheckDone), password, hash))
    {
        Indirect_Claim(cb);
        return true;
    }
    return false;
}

stock bool:Argon2_HashInline(const password[], const salt[], Func:cb<s>, E_ARGON2_VARIANT:variant = ARGON2ID, mem_cost = ARGON2_MEM_COST, time_cost = ARGON2_TIME_COST, lanes = ARGON2_LANES, hash_length = ARGON2_HASH_LENGTH)
{
    if (argon2_hash(_:cb, __nameof(_Inline_CryptoHashDone), password, salt, variant, mem_cost, time_cost, lanes, hash_length, "i", _:E_CRYPTO_INLINE_ARGON2))
    {
        Indirect_Claim(cb);
        return true;
    }
    return false;
}