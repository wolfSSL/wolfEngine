/* we_mac.c
 *
 * Copyright (C) 2019-2021 wolfSSL Inc.
 *
 * This file is part of wolfEngine.
 *
 * wolfEngine is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * wolfengine is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1335, USA
 */

#include <wolfengine/we_internal.h>


/* Note on CMAC implementation.
 * Alias used as EVP_PKEY created with OpenSSL and wolfEngine both have the
 * wolfEngine method. Need to distinguish between the two as different data
 * types are stored:
 *    OpenSSL    - CMAC_CTX
 *    wolfEngine - ASN1_OCTET_STRING
 * CMAC_CTX doesn't allow getting key data so can't be used by wolfEngine.
 */

#if defined(WE_HAVE_HMAC) || defined(WE_HAVE_CMAC)

/* Algorithm that object is set up for using. */
/** HMAC algorithm */
#define WE_HMAC_ALGO 1
/** CMAC algorithm */
#define WE_CMAC_ALGO 2

/**
 * Data required to complete an MAC operation.
 */
typedef struct we_Mac
{
    union {
        /** wolfSSL structure for holding HMAC state. */
        Hmac hmac;
        /** wolfSSL structure for holding CMAC state. */
        Cmac cmac;
    } state;
    /** Type of algorithm i.e HMAC, CMAC ... */
    int algo;

    /** Key to use with operation. Cached for init. */
    unsigned char *key;
    /** Size of key. */
    int keySz;

    /* HMAC specific fields. */
    /** Size of digest calculated. */
    int size;
    /** Type of digest to use. */
    int type;
} we_Mac;

/**
 * Clear out the existing MAC key in mac and allocate a new key buffer of
 * newKeySz bytes. Copy newKey into that buffer.
 *
 * @param  mac       [in]  Internal MAC object.
 * @param  newKey    [in]  New key buffer.
 * @param  newKeySz  [in]  New key buffer size.
 * @returns  1 on success and 0 on failure.
 */
static int we_mac_set_key(we_Mac* mac, const unsigned char* newKey,
    int newKeySz)
{
    int ret = 1;

    WOLFENGINE_ENTER(WE_LOG_MAC, "we_mac_set_key");

    if (mac == NULL) {
        WOLFENGINE_ERROR_MSG(WE_LOG_MAC, "we_mac_set_key called with NULL "
            "mac");
        ret = 0;
    }
    if (newKeySz < 0) {
        WOLFENGINE_ERROR_MSG(WE_LOG_MAC, "we_mac_set_key called with newKeySz "
            "< 0");
        ret = 0;
    }

    if (ret == 1) {
        /* Dispose of old key. */
        if (mac->key != NULL) {
            OPENSSL_clear_free(mac->key, mac->keySz);
        }
        /* We allow the key size to be 0, which OpenSSL also allows. In that
         * case, we need to allocate at least one byte, which we'll set to a
         * null terminator. */
        mac->key = (unsigned char *)OPENSSL_malloc(newKeySz + 1);
        if (mac->key == NULL) {
            WOLFENGINE_ERROR_FUNC_NULL(WE_LOG_MAC, "OPENSSL_malloc", mac->key);
            ret = 0;
        }
        else {
            XMEMCPY(mac->key, newKey, newKeySz);
            mac->key[newKeySz] = '\0';
            mac->keySz = newKeySz;
        }
    }

    WOLFENGINE_LEAVE(WE_LOG_MAC, "we_mac_set_key", ret);

    return ret;
}

/**
 * Create ASN.1 octet string from key in context.
 *
 * @param  ctx   [in]   EVP_PKEY context being used.
 * @param  pKey  [out]  ASN.1 octet string object.
 * @returns  1 on success and 0 on failure.
 */
static int we_mac_get_asn1_key(EVP_PKEY_CTX *ctx, ASN1_OCTET_STRING **pKey)
{
    int ret = 1;
    ASN1_OCTET_STRING *key = NULL;
    we_Mac *mac;

    WOLFENGINE_ENTER(WE_LOG_MAC, "we_mac_get_asn1_key");

    /* Retrieve the internal MAC object. */
    mac = (we_Mac *)EVP_PKEY_CTX_get_data(ctx);
    if (mac == NULL) {
        WOLFENGINE_ERROR_FUNC_NULL(WE_LOG_MAC, "EVP_PKEY_CTX_get_data", mac);
        ret = 0;
    }
    if (ret == 1) {
        /* Create new ASN1 octet string to hold key and be assigned to PKEY. */
        key = ASN1_OCTET_STRING_new();
        if (key == NULL) {
            ret = 0;
        }
    }
    if (ret == 1) {
        /* Copy the key into ASN.1 octet string. */
        ASN1_OCTET_STRING_set(key, mac->key, mac->keySz);
    }

    WOLFENGINE_LEAVE(WE_LOG_MAC, "we_mac_get_asn1_key", ret);

    *pKey = key;
    return ret;
}

/**
 * Initialize the MAC structure and set against context.
 *
 * @param  ctx   [in]   EVP_PKEY context of operation.
 * @param  pMac  [out]  New internal MAC object.
 * @returns  1 on success and 0 on failure.
 */
static int we_mac_pkey_init(EVP_PKEY_CTX *ctx, we_Mac** pMac)
{
    int ret = 1;
    we_Mac *mac = NULL;

    WOLFENGINE_ENTER(WE_LOG_MAC, "we_mac_pkey_init");
    WOLFENGINE_MSG_VERBOSE(WE_LOG_MAC, "ARGS [ctx = %p]", ctx);

    /* Parameter validation. */
    if (ctx == NULL) {
        WOLFENGINE_ERROR_FUNC_NULL(WE_LOG_MAC, "we_mac_pkey_init, ctx: ", ctx);
        ret = 0;
    }

    if (ret == 1) {
        /* Allocate internal MAC object. */
        mac = (we_Mac *)OPENSSL_zalloc(sizeof(we_Mac));
        if (mac == NULL) {
            WOLFENGINE_ERROR_FUNC_NULL(WE_LOG_MAC, "OPENSSL_zalloc", mac);
            ret = 0;
        }
    }

    if (ret == 1) {
        /* Store internal MAC object for later use. */
        EVP_PKEY_CTX_set_data(ctx, mac);
    }

    if ((ret == 0) && (mac != NULL)) {
        /* Deallocate and return NULL. */
        OPENSSL_free(mac);
        mac = NULL;
    }

    WOLFENGINE_LEAVE(WE_LOG_MAC, "we_mac_pkey_init", ret);

    *pMac = mac;
    return ret;
}

/**
 * Get the MAC key and cache it in internal MAC object.
 *
 * @param  ctx  [in]  EVP_PKEY context of operation.
 * @param  mac  [in]  Internal MAC object to initialize.
 * @returns  1 on success and 0 on failure.
 */
static int we_mac_cache_key(EVP_PKEY_CTX *ctx, we_Mac *mac)
{
    int ret = 1;
    ASN1_OCTET_STRING *key;
    EVP_PKEY *pkey;
    int dataLen;
    const unsigned char *data;

    WOLFENGINE_ENTER(WE_LOG_MAC, "we_mac_cache_key");

    if (ctx == NULL || mac == NULL) {
        WOLFENGINE_ERROR_MSG(WE_LOG_MAC, "we_mac_cache_key called with null "
            "parameter.");
        ret = 0;
    }

    if (ret == 1) {
        /* Get PKEY associated with ctx for password/key. */
        pkey = EVP_PKEY_CTX_get0_pkey(ctx);
        if (pkey == NULL) {
            ret = 0;
        }
        if (ret == 1) {
            /* Get password/key as an ASN.1 octet string. */
            key = (ASN1_OCTET_STRING*)EVP_PKEY_get0(pkey);
            if (key == NULL) {
                ret = 0;
            }
        }
    }

    if (ret == 1) {
        /* Get key length and data. */
        dataLen = ASN1_STRING_length(key);
        data    = ASN1_STRING_get0_data(key);
        if (data == NULL || dataLen < 0) {
            ret = 0;
        }
    }
    if (ret == 1) {
        ret = we_mac_set_key(mac, data, dataLen);
    }

    WOLFENGINE_LEAVE(WE_LOG_MAC, "we_mac_cache_key", ret);

    return ret;
}

#ifdef WE_HAVE_HMAC

/**
 * Initialize the MAC for HMAC operations.
 *
 * @param  ctx  [in]  EVP_PKEY context of operation.
 * @param  mac  [in]  MAC object initialize.
 * @returns  1 on success and 0 on failure.
 */
static int we_mac_hmac_init(EVP_PKEY_CTX *ctx, we_Mac *mac)
{
    int ret;
    int rc;
    int blockSize;

    WOLFENGINE_ENTER(WE_LOG_MAC, "we_mac_hmac_init");

    /* Get key into cache. */
    ret = we_mac_cache_key(ctx, mac);
    if (ret == 1) {
        /* Set HMAC key into wolfSSL HMAC object. */
        WOLFENGINE_MSG(WE_LOG_MAC, "Setting HMAC key");
        blockSize = wc_HashGetBlockSize(mac->type);
        if (blockSize <= 0) {
            WOLFENGINE_ERROR_FUNC(WE_LOG_MAC, "wc_HashGetBlockSize", blockSize);
            ret = 0;
        }
    }
    if (ret == 1 && mac->keySz < blockSize) {
        /* If the key is smaller than the block size of the underlying hash
         * algorithm, we need to pad the key with zeroes to the block
         * size. */
        mac->key = OPENSSL_realloc(mac->key, blockSize);
        if (mac->key == NULL) {
            WOLFENGINE_ERROR_FUNC_NULL(WE_LOG_MAC, "OPENSSL_realloc", 
                mac->key);
            ret = 0;
        }
        else {
            XMEMSET(mac->key + mac->keySz, 0, blockSize - mac->keySz);
            mac->keySz = blockSize;
        }
    }
    if (ret == 1) {
        rc = wc_HmacSetKey(&mac->state.hmac, mac->type,
                 (const byte*)mac->key, (word32)mac->keySz);
        if (rc != 0) {
            WOLFENGINE_ERROR_FUNC(WE_LOG_MAC, "wc_HmacSetKey", rc);
            ret = 0;
        }
    }

    WOLFENGINE_LEAVE(WE_LOG_MAC, "we_mac_hmac_init", ret);

    return ret;
}
#endif

#ifdef WE_HAVE_CMAC

/**
 * Initialize the MAC for CMAC operations.
 *
 * @param  ctx  [in]  EVP_PKEY context of operation.
 * @param  mac  [in]  MAC object initialize.
 * @returns  1 on success and 0 on failure.
 */
static int we_mac_cmac_init(EVP_PKEY_CTX *ctx, we_Mac *mac)
{
    int ret;
    int rc;

    WOLFENGINE_ENTER(WE_LOG_MAC, "we_mac_cmac_init");
    WOLFENGINE_MSG_VERBOSE(WE_LOG_MAC, "ARGS [ctx = %p, mac = %p]", ctx, mac);

    /* Get key into cache. */
    ret = we_mac_cache_key(ctx, mac);
    if (ret == 1) {
        WOLFENGINE_MSG(WE_LOG_MAC, "Initializing wolfCrypt Cmac structure: %p",
            &mac->state.cmac);
        /* Initialize wolfSSL CMAC object with key. */
        rc = wc_InitCmac(&mac->state.cmac, (const byte*)mac->key, mac->keySz,
            WC_CMAC_AES, NULL);
        if (rc != 0) {
            WOLFENGINE_ERROR_FUNC(WE_LOG_MAC, "wc_InitCmac", rc);
            ret = 0;
        }
    }

    WOLFENGINE_LEAVE(WE_LOG_MAC, "we_mac_cmac_init", ret);

    return ret;
}
#endif

#ifdef WE_HAVE_HMAC
/**
 * Convert an EVP_MD to a hash type that wolfSSL understands.
 *
 * @param  md [in] EVP_MD to get hash type from.
 * @returns  WC_HASH_TYPE_NONE on failure and hash type on success.
 */
static int we_mac_md_to_hash_type(EVP_MD *md)
{
    int ret;

    WOLFENGINE_ENTER(WE_LOG_MAC, "we_mac_md_to_hash_type");
    WOLFENGINE_MSG_VERBOSE(WE_LOG_MAC, "ARGS [md = %p]", md);

    /* Convert EVP_MD to a wolfCrypt hash type. */
    ret = we_nid_to_wc_hash_type(EVP_MD_type(md));

    WOLFENGINE_LEAVE(WE_LOG_MAC, "we_mac_md_to_hash_type", ret);

    return ret;
}
#endif

/**
 * Function that is called for setting key, EVP_MD, and digest init.
 *
 * Supported operations include:
 *  - EVP_PKEY_CTRL_MD: set digest to use or initialize CMAC operation.
 *  - EVP_PKEY_CTRL_SET_MAC_KEY: set password/key to use.
 *  - EVP_PKEY_CTRL_CIPHER: set cipher to use (ignored).
 *  - EVP_PKEY_CTRL_DIGESTINIT: initialize HMAC's digest.
 *
 * @param  ctx   [in]  EVP_PKEY context being used.
 * @param  type  [in]  Type of operation to perform.
 * @param  num   [in]  Integer parameter.
 * @param  ptr   [in]  Pointer parameter.
 * @returns  1 on success and 0 on failure.
 */
static int we_mac_pkey_ctrl(EVP_PKEY_CTX *ctx, int type, int num, void *ptr)
{
    int ret = 1;
    we_Mac *mac = NULL;
    char errBuff[WOLFENGINE_MAX_LOG_WIDTH];

    WOLFENGINE_ENTER(WE_LOG_MAC, "we_mac_pkey_ctrl");
    WOLFENGINE_MSG_VERBOSE(WE_LOG_MAC, "ARGS [ctx = %p, type = %d, num = %d, "
                           "ptr = %p]", ctx, type, num, ptr);

    /* Validate parameters. */
    if (ctx == NULL) {
        WOLFENGINE_ERROR_FUNC_NULL(WE_LOG_MAC, "we_mac_pkey_ctrl", ctx);
        ret = 0;
    }

    if (ret == 1) {
        /* Retrieve the internal MAC object. */
        mac = (we_Mac *)EVP_PKEY_CTX_get_data(ctx);
        if (mac == NULL) {
            WOLFENGINE_ERROR_FUNC_NULL(WE_LOG_MAC, "EVP_PKEY_CTX_get_data",
                                       mac);
            ret = 0;
        }
    }

    if (ret == 1) {
        switch (type) {
            /* Set digest to use or initialize CMAC. */
            case EVP_PKEY_CTRL_MD:
                /* ptr  [in]  EVP_MD digest to use with HMAC. */
                WOLFENGINE_MSG(WE_LOG_MAC, "type: EVP_PKEY_CTRL_MD");
            #ifdef WE_HAVE_HMAC
                if ((ptr != NULL) && (mac->algo == WE_HMAC_ALGO)) {
                    /* Get hash type from EVP_MD object. */
                    mac->type = we_mac_md_to_hash_type((EVP_MD *)ptr);
                    /* Check if digest is supported. */
                    if (mac->type == WC_HASH_TYPE_NONE) {
                        WOLFENGINE_ERROR_FUNC(WE_LOG_MAC,
                            "we_mac_md_to_hash_type", mac->type);
                        ret = 0;
                    }
                    else {
                        /* Get the size of the digest/HMAC output. */
                        mac->size = wc_HmacSizeByType(mac->type);
                        if (mac->size <= 0) {
                            WOLFENGINE_ERROR_FUNC(WE_LOG_MAC,
                                "wc_HmacSizeByType", mac->size);
                            ret = 0;
                        }
                    }
                }
                else
            #endif
            #ifdef WE_HAVE_CMAC
                if (mac->algo == WE_CMAC_ALGO) {
                    /* Set key into wolfSSL CMAC object. */
                    ret = we_mac_cmac_init(ctx, mac);
                }
                else
            #endif
                {
                    /* No EVP_MD or invalid algorithm. */
                    ret = 0;
                }
                break;

            /* Set password/key passed for MAC. */
            case EVP_PKEY_CTRL_SET_MAC_KEY:
                /* ptr  [in]  Buffer holding key.
                 * num  [in]  Length of key in bytes.
                 */
                WOLFENGINE_MSG(WE_LOG_MAC, "type: EVP_PKEY_CTRL_SET_MAC_KEY");
                if (ptr != NULL && num >= 0) {
                    ret = we_mac_set_key(mac, ptr, num);
                }
                else {
                    ret = 0;
                }
                break;

            /* Set EVP_CIPHER for MAC. */
            case EVP_PKEY_CTRL_CIPHER:
                /* ptr  [in]  EVP_CIPHER object. */
                WOLFENGINE_MSG(WE_LOG_MAC, "type: EVP_PKEY_CTRL_CIPHER");
                /* Do nothing, we use internal AES */
                break;

            /* Initialize the digest operation. */
            case EVP_PKEY_CTRL_DIGESTINIT:
                WOLFENGINE_MSG(WE_LOG_MAC, "type: EVP_PKEY_CTRL_DIGESTINIT");
            #ifdef WE_HAVE_HMAC
                if (mac->algo == WE_HMAC_ALGO) {
                    /* Set key into wolfSSL HMAC object. */
                    ret = we_mac_hmac_init(ctx, mac);
                }
                else
            #endif
                {
                    /* Not valid for CMAC. */
                    ret = 0;
                }
                break;

            default:
                /* Unsupported control type - return error. */
                XSNPRINTF(errBuff, sizeof(errBuff), "Unsupported ctrl type %d",
                          type);
                WOLFENGINE_ERROR_MSG(WE_LOG_CIPHER, errBuff);
                ret = 0;
        }
    }

    WOLFENGINE_LEAVE(WE_LOG_MAC, "we_mac_pkey_ctrl", ret);

    return ret;
}


/**
 * Handle control string values.
 *
 * Currently a stub function.
 *
 * @param  ctx   [in]  EVP_PKEY context being used.
 * @param  type  [in]  String with the type of ctrl to do.
 * @param  value [in]  Action or data to use.
 * @returns  1 on success and 0 on failure.
 */
static int we_mac_pkey_ctrl_str(EVP_PKEY_CTX *ctx, const char *type,
        const char *value)
{
    int ret = 0;

    (void)ctx;
    (void)type;
    (void)value;

    WOLFENGINE_ENTER(WE_LOG_MAC, "we_mac_pkey_ctrl_str");
    WOLFENGINE_ERROR_MSG(WE_LOG_MAC,
            "This function is currently a stub, was not used in test cases");

    /* TODO: "key", "hexkey", "cipher" */

    WOLFENGINE_LEAVE(WE_LOG_MAC, "we_mac_pkey_ctrl_str", ret);

    return ret;
}

/**
 * Duplicate an internal MAC object.
 *
 * @param  src   [in]   Structure to make a copy of.
 * @param  dst   [out]  New internal MAC object.
 * @returns  1 on success and 0 on failure.
 */
static int we_mac_dup(we_Mac *src, we_Mac **dst)
{
    int ret = 1;
    we_Mac *mac = NULL;

    WOLFENGINE_ENTER(WE_LOG_MAC, "we_mac_dup");
    WOLFENGINE_MSG_VERBOSE(WE_LOG_MAC, "ARGS [src = %p]", src);

    /* Validate parameters. */
    if (src == NULL) {
        WOLFENGINE_ERROR_FUNC_NULL(WE_LOG_MAC, "we_mac_dup", src);
        ret = 0;
    }

    if (ret == 1) {
        /* Allocate memory for new internal MAC object. */
        mac = (we_Mac *)OPENSSL_zalloc(sizeof(we_Mac));
        if (mac == NULL) {
            WOLFENGINE_ERROR_FUNC_NULL(WE_LOG_MAC, "OPENSSL_zalloc", mac);
            ret = 0;
        }
    }

    if (ret == 1) {
        /* Copy over fields. */
        mac->algo  = src->algo;
        mac->size  = src->size;
        mac->type  = src->type;
        mac->keySz = src->keySz;
        /* Duplicate the key if set. */
        if (src->keySz >= 0) {
            ret = we_mac_set_key(mac, src->key, src->keySz);
        }
        else {
            mac->key = NULL;
        }
    }

    if ((ret != 1) && (mac != NULL)) {
        /* Duplicating key is last thing attempted - no need to free. */
        /* Dispose of duplicate object on failure. */
        OPENSSL_free(mac);
        /* Ensure no MAC object on failure. */
        mac = NULL;
    }

    WOLFENGINE_LEAVE(WE_LOG_MAC, "we_mac_dup", ret);

    /* Return duplicate MAC object. */
    *dst = mac;
    return ret;
}

/**
 * Free up the state and MAC object.
 *
 * @param  ctx  [in]  EVP_PKEY context of operation.
 */
static void we_mac_pkey_cleanup(EVP_PKEY_CTX *ctx)
{
    int ret = 1;
    we_Mac *mac;

    WOLFENGINE_ENTER(WE_LOG_MAC, "we_mac_pkey_cleanup");
    if (ctx == NULL) {
        WOLFENGINE_ERROR_FUNC_NULL(WE_LOG_MAC, "we_mac_pkey_cleanup, ctx: ",
                                   ctx);
        ret = 0;
    }

    if (ret == 1) {
        /* Retrieve the internal MAC object. */
        mac = (we_Mac *)EVP_PKEY_CTX_get_data(ctx);
        if (mac == NULL) {
            WOLFENGINE_ERROR_FUNC_NULL(WE_LOG_MAC,
                                       "EVP_PKEY_CTX_get_data", mac);
            ret = 0;
        }
    }

    if (ret == 1) {
        /* Remove reference in context to internal MAC object. */
        EVP_PKEY_CTX_set_data(ctx, NULL);

        switch (mac->algo) {
        #ifdef WE_HAVE_HMAC
            case WE_HMAC_ALGO:
                WOLFENGINE_MSG(WE_LOG_MAC, "MAC algo: WE_HMAC_ALGO");
                /* Free the wolfSSL HMAC object. */
                wc_HmacFree(&mac->state.hmac);
                break;
        #endif
        #ifdef WE_HAVE_CMAC
            case WE_CMAC_ALGO:
                WOLFENGINE_MSG(WE_LOG_MAC, "MAC algo: WE_CMAC_ALGO");
                /* No free for wolfCrypt CMAC. */
                break;
        #endif
            default:
                /* Unsupported algorithm. */
                ret = 0;
        }

        if (mac->key != NULL) {
            /* Safely dispose of key memory. */
            OPENSSL_clear_free(mac->key, mac->keySz);
        }
        /* Dispose of internal MAC object memory. */
        OPENSSL_free(mac);
    }
    WOLFENGINE_LEAVE(WE_LOG_MAC, "we_mac_pkey_cleanup", ret);
    (void)ret;
}

/**
 * Initialize sign operation. Sets the update function into digest.
 *
 * Called by both HMAC and CMAC implementations.
 *
 * @param  ctx   [in]  EVP_PKEY context being used.
 * @param  mdCtx [in]  EVP_MD context to setup.
 * @returns  1 on success and 0 on failure.
 */
static int we_mac_pkey_signctx_init(EVP_PKEY_CTX *ctx, EVP_MD_CTX *mdCtx,
        int (fn)(EVP_MD_CTX *ctx, const void *data, size_t dataSz))
{
    int ret = 1;

    WOLFENGINE_ENTER(WE_LOG_MAC, "wc_mac_pkey_signctx_init");
    WOLFENGINE_MSG_VERBOSE(WE_LOG_MAC, "ARGS [ctx = %p, mdCtx = %p]",
                           ctx, mdCtx);

    /* Validate parameters. */
    if ((ctx == NULL) || (mdCtx == NULL)) {
        WOLFENGINE_ERROR_FUNC_NULL(WE_LOG_MAC,
                                   "we_mac_pkey_signctx_init, ctx: ", ctx);
        WOLFENGINE_ERROR_FUNC_NULL(WE_LOG_MAC,
                                   "we_mac_pkey_signctx_init, data:", mdCtx);
        ret = 0;
    }

    if (ret == 1) {
        /* Adjust the MD CTX to use our update function when EVP_DigestUpdate is
         * called. Set the flag EVP_MD_CTX_FLAG_NO_INIT to avoid 'mdCtx'
         * overriding mdCtx->update with initialization calls.
         */
        EVP_MD_CTX_set_flags(mdCtx, EVP_MD_CTX_FLAG_NO_INIT);
        EVP_MD_CTX_set_update_fn(mdCtx, fn);
    }

    WOLFENGINE_LEAVE(WE_LOG_MAC, "wc_mac_pkey_signctx_init", ret);

    return ret;
}


#ifdef WE_HAVE_HMAC

/** EVP PKEY digest method - HMAC using wolfSSL for the implementation. */
EVP_PKEY_METHOD *we_hmac_pkey_method = NULL;

/** EVP PKEY asn1 method - HMAC using wolfSSL for the implementation. */
EVP_PKEY_ASN1_METHOD *we_hmac_pkey_asn1_method = NULL;

/**
 * Setup PKEY from context.
 *
 * PKEY takes a copy of key from the internal MAC object.
 *
 * @param  ctx   [in]  EVP_PKEY context being used.
 * @param  pkey  [out] EVP_PKEY to assign values to.
 * @returns  1 on success and 0 on failure.
 */
static int we_hmac_pkey_keygen(EVP_PKEY_CTX *ctx, EVP_PKEY *pkey)
{
    int ret = 1;
    ASN1_OCTET_STRING *key;

    WOLFENGINE_ENTER(WE_LOG_MAC, "we_hmac_pkey_keygen");
    WOLFENGINE_MSG_VERBOSE(WE_LOG_MAC, "ARGS [ctx = %p, pkey = %p]", ctx, pkey);

    /* Validate parameters. */
    if ((ctx == NULL) || (pkey == NULL)) {
        WOLFENGINE_ERROR_FUNC_NULL(WE_LOG_MAC, "we_hmac_pkey_keygen, ctx:  ",
                                   ctx);
        WOLFENGINE_ERROR_FUNC_NULL(WE_LOG_MAC, "we_hmac_pkey_keygen, pkey: ",
                                   pkey);
        ret = 0;
    }

    if (ret == 1) {
        /* Make an ASN.1 octet string from key data. */
        ret = we_mac_get_asn1_key(ctx, &key);
    }
    if (ret == 1) {
        /* Assign algorithm and key to PKEY. */
        EVP_PKEY_assign(pkey, EVP_PKEY_HMAC, key);
    }

    WOLFENGINE_LEAVE(WE_LOG_MAC, "we_hmac_pkey_keygen", ret);
    return ret;
}

/**
 * Free PKEY data that is an ASN.1 octet string.
 *
 * @param  pkey  [in]  EVP PKEY being freed.
 */
static void we_hmac_pkey_free(EVP_PKEY *pkey)
{
    int ret = 1;
    ASN1_OCTET_STRING *key;

    WOLFENGINE_ENTER(WE_LOG_MAC, "we_hmac_pkey_free");
    WOLFENGINE_MSG_VERBOSE(WE_LOG_MAC, "ARGS [pkey = %p]", pkey);

    /* Get PKEY data as an ASN.1 octet string. */
    key = (ASN1_OCTET_STRING*)EVP_PKEY_get0(pkey);
    if (key == NULL) {
        ret = 0;
    }
    if (ret == 1) {
        /* Dispose of key. */
        ASN1_OCTET_STRING_free(key);
    }

    WOLFENGINE_LEAVE(WE_LOG_MAC, "we_hmac_pkey_free", ret);

    (void)ret;
}

/**
 * Copy the wolfCrypt HMAC state into new object.
 *
 * Based on wolfSSL_HmacCopy in src/ssl.c in wolfSSL.
 * Helper function for deep copy of internal wolfSSL HMAC structure
 *
 * @param  dst  [out]  wolfSSL HMAC operation to copy into.
 * @param  src  [in]   wolfSSL HMAC operation to copy from.
 * returns 1 on success, 0 on failure
 */
static int we_hmac_copy(Hmac* dst, Hmac* src)
{
    void* heap;
    int ret = 1;
    int rc = 0;
    char errBuff[WOLFENGINE_MAX_LOG_WIDTH];

    WOLFENGINE_ENTER(WE_LOG_MAC, "we_hmac_copy");
    WOLFENGINE_MSG_VERBOSE(WE_LOG_MAC, "ARGS [dst = %p, src = %p]",
                           dst, src);

#ifndef HAVE_FIPS
    heap = src->heap;
#else
    heap = NULL;
#endif
    /* Initialize new wolfCrypt HMAC object. */
    if (wc_HmacInit(dst, heap, INVALID_DEVID) != 0) {
        ret = 0;
    }

    if (ret == 1) {
        /* Use digest algorithm specific copy function for deep copy. */
        switch (src->macType) {
        #ifndef NO_MD5
            case WC_MD5:
                WOLFENGINE_MSG(WE_LOG_MAC, "macType: WC_MD5");
                rc = wc_Md5Copy(&src->hash.md5, &dst->hash.md5);
                break;
        #endif /* !NO_MD5 */

        #ifndef NO_SHA
            case WC_SHA:
                WOLFENGINE_MSG(WE_LOG_MAC, "macType: WC_SHA");
                rc = wc_ShaCopy(&src->hash.sha, &dst->hash.sha);
                break;
        #endif /* !NO_SHA */

        #ifdef WOLFSSL_SHA224
            case WC_SHA224:
                WOLFENGINE_MSG(WE_LOG_MAC, "macType: WC_SHA224");
                rc = wc_Sha224Copy(&src->hash.sha224, &dst->hash.sha224);
                break;
        #endif /* WOLFSSL_SHA224 */

        #ifndef NO_SHA256
            case WC_SHA256:
                WOLFENGINE_MSG(WE_LOG_MAC, "macType: WC_SHA256");
                rc = wc_Sha256Copy(&src->hash.sha256, &dst->hash.sha256);
                break;
        #endif /* !NO_SHA256 */

        #ifdef WOLFSSL_SHA384
            case WC_SHA384:
                WOLFENGINE_MSG(WE_LOG_MAC, "macType: WC_SHA384");
                rc = wc_Sha384Copy(&src->hash.sha384, &dst->hash.sha384);
                break;
        #endif /* WOLFSSL_SHA384 */
        #ifdef WOLFSSL_SHA512
            case WC_SHA512:
                WOLFENGINE_MSG(WE_LOG_MAC, "macType: WC_SHA512");
                rc = wc_Sha512Copy(&src->hash.sha512, &dst->hash.sha512);
                break;
        #endif /* WOLFSSL_SHA512 */
    #ifdef WOLFSSL_SHA3
        #ifndef WOLFSSL_NOSHA3_224
            case WC_SHA3_224:
                WOLFENGINE_MSG(WE_LOG_MAC, "macType: WC_SHA3_224");
                rc = wc_Sha3_224_Copy(&src->hash.sha3, &dst->hash.sha3);
                break;
        #endif /* WOLFSSL_NO_SHA3_224 */
        #ifndef WOLFSSL_NOSHA3_256
            case WC_SHA3_256:
                WOLFENGINE_MSG(WE_LOG_MAC, "macType: WC_SHA3_256");
                rc = wc_Sha3_256_Copy(&src->hash.sha3, &dst->hash.sha3);
                break;
        #endif /* WOLFSSL_NO_SHA3_256 */
        #ifndef WOLFSSL_NOSHA3_384
            case WC_SHA3_384:
                WOLFENGINE_MSG(WE_LOG_MAC, "macType: WC_SHA3_384");
                rc = wc_Sha3_384_Copy(&src->hash.sha3, &dst->hash.sha3);
                break;
        #endif /* WOLFSSL_NO_SHA3_384 */
        #ifndef WOLFSSL_NOSHA3_512
            case WC_SHA3_512:
                WOLFENGINE_MSG(WE_LOG_MAC, "macType: WC_SHA3_512");
                rc = wc_Sha3_512_Copy(&src->hash.sha3, &dst->hash.sha3);
                break;
        #endif /* WOLFSSL_NO_SHA3_512 */
    #endif /* WOLFSSL_SHA3 */

            default:
                XSNPRINTF(errBuff, sizeof(errBuff), "Unknown/unsupported hash "
                          "used with HMAC: %d", src->macType);
                WOLFENGINE_ERROR_MSG(WE_LOG_MAC, errBuff);
                rc = -1;
        }

        if (rc != 0) {
            ret = 0;
        }
    }

    if (ret == 1) {
        /* Copy over the HMAC state. */
        XMEMCPY((byte*)dst->ipad, (byte*)src->ipad, WC_HMAC_BLOCK_SIZE);
        XMEMCPY((byte*)dst->opad, (byte*)src->opad, WC_HMAC_BLOCK_SIZE);
        XMEMCPY((byte*)dst->innerHash, (byte*)src->innerHash,
                WC_MAX_DIGEST_SIZE);
        /* Copy over other fields. (heap set in init call.) */
        dst->macType        = src->macType;
        dst->innerHashKeyed = src->innerHashKeyed;
    }

    WOLFENGINE_LEAVE(WE_LOG_MAC, "we_hmac_copy", ret);

    return ret;
}

/**
 * Deep copy of the EVP_PKEY that is performing HMAC operations.
 *
 * @param  dst  [out] EVP_PKEY to copy to.
 * @param  src  [in]  EVP_PKEY to copy from.
 * @returns  1 on success and 0 on failure.
 */
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
static int we_hmac_pkey_copy(EVP_PKEY_CTX *dst, const EVP_PKEY_CTX *src)
#else
static int we_hmac_pkey_copy(EVP_PKEY_CTX *dst, EVP_PKEY_CTX *src)
#endif
{
    int ret = 1;
    we_Mac *mac;
    we_Mac *dup;

    WOLFENGINE_ENTER(WE_LOG_MAC, "we_hmac_pkey_copy");
    WOLFENGINE_MSG_VERBOSE(WE_LOG_MAC, "ARGS [dst = %p, src = %p]", dst, src);

    /* Validate parameters. */
    if ((dst == NULL) || (src == NULL)) {
        WOLFENGINE_ERROR_FUNC_NULL(WE_LOG_MAC, "we_hmac_pkey_copy, dst: ", dst);
        WOLFENGINE_ERROR_FUNC_NULL(WE_LOG_MAC, "we_hmac_pkey_copy, src: ", src);
        ret = 0;
    }

    if (ret == 1) {
        /* Retrieve the internal MAC object. */
        mac = (we_Mac *)EVP_PKEY_CTX_get_data(src);
        if (mac == NULL) {
            WOLFENGINE_ERROR_FUNC_NULL(WE_LOG_MAC, "EVP_PKEY_CTX_get_data",
                                       mac);
            ret = 0;
        }
    }

    if (ret == 1) {
        /* Duplicate internal MAC object. */
        ret = we_mac_dup(mac, &dup);
    }
    if (ret == 1) {
        /* Copy wolfSSL HMAC object. */
        ret = we_hmac_copy(&dup->state.hmac, &mac->state.hmac);
    }
    if (ret == 1) {
        /* Set the internal MAC object against context. */
        EVP_PKEY_CTX_set_data(dst, dup);
    }

    WOLFENGINE_LEAVE(WE_LOG_MAC, "we_hmac_pkey_copy", ret);

    return ret;
}

/**
 * Initialize for HMAC operation using wolfSSL.
 *
 * @param  ctx  [in]  EVP_PKEY context of operation.
 * @return  1 on success and 0 on failure.
 */
static int we_hmac_pkey_init(EVP_PKEY_CTX *ctx)
{
    int ret = 1, rc;
    we_Mac *mac = NULL;

    WOLFENGINE_ENTER(WE_LOG_MAC, "we_hmac_pkey_init");
    WOLFENGINE_MSG_VERBOSE(WE_LOG_MAC, "ARGS [ctx = %p]", ctx);

    /* Initialize the internal MAC object. */
    ret = we_mac_pkey_init(ctx, &mac);
    if (ret == 1) {
        /* Initialize the wolfCrypt HMAC object. */
        rc = wc_HmacInit(&mac->state.hmac, NULL, INVALID_DEVID);
        if (rc != 0) {
            WOLFENGINE_ERROR_FUNC(WE_LOG_MAC, "wc_HmacInit", rc);
            ret = 0;
        }
    }

    if (ret == 1) {
        /* Set the algorithm to HMAC. */
        mac->algo = WE_HMAC_ALGO;
    }

    WOLFENGINE_LEAVE(WE_LOG_MAC, "we_hmac_pkey_init", ret);
    return ret;
}

/**
 * Update the HMAC hmac with dataSz bytes from data. If wolfEngine has been
 * built with WE_ALIGNMENT_SAFETY, this function provides a fix for a potential
 * alignment crash in the wolfCrypt FIPS 140-2 code.
 *
 * @param  hmac   [in]  wolfCrypt HMAC data structure.
 * @param  data   [in]  Data to be passed to HMAC update.
 * @param  dataSz [in]  Size of data buffer to be passed to HMAC update.
 * @returns  1 on success and 0 on failure.
 */
int we_hmac_update(Hmac* hmac, const void *data, size_t dataSz) {
    int ret = 1;
    int rc;

    WOLFENGINE_ENTER(WE_LOG_MAC, "we_hmac_update");
    WOLFENGINE_MSG_VERBOSE(WE_LOG_MAC, "ARGS [hmac = %p, data = %p, "
                           "dataSz = %zu]", hmac, data, dataSz);

#ifdef WE_ALIGNMENT_SAFETY
    const word32 ALIGNMENT_REQ = 8;
    word32 add = 0;
    word32 internalBuffLen = 0;
    byte* tmp = NULL;
    if (hmac->macType == WC_HASH_TYPE_SHA384 ||
        hmac->macType == WC_HASH_TYPE_SHA512)  {
        internalBuffLen = hmac->hash.sha512.buffLen;
        add = dataSz > (WC_SHA512_BLOCK_SIZE - internalBuffLen) ?
              (WC_SHA512_BLOCK_SIZE - internalBuffLen) : dataSz;
    }
    /* If the conditions below are satisfied, just calling wc_HmacUpdate with
     * the passed in buffer and length can cause a memory alignment crash on
     * certain platforms. The alternate algorithm used below (2 calls to
     * wc_HmacUpdate) avoids this crash. */
    if (dataSz > 0 && add > 0 && ((dataSz - add) >= WC_SHA512_BLOCK_SIZE) &&
        (((unsigned long)data + add) % ALIGNMENT_REQ != 0)) {
        /* Update the hash with "add" bytes of data, which will result in
         * an update with a full WC_SHA512_BLOCK_SIZE number of bytes with no
         * leftovers. */
        rc = wc_HmacUpdate(hmac, (const byte*)data, add);
        if (rc != 0) {
            WOLFENGINE_ERROR_FUNC(WE_LOG_MAC, "wc_HmacUpdate", rc);
            ret = 0;
        }
        if (ret == 1) {
            /* Allocate new, aligned buffer. */
            tmp = (byte*)XMALLOC(WC_SHA512_BLOCK_SIZE, NULL, DYNAMIC_TYPE_TMP_BUFFER);
            if (tmp == NULL) {
                WOLFENGINE_ERROR_FUNC_NULL(WE_LOG_MAC, "XMALLOC", tmp);
                ret = 0;
            }
        }
        if (ret == 1) {
            /* Copy remaining data from the unaligned buffer to the aligned one
             * and update the hash iteratively, one block's worth of data at a
             * time. */
            byte* nextData = (byte*)data + add;
            for (size_t remaining = dataSz - add; remaining > 0;) {
                size_t nextLen = (remaining <= WC_SHA512_BLOCK_SIZE) ?
                    remaining : WC_SHA512_BLOCK_SIZE;
                XMEMCPY(tmp, nextData, nextLen);
                rc = wc_HmacUpdate(hmac, (const byte*)tmp, nextLen);
                if (rc != 0) {
                    WOLFENGINE_ERROR_FUNC(WE_LOG_MAC, "wc_HmacUpdate", rc);
                    ret = 0;
                    break;
                }
                nextData += nextLen;
                remaining -= nextLen;
            }
        }

        if (tmp != NULL) {
            XFREE(tmp, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        }
    }
    else
#endif
    {
        /* Update the wolfCrypt HMAC object with more data. */
        rc = wc_HmacUpdate(hmac, (const byte*)data, (word32)dataSz);
        if (rc != 0) {
            WOLFENGINE_ERROR_FUNC(WE_LOG_MAC, "wc_HmacUpdate", rc);
            ret = 0;
        }
    }

    WOLFENGINE_LEAVE(WE_LOG_MAC, "we_hmac_update", ret);

    return ret;
}

/**
 * Replacement update function for EVP_MD context.
 *
 * @param  ctx    [in]  EVP_MD context being used.
 * @param  data   [in]  Data to be passed to HMAC update.
 * @param  dataSz [in]  Size of data buffer to be passed to HMAC update.
 * @returns  1 on success and 0 on failure.
 */
static int we_hmac_pkey_update(EVP_MD_CTX *ctx, const void *data, size_t dataSz)
{
    int ret = 1;
    we_Mac *mac;
    EVP_PKEY_CTX *pkeyCtx;

    WOLFENGINE_ENTER(WE_LOG_MAC, "we_hmac_pkey_update");
    WOLFENGINE_MSG_VERBOSE(WE_LOG_MAC, "ARGS [ctx = %p, data = %p, "
                           "dataSz = %zu]", ctx, data, dataSz);

    /* If this function is called with an input buffer length of 0, we need to
     * return success immediately. This is how OpenSSL handles this scenario. */
    if (dataSz == 0) {
        WOLFENGINE_MSG(WE_LOG_MAC, "dataSz == 0, returning success.");
        return 1;
    }

    /* Validate parameters. */
    if ((ctx == NULL) || (data == NULL)) {
        WOLFENGINE_ERROR_FUNC_NULL(WE_LOG_MAC,
                                   "we_hmac_pkey_update, ctx: ", ctx);
        WOLFENGINE_ERROR_FUNC_NULL(WE_LOG_MAC,
                                   "we_hmac_pkey_update, data:", (void*)data);
        ret = 0;
    }

    if (ret == 1) {
        /* Get PKEY context from digest context. */
        pkeyCtx = EVP_MD_CTX_pkey_ctx(ctx);
        if (pkeyCtx == NULL) {
            ret = 0;
        }
    }
    if (ret == 1) {
        /* Retrieve the internal MAC object. */
        mac = (we_Mac *)EVP_PKEY_CTX_get_data(pkeyCtx);
        if (mac == NULL) {
            WOLFENGINE_ERROR_FUNC_NULL(WE_LOG_MAC, "EVP_PKEY_CTX_get_data",
                                       mac);
            ret = 0;
        }
    }
    if (ret == 1) {
        ret = we_hmac_update(&mac->state.hmac, data, dataSz);
    }

    WOLFENGINE_LEAVE(WE_LOG_MAC, "we_hmac_pkey_update", ret);

    return ret;
}

/**
 * Initialize sign operation. Sets the update function into digest.
 *
 * @param  ctx   [in]  EVP_PKEY context being used.
 * @param  mdCtx [in]  EVP_MD context to setup.
 * @returns  1 on success and 0 on failure.
 */
static int we_hmac_pkey_signctx_init(EVP_PKEY_CTX *ctx, EVP_MD_CTX *mdCtx)
{
    int ret;

    WOLFENGINE_ENTER(WE_LOG_MAC, "we_hmac_pkey_signctx_init");
    WOLFENGINE_MSG_VERBOSE(WE_LOG_MAC, "ARGS [ctx = %p, mdCtx = %p]", ctx,
                           mdCtx);

    /* Sign and set update function to do HMAC. */
    ret = we_mac_pkey_signctx_init(ctx, mdCtx, we_hmac_pkey_update);

    WOLFENGINE_LEAVE(WE_LOG_MAC, "we_hmac_pkey_signctx_init", ret);

    return ret;
}

/**
 * Function that is called after the EVP_MD context is done being updated.
 *
 * @param  ctx    [in]   EVP_PKEY context being used.
 * @param  sig    [out]  MAC output to be filled.
 * @param  sigLen [out]  Signature length generated.
 * @param  mdCtx  [in]   EVP_MD context to setup.
 * @returns  1 on success and 0 on failure.
 */
static int we_hmac_pkey_signctx(EVP_PKEY_CTX *ctx, unsigned char *sig,
        size_t *sigLen, EVP_MD_CTX *mdCtx)
{
    int ret = 1, rc;
    we_Mac *mac;

    WOLFENGINE_ENTER(WE_LOG_MAC, "we_hmac_pkey_signctx");
    WOLFENGINE_MSG_VERBOSE(WE_LOG_MAC, "ARGS [ctx = %p, sig = %p, "
                           "sigLen = %p, mdCtx = %p]", ctx, sig, sigLen, mdCtx);

    /* Validate parameters. */
    if ((ctx == NULL) || (sigLen == NULL) || (mdCtx == NULL)) {
        WOLFENGINE_ERROR_FUNC_NULL(WE_LOG_MAC,
                                   "we_hmac_pkey_signctx, ctx:    ", ctx);
        WOLFENGINE_ERROR_FUNC_NULL(WE_LOG_MAC,
                                   "we_hmac_pkey_signctx, sigLen: ", sigLen);
        WOLFENGINE_ERROR_FUNC_NULL(WE_LOG_MAC,
                                   "we_hmac_pkey_signctx, mdCtx:  ", mdCtx);
        ret = 0;
    }

    if (ret == 1) {
        /* Retrieve the internal MAC object. */
        mac = (we_Mac *)EVP_PKEY_CTX_get_data(ctx);
        if (mac == NULL) {
            WOLFENGINE_ERROR_FUNC_NULL(WE_LOG_MAC,
                                       "EVP_PKEY_CTX_get_data", mac);
            ret = 0;
        }
    }

    /* Input signature length ignored - set to algorithm output size. */
    if (ret == 1) {
        *sigLen = (size_t)mac->size;
    }

    if ((ret == 1) && (sig != NULL)) {
        /* Calculate HMAC output. */
        rc = wc_HmacFinal(&mac->state.hmac, (byte*)sig);
        if (rc != 0) {
            WOLFENGINE_ERROR_FUNC(WE_LOG_MAC, "wc_HmacFinal", rc);
            ret = 0;
        }
    }

    WOLFENGINE_LEAVE(WE_LOG_MAC, "we_hmac_pkey_signctx", ret);

    return ret;
}


/**
 * Create a new method and assign the functions to use for HMAC
 *
 * @returns  1 on success and 0 on failure.
 */
int we_init_hmac_pkey_meth(void)
{
    int ret = 1;

    WOLFENGINE_ENTER(WE_LOG_MAC, "we_init_hmac_pkey_meth");

    /* Create method object that implemets HMAC with wolfSSL. */
    we_hmac_pkey_method = EVP_PKEY_meth_new(EVP_PKEY_HMAC, 0);
    if (we_hmac_pkey_method == NULL) {
        WOLFENGINE_ERROR_FUNC_NULL(WE_LOG_MAC,
                                   "EVP_PKEY_meth_new", we_hmac_pkey_method);
        ret = 0;
    }
    if (ret == 1) {
        /* Set with HMAC methods. */
        EVP_PKEY_meth_set_init(we_hmac_pkey_method, we_hmac_pkey_init);
        EVP_PKEY_meth_set_signctx(we_hmac_pkey_method,
                we_hmac_pkey_signctx_init, we_hmac_pkey_signctx);
        EVP_PKEY_meth_set_cleanup(we_hmac_pkey_method, we_mac_pkey_cleanup);
        EVP_PKEY_meth_set_ctrl(we_hmac_pkey_method, we_mac_pkey_ctrl,
                we_mac_pkey_ctrl_str);
        EVP_PKEY_meth_set_copy(we_hmac_pkey_method, we_hmac_pkey_copy);
        EVP_PKEY_meth_set_keygen(we_hmac_pkey_method, NULL,
                we_hmac_pkey_keygen);
    }
    /* No failure after allocation - no need to free on error. */

    WOLFENGINE_LEAVE(WE_LOG_MAC, "we_init_hmac_pkey_meth", ret);

    return ret;
}


/**
 * Maximum HMAC output size.
 *
 * @returns  Maximum HMAC output size.
 */
static int we_hmac_pkey_asn1_size(const EVP_PKEY *pkey)
{
    /* Return wolfCrypt's maximum HMAC block size that is the output size. */
    int ret = WC_HMAC_BLOCK_SIZE;

    WOLFENGINE_ENTER(WE_LOG_MAC, "we_hmac_pkey_asn1_size");
    WOLFENGINE_MSG_VERBOSE(WE_LOG_MAC, "ARGS [pkey = %p]", pkey);

    (void)pkey;

    WOLFENGINE_LEAVE(WE_LOG_MAC, "we_hmac_pkey_asn1_size", ret);

    return ret;
}

#if OPENSSL_VERSION_NUMBER >= 0x10101000L
/**
 * Set the private key into EVP_PKEY object.
 *
 * @param  pkey  [in,out]  EVP_PKEY object.
 * @param  priv  [in]      Buffer holding private key.
 * @param  len   [in]      Length of data in buffer.
 * @returns  1 on success and 0 on failure.
 */
static int we_hmac_set_priv_key(EVP_PKEY *pkey, const unsigned char *priv,
                                size_t len)
{
    int ret = 1;
    ASN1_OCTET_STRING *asn1 = NULL;

    WOLFENGINE_ENTER(WE_LOG_MAC, "we_hmac_set_priv_key");
    WOLFENGINE_MSG_VERBOSE(WE_LOG_MAC, "ARGS [pkey = %p, priv = %p, len = %zu]",
                           pkey, priv, len);

    /* Check we don't have a key set already. */
    if (EVP_PKEY_get0(pkey) != NULL) {
        ret = 0;
    }
    if (ret == 1) {
        /* Allocate a new ASN.1 octet string to assign to pkey. */
        asn1 = ASN1_OCTET_STRING_new();
        if (asn1 == NULL) {
            ret = 0;
        }
    }
    /* Set the copy the private key data into object. */
    if ((ret == 1) && (ASN1_OCTET_STRING_set(asn1, priv, (int)len) != 1)) {
        ret = 0;
    }
    /* Assign object into PKEY and set type to HMAC. */
    if ((ret == 1) && (EVP_PKEY_assign(pkey, EVP_PKEY_HMAC, asn1) != 1)) {
        ret = 0;
    }

    /* Dispose of ASN.1 object on failure. */
    if ((ret == 0) && (asn1 != NULL)) {
        ASN1_OCTET_STRING_free(asn1);
    }

    WOLFENGINE_LEAVE(WE_LOG_MAC, "we_hmac_set_priv_key", ret);

    return ret;
}
#endif

/**
 * Create a new method and assign the functions to use for ASN.1 HMAC
 * operations.
 *
 * @returns  1 on success and 0 on failure.
 */
int we_init_hmac_pkey_asn1_meth(void)
{
    int ret = 1;

    WOLFENGINE_ENTER(WE_LOG_MAC, "we_init_hmac_pkey_asn1_meth");

    /* Create ASN.1 method object that implemets HMAC with wolfSSL. */
    we_hmac_pkey_asn1_method = EVP_PKEY_asn1_new(EVP_PKEY_HMAC, 0, "HMAC",
            "wolfSSL ASN1 HMAC method");
    if (we_hmac_pkey_asn1_method == NULL) {
        WOLFENGINE_ERROR_FUNC_NULL(WE_LOG_MAC, "EVP_PKEY_asn1_new",
                we_hmac_pkey_asn1_method);
        ret = 0;
    }
    if (ret == 1) {
        /* Set with HMAC methods. */
        EVP_PKEY_asn1_set_free(we_hmac_pkey_asn1_method, we_hmac_pkey_free);
        EVP_PKEY_asn1_set_public(we_hmac_pkey_asn1_method, 0, 0, 0, 0,
                we_hmac_pkey_asn1_size, 0);
    #if OPENSSL_VERSION_NUMBER >= 0x10101000L
        EVP_PKEY_asn1_set_set_priv_key(we_hmac_pkey_asn1_method,
                we_hmac_set_priv_key);
    #endif
        /* Add our created asn1 method to the internal list of available
         * methods. */
        EVP_PKEY_asn1_add0(we_hmac_pkey_asn1_method);
    }
    /* No failure after allocation - no need to free on error. */

    WOLFENGINE_LEAVE(WE_LOG_MAC, "we_init_hmac_pkey_asn1_meth", ret);

    return ret;
}
#endif /* WE_HAVE_HMAC */

#ifdef WE_HAVE_CMAC

/** EVP PKEY digest method - CMAC using wolfSSL for the implementation. */
EVP_PKEY_METHOD *we_cmac_pkey_method = NULL;
/** EVP PKEY digest method alias - CMAC using wolfSSL for the implementation. */
EVP_PKEY_METHOD *we_cmac_we_pkey_method = NULL;


/** EVP PKEY asn1 method - CMAC using wolfSSL for the implementation. */
EVP_PKEY_ASN1_METHOD *we_cmac_pkey_asn1_method = NULL;
/** EVP PKEY asn1 method alias - CMAC using wolfSSL for the implementation. */
EVP_PKEY_ASN1_METHOD *we_cmac_we_pkey_asn1_method = NULL;

/**
 * Setup PKEY from context.
 *
 * PKEY takes a copy of key from the internal MAC object.
 *
 * @param  ctx   [in]  EVP_PKEY context being used.
 * @param  pkey  [out] EVP_PKEY to assign values to.
 * @returns  1 on success and 0 on failure.
 */
static int we_cmac_pkey_keygen(EVP_PKEY_CTX *ctx, EVP_PKEY *pkey)
{
    int ret = 1;
    ASN1_OCTET_STRING *key;

    WOLFENGINE_ENTER(WE_LOG_MAC, "we_cmac_pkey_keygen");
    WOLFENGINE_MSG_VERBOSE(WE_LOG_MAC, "ARGS [ctx = %p, pkey = %p]", ctx, pkey);

    /* Validate parameters. */
    if ((ctx == NULL) || (pkey == NULL)) {
        WOLFENGINE_ERROR_FUNC_NULL(WE_LOG_MAC,
                                   "we_cmac_pkey_keygen, ctx:  ", ctx);
        WOLFENGINE_ERROR_FUNC_NULL(WE_LOG_MAC,
                                   "we_cmac_pkey_keygen, pkey: ", pkey);
        ret = 0;
    }

    if (ret == 1) {
        /* Make an ASN.1 octet string from key data. */
        ret = we_mac_get_asn1_key(ctx, &key);
    }
    if (ret == 1) {
        /* Assign algorithm and key to PKEY. */
        EVP_PKEY_assign(pkey, EVP_PKEY_CMAC, key);
    #if OPENSSL_VERSION_NUMBER >= 0x10101000L
        /* Set alias to distinguish between OpenSSL and wolfEngine created. */
        ret = EVP_PKEY_set_alias_type(pkey, NID_wolfengine_cmac);
    #endif
    }

    WOLFENGINE_LEAVE(WE_LOG_MAC, "we_cmac_pkey_keygen", ret);
    return ret;
}

/**
 * Free PKEY data that is either of type ASN1_OCTET_STRING or CMAC_CTX.
 *
 * @param  pkey  [in]  EVP PKEY being freed.
 */
static void we_cmac_pkey_free(EVP_PKEY *pkey)
{
    int ret = 1;

    WOLFENGINE_ENTER(WE_LOG_MAC, "we_cmac_pkey_free");
    WOLFENGINE_MSG_VERBOSE(WE_LOG_MAC, "ARGS [pkey = %p]", pkey);

    /* Can be either local alias or CMAC with OpenSSL data. */
#if OPENSSL_VERSION_NUMBER >= 0x10101000L
    if (EVP_PKEY_id(pkey) == NID_wolfengine_cmac)
#endif
    {
        ASN1_OCTET_STRING *key;

        WOLFENGINE_MSG(WE_LOG_MAC, "EVP_PKEY_id: NID_wolfengine_cmac");

        /* Get the key as an ASN.1 octet string. */
        key = (ASN1_OCTET_STRING*)EVP_PKEY_get0(pkey);
        if (key != NULL) {
            /* Dispose of object. */
            ASN1_OCTET_STRING_free(key);
        }
        else {
            ret = 0;
        }
    }
#if OPENSSL_VERSION_NUMBER >= 0x10101000L
    else {
        CMAC_CTX *cmac;

        WOLFENGINE_MSG(WE_LOG_MAC, "EVP_PKEY_id: EVP_PKEY_CMAC");

        /* Get the key as CMAC_CTX. */
        cmac = (CMAC_CTX*)EVP_PKEY_get0(pkey);
        if (cmac != NULL) {
            /* Dispose of object. */
            CMAC_CTX_free(cmac);
        }
        else {
            ret = 0;
        }
    }
#endif

    WOLFENGINE_LEAVE(WE_LOG_MAC, "we_cmac_pkey_free", ret);

    (void)ret;
}

 /**
  * Does a deep copy of the Cmac structure
  *
  * @param  mac [in]  Internal MAC object copying from.
  * @param  dst [out] Destination wolfCrypt CMAC object.
  * @param  src [in]  wolfCrypt CMAC object copying from.
  * @returns  1 on success
  */
static int we_cmac_copy(we_Mac* mac, Cmac* dst, Cmac* src)
{
    int ret = 1;
    int rc;

    WOLFENGINE_ENTER(WE_LOG_MAC, "we_cmac_copy");
    WOLFENGINE_MSG_VERBOSE(WE_LOG_MAC, "ARGS [mac = %p, dst = %p, src = %p]",
                           mac, dst, src);

    /* Initialize the wolfCrypt CMAC object for AES. */
    rc = wc_InitCmac(dst, (const byte*)mac->key, mac->keySz, WC_CMAC_AES, NULL);
    if (rc != 0) {
        WOLFENGINE_ERROR_FUNC(WE_LOG_MAC, "wc_InitCmac", ret);
        ret = 0;
    }

    if (ret == 1) {
        /* Copy over state of CMAC. */
        /* Partially stored block. */
        XMEMCPY(dst->buffer, src->buffer, AES_BLOCK_SIZE);
        /* Running digest. */
        XMEMCPY(dst->digest, src->digest, AES_BLOCK_SIZE);
        XMEMCPY(dst->k1, src->k1, AES_BLOCK_SIZE);
        XMEMCPY(dst->k2, src->k2, AES_BLOCK_SIZE);
        dst->bufferSz = src->bufferSz;
        dst->totalSz = src->totalSz;
    }

    WOLFENGINE_LEAVE(WE_LOG_MAC, "we_cmac_copy", ret);

    return ret;
}

/**
 * Deep copy of the EVP_PKEY that is performing CMAC operations.
 *
 * @param  dst  [out] EVP_PKEY to copy to.
 * @param  src  [in]  EVP_PKEY to copy from.
 * @returns  1 on success and 0 on failure.
 */
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
static int we_cmac_pkey_copy(EVP_PKEY_CTX *dst, const EVP_PKEY_CTX *src)
#else
static int we_cmac_pkey_copy(EVP_PKEY_CTX *dst, EVP_PKEY_CTX *src)
#endif
{
    int ret = 1;
    we_Mac *mac;
    we_Mac *dup;

    WOLFENGINE_ENTER(WE_LOG_MAC, "we_cmac_pkey_copy");
    WOLFENGINE_MSG_VERBOSE(WE_LOG_MAC, "ARGS [dst = %p, src = %p]", dst, src);

    /* Validate parameters. */
    if ((dst == NULL) || (src == NULL)) {
        WOLFENGINE_ERROR_FUNC_NULL(WE_LOG_MAC, "we_cmac_pkey_copy, dst: ", dst);
        WOLFENGINE_ERROR_FUNC_NULL(WE_LOG_MAC, "we_cmac_pkey_copy, src: ", src);
        ret = 0;
    }

    if (ret == 1) {
        /* Retrieve the internal MAC object. */
        mac = (we_Mac *)EVP_PKEY_CTX_get_data(src);
        if (mac == NULL) {
            WOLFENGINE_ERROR_FUNC_NULL(WE_LOG_MAC, "EVP_PKEY_CTX_get_data",
                                       mac);
            ret = 0;
        }
    }

    if (ret == 1) {
        /* Duplicate internal MAC object. */
        ret = we_mac_dup(mac, &dup);
    }
    if (ret == 1) {
        /* Copy wolfSSL CMAC object. */
        ret = we_cmac_copy(mac, &dup->state.cmac, &mac->state.cmac);
    }
    if (ret == 1) {
        /* Set the internal MAC object against context. */
        EVP_PKEY_CTX_set_data(dst, dup);
    }

    WOLFENGINE_LEAVE(WE_LOG_MAC, "we_cmac_pkey_copy", ret);

    return ret;
}

/**
 * Replacement update function for EVP_MD context.
 *
 * @param  ctx    [in]  EVP_MD context being used.
 * @param  data   [in]  Data to be passed to CMAC update.
 * @param  dataSz [in]  Size of data buffer to be passed to CMAC update.
 * @returns  1 on success and 0 on failure.
 */
static int we_cmac_pkey_update(EVP_MD_CTX *ctx, const void *data, size_t dataSz)
{
    int ret = 1, rc = 0;
    we_Mac *mac;

    WOLFENGINE_ENTER(WE_LOG_MAC, "we_cmac_pkey_update");
    WOLFENGINE_MSG_VERBOSE(WE_LOG_MAC, "ARGS [ctx = %p, data = %p, "
                           "dataSz = %zu]", ctx, data, dataSz);

    /* Validate parameters. */
    if ((ctx == NULL) || (data == NULL)) {
        WOLFENGINE_ERROR_FUNC_NULL(WE_LOG_MAC,
                                   "we_cmac_pkey_update, ctx: ", ctx);
        WOLFENGINE_ERROR_FUNC_NULL(WE_LOG_MAC,
                                   "we_cmac_pkey_update, data:", (void*)data);
        ret = 0;
    }

    if (ret == 1) {
        EVP_PKEY_CTX *pkeyCtx;

        /* Get PKEY context from digest context. */
        pkeyCtx = EVP_MD_CTX_pkey_ctx(ctx);
        if (pkeyCtx == NULL) {
            ret = 0;
        }
        else {
            /* Retrieve the internal MAC object. */
            mac = (we_Mac *)EVP_PKEY_CTX_get_data(pkeyCtx);
            if (mac == NULL) {
                WOLFENGINE_ERROR_FUNC_NULL(WE_LOG_MAC,
                                           "EVP_PKEY_CTX_get_data", mac);
                ret = 0;
            }
        }
    }

    if (ret == 1) {
        /* Update the wolfCrypt CMAC object with more data. */
        rc = wc_CmacUpdate(&mac->state.cmac, (const byte*)data, (word32)dataSz);
        if (rc != 0) {
            WOLFENGINE_ERROR_FUNC(WE_LOG_MAC, "wc_CmacUpdate", rc);
            ret = 0;
        }
    }

    WOLFENGINE_LEAVE(WE_LOG_MAC, "we_cmac_pkey_update", ret);

    return ret;
}

/**
 * Initialize sign operation. Sets the update function into digest.
 *
 * @param  ctx   [in]  EVP_PKEY context being used.
 * @param  mdCtx [in]  EVP_MD context to setup.
 * @returns  1 on success and 0 on failure.
 */
static int we_cmac_pkey_signctx_init(EVP_PKEY_CTX *ctx, EVP_MD_CTX *mdCtx)
{
    int ret;

    WOLFENGINE_ENTER(WE_LOG_MAC, "we_cmac_pkey_signctx_init");
    WOLFENGINE_MSG_VERBOSE(WE_LOG_MAC, "ARGS [ctx = %p, mdCtx = %p]", ctx,
                           mdCtx);

    /* Sign and set update function to do CMAC. */
    ret = we_mac_pkey_signctx_init(ctx, mdCtx, we_cmac_pkey_update);

    WOLFENGINE_LEAVE(WE_LOG_MAC, "we_cmac_pkey_signctx_init", ret);

    return ret;
}

/**
 * Function that is called after the EVP_MD context is done being updated.
 *
 * @param  ctx    [in]   EVP_PKEY context being used.
 * @param  sig    [out]  MAC output to be filled.
 * @param  sigLen [out]  Signature length generated.
 * @param  mdCtx  [in]   EVP_MD context to setup.
 * @returns  1 on success and 0 on failure.
 */
static int we_cmac_pkey_signctx(EVP_PKEY_CTX *ctx, unsigned char *sig,
        size_t *sigLen, EVP_MD_CTX *mdCtx)
{
    int ret = 1, rc;
    we_Mac *mac;

    WOLFENGINE_ENTER(WE_LOG_MAC, "we_cmac_pkey_signctx");
    WOLFENGINE_MSG_VERBOSE(WE_LOG_MAC, "ARGS [ctx = %p, sig = %p, "
                           "sigLen = %p, mdCtx = %p]", ctx, sig, sigLen, mdCtx);

    /* Validate parameters. */
    if ((ctx == NULL) || (sigLen == NULL) || (mdCtx == NULL)) {
        WOLFENGINE_ERROR_FUNC_NULL(WE_LOG_MAC,
                                   "we_cmac_pkey_signctx, ctx:    ", ctx);
        WOLFENGINE_ERROR_FUNC_NULL(WE_LOG_MAC,
                                    "we_cmac_pkey_signctx, sigLen: ", sigLen);
        WOLFENGINE_ERROR_FUNC_NULL(WE_LOG_MAC,
                                   "we_cmac_pkey_signctx, mdCtx:  ", mdCtx);
        ret = 0;
    }

    if (ret == 1) {
        /* Retrieve the internal MAC object. */
        mac = (we_Mac *)EVP_PKEY_CTX_get_data(ctx);
        if (mac == NULL) {
            WOLFENGINE_ERROR_FUNC_NULL(WE_LOG_MAC,
                                       "EVP_PKEY_CTX_get_data", mac);
            ret = 0;
        }
    }

    if ((ret == 1) && (sig == NULL)) {
        /* Set to full CMAC output size. */
        *sigLen = WC_CMAC_TAG_MAX_SZ;
    }
    else if ((ret == 1) && (sig != NULL)) {
        word32 len = WC_CMAC_TAG_MAX_SZ;

        /* Calculate MAC output. */
        rc = wc_CmacFinal(&mac->state.cmac, (byte*)sig, &len);
        if (rc != 0) {
            WOLFENGINE_ERROR_FUNC(WE_LOG_MAC, "wc_CmacFinal", rc);
            ret = 0;
        }
        else {
            /* Input signature length ignored - set to output size. */
            *sigLen = (size_t)len;
        }
    }

    WOLFENGINE_LEAVE(WE_LOG_MAC, "we_cmac_pkey_signctx", ret);

    return ret;
}


/**
 * Initialize for CMAC operation using wolfSSL.
 *
 * @param  ctx [in] EVP_PKEY context to setup.
 * @returns  1 on success and 0 on failure.
 */
static int we_cmac_pkey_init(EVP_PKEY_CTX *ctx)
{
    int ret = 1;
    we_Mac *mac = NULL;

    WOLFENGINE_ENTER(WE_LOG_MAC, "we_cmac_pkey_init");
    WOLFENGINE_MSG_VERBOSE(WE_LOG_MAC, "ARGS [ctx = %p]", ctx);

    /* Initialize the internal MAC object. */
    ret = we_mac_pkey_init(ctx, &mac);
    if (ret == 1) {
        /* Set the algorithm to CMAC. */
        mac->algo = WE_CMAC_ALGO;
    }

    WOLFENGINE_LEAVE(WE_LOG_MAC, "we_cmac_pkey_init", ret);
    return ret;
}


/**
 * Initialize key generation.
 *
 * Nothing to do.
 *
 * @returns  1 on success and 0 on failure.
 */
static int we_cmac_pkey_keygen_init(EVP_PKEY_CTX *ctx)
{
    int ret = 1;

    WOLFENGINE_ENTER(WE_LOG_MAC, "we_cmac_pkey_keygen_init");
    WOLFENGINE_MSG_VERBOSE(WE_LOG_MAC, "ARGS [ctx = %p]", ctx);

    (void)ctx;

    WOLFENGINE_LEAVE(WE_LOG_MAC, "we_cmac_pkey_keygen_init", ret);

    return ret;
}


/**
 * Create a new method and assign the functions to use for CMAC.
 *
 * @returns  1 on success and 0 on failure.
 */
int we_init_cmac_pkey_meth(void)
{
    int ret = 1;

    WOLFENGINE_ENTER(WE_LOG_MAC, "we_init_cmac_pkey_meth");

    /* Create method object that implemets CMAC with wolfSSL. */
    we_cmac_pkey_method = EVP_PKEY_meth_new(EVP_PKEY_CMAC,
            EVP_PKEY_FLAG_SIGCTX_CUSTOM);
    if (we_cmac_pkey_method == NULL) {
        WOLFENGINE_ERROR_FUNC_NULL(WE_LOG_MAC, "EVP_PKEY_meth_new",
                                   we_cmac_pkey_method);
        ret = 0;
    }
    if (ret == 1) {
        /* Set with CMAC methods. */
        EVP_PKEY_meth_set_init(we_cmac_pkey_method, we_cmac_pkey_init);
        EVP_PKEY_meth_set_signctx(we_cmac_pkey_method,
                we_cmac_pkey_signctx_init, we_cmac_pkey_signctx);
        EVP_PKEY_meth_set_cleanup(we_cmac_pkey_method, we_mac_pkey_cleanup);
        EVP_PKEY_meth_set_ctrl(we_cmac_pkey_method, we_mac_pkey_ctrl,
                we_mac_pkey_ctrl_str);
        EVP_PKEY_meth_set_copy(we_cmac_pkey_method, we_cmac_pkey_copy);
        EVP_PKEY_meth_set_keygen(we_cmac_pkey_method, we_cmac_pkey_keygen_init,
                we_cmac_pkey_keygen);

        /* Create alternative method object for local NID.
         * (See comment at top.) */
        we_cmac_we_pkey_method = EVP_PKEY_meth_new(NID_wolfengine_cmac,
            EVP_PKEY_FLAG_SIGCTX_CUSTOM);
        if (we_cmac_we_pkey_method == NULL) {
            WOLFENGINE_ERROR_FUNC_NULL(WE_LOG_MAC, "EVP_PKEY_meth_new",
                                       we_cmac_pkey_method);
            ret = 0;
        }
    }
    if (ret == 1) {
        /* Set with same CMAC methods. */
        EVP_PKEY_meth_copy(we_cmac_we_pkey_method, we_cmac_pkey_method);
    }

    /* No failure after alias creation - no need to free on error. */
    if ((ret == 0) && (we_cmac_pkey_method != NULL)) {
        /* Free the CMAC method object and reset pointer to NULL. */
        EVP_PKEY_meth_free(we_cmac_pkey_method);
        we_cmac_pkey_method = NULL;
    }

    WOLFENGINE_LEAVE(WE_LOG_MAC, "we_init_cmac_pkey_meth", ret);
    return ret;
}


/**
 * Maximum CMAC output size.
 *
 * @returns  Maximum CMAC output size.
 */
static int we_cmac_pkey_asn1_size(const EVP_PKEY *pkey)
{
    /* Maximum output size of CMAC - always required. */
    int ret = WC_CMAC_TAG_MAX_SZ;

    WOLFENGINE_ENTER(WE_LOG_MAC, "we_cmac_pkey_asn1_size");
    WOLFENGINE_MSG_VERBOSE(WE_LOG_MAC, "ARGS [pkey = %p]", pkey);

    (void)pkey;

    WOLFENGINE_LEAVE(WE_LOG_MAC, "we_cmac_pkey_asn1_size", ret);

    return ret;
}


/**
 * Create a new method and assign the functions to use for ASN.1 CMAC
 * operations.
 *
 * @returns  1 on success and 0 on failure.
 */
int we_init_cmac_pkey_asn1_meth(void)
{
    int ret = 1;

    WOLFENGINE_ENTER(WE_LOG_MAC, "we_init_cmac_pkey_asn1_meth");

    /* Create ASN.1 method object that implemets HMAC with wolfSSL. */
    we_cmac_pkey_asn1_method = EVP_PKEY_asn1_new(EVP_PKEY_CMAC, 0, "CMAC",
            "wolfSSL ASN1 CMAC method");
    if (we_cmac_pkey_asn1_method == NULL) {
        WOLFENGINE_ERROR_FUNC_NULL(WE_LOG_MAC, "EVP_PKEY_asn1_new",
                we_cmac_pkey_asn1_method);
        ret = 0;
    }
    if (ret == 1) {
        /* Set with CMAC methods. */
        EVP_PKEY_asn1_set_free(we_cmac_pkey_asn1_method, we_cmac_pkey_free);
        EVP_PKEY_asn1_set_public(we_cmac_pkey_asn1_method, 0, 0, 0, 0,
                we_cmac_pkey_asn1_size, 0);
        /* Add our created asn1 method to the internal list of available
         * methods. */
        EVP_PKEY_asn1_add0(we_cmac_pkey_asn1_method);
        EVP_PKEY_asn1_add_alias(EVP_PKEY_CMAC, NID_wolfengine_cmac);

        /* Create alternative ASN.1 method object for local NID.
         * (See comment at top.) */
        we_cmac_we_pkey_asn1_method = EVP_PKEY_asn1_new(NID_wolfengine_cmac, 0,
                "CMAC", "wolfSSL ASN1 CMAC method");
        if (we_cmac_we_pkey_asn1_method == NULL) {
            WOLFENGINE_ERROR_FUNC_NULL(WE_LOG_MAC, "EVP_PKEY_asn1_new",
                                       we_cmac_we_pkey_asn1_method);
            ret = 0;
        }
    }
    if (ret == 1) {
        /* Set with same CMAC methods. */
        EVP_PKEY_asn1_copy(we_cmac_we_pkey_asn1_method,
                           we_cmac_pkey_asn1_method);
    }

    /* No failure after alias creation - no need to free on error. */
    if ((ret == 0) && (we_cmac_pkey_asn1_method != NULL)) {
        /* Free the CMAC method object and reset pointer to NULL. */
        EVP_PKEY_asn1_free(we_cmac_pkey_asn1_method);
        we_cmac_pkey_asn1_method = NULL;
    }

    WOLFENGINE_LEAVE(WE_LOG_MAC, "we_init_cmac_pkey_asn1_meth", ret);

    return ret;
}

#endif /* WE_HAVE_CMAC */

#endif /* WE_HAVE_MAC || WE_HAVE_CMAC */


