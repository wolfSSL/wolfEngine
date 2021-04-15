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

#if defined(WE_HAVE_HMAC) || defined(WE_HAVE_CMAC)

/* type of algorithms that the we_mac structure could be */
#define WE_HMAC_ALGO 1
#define WE_CMAC_ALGO 2

/**
 * Data required to complete an MAC operation.
 */
typedef struct we_mac
{
    union {
        /** wolfSSL structure for holding HMAC state. */
        Hmac hmac;
        /** wolfSSL structure for holding CMAC state. */
        Cmac cmac;
    } state;

    /** Hold on to key until init of structure */
    unsigned char *key;
    int keySz;

    /** Size of digest expected */
    int size;
    /** Type of digest used */
    int type;
    /** Type of algorithm structure holds i.e HMAC, CMAC ... */
    int algo;
} we_mac;

/* value used for identifying if the ctrl is a key set command */
#define WE_CTRL_KEY 6

/* value used for identifying if the ctrl is a EVP_MD set command */
#define WE_CTRL_MD_TYPE 1

/* value used for identifying if the ctrl is a digest init command */
#define WE_CTRL_DIGEST_INIT 7

/* value used for identifying if the ctrl is a EVP_CIPHER set command */
#define WE_CTRL_CIPHER 12

/**
 * Initialize the MAC structure and set it
 *
 * @param  ctx  [in]  EVP_PKEY context of operation.
 * @return pointer to we_mac structure on success and NULL on failure.
 */
static we_mac* we_mac_pkey_init(EVP_PKEY_CTX *ctx)
{
    int ret = 1;
    we_mac *mac = NULL;

    WOLFENGINE_ENTER(WE_LOG_MAC, "we_mac_pkey_init");

    if (ctx == NULL) {
        WOLFENGINE_ERROR_FUNC_NULL(WE_LOG_MAC, "we_mac_pkey_init, ctx: ", ctx);
        ret = 0;
    }

    if (ret == 1) {
        /* Allocate internal MAC object. */
        mac = (we_mac *)OPENSSL_zalloc(sizeof(we_mac));
        if (mac == NULL) {
            WOLFENGINE_ERROR_FUNC_NULL(WE_LOG_MAC, "OPENSSL_zalloc", mac);
            ret = 0;
        }
    }

    if (ret == 1) {
        EVP_PKEY_CTX_set_data(ctx, mac);
    }

    if (ret != 1 && mac != NULL) {
        OPENSSL_free(mac);
        mac = NULL;
    }
    WOLFENGINE_LEAVE(WE_LOG_MAC, "we_mac_pkey_init", ret);

    return mac;
}


/**
 * Initialize the MAC wolfSSL structure and set it
 *
 * @param  ctx  [in]  EVP_PKEY context of operation.
 * @param  mac  [in]  we_mac structure to use with initialization
 * @return pointer to we_mac structure on success and NULL on failure.
 */
static int we_do_digest_init(EVP_PKEY_CTX *ctx, we_mac *mac)
{
    int ret = 1, rc;
    ASN1_OCTET_STRING *key;
    EVP_PKEY *pkey;

    WOLFENGINE_ENTER(WE_LOG_MAC, "we_do_digest_init");

    if (mac == NULL) {
        WOLFENGINE_ERROR_MSG(WE_LOG_MAC,
                             "we_mac pointer is NULL in we_do_digest_init");
        ret = 0;
    }

    if (ret == 1) {
        /* pkey associated with ctx should have a password set to use */
        pkey = EVP_PKEY_CTX_get0_pkey(ctx);
        if (pkey == NULL) {
            ret = 0;
        }
    }

    if (ret == 1) {
        key = (ASN1_OCTET_STRING*)EVP_PKEY_get0(pkey);
        if (key == NULL) {
            ret = 0;
        }
    }

    if (ret == 1) {
        const unsigned char *pt;

        mac->keySz = ASN1_STRING_length(key);
        pt         = ASN1_STRING_get0_data(key);
        if (pt == NULL) {
            ret = 0;
        }
        else {
            if (mac->key != NULL) {
                OPENSSL_clear_free(mac->key, mac->keySz);
            }
            mac->key = (unsigned char *)OPENSSL_zalloc(mac->keySz);
            if (mac->key == NULL) {
                ret = 0;
            }
            else {
                memcpy(mac->key, pt, mac->keySz);
            }
        }
    }

    if (ret == 1) {
        switch (mac->algo) {
            case WE_CMAC_ALGO:
                rc = wc_InitCmac(&mac->state.cmac, (const byte*)mac->key,
                    mac->keySz, WC_CMAC_AES, NULL);
                if (rc != 0) {
                    WOLFENGINE_ERROR_FUNC(WE_LOG_MAC, "wc_InitCmac", rc);
                    ret = 0;
                }
                break;

            case WE_HMAC_ALGO:
                rc = wc_HmacSetKey(&mac->state.hmac, mac->type,
                    (const byte*)mac->key, (word32)mac->keySz);
                if (rc != 0) {
                    WOLFENGINE_ERROR_FUNC(WE_LOG_MAC, "wc_HmacSetKey", rc);
                    ret = 0;
                }
                break;

            default:
                WOLFENGINE_ERROR_MSG(WE_LOG_MAC, "Unknown mac algo found!");
                ret = 0;
        }
    }

    WOLFENGINE_LEAVE(WE_LOG_MAC, "we_do_digest_init", ret);

    return ret;
}


/**
 * Helper function to convert an EVP_MD to a hash type that wolfSSL understands.
 *
 * @param  md [in] EVP_MD to get hash type from.
 * @returns  -1 on failure and hash type on success.
 */
static int we_mac_md_to_hash_type(EVP_MD *md)
{
    int ret;
    int wcHashType;

    wcHashType = we_nid_to_wc_hash_type(EVP_MD_type(md));
    if (wcHashType == WC_HASH_TYPE_NONE) {
        WOLFENGINE_ERROR_FUNC(WE_LOG_MAC, "we_nid_to_wc_hash_type", wcHashType);
        ret = -1;
    }
    else {
        ret = wcHashType;
    }

    return ret;
}


/**
 * Function that is called for setting key, EVP_MD, and digest init.
 *
 * @param  ctx  [in]  EVP_PKEY context being used.
 * @param  type [in]  type of ctrl to do.
 * @param  num  [in]  used with certain control commands, i.e holds
 *                    key size.
 * @param  ptr  [in]  pointer used for EVP_MD and password
 * @returns  1 on success and 0 on failure.
 */
static int we_mac_pkey_ctrl(EVP_PKEY_CTX *ctx, int type, int num, void *ptr)
{
    int ret = 1;
    we_mac *mac = NULL;
    char errBuff[WOLFENGINE_MAX_LOG_WIDTH];

    WOLFENGINE_ENTER(WE_LOG_MAC, "we_mac_pkey_ctrl");
    if (ctx == NULL) {
        WOLFENGINE_ERROR_FUNC_NULL(WE_LOG_MAC, "we_mac_pkey_ctrl", ctx);
        ret = 0;
    }

    if (ret == 1) {
        mac = (we_mac *)EVP_PKEY_CTX_get_data(ctx);
        if (mac == NULL) {
            WOLFENGINE_ERROR_FUNC_NULL(WE_LOG_MAC,
                                       "EVP_PKEY_CTX_get_data", mac);
            ret = 0;
        }
    }

    if (ret == 1) {

        switch (type) {
            case WE_CTRL_MD_TYPE: /* handle MD passed in */
                if (ptr != NULL && mac->algo == WE_HMAC_ALGO) {
                    mac->type = we_mac_md_to_hash_type((EVP_MD *)ptr);
                    if (mac->type < 0) {
                        WOLFENGINE_ERROR_FUNC(WE_LOG_MAC,
                                              "we_mac_md_to_hash_type",
                                              mac->type);
                        ret = 0;
                    }
                    else {
                        mac->size = wc_HmacSizeByType(mac->type);
                        if (mac->size <= 0) {
                            WOLFENGINE_ERROR_FUNC(WE_LOG_MAC,
                                                  "wc_HmacSizeByType",
                                                  mac->size);
                            ret = 0;
                        }
                    }
                }

                /* with CMAC the key should be set in the Cmac structure now */
                if (mac->algo == WE_CMAC_ALGO) {
                    ret = we_do_digest_init(ctx, mac);
                }
                break;

            case WE_CTRL_KEY: /* handle password passed in */
                if (ptr != NULL) {
                    if (mac->key != NULL) {
                        OPENSSL_clear_free(mac->key, mac->keySz);
                    }
                    mac->key = (unsigned char *)OPENSSL_zalloc(num);
                    if (mac->key == NULL) {
                        ret = 0;
                    }
                    else {
                        mac->keySz = num;
                        memcpy(mac->key, ptr, num);
                    }
                }
                else {
                    ret = 0;
                }
                break;

            case WE_CTRL_CIPHER: /* handle cipher set */
                /* do nothing with it, we use internal AES */
                break;

            case WE_CTRL_DIGEST_INIT: /* handle digest init */
                WOLFENGINE_MSG(WE_LOG_MAC, "Doing digest init from ctrl");
                ret = we_do_digest_init(ctx, mac);
                break;

            default:
                XSNPRINTF(errBuff, sizeof(errBuff),
                          "Unsupported ctrl type %d", type);
                WOLFENGINE_ERROR_MSG(WE_LOG_CIPHER, errBuff);
                ret = 0;
        }
    }
    WOLFENGINE_LEAVE(WE_LOG_MAC, "we_mac_pkey_ctrl", ret);
    return ret;
}


/**
 * Function to handle control string values. Currently a stub function.
 *
 * @param  ctx   [in]  EVP_PKEY context being used.
 * @param  type  [in]  string with the type of ctrl to do.
 * @param  value [in]  action or data to use
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
    WOLFENGINE_LEAVE(WE_LOG_MAC, "we_mac_pkey_ctrl_str", ret);
    return ret;
}


/**
 * Function to assign the pkey value
 *
 * @param  ctx   [in]  EVP_PKEY context being used
 * @param  pkey  [out] EVP_PKEY to assign value to
 * @returns  1 on success and 0 on failure.
 */
static int we_mac_pkey_keygen(EVP_PKEY_CTX *ctx, EVP_PKEY *pkey)
{
    int ret = 1;
    ASN1_OCTET_STRING *key;
    we_mac *mac;

    WOLFENGINE_ENTER(WE_LOG_MAC, "we_mac_pkey_keygen");
    if (ctx == NULL || pkey == NULL) {
        WOLFENGINE_ERROR_FUNC_NULL(WE_LOG_MAC,
                                   "we_mac_pkey_keygen, ctx:  ", ctx);
        WOLFENGINE_ERROR_FUNC_NULL(WE_LOG_MAC,
                                   "we_mac_pkey_keygen, pkey: ", pkey);
        ret = 0;
    }

    if (ret == 1) {
        mac = (we_mac *)EVP_PKEY_CTX_get_data(ctx);
        if (mac == NULL) {
            WOLFENGINE_ERROR_FUNC_NULL(WE_LOG_MAC,
                                       "EVP_PKEY_CTX_get_data", mac);
            ret = 0;
        }
    }

    if (ret == 1) {
        key = ASN1_OCTET_STRING_new();
        if (key == NULL) {
            ret = 0;
        }
    }

    if (ret == 1) {
        int algo = 0;

        ASN1_OCTET_STRING_set(key, mac->key, mac->keySz);
        switch (mac->algo) {
            case WE_HMAC_ALGO: algo = EVP_PKEY_HMAC; break;
            case WE_CMAC_ALGO: algo = EVP_PKEY_CMAC; break;
            default:
                ret = 0;
        }
        EVP_PKEY_assign(pkey, algo, key);
    #if OPENSSL_VERSION_NUMBER >= 0x10101000L
        if (ret == 1 && algo == EVP_PKEY_CMAC) {
            ret = EVP_PKEY_set_alias_type(pkey, NID_wolfengine_cmac);
        }
    #endif
    }

    WOLFENGINE_LEAVE(WE_LOG_MAC, "we_mac_pkey_keygen", ret);
    return ret;
}


/**
 * Initialization function called right before signctx function calls.
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
    if (ctx == NULL || mdCtx == NULL) {
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


/**
 * Helper function that returns a newly malloc'd copy of 'src'
 *
 * @param  src   [in]  structure to make a copy of
 * @returns  we_mac pointer on success and NULL on failure.
 */
static we_mac* we_mac_copy(we_mac *src)
{
    int ret = 1;
    we_mac *mac = NULL;

    if (src == NULL) {
        WOLFENGINE_ERROR_FUNC_NULL(WE_LOG_MAC, "we_mac_copy", src);
        ret = 0;
    }

    if (ret == 1) {
        mac = (we_mac *)OPENSSL_zalloc(sizeof(we_mac));
        if (mac == NULL) {
            WOLFENGINE_ERROR_FUNC_NULL(WE_LOG_MAC, "OPENSSL_zalloc", mac);
            ret = 0;
        }
    }

    if (ret == 1) {
        mac->algo  = src->algo;
        mac->size  = src->size;
        mac->type  = src->type;
        mac->keySz = src->keySz;
        if (src->keySz > 0) {
            mac->key = (unsigned char *)OPENSSL_zalloc(src->keySz);
            if (mac->key == NULL) {
                ret = 0;
            }
            else {
                memcpy(mac->key, src->key, src->keySz);
            }
        }
        else {
            mac->key = NULL;
        }
    }

    if (ret != 1 && mac != NULL) {
        OPENSSL_free(mac);
        mac = NULL;
    }

    return mac;
}

/**
 * Treat pkey as an ASN1_OCTET_STRING and free it.
 *
 * @param  pkey  [in]  Key to free.
 * @returns  1 on success and 0 on failure.
 */
static void we_mac_pkey_asn1_free(EVP_PKEY *pkey)
{
    int id;
    int ret = 1;
    void *key;

    WOLFENGINE_ENTER(WE_LOG_MAC, "we_mac_pkey_asn1_free");

    id = EVP_PKEY_id(pkey);

    switch (id) {
        case EVP_PKEY_HMAC:
        case NID_wolfengine_cmac:
            /* Always free ASN1_OCTET_STRING with HMAC (it is default type)
             * and if the EVP_PKEY is aliased to our unique ID
             */
            key = (ASN1_OCTET_STRING*)EVP_PKEY_get0(pkey);
            if (key == NULL) {
                ret = 0;
            }
            else {
                ASN1_OCTET_STRING_free(key);
            }
            break;

    #if OPENSSL_VERSION_NUMBER >= 0x10101000L
        case EVP_PKEY_CMAC:
            key = (CMAC_CTX*)EVP_PKEY_get0(pkey);
            if (key == NULL) {
                ret = 0;
            }
            else {
                CMAC_CTX_free(key);
            }
            break;
    #endif

        default:
            WOLFENGINE_LEAVE(WE_LOG_MAC,
                    "we_mac_pkey_asn1_free: unsupported id", id);
    }

    WOLFENGINE_LEAVE(WE_LOG_MAC, "we_mac_pkey_asn1_free", ret);
    (void)ret;
}

#ifdef WE_HAVE_HMAC
/* Based on wolfSSL_HmacCopy in src/ssl.c in wolfSSL
 * helper function for Deep copy of internal wolfSSL hmac structure
 * returns 1 on success, 0 on failure */
static int we_hmac_copy(Hmac* des, Hmac* src)
{
    void* heap;
    int ret = 1;
    int rc = 0;
    char errBuff[WOLFENGINE_MAX_LOG_WIDTH];

    WOLFENGINE_ENTER(WE_LOG_MAC, "we_hmac_copy");

#ifndef HAVE_FIPS
    heap = src->heap;
#else
    heap = NULL;
#endif
    if (wc_HmacInit(des, heap, 0) != 0) {
        ret = 0;
    }

    if (ret == 1) {
        /* requires that hash structures have no dynamic parts to them */
        switch (src->macType) {
        #ifndef NO_MD5
            case WC_MD5:
                rc = wc_Md5Copy(&src->hash.md5, &des->hash.md5);
                break;
        #endif /* !NO_MD5 */

        #ifndef NO_SHA
            case WC_SHA:
                rc = wc_ShaCopy(&src->hash.sha, &des->hash.sha);
                break;
        #endif /* !NO_SHA */

        #ifdef WOLFSSL_SHA224
            case WC_SHA224:
                rc = wc_Sha224Copy(&src->hash.sha224, &des->hash.sha224);
                break;
        #endif /* WOLFSSL_SHA224 */

        #ifndef NO_SHA256
            case WC_SHA256:
                rc = wc_Sha256Copy(&src->hash.sha256, &des->hash.sha256);
                break;
        #endif /* !NO_SHA256 */

        #ifdef WOLFSSL_SHA384
            case WC_SHA384:
                rc = wc_Sha384Copy(&src->hash.sha384, &des->hash.sha384);
                break;
        #endif /* WOLFSSL_SHA384 */
        #ifdef WOLFSSL_SHA512
            case WC_SHA512:
                rc = wc_Sha512Copy(&src->hash.sha512, &des->hash.sha512);
                break;
        #endif /* WOLFSSL_SHA512 */
    #ifdef WOLFSSL_SHA3
        #ifndef WOLFSSL_NOSHA3_224
            case WC_SHA3_224:
                rc = wc_Sha3_224_Copy(&src->hash.sha3, &des->hash.sha3);
                break;
        #endif /* WOLFSSL_NO_SHA3_224 */
        #ifndef WOLFSSL_NOSHA3_256
            case WC_SHA3_256:
                rc = wc_Sha3_256_Copy(&src->hash.sha3, &des->hash.sha3);
                break;
        #endif /* WOLFSSL_NO_SHA3_256 */
        #ifndef WOLFSSL_NOSHA3_384
            case WC_SHA3_384:
                rc = wc_Sha3_384_Copy(&src->hash.sha3, &des->hash.sha3);
                break;
        #endif /* WOLFSSL_NO_SHA3_384 */
        #ifndef WOLFSSL_NOSHA3_512
            case WC_SHA3_512:
                rc = wc_Sha3_512_Copy(&src->hash.sha3, &des->hash.sha3);
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
        XMEMCPY((byte*)des->ipad, (byte*)src->ipad, WC_HMAC_BLOCK_SIZE);
        XMEMCPY((byte*)des->opad, (byte*)src->opad, WC_HMAC_BLOCK_SIZE);
        XMEMCPY((byte*)des->innerHash, (byte*)src->innerHash,
                WC_MAX_DIGEST_SIZE);
    #ifndef HAVE_FIPS
        des->heap    = heap;
    #endif
        des->macType = src->macType;
        des->innerHashKeyed = src->innerHashKeyed;
    }

    WOLFENGINE_LEAVE(WE_LOG_MAC, "we_hmac_copy", ret);

    return ret;
}
#endif /* WE_HAVE_HMAC */
#ifdef WE_HAVE_CMAC
 /**
  * Does a deep copy of the Cmac structure
  *
  * @param  mac [in]  The we_mac structure copying from
  * @param  des [out] The destination Cmac structure
  * @param  src [in]  The Cmac structure copying from
  * @returns  1 on success
  */
static int we_cmac_copy(we_mac* mac, Cmac* des, Cmac* src)
{
    int ret = 1, rc;

    WOLFENGINE_ENTER(WE_LOG_MAC, "we_cmac_copy");

    rc = wc_InitCmac(des, (const byte*)mac->key, mac->keySz, WC_CMAC_AES, NULL);
    if (rc != 0) {
        WOLFENGINE_ERROR_FUNC(WE_LOG_MAC, "wc_InitCmac", ret);
        ret = 0;
    }

    if (ret == 1) {
        /* copy over state of CMAC */
        /* partially stored block */
        memcpy(des->buffer, src->buffer, AES_BLOCK_SIZE);
        /* running digest */
        memcpy(des->digest, src->digest, AES_BLOCK_SIZE);
        memcpy(des->k1, src->k1, AES_BLOCK_SIZE);
        memcpy(des->k2, src->k2, AES_BLOCK_SIZE);
        des->bufferSz = src->bufferSz;
        des->totalSz = src->totalSz;
    }

    WOLFENGINE_LEAVE(WE_LOG_MAC, "we_cmac_copy", ret);

    return ret;
}
#endif /* WE_HAVE_CMAC */


/**
 * Function to do a deep copy of the algo state information
 *
 * @param  dst  [out] EVP_PKEY to copy to
 * @param  src  [in]  EVP_PKEY to copy from
 * @returns  1 on success and 0 on failure.
 */
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
static int we_mac_pkey_copy(EVP_PKEY_CTX *dst, const EVP_PKEY_CTX *src)
#else
static int we_mac_pkey_copy(EVP_PKEY_CTX *dst, EVP_PKEY_CTX *src)
#endif
{
    int ret = 1;
    we_mac *mac;
    we_mac *dup;

    WOLFENGINE_ENTER(WE_LOG_MAC, "we_mac_pkey_copy");

    if (dst == NULL || src == NULL) {
        WOLFENGINE_ERROR_FUNC_NULL(WE_LOG_MAC, "we_mac_pkey_copy, dst: ", dst);
        WOLFENGINE_ERROR_FUNC_NULL(WE_LOG_MAC, "we_mac_pkey_copy, src: ", src);
        ret = 0;
    }

    if (ret == 1) {
        mac = (we_mac *)EVP_PKEY_CTX_get_data(src);
        if (mac == NULL) {
            WOLFENGINE_ERROR_FUNC_NULL(WE_LOG_MAC,
                                       "EVP_PKEY_CTX_get_data", mac);
            ret = 0;
        }
    }

    if (ret == 1) {
        dup = we_mac_copy(mac);
        if (dup == NULL) {
            WOLFENGINE_ERROR_FUNC_NULL(WE_LOG_MAC, "we_mac_copy", dup);
            ret = 0;
        }
    }

    if (ret == 1) {
        switch (mac->algo) {
        #ifdef WE_HAVE_HMAC
            case WE_HMAC_ALGO:
                ret = we_hmac_copy(&dup->state.hmac, &mac->state.hmac);
                break;
        #endif

        #ifdef WE_HAVE_CMAC
            case WE_CMAC_ALGO:
                ret = we_cmac_copy(mac, &dup->state.cmac, &mac->state.cmac);
                break;
        #endif

            default:
                WOLFENGINE_ERROR_MSG(WE_LOG_MAC, "Unknown/supported MAC algo");
                ret = 0;
        }

        if (ret != 1) {
            WOLFENGINE_ERROR_FUNC(WE_LOG_MAC, "we_*mac_copy", ret);
        }
    }

    if (ret == 1) {
        EVP_PKEY_CTX_set_data(dst, dup);
    }

    WOLFENGINE_LEAVE(WE_LOG_MAC, "we_mac_pkey_copy", ret);

    return ret;
}


/**
 * Free up the state and we_mac structure
 *
 * @param  ctx  [in]  EVP_PKEY context of operation.
 */
static void we_mac_pkey_cleanup(EVP_PKEY_CTX *ctx)
{
    int ret = 1;
    we_mac *mac;

    WOLFENGINE_ENTER(WE_LOG_MAC, "we_mac_pkey_cleanup");
    if (ctx == NULL) {
        WOLFENGINE_ERROR_FUNC_NULL(WE_LOG_MAC,
                                   "we_mac_pkey_cleanup, ctx: ", ctx);
        ret = 0;
    }

    if (ret == 1) {
        mac = (we_mac *)EVP_PKEY_CTX_get_data(ctx);
        if (mac == NULL) {
            WOLFENGINE_ERROR_FUNC_NULL(WE_LOG_MAC,
                                       "EVP_PKEY_CTX_get_data", mac);
            ret = 0;
        }
    }

    if (ret == 1) {
        switch (mac->algo) {
        #ifdef WE_HAVE_HMAC
            case WE_HMAC_ALGO:
                wc_HmacFree(&mac->state.hmac);
                break;
        #endif
        #ifdef WE_HAVE_CMAC
            case WE_CMAC_ALGO:
                break;
        #endif
            default:
                ret = 0;
        }

        EVP_PKEY_CTX_set_data(ctx, NULL);
        if (mac->key != NULL) {
            OPENSSL_clear_free(mac->key, mac->keySz);
        }
        OPENSSL_free(mac);
    }
    WOLFENGINE_LEAVE(WE_LOG_MAC, "we_mac_pkey_cleanup", ret);
    (void)ret;
}


#ifdef WE_HAVE_HMAC

/** EVP PKEY digest method - HMAC using wolfSSL for the implementation. */
EVP_PKEY_METHOD *we_hmac_pkey_method = NULL;

/** EVP PKEY asn1 method - HMAC using wolfSSL for the implementation. */
EVP_PKEY_ASN1_METHOD *we_hmac_pkey_asn1_method = NULL;


/**
 * Initialize the HMAC operation using wolfSSL.
 *
 * @param  ctx  [in]  EVP_PKEY context of operation.
 * @return  1 on success and 0 on failure.
 */
static int we_hmac_pkey_init(EVP_PKEY_CTX *ctx)
{
    int ret = 1, rc;
    we_mac *mac = NULL;

    WOLFENGINE_ENTER(WE_LOG_MAC, "we_hmac_pkey_init");

    mac = we_mac_pkey_init(ctx);
    if (mac == NULL) {
        WOLFENGINE_ERROR_FUNC_NULL(WE_LOG_MAC, "wc_mac_pkey_init", mac);
        ret = 0;
    }

    if (ret == 1) {
        rc = wc_HmacInit(&mac->state.hmac, NULL, INVALID_DEVID);
        if (rc != 0) {
            WOLFENGINE_ERROR_FUNC(WE_LOG_MAC, "wc_HmacInit", rc);
            ret = 0;
        }
    }

    if (ret == 1) {
        mac->algo = WE_HMAC_ALGO;
    }

    WOLFENGINE_LEAVE(WE_LOG_MAC, "we_hmac_pkey_init", ret);
    return ret;
}


/**
 * Replacement update function for EVP_MD context
 *
 * @param  ctx    [in]  EVP_MD context being used.
 * @param  data   [in]  data to be passed to HMAC update.
 * @param  dataSz [in]  size of data buffer to be passed to HMAC update.
 * @returns  1 on success and 0 on failure.
 */
static int we_hmac_pkey_update(EVP_MD_CTX *ctx, const void *data, size_t dataSz)
{
    int ret = 1, rc = 0;
    we_mac *mac;

    WOLFENGINE_ENTER(WE_LOG_MAC, "we_hmac_pkey_update");

    if (ctx == NULL || data == NULL) {
        WOLFENGINE_ERROR_FUNC_NULL(WE_LOG_MAC,
                                   "we_hmac_pkey_update, ctx: ", ctx);
        WOLFENGINE_ERROR_FUNC_NULL(WE_LOG_MAC,
                                   "we_hmac_pkey_update, data:", (void*)data);
        ret = 0;
    }

    if (ret == 1) {
        EVP_PKEY_CTX *pkeyCtx;

        pkeyCtx = EVP_MD_CTX_pkey_ctx(ctx);
        if (pkeyCtx == NULL) {
            ret = 0;
        }
        else {
            mac = (we_mac *)EVP_PKEY_CTX_get_data(pkeyCtx);
            if (mac == NULL) {
                WOLFENGINE_ERROR_FUNC_NULL(WE_LOG_MAC,
                                           "EVP_PKEY_CTX_get_data", mac);
                ret = 0;
            }
        }
    }

    if (ret == 1) {
        rc = wc_HmacUpdate(&mac->state.hmac, (const byte*)data, (word32)dataSz);
        if (rc != 0) {
            WOLFENGINE_ERROR_FUNC(WE_LOG_MAC, "wc_HmacUpdate", rc);
            ret = 0;
        }
    }

    WOLFENGINE_LEAVE(WE_LOG_MAC, "we_hmac_pkey_update", ret);

    return ret;
}


/**
 * Initialization function called right before signctx function calls.
 *
 * @param  ctx   [in]  EVP_PKEY context being used.
 * @param  mdCtx [in]  EVP_MD context to setup.
 * @returns  1 on success and 0 on failure.
 */
static int we_hmac_pkey_signctx_init(EVP_PKEY_CTX *ctx, EVP_MD_CTX *mdCtx)
{
    return we_mac_pkey_signctx_init(ctx, mdCtx, we_hmac_pkey_update);
}


/**
 * Function that is called after the EVP_MD context is done being updated.
 *
 * @param  ctx    [in]     EVP_PKEY context being used.
 * @param  sig    [out]    MAC output to be filled.
 * @param  siglen [in/out] Contains the size of 'sig' buffer and gets
 *                         updated with size used.
 * @param  mdCtx  [in]     EVP_MD context to setup.
 * @returns  1 on success and 0 on failure.
 */
static int we_hmac_pkey_signctx(EVP_PKEY_CTX *ctx, unsigned char *sig,
        size_t *siglen, EVP_MD_CTX *mdCtx)
{
    int ret = 1, rc;
    we_mac *mac;

    WOLFENGINE_ENTER(WE_LOG_MAC, "we_hmac_pkey_signctx");
    if (ctx == NULL || siglen == NULL || mdCtx == NULL) {
        WOLFENGINE_ERROR_FUNC_NULL(WE_LOG_MAC,
                                   "we_hmac_pkey_signctx, ctx:    ", ctx);
        WOLFENGINE_ERROR_FUNC_NULL(WE_LOG_MAC,
                                   "we_hmac_pkey_signctx, siglen: ", siglen);
        WOLFENGINE_ERROR_FUNC_NULL(WE_LOG_MAC,
                                   "we_hmac_pkey_signctx, mdCtx:  ", mdCtx);
        ret = 0;
    }

    if (ret == 1) {
        mac = (we_mac *)EVP_PKEY_CTX_get_data(ctx);
        if (mac == NULL) {
            WOLFENGINE_ERROR_FUNC_NULL(WE_LOG_MAC,
                                       "EVP_PKEY_CTX_get_data", mac);
            ret = 0;
        }
    }

    /* siglen always gets set, even if smaller than mac->size */
    if (ret == 1) {
        *siglen = (size_t)mac->size;
    }

    if (ret == 1 && sig != NULL) {
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

    we_hmac_pkey_method = EVP_PKEY_meth_new(EVP_PKEY_HMAC, 0);
    if (we_hmac_pkey_method == NULL) {
        WOLFENGINE_ERROR_FUNC_NULL(WE_LOG_MAC,
                                   "EVP_PKEY_meth_new", we_hmac_pkey_method);
        ret = 0;
    }

    if (ret == 1) {
        EVP_PKEY_meth_set_init(we_hmac_pkey_method, we_hmac_pkey_init);
        EVP_PKEY_meth_set_signctx(we_hmac_pkey_method,
                we_hmac_pkey_signctx_init, we_hmac_pkey_signctx);
        EVP_PKEY_meth_set_cleanup(we_hmac_pkey_method, we_mac_pkey_cleanup);
        EVP_PKEY_meth_set_ctrl(we_hmac_pkey_method, we_mac_pkey_ctrl,
                we_mac_pkey_ctrl_str);
        EVP_PKEY_meth_set_copy(we_hmac_pkey_method, we_mac_pkey_copy);
        EVP_PKEY_meth_set_keygen(we_hmac_pkey_method, NULL, we_mac_pkey_keygen);
    }

    if (ret == 0 && we_hmac_pkey_method != NULL) {
        EVP_PKEY_meth_free(we_hmac_pkey_method);
        we_hmac_pkey_method = NULL;
    }

    WOLFENGINE_LEAVE(WE_LOG_MAC, "we_init_hmac_pkey_meth", ret);

    return ret;
}


/**
 * Gets the max HMAC tag size.
 *
 * @returns max HMAC tag size.
 */
static int we_hmac_pkey_asn1_size(const EVP_PKEY *pkey)
{
    (void)pkey;
    return WC_HMAC_BLOCK_SIZE;
}

#if OPENSSL_VERSION_NUMBER >= 0x10101000L
/**
 * Set the private key into EVP_PKEY object.
 *
 * @param  pk  [in]  EVP_PKEY object.
 * @returns  1 on success and 0 on failure.
 */
static int we_hmac_set_priv_key(EVP_PKEY *pk, const unsigned char *priv,
                                size_t len)
{
    int ret = 1;
    ASN1_OCTET_STRING *asn1 = NULL;

    /* Check we don't have a key set already. */
    if (EVP_PKEY_get0(pk) != NULL) {
        ret = 0;
    }
    if (ret == 1) {
        asn1 = ASN1_OCTET_STRING_new();
        if (asn1 == NULL) {
            ret = 0;
        }
    }
    if ((ret == 1) && (ASN1_OCTET_STRING_set(asn1, priv, (int)len) == 0)) {
        ASN1_OCTET_STRING_free(asn1);
        ret = 0;
    }
    if ((ret == 1) && (EVP_PKEY_assign(pk, EVP_PKEY_HMAC, asn1) == 0)) {
        ret = 0;
    }

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
    we_hmac_pkey_asn1_method = EVP_PKEY_asn1_new(EVP_PKEY_HMAC, 0, "HMAC",
            "wolfSSL ASN1 HMAC method");
    if (we_hmac_pkey_asn1_method == NULL) {
        WOLFENGINE_ERROR_FUNC_NULL(WE_LOG_MAC, "EVP_PKEY_asn1_new",
                we_hmac_pkey_asn1_method);
        ret = 0;
    }

    if (ret == 1) {
        EVP_PKEY_asn1_set_free(we_hmac_pkey_asn1_method, we_mac_pkey_asn1_free);
        EVP_PKEY_asn1_set_public(we_hmac_pkey_asn1_method, 0, 0, 0, 0,
                we_hmac_pkey_asn1_size, 0);
    #if OPENSSL_VERSION_NUMBER >= 0x10101000L
        EVP_PKEY_asn1_set_set_priv_key(we_hmac_pkey_asn1_method,
                we_hmac_set_priv_key);
    #endif
    }

    /* add our created asn1 method to the internal list of available methods */
    if (ret == 1) {
        EVP_PKEY_asn1_add0(we_hmac_pkey_asn1_method);
    }

    if (ret == 0 && we_hmac_pkey_asn1_method != NULL) {
        EVP_PKEY_asn1_free(we_hmac_pkey_asn1_method);
        we_hmac_pkey_asn1_method = NULL;
    }

    WOLFENGINE_LEAVE(WE_LOG_MAC, "we_init_hmac_pkey_asn1_meth", ret);
    return ret;
}
#endif /* WE_HAVE_HMAC */

#ifdef WE_HAVE_CMAC

/** EVP PKEY digest method - CMAC using wolfSSL for the implementation. */
EVP_PKEY_METHOD *we_cmac_pkey_method = NULL;
EVP_PKEY_METHOD *we_cmac_we_pkey_method = NULL;


/** EVP PKEY asn1 method - CMAC using wolfSSL for the implementation. */
EVP_PKEY_ASN1_METHOD *we_cmac_pkey_asn1_method = NULL;
EVP_PKEY_ASN1_METHOD *we_cmac_we_pkey_asn1_method = NULL;


/**
 * Replacement update function for EVP_MD context
 *
 * @param  ctx    [in]  EVP_MD context being used.
 * @param  data   [in]  data to be passed to CMAC update.
 * @param  dataSz [in]  size of data buffer to be passed to CMAC update.
 * @returns  1 on success and 0 on failure.
 */
static int we_cmac_pkey_update(EVP_MD_CTX *ctx, const void *data, size_t dataSz)
{
    int ret = 1, rc = 0;
    we_mac *mac;

    WOLFENGINE_ENTER(WE_LOG_MAC, "we_cmac_pkey_update");

    if (ctx == NULL || data == NULL) {
        WOLFENGINE_ERROR_FUNC_NULL(WE_LOG_MAC,
                                   "we_cmac_pkey_update, ctx: ", ctx);
        WOLFENGINE_ERROR_FUNC_NULL(WE_LOG_MAC,
                                   "we_cmac_pkey_update, data:", (void*)data);
        ret = 0;
    }

    if (ret == 1) {
        EVP_PKEY_CTX *pkeyCtx;

        pkeyCtx = EVP_MD_CTX_pkey_ctx(ctx);
        if (pkeyCtx == NULL) {
            ret = 0;
        }
        else {
            mac = (we_mac *)EVP_PKEY_CTX_get_data(pkeyCtx);
            if (mac == NULL) {
                WOLFENGINE_ERROR_FUNC_NULL(WE_LOG_MAC,
                                           "EVP_PKEY_CTX_get_data", mac);
                ret = 0;
            }
        }
    }

    if (ret == 1) {
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
 * Initialization function called right before signctx function calls.
 *
 * @param  ctx   [in]  EVP_PKEY context being used.
 * @param  mdCtx [in]  EVP_MD context to setup.
 * @returns  1 on success and 0 on failure.
 */
static int we_cmac_pkey_signctx_init(EVP_PKEY_CTX *ctx, EVP_MD_CTX *mdCtx)
{
    return we_mac_pkey_signctx_init(ctx, mdCtx, we_cmac_pkey_update);
}


/**
 * Function that is called after the EVP_MD context is done being updated.
 *
 * @param  ctx    [in]     EVP_PKEY context being used.
 * @param  sig    [out]    MAC output to be filled.
 * @param  siglen [in/out] Contains the size of 'sig' buffer and gets
 *                         updated with size used.
 * @param  mdCtx  [in]     EVP_MD context to setup.
 * @returns  1 on success and 0 on failure.
 */
static int we_cmac_pkey_signctx(EVP_PKEY_CTX *ctx, unsigned char *sig,
        size_t *siglen, EVP_MD_CTX *mdCtx)
{
    int ret = 1, rc;
    we_mac *mac;

    WOLFENGINE_ENTER(WE_LOG_MAC, "we_cmac_pkey_signctx");
    if (ctx == NULL || siglen == NULL || mdCtx == NULL) {
        WOLFENGINE_ERROR_FUNC_NULL(WE_LOG_MAC,
                                   "we_cmac_pkey_signctx, ctx:    ", ctx);
        WOLFENGINE_ERROR_FUNC_NULL(WE_LOG_MAC,
                                    "we_cmac_pkey_signctx, siglen: ", siglen);
        WOLFENGINE_ERROR_FUNC_NULL(WE_LOG_MAC,
                                   "we_cmac_pkey_signctx, mdCtx:  ", mdCtx);
        ret = 0;
    }

    if (ret == 1) {
        mac = (we_mac *)EVP_PKEY_CTX_get_data(ctx);
        if (mac == NULL) {
            WOLFENGINE_ERROR_FUNC_NULL(WE_LOG_MAC,
                                       "EVP_PKEY_CTX_get_data", mac);
            ret = 0;
        }
    }

    if (ret == 1 && sig != NULL) {
        if (*siglen < WC_CMAC_TAG_MIN_SZ) {
            WOLFENGINE_ERROR_MSG(WE_LOG_MAC, "MAC output buffer was too small");
            ret = 0;
        }
    }

    if (ret == 1 && sig != NULL) {
        rc = wc_CmacFinal(&mac->state.cmac, (byte*)sig, (word32*)siglen);
        if (rc != 0) {
            WOLFENGINE_ERROR_FUNC(WE_LOG_MAC, "wc_CmacFinal", rc);
            ret = 0;
        }
    }

    /* with request for size provide max CMAC tag size */
    if (ret == 1 && sig == NULL) {
        *siglen = WC_CMAC_TAG_MAX_SZ;
    }

    WOLFENGINE_LEAVE(WE_LOG_MAC, "we_cmac_pkey_signctx", ret);
    return ret;
}


/**
 * Initialize the context for use with CMAC
 *
 * @param  ctx [in] EVP_PKEY context to setup
 * @returns  1 on success and 0 on failure.
 */
static int we_cmac_pkey_init(EVP_PKEY_CTX *ctx)
{
    int ret = 1;
    we_mac *mac = NULL;

    WOLFENGINE_ENTER(WE_LOG_MAC, "we_cmac_pkey_init");

    mac = we_mac_pkey_init(ctx);
    if (mac == NULL) {
        WOLFENGINE_ERROR_FUNC_NULL(WE_LOG_MAC, "wc_mac_pkey_init", mac);
        ret = 0;
    }

    if (ret == 1) {
        mac->algo = WE_CMAC_ALGO;
    }

    WOLFENGINE_LEAVE(WE_LOG_MAC, "we_cmac_pkey_init", ret);
    return ret;
}


/**
 * No op function for keygen init
 *
 * @returns  1 on success and 0 on failure.
 */
static int we_cmac_pkey_keygen_init(EVP_PKEY_CTX *ctx)
{
    (void)ctx;
    return 1;
}


/**
 * Create a new method and assign the functions to use for CMAC
 *
 * @returns  1 on success and 0 on failure.
 */
int we_init_cmac_pkey_meth(void)
{
    int ret = 1;

    WOLFENGINE_ENTER(WE_LOG_MAC, "we_init_cmac_pkey_meth");
    we_cmac_we_pkey_method = NULL;
    we_cmac_pkey_method = EVP_PKEY_meth_new(EVP_PKEY_CMAC,
            EVP_PKEY_FLAG_SIGCTX_CUSTOM);
    if (we_cmac_pkey_method == NULL) {
        WOLFENGINE_ERROR_FUNC_NULL(WE_LOG_MAC,
                                   "EVP_PKEY_meth_new", we_cmac_pkey_method);
        ret = 0;
    }

    if (ret == 1) {
        EVP_PKEY_meth_set_init(we_cmac_pkey_method, we_cmac_pkey_init);
        EVP_PKEY_meth_set_signctx(we_cmac_pkey_method,
                we_cmac_pkey_signctx_init, we_cmac_pkey_signctx);
        EVP_PKEY_meth_set_cleanup(we_cmac_pkey_method, we_mac_pkey_cleanup);
        EVP_PKEY_meth_set_ctrl(we_cmac_pkey_method, we_mac_pkey_ctrl,
                we_mac_pkey_ctrl_str);
        EVP_PKEY_meth_set_copy(we_cmac_pkey_method, we_mac_pkey_copy);
        EVP_PKEY_meth_set_keygen(we_cmac_pkey_method, we_cmac_pkey_keygen_init,
                we_mac_pkey_keygen);
    }

    if (ret == 1) {
        we_cmac_we_pkey_method = EVP_PKEY_meth_new(NID_wolfengine_cmac,
            EVP_PKEY_FLAG_SIGCTX_CUSTOM);
        if (we_cmac_we_pkey_method == NULL) {
            WOLFENGINE_ERROR_FUNC_NULL(WE_LOG_MAC,
                                       "EVP_PKEY_meth_new", we_cmac_pkey_method);
            ret = 0;
        }
    }

    if (ret == 1) {
        EVP_PKEY_meth_copy(we_cmac_we_pkey_method, we_cmac_pkey_method);
     }

    if (ret == 0 && we_cmac_pkey_method != NULL) {
        EVP_PKEY_meth_free(we_cmac_pkey_method);
        we_cmac_pkey_method = NULL;
    }

    WOLFENGINE_LEAVE(WE_LOG_MAC, "we_init_cmac_pkey_meth", ret);
    return ret;
}


/**
 * Gets the max CMAC tag size.
 *
 * @returns max CMAC tag size.
 */
static int we_cmac_pkey_asn1_size(const EVP_PKEY *pkey)
{
    (void)pkey;
    return WC_CMAC_TAG_MAX_SZ;
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
    we_cmac_we_pkey_asn1_method = NULL;
    we_cmac_pkey_asn1_method = EVP_PKEY_asn1_new(EVP_PKEY_CMAC, 0,
            "CMAC", "wolfSSL ASN1 CMAC method");
    if (we_cmac_pkey_asn1_method == NULL) {
        WOLFENGINE_ERROR_FUNC_NULL(WE_LOG_MAC, "EVP_PKEY_asn1_new",
                we_cmac_pkey_asn1_method);
        ret = 0;
    }

    if (ret == 1) {
        EVP_PKEY_asn1_set_free(we_cmac_pkey_asn1_method, we_mac_pkey_asn1_free);
        EVP_PKEY_asn1_set_public(we_cmac_pkey_asn1_method, 0, 0, 0, 0,
                we_cmac_pkey_asn1_size, 0);
    }

    /* add our created asn1 method to the internal list of available methods */
    if (ret == 1) {
        EVP_PKEY_asn1_add0(we_cmac_pkey_asn1_method);
        EVP_PKEY_asn1_add_alias(EVP_PKEY_CMAC, NID_wolfengine_cmac);
    }

    if (ret == 1) {
        we_cmac_we_pkey_asn1_method = EVP_PKEY_asn1_new(NID_wolfengine_cmac, 0,
            "CMAC", "wolfSSL ASN1 CMAC method");
        if (we_cmac_we_pkey_asn1_method == NULL) {
            WOLFENGINE_ERROR_FUNC_NULL(WE_LOG_MAC,
                                       "EVP_PKEY_asn1_new", we_cmac_we_pkey_asn1_method);
            ret = 0;
        }
    }

    if (ret == 1) {
        EVP_PKEY_asn1_copy(we_cmac_we_pkey_asn1_method, we_cmac_pkey_asn1_method);
     }

    if (ret == 0 && we_cmac_pkey_asn1_method != NULL) {
        EVP_PKEY_asn1_free(we_cmac_pkey_asn1_method);
        we_cmac_pkey_asn1_method = NULL;
    }

    WOLFENGINE_LEAVE(WE_LOG_MAC, "we_init_cmac_pkey_asn1_meth", ret);
    return ret;
}
#endif /* WE_HAVE_CMAC */
#endif /* WE_HAVE_MAC*/


