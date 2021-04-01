/* mac.c
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

#include "internal.h"

#if defined(WE_HAVE_MAC)

#ifdef WE_HAVE_HMAC
/**
 * Data required to complete an HMAC operation.
 */
typedef struct we_Hmac
{
    /* wolfSSL structure for holding HMAC state. */
    Hmac hmac;
    /* Hold on to key until init of Hmac structure */
    unsigned char *key;
    int keySz;
    /* Size of digest expected */
    int size;
    /* Type of digest used */
    int type;
} we_Hmac;

/** EVP PKEY digest method - HMAC using wolfSSL for the implementation. */
EVP_PKEY_METHOD *we_hmac_pkey_method = NULL;

/* value used for identifying if the ctrl is a key set command */
#define WE_CTRL_KEY 6

/* value used for identifying if the ctrl is a EVP_MD set command */
#define WE_CTRL_MD_TYPE 1

/* value used for identifying if the ctrl is a digest init command */
#define WE_CTRL_DIGEST_INIT 7

/**
 * Initialize the HMAC operation using wolfSSL.
 *
 * @param  ctx  [in]  EVP_PKEY context of operation.
 * @return  1 on success and 0 on failure.
 */
static int we_hmac_pkey_init(EVP_PKEY_CTX *ctx)
{
    int ret = 1, rc;
    we_Hmac *hmac = NULL;

    WOLFENGINE_ENTER("we_hmac_pkey_init");

    if (ctx == NULL) {
        WOLFENGINE_ERROR_FUNC_NULL("we_hmac_pkey_init, ctx: ", ctx);
        ret = 0;
    }

    if (ret == 1) {
        hmac = (we_Hmac *)OPENSSL_zalloc(sizeof(we_Hmac));
        if (hmac == NULL) {
            WOLFENGINE_ERROR_FUNC_NULL("OPENSSL_zalloc", hmac);
            ret = 0;
        }
    }

    if (ret == 1) {
        rc = wc_HmacInit(&hmac->hmac, NULL, INVALID_DEVID);
        if (rc != 0) {
            WOLFENGINE_ERROR_FUNC("wc_HmacInit", rc);
            ret = 0;
        }
    }

    if (ret == 1) {
        EVP_PKEY_CTX_set_data(ctx, hmac);
    }

    if (ret != 1 && hmac != NULL) {
        OPENSSL_free(hmac);
    }
    WOLFENGINE_LEAVE("we_hmac_pkey_init", ret);
    return ret;
}


/**
 * Free up the HMAC operation using wolfSSL.
 *
 * @param  ctx  [in]  EVP_PKEY context of operation.
 */
static void we_hmac_pkey_cleanup(EVP_PKEY_CTX *ctx)
{
    int ret = 1;
    we_Hmac *hmac;

    WOLFENGINE_ENTER("we_hmac_pkey_cleanup");
    if (ctx == NULL) {
        WOLFENGINE_ERROR_FUNC_NULL("we_hmac_pkey_cleanup, ctx: ", ctx);
        ret = 0;
    }

    if (ret == 1) {
        hmac = (we_Hmac *)EVP_PKEY_CTX_get_data(ctx);
        if (hmac == NULL) {
            WOLFENGINE_ERROR_FUNC_NULL("EVP_PKEY_CTX_get_data", hmac);
            ret = 0;
        }
    }

    if (ret == 1) {
        wc_HmacFree(&hmac->hmac);
        EVP_PKEY_CTX_set_data(ctx, NULL);
        if (hmac->key != NULL) {
            OPENSSL_clear_free(hmac->key, hmac->keySz);
        }
        OPENSSL_free(hmac);
    }
    WOLFENGINE_LEAVE("we_hmac_pkey_cleanup", ret);
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
    we_Hmac *hmac;

    if (ctx == NULL || data == NULL) {
        WOLFENGINE_ERROR_FUNC_NULL("we_hmac_pkey_update, ctx: ", ctx);
        WOLFENGINE_ERROR_FUNC_NULL("we_hmac_pkey_update, data:", (void*)data);
        ret = 0;
    }

    if (ret == 1) {
        EVP_PKEY_CTX *pkeyCtx;

        pkeyCtx = EVP_MD_CTX_pkey_ctx(ctx);
        if (pkeyCtx == NULL) {
            ret = 0;
        }
        else {
            hmac = (we_Hmac *)EVP_PKEY_CTX_get_data(pkeyCtx);
            if (hmac == NULL) {
                WOLFENGINE_ERROR_FUNC_NULL("EVP_PKEY_CTX_get_data", hmac);
                ret = 0;
            }
        }
    }

    if (ret == 1) {
        rc = wc_HmacUpdate(&hmac->hmac, (const byte*)data, (word32)dataSz);
        if (rc != 0) {
            WOLFENGINE_ERROR_FUNC("wc_HmacUpdate", rc);
            ret = 0;
        }
    }
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
    int ret = 1;

    WOLFENGINE_ENTER("wc_hmac_pkey_signctx_init");
    if (ctx == NULL || mdCtx == NULL) {
        WOLFENGINE_ERROR_FUNC_NULL("we_hmac_pkey_signctx_init, ctx: ", ctx);
        WOLFENGINE_ERROR_FUNC_NULL("we_hmac_pkey_signctx_init, data:", mdCtx);
        ret = 0;
    }

    if (ret == 1) {
        /* Adjust the MD CTX to use our update function when EVP_DigestUpdate is
         * called. Set the flag EVP_MD_CTX_FLAG_NO_INIT to avoid 'mdCtx'
         * overriding mdCtx->update with initialization calls.
         */
        EVP_MD_CTX_set_flags(mdCtx, EVP_MD_CTX_FLAG_NO_INIT);
        EVP_MD_CTX_set_update_fn(mdCtx, we_hmac_pkey_update);
    }

    WOLFENGINE_LEAVE("wc_hmac_pkey_signctx_init", ret);
    return ret;
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
    we_Hmac *hmac;

    WOLFENGINE_ENTER("we_hmac_pkey_signctx");
    if (ctx == NULL || siglen == NULL || mdCtx == NULL) {
        WOLFENGINE_ERROR_FUNC_NULL("we_hmac_pkey_signctx, ctx:    ", ctx);
        WOLFENGINE_ERROR_FUNC_NULL("we_hmac_pkey_signctx, siglen: ", siglen);
        WOLFENGINE_ERROR_FUNC_NULL("we_hmac_pkey_signctx, mdCtx:  ", mdCtx);
        ret = 0;
    }

    if (ret == 1) {
        hmac = (we_Hmac *)EVP_PKEY_CTX_get_data(ctx);
        if (hmac == NULL) {
            WOLFENGINE_ERROR_FUNC_NULL("EVP_PKEY_CTX_get_data", hmac);
            ret = 0;
        }
    }

    if (ret == 1 && sig != NULL) {
        if (*siglen < (size_t)hmac->size) {
            WOLFENGINE_ERROR_MSG("MAC output buffer was too small");
            ret = 0;
        }
    }

    if (ret == 1 && sig != NULL) {
        rc = wc_HmacFinal(&hmac->hmac, (byte*)sig);
        if (rc != 0) {
            WOLFENGINE_ERROR_FUNC("wc_HmacFinal", rc);
            ret = 0;
        }
    }

    if (ret == 1) {
        *siglen = (size_t)hmac->size;
    }

    return ret;
}


/**
 * Helper function to convert an EVP_MD to a hash type that Hmac understands.
 *
 * @param  md [in] EVP_MD to get hash type from.
 * @returns  -1 on failure and hash type on success.
 */
static int we_hmac_md_to_hash_type(EVP_MD *md)
{
    int nid;

    nid = EVP_MD_type(md);
    switch (nid) {
        case NID_md5:    return WC_MD5;
        case NID_sha1:   return WC_SHA;
        case NID_sha256: return WC_SHA256;
        case NID_sha512: return WC_SHA512;
        case NID_sha384: return WC_SHA384;
        case NID_sha224: return WC_SHA224;
    #if OPENSSL_VERSION_NUMBER >= 0x10101000L
        case NID_sha3_224: return WC_SHA3_224;
        case NID_sha3_256: return WC_SHA3_256;
        case NID_sha3_384: return WC_SHA3_384;
        case NID_sha3_512: return WC_SHA3_512;
    #endif
        default:
            return -1;
    }
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
static int we_hmac_pkey_ctrl(EVP_PKEY_CTX *ctx, int type, int num, void *ptr)
{
    int ret = 1;
    we_Hmac *hmac = NULL;

    if (ctx == NULL) {
        WOLFENGINE_ERROR_FUNC_NULL("we_hmac_pkey_ctrl", ctx);
        ret = 0;
    }

    if (ret == 1) {
        hmac = (we_Hmac *)EVP_PKEY_CTX_get_data(ctx);
        if (hmac == NULL) {
            WOLFENGINE_ERROR_FUNC_NULL("EVP_PKEY_CTX_get_data", hmac);
            ret = 0;
        }
    }

    switch (type) {
        case WE_CTRL_MD_TYPE: /* handle MD passed in */
            if (ptr != NULL) {
                hmac->type = we_hmac_md_to_hash_type((EVP_MD *)ptr);
                if (hmac->type < 0) {
                    WOLFENGINE_ERROR_FUNC("we_hmac_md_to_hash_type",
                            hmac->type);
                    ret = 0;
                }
                else {
                    hmac->size = wc_HmacSizeByType(hmac->type);
                    if (hmac->size <= 0) {
                        WOLFENGINE_ERROR_FUNC("wc_HmacSizeByType", hmac->size);
                        ret = 0;
                    }
                }
            }
            else {
                ret = 0;
            }
            break;

        case WE_CTRL_KEY: /* handle password passed in */
            if (ptr != NULL) {
                if (hmac->key != NULL) {
                    OPENSSL_clear_free(hmac->key, hmac->keySz);
                }
                hmac->key = (unsigned char *)OPENSSL_zalloc(num);
                if (hmac->key == NULL) {
                    ret = 0;
                }
                else {
                    hmac->keySz = num;
                    memcpy(hmac->key, ptr, num);
                }
            }
            else {
                ret = 0;
            }
            break;

        case WE_CTRL_DIGEST_INIT: /* handle digest init */
            {
                int rc;
                ASN1_OCTET_STRING *key;
                EVP_PKEY *pkey;

                /* pkey associated with ctx should have a password set to use */
                pkey = EVP_PKEY_CTX_get0_pkey(ctx);
                if (pkey == NULL) {
                    ret = 0;
                }

                if (ret == 1) {
                    key = (ASN1_OCTET_STRING*)EVP_PKEY_get0(pkey);
                    if (key == NULL) {
                        ret = 0;
                    }
                }

                if (ret == 1) {
                    unsigned char *pt;

                    hmac->keySz = ASN1_STRING_length(key);
                    pt          = ASN1_STRING_data(key);
                    if (pt == NULL) {
                        ret = 0;
                    }
                    else {
                        if (hmac->key != NULL) {
                            OPENSSL_free(hmac->key);
                        }
                        hmac->key = (unsigned char *)OPENSSL_zalloc(hmac->keySz);
                        if (hmac->key == NULL) {
                            ret = 0;
                        }
                        else {
                            memcpy(hmac->key, pt, hmac->keySz);
                        }
                    }
                }

                if (ret == 1) {
                    rc = wc_HmacSetKey(&hmac->hmac, hmac->type,
                            (const byte*)hmac->key, (word32)hmac->keySz);
                    if (rc != 0) {
                        WOLFENGINE_ERROR_FUNC("wc_HmacSetKey", rc);
                        ret = 0;
                    }
                }
            }
            break;

        default:
            WOLFENGINE_MSG("Unsupported HMAC ctrl encountered");
            ret = 0;
    }
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
static int we_hmac_pkey_ctrl_str(EVP_PKEY_CTX *ctx, const char *type,
        const char *value)
{
    int ret = 0;
    (void)ctx;
    (void)type;
    (void)value;
    WOLFENGINE_ENTER("we_hmac_pkey_ctrl_str");
    WOLFENGINE_LEAVE("we_hmac_pkey_ctrl_str", ret);
    return ret;
}

/* From src/ssl.c in wolfSSL
 * helper function for Deep copy of internal wolfSSL hmac structure
 * returns 1 on success */
static int wolfSSL_HmacCopy(Hmac* des, Hmac* src)
{
    void* heap;
    int ret;

#ifndef HAVE_FIPS
    heap = src->heap;
#else
    heap = NULL;
#endif
    if (wc_HmacInit(des, heap, 0) != 0) {
        return 0;
    }

    /* requires that hash structures have no dynamic parts to them */
    switch (src->macType) {
    #ifndef NO_MD5
        case WC_MD5:
            ret = wc_Md5Copy(&src->hash.md5, &des->hash.md5);
            break;
    #endif /* !NO_MD5 */

    #ifndef NO_SHA
        case WC_SHA:
            ret = wc_ShaCopy(&src->hash.sha, &des->hash.sha);
            break;
    #endif /* !NO_SHA */

    #ifdef WOLFSSL_SHA224
        case WC_SHA224:
            ret = wc_Sha224Copy(&src->hash.sha224, &des->hash.sha224);
            break;
    #endif /* WOLFSSL_SHA224 */

    #ifndef NO_SHA256
        case WC_SHA256:
            ret = wc_Sha256Copy(&src->hash.sha256, &des->hash.sha256);
            break;
    #endif /* !NO_SHA256 */

    #ifdef WOLFSSL_SHA384
        case WC_SHA384:
            ret = wc_Sha384Copy(&src->hash.sha384, &des->hash.sha384);
            break;
    #endif /* WOLFSSL_SHA384 */
    #ifdef WOLFSSL_SHA512
        case WC_SHA512:
            ret = wc_Sha512Copy(&src->hash.sha512, &des->hash.sha512);
            break;
    #endif /* WOLFSSL_SHA512 */
#ifdef WOLFSSL_SHA3
    #ifndef WOLFSSL_NOSHA3_224
        case WC_SHA3_224:
            ret = wc_Sha3_224_Copy(&src->hash.sha3, &des->hash.sha3);
            break;
    #endif /* WOLFSSL_NO_SHA3_224 */
    #ifndef WOLFSSL_NOSHA3_256
        case WC_SHA3_256:
            ret = wc_Sha3_256_Copy(&src->hash.sha3, &des->hash.sha3);
            break;
    #endif /* WOLFSSL_NO_SHA3_256 */
    #ifndef WOLFSSL_NOSHA3_384
        case WC_SHA3_384:
            ret = wc_Sha3_384_Copy(&src->hash.sha3, &des->hash.sha3);
            break;
    #endif /* WOLFSSL_NO_SHA3_384 */
    #ifndef WOLFSSL_NOSHA3_512
        case WC_SHA3_512:
            ret = wc_Sha3_512_Copy(&src->hash.sha3, &des->hash.sha3);
            break;
    #endif /* WOLFSSL_NO_SHA3_512 */
#endif /* WOLFSSL_SHA3 */

        default:
            return 0;
    }

    if (ret != 0)
        return 0;

    XMEMCPY((byte*)des->ipad, (byte*)src->ipad, WC_HMAC_BLOCK_SIZE);
    XMEMCPY((byte*)des->opad, (byte*)src->opad, WC_HMAC_BLOCK_SIZE);
    XMEMCPY((byte*)des->innerHash, (byte*)src->innerHash, WC_MAX_DIGEST_SIZE);
#ifndef HAVE_FIPS
    des->heap    = heap;
#endif
    des->macType = src->macType;
    des->innerHashKeyed = src->innerHashKeyed;

    return 1;
}


/**
 * Helper function that returns a newly malloc'd copy of 'src'
 *
 * @param  src   [in]  structure to make a copy of
 * @returns  we_Hmac pointer on success and NULL on failure.
 */
static we_Hmac* we_hmac_copy(we_Hmac *src)
{
    int ret = 1, rc;
    we_Hmac *hmac = NULL;

    if (src == NULL) {
        WOLFENGINE_ERROR_FUNC_NULL("we_hmac_copy", src);
        ret = 0;
    }

    if (ret == 1) {
        hmac = (we_Hmac *)OPENSSL_zalloc(sizeof(we_Hmac));
        if (hmac == NULL) {
            WOLFENGINE_ERROR_FUNC_NULL("OPENSSL_zalloc", hmac);
            ret = 0;
        }
    }

    if (ret == 1) {
        rc = wolfSSL_HmacCopy(&hmac->hmac, &src->hmac);
        if (rc != 1) {
            WOLFENGINE_ERROR_FUNC("wolfSSL_HmacCopy", rc);
            ret = 0;
        }
    }

    if (ret == 1) {
        hmac->size = src->size;
        hmac->type = src->type;


        hmac->keySz = src->keySz;
        if (src->keySz > 0) {
            hmac->key = (unsigned char *)OPENSSL_zalloc(src->keySz);
            if (hmac->key == NULL) {
                ret = 0;
            }
            else {
                memcpy(hmac->key, src->key, src->keySz);
            }
        }
        else {
            hmac->key = NULL;
        }
    }

    if (ret != 1 && hmac != NULL) {
        OPENSSL_free(hmac);
        return NULL;
    }
    return hmac;
}

/**
 * Function to do a deep copy of the HMAC information
 *
 * @param  dst  [out] EVP_PKEY to copy to
 * @param  src  [in]  EVP_PKEY to copy from
 * @returns  1 on success and 0 on failure.
 */
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
static int we_hmac_pkey_copy(EVP_PKEY_CTX *dst, const EVP_PKEY_CTX *src)
#else
static int we_hmac_pkey_copy(EVP_PKEY_CTX *dst, EVP_PKEY_CTX *src)
#endif
{
    int ret = 1;
    we_Hmac *hmac;
    we_Hmac *dup;

    if (dst == NULL || src == NULL) {
        WOLFENGINE_ERROR_FUNC_NULL("we_hmac_pkey_copy, dst: ", dst);
        WOLFENGINE_ERROR_FUNC_NULL("we_hmac_pkey_copy, src: ", src);
        ret = 0;
    }

    if (ret == 1) {
        hmac = (we_Hmac *)EVP_PKEY_CTX_get_data(src);
        if (hmac == NULL) {
            WOLFENGINE_ERROR_FUNC_NULL("EVP_PKEY_CTX_get_data", hmac);
            ret = 0;
        }
    }

    if (ret == 1) {
        dup = we_hmac_copy(hmac);
        if (dup == NULL) {
            WOLFENGINE_ERROR_FUNC_NULL("we_hmac_copy", dup);
            ret = 0;
        }
    }

    if (ret == 1) {
        EVP_PKEY_CTX_set_data(dst, dup);
    }
    return ret;
}


/**
 * Function to assign the pkey value
 *
 * @param  ctx   [in]  EVP_PKEY context being used
 * @param  pkey  [out] EVP_PKEY to assign value to
 * @returns  1 on success and 0 on failure.
 */
static int we_hmac_pkey_keygen(EVP_PKEY_CTX *ctx, EVP_PKEY *pkey)
{
    int ret = 1;
    ASN1_OCTET_STRING *key;
    we_Hmac *hmac;

    WOLFENGINE_ENTER("we_hmac_pkey_keygen");
    if (ctx == NULL || pkey == NULL) {
        WOLFENGINE_ERROR_FUNC_NULL("we_hmac_pkey_keygen, ctx:  ", ctx);
        WOLFENGINE_ERROR_FUNC_NULL("we_hmac_pkey_keygen, pkey: ", pkey);
        ret = 0;
    }

    if (ret == 1) {
        hmac = (we_Hmac *)EVP_PKEY_CTX_get_data(ctx);
        if (hmac == NULL) {
            WOLFENGINE_ERROR_FUNC_NULL("EVP_PKEY_CTX_get_data", hmac);
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
        ASN1_OCTET_STRING_set(key, hmac->key, hmac->keySz);
        EVP_PKEY_assign(pkey, EVP_PKEY_HMAC, key);
    }

    WOLFENGINE_LEAVE("we_hmac_pkey_keygen", ret);
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

    we_hmac_pkey_method = EVP_PKEY_meth_new(EVP_PKEY_HMAC, 0);
    if (we_hmac_pkey_method == NULL) {
        WOLFENGINE_ERROR_FUNC_NULL("EVP_PKEY_meth_new", we_hmac_pkey_method);
        ret = 0;
    }

    if (ret == 1) {
        EVP_PKEY_meth_set_init(we_hmac_pkey_method, we_hmac_pkey_init);
        EVP_PKEY_meth_set_signctx(we_hmac_pkey_method,
                we_hmac_pkey_signctx_init, we_hmac_pkey_signctx);
        EVP_PKEY_meth_set_cleanup(we_hmac_pkey_method, we_hmac_pkey_cleanup);
        EVP_PKEY_meth_set_ctrl(we_hmac_pkey_method, we_hmac_pkey_ctrl,
                we_hmac_pkey_ctrl_str);
        EVP_PKEY_meth_set_copy(we_hmac_pkey_method, we_hmac_pkey_copy);
        EVP_PKEY_meth_set_keygen(we_hmac_pkey_method, NULL, we_hmac_pkey_keygen);
    }

    if (ret == 0 && we_hmac_pkey_method != NULL) {
        EVP_PKEY_meth_free(we_hmac_pkey_method);
        we_hmac_pkey_method = NULL;
    }

    return ret;
}
#endif /* WE_HAVE_HMAC */
#endif /* WE_HAVE_MAC*/


