/* wolfengine.c
 *
 * Copyright (C) 2006-2019 wolfSSL Inc.
 *
 * This file is part of wolfengine.
 *
 * wolfengine is free software; you can redistribute it and/or modify
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

/* OpenSSL 3.0.0 has deprecated the ENGINE API. */
#define OPENSSL_API_COMPAT      10101

#include <openssl/engine.h>
#include <openssl/evp.h>
#include <openssl/ec.h>

#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/hash.h>
#include <wolfssl/wolfcrypt/sha256.h>
#include <wolfssl/wolfcrypt/aes.h>
#include <wolfssl/wolfcrypt/ecc.h>

#include "openssl_bc.h"

/* May not be available in FIPS builds of wolfSSL */
#ifndef GCM_NONCE_MAX_SZ
#define GCM_NONCE_MAX_SZ        16
#endif
#ifndef GCM_NONCE_MID_SZ
#define GCM_NONCE_MID_SZ        12
#endif

#ifdef WOLFENGINE_DEBUG
#define WOLFENGINE_MSG(msg)     (void)fprintf(stderr, "WOLFENG: %s\n", msg);
#else
#define WOLFENGINE_MSG(msg)     (void)msg
#endif

/* Engine library name - implementation uses wolfSSL */
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
    static const char *wolfengine_lib = "libwolfengine";
#else
    static const char *wolfengine_lib = "wolfengine";
#endif
/* Engine id - implementation uses wolfSSL */
static const char *wolfengine_id = "wolfSSL";
/* Engine name ... or description.  */
static const char *wolfengine_name = "An engine using wolfSSL";

#if defined(WE_HAVE_EVP_PKEY) || defined(WE_USE_HASH)
/** List of public key types supported as ids. */
static const int we_pkey_nids[] = {
#ifdef WE_HAVE_ECC
    NID_X9_62_id_ecPublicKey,
#ifdef WE_HAVE_ECKEYGEN
#ifdef WE_HAVE_EC_P256
    NID_X9_62_prime256v1,
#endif
#ifdef WE_HAVE_EC_P384
    NID_secp384r1,
#endif
#endif
#endif
};
#endif /* WE_HAVE_EVP_PKEY || WE_USE_HASH */

#if defined(WE_HAVE_ECC) || defined(WE_HAVE_AESGCM)

/*
 * Random number generator
 */

/* Global random number generator. */
static WC_RNG we_globalRng;
/* Global RNG has been initialized. */
static int we_globalRngInited = 0;

/**
 * Initialize the global random number generator object.
 *
 * @returns  1 on success and 0 on failure.
 */
static int we_init_random()
{
    int ret = 1;

    if (!we_globalRngInited) {
        ret = wc_InitRng(&we_globalRng) == 0;
        if (ret == 1) {
            we_globalRngInited = 1;
        }
    }

    return ret;
}

#endif /* WE_HAVE_ECC || WE_HAVE_AESGCM */

/*
 * Digests
 */

#if defined(WE_HAVE_SHA256) && defined(WE_SHA256_DIRECT)

/*
 * SHA-256
 */

/**
 * Initialize the SHA-256 digest operation using wolfSSL.
 *
 * @param  ctx  [in]  EVP digest context of operation.
 * @return  1 on success and 0 on failure.
 */
static int we_sha256_init(EVP_MD_CTX *ctx)
{
    WOLFENGINE_MSG("Init SHA-256");
    return wc_InitSha256((wc_Sha256*)EVP_MD_CTX_md_data(ctx)) == 0;
}

/**
 * Digest some more data with SHA-256 using wolfSSL.
 *
 * @param  ctx   [in]  EVP digest context of operation.
 * @param  data  [in]  More data to digest with SHA-256.
 * @param  len   [in]  Length of data to digest.
 * @return  1 on success and 0 on failure.
 */
static int we_sha256_update(EVP_MD_CTX *ctx, const void *data, size_t len)
{
    WOLFENGINE_MSG("Update SHA-256");
    return wc_Sha256Update((wc_Sha256*)EVP_MD_CTX_md_data(ctx),
                           (const byte*)data, (word32)len) == 0;
}

/**
 * Finalize the SHA-256 digest operation.
 *
 * @param  ctx  [in]  EVP digest context of operation.
 * @param  md   [in]  SHA-256 digest of data.
 * @return  1 on success and 0 on failure.
 */
static int we_sha256_final(EVP_MD_CTX *ctx, unsigned char *md)
{
    WOLFENGINE_MSG("Final SHA-256");
    return wc_Sha256Final((wc_Sha256*)EVP_MD_CTX_md_data(ctx), (byte*)md) == 0;
}

/**
 * Cleanup the SHA-256 digest object.
 *
 * @param  ctx  [in]  EVP digest context of operation.
 * @return  1 for success.
 */
static int we_sha256_cleanup(EVP_MD_CTX *ctx)
{
    WOLFENGINE_MSG("Free SHA-256");
    wc_Sha256Free((wc_Sha256*)EVP_MD_CTX_md_data(ctx));
    return 1;
}

/** EVP digest method - SHA-256 using wolfSSL for the implementation. */
static EVP_MD *we_sha256_md = NULL;

/**
 * Initialize the global SHA-256 EVP digest method.
 *
 * @return  1 on success else failure.
 */
static int we_init_sha256_meth()
{
    int ret;

    ret = (we_sha256_md = EVP_MD_meth_new(NID_sha256, EVP_PKEY_NONE)) != NULL;
    if (ret == 1) {
        ret = EVP_MD_meth_set_init(we_sha256_md, we_sha256_init);
    }
    if (ret == 1) {
        ret = EVP_MD_meth_set_update(we_sha256_md, we_sha256_update);
    }
    if (ret == 1) {
        ret = EVP_MD_meth_set_final(we_sha256_md, we_sha256_final);
    }
    if (ret == 1) {
        ret = EVP_MD_meth_set_cleanup(we_sha256_md, we_sha256_cleanup);
    }
    if (ret == 1) {
        ret = EVP_MD_meth_set_result_size(we_sha256_md, WC_SHA256_DIGEST_SIZE);
    }
    if (ret == 1) {
        ret = EVP_MD_meth_set_app_datasize(we_sha256_md, sizeof(wc_Sha256));
    }

    if ((ret != 1) && (we_sha256_md != NULL)) {
        EVP_MD_meth_free(we_sha256_md);
    }
    return ret;
};

#endif /* WE_HAVE_SHA256 && WE_SHA256_DIRECT */

#ifdef WE_USE_HASH

/**
 * Data required to complete an AES-GCM encrypt/decrypt operation.
 */
typedef struct we_Digest
{
    wc_HashAlg       hash;
    enum wc_HashType hashType;
} we_Digest;

#ifdef WE_HAVE_SHA256
/**
 * Initialize the SHA-256 digest operation using wolfSSL.
 *
 * @param  ctx  [in]  EVP digest context of operation.
 * @return  1 on success and 0 on failure.
 */
static int we_sha256_init(EVP_MD_CTX *ctx)
{
    we_Digest *digest;

    WOLFENGINE_MSG("Init SHA-256");

    digest = (we_Digest *)EVP_MD_CTX_md_data(ctx);
    digest->hashType = WC_SHA256;

    return wc_HashInit(&digest->hash, digest->hashType) == 0;
}
#endif

#ifdef WE_HAVE_SHA384
/**
 * Initialize the SHA-384 digest operation using wolfSSL.
 *
 * @param  ctx  [in]  EVP digest context of operation.
 * @return  1 on success and 0 on failure.
 */
static int we_sha384_init(EVP_MD_CTX *ctx)
{
    we_Digest *digest;

    WOLFENGINE_MSG("Init SHA-384");

    digest = (we_Digest *)EVP_MD_CTX_md_data(ctx);
    digest->hashType = WC_SHA384;

    return wc_HashInit(&digest->hash, digest->hashType) == 0;
}
#endif

#ifdef WE_HAVE_SHA512
/**
 * Initialize the SHA-512 digest operation using wolfSSL.
 *
 * @param  ctx  [in]  EVP digest context of operation.
 * @return  1 on success and 0 on failure.
 */
static int we_sha512_init(EVP_MD_CTX *ctx)
{
    we_Digest *digest;

    WOLFENGINE_MSG("Init SHA-512");

    digest = (we_Digest *)EVP_MD_CTX_md_data(ctx);
    digest->hashType = WC_SHA512;

    return wc_HashInit(&digest->hash, digest->hashType) == 0;
}
#endif

/**
 * Digest some more data using wolfSSL.
 *
 * @param  ctx   [in]  EVP digest context of operation.
 * @param  data  [in]  More data to digest with SHA-256.
 * @param  len   [in]  Length of data to digest.
 * @return  1 on success and 0 on failure.
 */
static int we_digest_update(EVP_MD_CTX *ctx, const void *data, size_t len)
{
    we_Digest *digest;

    WOLFENGINE_MSG("Update Digest");

    digest = (we_Digest *)EVP_MD_CTX_md_data(ctx);

    return wc_HashUpdate(&digest->hash, digest->hashType, (const byte*)data,
                         (word32)len) == 0;
}

/**
 * Finalize the digest operation.
 *
 * @param  ctx  [in]  EVP digest context of operation.
 * @param  md   [in]  SHA-256 digest of data.
 * @return  1 on success and 0 on failure.
 */
static int we_digest_final(EVP_MD_CTX *ctx, unsigned char *md)
{
    we_Digest *digest;

    WOLFENGINE_MSG("Final Digest");

    digest = (we_Digest *)EVP_MD_CTX_md_data(ctx);

    return wc_HashFinal(&digest->hash, digest->hashType, (byte*)md) == 0;
}

/**
 * Cleanup the digest object.
 *
 * @param  ctx  [in]  EVP digest context of operation.
 * @return  1 for success.
 */
static int we_digest_cleanup(EVP_MD_CTX *ctx)
{
#if !defined(HAVE_FIPS_VERSION) || HAVE_FIPS_VERSION >= 2
    we_Digest *digest;

    WOLFENGINE_MSG("Free Digest");

    digest = (we_Digest *)EVP_MD_CTX_md_data(ctx);

    if (digest == NULL)
        return 1;

    return wc_HashFree(&digest->hash, digest->hashType) == 0;
#else
    WOLFENGINE_MSG("Free Digest");

    (void)ctx;

    return 1;
#endif
}

/**
 * Initialize the EVP digest method.
 *
 * @param  method  [in]  EVP digest method to modify.
 * @return  1 on success else failure.
 */
static int we_init_digest_meth(EVP_MD *method)
{
    int ret;

    ret = EVP_MD_meth_set_update(method, we_digest_update);
    if (ret == 1) {
        ret = EVP_MD_meth_set_final(method, we_digest_final);
    }
    if (ret == 1) {
        ret = EVP_MD_meth_set_cleanup(method, we_digest_cleanup);
    }
    if (ret == 1) {
        ret = EVP_MD_meth_set_app_datasize(method, sizeof(we_Digest));
    }

#if OPENSSL_VERSION_NUMBER < 0x10100000L
    if (ret == 1) {
        XMEMCPY(method->required_pkey_type, we_pkey_nids,
               sizeof(we_pkey_nids) / sizeof(int));
        method->flags |= EVP_MD_FLAG_PKEY_METHOD_SIGNATURE;
    }
#endif

    return ret;
}

#ifdef WE_HAVE_SHA256
/** EVP digest method - SHA-256 using wolfSSL for the implementation. */
static EVP_MD *we_sha256_md = NULL;

/**
 * Initialize the global SHA-256 EVP digest method.
 *
 * @return  1 on success else failure.
 */
static int we_init_sha256_meth()
{
    int ret;

    ret = (we_sha256_md = EVP_MD_meth_new(NID_sha256, EVP_PKEY_NONE)) != NULL;
    if (ret == 1) {
        ret = EVP_MD_meth_set_init(we_sha256_md, we_sha256_init);
    }
    if (ret == 1) {
        ret = EVP_MD_meth_set_result_size(we_sha256_md, WC_SHA256_DIGEST_SIZE);
    }
    if (ret == 1) {
        ret = we_init_digest_meth(we_sha256_md);
    }

    if ((ret != 1) && (we_sha256_md != NULL)) {
        EVP_MD_meth_free(we_sha256_md);
    }
    return ret;
};
#endif

#ifdef WE_HAVE_SHA384
/** EVP digest method - SHA-384 using wolfSSL for the implementation. */
static EVP_MD *we_sha384_md = NULL;

/**
 * Initialize the global SHA-384 EVP digest method.
 *
 * @return  1 on success else failure.
 */
static int we_init_sha384_meth()
{
    int ret;

    ret = (we_sha384_md = EVP_MD_meth_new(NID_sha384, EVP_PKEY_NONE)) != NULL;
    if (ret == 1) {
        ret = EVP_MD_meth_set_init(we_sha384_md, we_sha384_init);
    }
    if (ret == 1) {
        ret = EVP_MD_meth_set_result_size(we_sha384_md, WC_SHA384_DIGEST_SIZE);
    }
    if (ret == 1) {
        ret = we_init_digest_meth(we_sha384_md);
    }

    if ((ret != 1) && (we_sha384_md != NULL)) {
        EVP_MD_meth_free(we_sha384_md);
    }
    return ret;
};
#endif

#ifdef WE_HAVE_SHA512
/** EVP digest method - SHA-512 using wolfSSL for the implementation. */
static EVP_MD *we_sha512_md = NULL;

/**
 * Initialize the global SHA-512 EVP digest method.
 *
 * @return  1 on success else failure.
 */
static int we_init_sha512_meth()
{
    int ret = 1;

    ret = (we_sha512_md = EVP_MD_meth_new(NID_sha512, EVP_PKEY_NONE)) != NULL;
    if (ret == 1) {
        ret = EVP_MD_meth_set_init(we_sha512_md, we_sha512_init);
    }
    if (ret == 1) {
        ret = EVP_MD_meth_set_result_size(we_sha512_md, WC_SHA512_DIGEST_SIZE);
    }
    if (ret == 1) {
        ret = we_init_digest_meth(we_sha512_md);
    }

    if ((ret != 1) && (we_sha512_md != NULL)) {
        EVP_MD_meth_free(we_sha512_md);
    }
    return ret;
};
#endif

#endif /* WE_USE_HASH */

/** List of supported digest algorithms. */
static const int we_digest_nids[] = {
#ifdef WE_HAVE_SHA256
    NID_sha256,
#endif
#ifdef WE_HAVE_SHA384
    NID_sha384,
#endif
#ifdef WE_HAVE_SHA512
    NID_sha512,
#endif
};

/**
 * Returns the list of digests supported or the digest method for the algorithm.
 *
 * @param  e       [in]   Engine object.
 * @param  digest  [out]  Digest method for algorithm.
 *                        When NULL, return list of algorithms.
 * @param  nids    [out]  List of supported digest algorithms.
 * @param  nid     [in]   Digest algorithm required.
 * @return  When digest is NULL, the number of NIDs returned.<br>
 *          When digest is not NULL, 1 on success and 0 when algorithm not
 *          supported.
 */
static int we_digests(ENGINE *e, const EVP_MD **digest, const int **nids,
                      int nid)
{
    int ret = 1;

    (void)e;

    if (digest == NULL) {
        /* Return a list of supported NIDs (Numerical IDentifiers) */
        *nids = we_digest_nids;
        ret = (sizeof(we_digest_nids)) / sizeof(*we_digest_nids);
    }
    else {
        switch (nid) {
#ifdef WE_HAVE_SHA256
        case NID_sha256:
            *digest = we_sha256_md;
            break;
#endif
#ifdef WE_HAVE_SHA384
        case NID_sha384:
            *digest = we_sha384_md;
            break;
#endif
#ifdef WE_HAVE_SHA512
        case NID_sha512:
            *digest = we_sha512_md;
            break;
#endif
        default:
            *digest = NULL;
            ret = 0;
            break;
        }
    }

    return ret;
}


#ifdef WE_HAVE_AESGCM

/*
 * AES-GCM
 */

/**
 * Data required to complete an AES-GCM encrypt/decrypt operation.
 */
typedef struct we_AesGcm
{
    /** The wolfSSL AES data object. */
    Aes            aes;
    /** IV to use with encrypt/decrypt. */
    unsigned char  iv[GCM_NONCE_MAX_SZ];
    /** Length of IV data. */
    int            ivLen;
    /** IV set. */
    int            ivSet;
    /** Tag created when encrypting or tag set for decryption. */
    unsigned char  tag[AES_BLOCK_SIZE];
    /** Length of tag data stored.  */
    int            tagLen;
    /** Additional Authentication Data (AAD) - cumulative. */
    unsigned char *aad;
    /** Length of AAD stored. */
    int            aadLen;
    /** Flag to indicate whether we are doing encrypt (1) or decrpyt (0). */
    unsigned int   enc:1;
    /** Flag to indicate whether dping this for TLS */
    unsigned int   tls:1;
} we_AesGcm;

/**
 * Initialize the AES-GCM encrypt/decrypt operation using wolfSSL.
 *
 * @param  ctx  [in]  EVP cipher context of operation.
 * @param  key  [in]  AES key - 16 bytes.
 * @param  iv   [in]  Initialization Vector/nonce - 12 bytes.
 * @param  enc  [in]  1 when initializing for encrypt and 0 when decrypt.
 * @return  1 on success and 0 on failure.
 */
static int we_aes_gcm_init(EVP_CIPHER_CTX *ctx, const unsigned char *key,
                           const unsigned char *iv, int enc)
{
    int ret = 1;
    we_AesGcm *aes;

    WOLFENGINE_MSG("AES-GCM: Init");

    if (iv == NULL && key == NULL)
        ret = 0;

    if (ret == 1) {
        ret = (aes = (we_AesGcm *)EVP_CIPHER_CTX_get_cipher_data(ctx)) != NULL;
    }

    if (ret == 1) {
        /* No IV yet. */
        aes->ivLen = 0;
        aes->ivSet = 0;
        /* No tag set. */
        aes->tagLen = 0;
        /* Start with no AAD. */
        aes->aad = NULL;
        aes->aadLen = 0;
        aes->enc = enc;

        if (key != NULL) {
            ret = wc_AesGcmSetKey(&aes->aes, key,
                                  EVP_CIPHER_CTX_key_length(ctx)) == 0;
        }
    }
    if (ret == 1 && (key == NULL || iv != NULL)) {
        aes->ivLen = GCM_NONCE_MID_SZ;
        XMEMCPY(aes->iv, iv, GCM_NONCE_MID_SZ);
    }

    return ret;
}

/**
 * Encrypt/decrypt the data.
 * One-shot encrypt/decrypt - not streaming.
 *
 * @param  ctx  [in]  EVP cipher context of operation.
 * @param  out  [in]  Buffer to store enciphered result.<br>
 *                    NULL indicates AAD in.
 * @param  in   [in]  AAD or data to encrypt/decrypt.
 * @param  len  [in]  Length of AAD or data to encrypt/decrypt.
 * @return  When out is NULL, length of input data on success and 0 on failure.
 *          <br>
 *          When out is not NULL, length of output data on success and 0 on
 *          failure.
 */
static int we_aes_gcm_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out,
                             const unsigned char *in, size_t len)
{
    int ret = len;
    we_AesGcm *aes;
    unsigned char *p;

    WOLFENGINE_MSG("AES-GCM: Cipher");

    /* Get the AES-GCM data to work with. */
    aes = (we_AesGcm *)EVP_CIPHER_CTX_get_cipher_data(ctx);
    if (aes == NULL) {
        ret = 0;
    }

    if (ret != 0 && aes->tls) {
        if (aes->enc) {
            word32 encLen = (word32)len - EVP_GCM_TLS_EXPLICIT_IV_LEN - 16;
            if (ret != 0) {
                XMEMCPY(out, aes->iv + EVP_GCM_TLS_FIXED_IV_LEN,
                        EVP_GCM_TLS_EXPLICIT_IV_LEN);

                ret = wc_AesGcmEncrypt_ex(&aes->aes,
                                          out + EVP_GCM_TLS_EXPLICIT_IV_LEN,
                                          in + EVP_GCM_TLS_EXPLICIT_IV_LEN,
                                          encLen, aes->iv, aes->ivLen,
                                          out + len - 16, 16, aes->aad,
                                          aes->aadLen) == 0;
            }
            if (ret != 0) {
#if OPENSSL_VERSION_NUMBER < 0x30000000L
                ret = len;
#endif
                XMEMCPY(aes->iv, aes->aes.reg, aes->ivLen);
            }
        }
        else {
            word32 decLen = (word32)len - EVP_GCM_TLS_EXPLICIT_IV_LEN - 16;
            if (ret != 0) {
                XMEMCPY(aes->iv + EVP_GCM_TLS_FIXED_IV_LEN, in,
                        EVP_GCM_TLS_EXPLICIT_IV_LEN);

                ret = wc_AesGcmDecrypt(&aes->aes,
                                       out + EVP_GCM_TLS_EXPLICIT_IV_LEN,
                                       in + EVP_GCM_TLS_EXPLICIT_IV_LEN,
                                       decLen, aes->iv, aes->ivLen,
                                       out + len - 16, 16, aes->aad,
                                       aes->aadLen) == 0;
            }
            if (ret != 0) {
#if OPENSSL_VERSION_NUMBER < 0x30000000L
                ret = decLen;
#endif
                XMEMCPY(aes->iv, aes->aes.reg, aes->ivLen);
            }
        }

        /* Dispose of any AAD - all used now. */
        OPENSSL_free(aes->aad);
        aes->aad = NULL;
        aes->aadLen = 0;
    }
    else if (ret != 0 && out == NULL) {
        /* Resize stored AAD and append new data. */
        p = OPENSSL_realloc(aes->aad, aes->aadLen + len);
        if (p == NULL) {
            ret = 0;
        }
        else {
            aes->aad = p;
            XMEMCPY(aes->aad + aes->aadLen, in, len);
            aes->aadLen += len;
        }
    }
    else if (ret != 0) {
        if (aes->enc) {
            if (!aes->ivSet) {
                ret = wc_AesGcmSetExtIV(&aes->aes, aes->iv, aes->ivLen) == 0;
            }
            if (ret != 0) {
                aes->tagLen = AES_BLOCK_SIZE;
                ret = wc_AesGcmEncrypt_ex(&aes->aes, out, in, (word32)len,
                                          aes->iv, aes->ivLen, aes->tag,
                                          aes->tagLen, aes->aad,
                                          aes->aadLen) == 0;
            }
            if (ret != 0) {
                XMEMCPY(aes->iv, aes->aes.reg, aes->ivLen);
            }
        }
        else {
            ret = wc_AesGcmDecrypt(&aes->aes, out, in, (word32)len, aes->iv,
                                   aes->ivLen, aes->tag, aes->tagLen,
                                   aes->aad, aes->aadLen) == 0;
            if (ret != 0) {
                XMEMCPY(aes->iv, aes->aes.reg, aes->ivLen);
            }
        }

        /* Dispose of any AAD - all used now. */
        OPENSSL_free(aes->aad);
        aes->aad = NULL;
        aes->aadLen = 0;
    }

    return ret;
}

/**
 * Extra operations for AES-GCM.
 * Supported operations include:
 *  - EVP_CTRL_GET_IV (version 3.0+): get IV from wolfengine object
 *  - EVP_CTRL_AEAD_SET_IVLEN: set the length of an IV/nonce
 *  - EVP_CTRL_GCM_SET_IV_FIXED: set the fixed part of an IV/nonce
 *  - EVP_CTRL_GCM_IV_GEN: set the generated IV/nonce
 *  - EVP_CTRL_AEAD_GET_TAG: get the tag value after encrypt
 *  - EVP_CTRL_AEAD_SET_TAG: set the tag value before decrypt
 *  - EVP_CTRL_AEAD_TLS1_AAD: set AAD for TLS
 *
 * @param  ctx   [in]  EVP cipher context of operation.
 * @param  type  [in]  Type of operation to perform.
 * @param  arg   [in]  Integer argument.
 * @param  ptr   [in]  Pointer argument.
 * @return  1 on success and 0 on failure.
 */
static int we_aes_gcm_ctrl(EVP_CIPHER_CTX *ctx, int type, int arg, void *ptr)
{
    int ret = 1;
    we_AesGcm *aes;

    WOLFENGINE_MSG("AES-GCM - CTRL");

    /* Get the AES-GCM data to work with. */
    ret = (aes = (we_AesGcm *)EVP_CIPHER_CTX_get_cipher_data(ctx)) != NULL;
    if (ret == 1) {
        switch (type) {
            case EVP_CTRL_AEAD_SET_IVLEN:
                /* Set the IV/nonce length to use
                 *   arg [in] length of IV/nonce to use
                 *   ptr [in] Unused
                 */
                if (arg <= 0 || arg > GCM_NONCE_MAX_SZ) {
                    ret = 0;
                }
                else {
                    aes->ivLen = arg;
                }
                break;

            case EVP_CTRL_GCM_SET_IV_FIXED:
                 /* Set the fixed part of an IV
                 *   arg [in] size of fixed part of IV/nonce
                 *   ptr [in] fixed part of IV/nonce data
                 */
                if (arg == -1) {
                    /* arg of -1 means copy all data. */
                    if (aes->ivLen == 0)
                        aes->ivLen = GCM_NONCE_MID_SZ;
                    XMEMCPY(aes->iv, ptr, aes->ivLen);
                    XMEMCPY(EVP_CIPHER_CTX_iv_noconst(ctx), ptr, aes->ivLen);
                }
                else {
                    /* Set ta fixed IV and have the rest generated. */
                    if (aes->ivLen == 0)
                        aes->ivLen = GCM_NONCE_MID_SZ;
                    ret = wc_AesGcmSetIV(&aes->aes, aes->ivLen, ptr, arg,
                                         &we_globalRng) == 0;
                    if (ret == 1) {
                       aes->ivSet = 1;
                       XMEMCPY(aes->iv, aes->aes.reg, aes->ivLen);
                       XMEMCPY(EVP_CIPHER_CTX_iv_noconst(ctx), aes->iv,
                               aes->ivLen);
                    }
                }
                break;

            case EVP_CTRL_GCM_IV_GEN:
                 /* Set the generated IV
                 *   arg [in] size of generated IV/nonce
                 *   ptr [in] generated IV/nonce data
                 */
                if (arg <= 0 || arg > GCM_NONCE_MAX_SZ) {
                    ret = 0;
                }
                else {
                    int i;
                    XMEMCPY(aes->iv, ptr, arg);
                    for (i = aes->ivLen - 1; i >= aes->ivLen - 8; i--) {
                        if ((++aes->iv[i]) != 0) {
                            break;
                        }
                    }
                }
                break;

            case EVP_CTRL_AEAD_GET_TAG:
                /* Get the tag from encryption.
                 *   arg [in] size of buffer
                 *   ptr [in] buffer to copy into
                 */
                if (!aes->enc || arg <= 0 || arg > aes->tagLen) {
                    ret = 0;
                }
                else {
                    XMEMCPY(ptr, aes->tag, arg);
                }
                break;

            case EVP_CTRL_AEAD_SET_TAG:
                /* Set the tag for decryption.
                 *   arg [in] size of tag
                 *   ptr [in] tag data to copy
                 */
                if (aes->enc || arg <= 0 || arg > AES_BLOCK_SIZE) {
                    ret = 0;
                }
                else {
                    XMEMCPY(aes->tag, ptr, arg);
                    aes->tagLen = arg;
                }
                break;

            case EVP_CTRL_AEAD_TLS1_AAD:
                /* Set additional authentication data for TLS
                 *   arg [in] size of AAD
                 *   ptr [in] AAD to use
                 */
                if (arg != EVP_AEAD_TLS1_AAD_LEN) {
                    ret = 0;
                }
                if (ret == 1) {
                    unsigned int len;

                    /* Set modified AAD based on record header */
                    if (aes->aad != NULL) {
                        OPENSSL_free(aes->aad);
                    }
                    ret = (aes->aad = OPENSSL_malloc(arg)) != NULL;
                    if (ret == 1) {
                        XMEMCPY(aes->aad, ptr, arg);
                        aes->aadLen = arg;
                        len = (aes->aad[arg - 2] << 8) | aes->aad[arg - 1];
                        if (len < EVP_GCM_TLS_EXPLICIT_IV_LEN) {
                            ret = 0;
                        }
                    }
                    if (ret == 1) {
                        len -= EVP_GCM_TLS_EXPLICIT_IV_LEN;
                        if (!aes->enc) {
                            if (len < EVP_GCM_TLS_TAG_LEN) {
                                ret = 0;
                            }
                            else {
                                len -= EVP_GCM_TLS_TAG_LEN;
                            }
                        }
                    }
                    if (ret == 1) {
                        aes->aad[arg - 2] = len >> 8;
                        aes->aad[arg - 1] = len;
                        aes->tls = 1;
                        ret = EVP_GCM_TLS_TAG_LEN;
                    }
                }
                break;

            default:
                ret = 0;
                break;
        }
    }

    return ret;
}

/** Flags for AES-GCM method. */
#define AES_GCM_FLAGS              \
    (EVP_CIPH_FLAG_CUSTOM_CIPHER | \
     EVP_CIPH_ALWAYS_CALL_INIT   | \
     EVP_CIPH_FLAG_AEAD_CIPHER   | \
     EVP_CIPH_GCM_MODE)

/** AES128-GCM EVP cipher method. */
static EVP_CIPHER* we_aes128_gcm_ciph = NULL;
/** AES256-GCM EVP cipher method. */
static EVP_CIPHER* we_aes256_gcm_ciph = NULL;


/**
 * Initialize an AES-GCM method.
 *
 * @return  1 on success and 0 on failure.
 */
static int we_init_aesgcm_meth(EVP_CIPHER *cipher)
{
    int ret;

    ret = EVP_CIPHER_meth_set_iv_length(cipher, GCM_NONCE_MID_SZ);
    if (ret == 1) {
        ret = EVP_CIPHER_meth_set_flags(cipher, AES_GCM_FLAGS);
    }
    if (ret == 1) {
        ret = EVP_CIPHER_meth_set_init(cipher, we_aes_gcm_init);
    }
    if (ret == 1) {
        ret = EVP_CIPHER_meth_set_do_cipher(cipher, we_aes_gcm_cipher);
    }
    if (ret == 1) {
        ret = EVP_CIPHER_meth_set_ctrl(cipher, we_aes_gcm_ctrl);
    }
    if (ret == 1) {
        ret = EVP_CIPHER_meth_set_impl_ctx_size(cipher, sizeof(we_AesGcm));
    }

    return ret;
}

/**
 * Initialize the AES-GCM methods.
 *
 * @return  1 on success and 0 on failure.
 */
static int we_init_aesgcm_meths()
{
    int ret = 1;

    /* AES128-GCM */
    we_aes128_gcm_ciph = EVP_CIPHER_meth_new(NID_aes_128_gcm, 1,
                                             AES_128_KEY_SIZE);
    if (we_aes128_gcm_ciph == NULL) {
        ret = 0;
    }
    if (ret == 1) {
        ret = we_init_aesgcm_meth(we_aes128_gcm_ciph);
    }

    /* AES256-GCM */
    if (ret == 1) {
        we_aes256_gcm_ciph = EVP_CIPHER_meth_new(NID_aes_256_gcm, 1,
                                                 AES_256_KEY_SIZE);
        if (we_aes256_gcm_ciph == NULL) {
            ret = 0;
        }
    }
    if (we_aes256_gcm_ciph == NULL) {
        ret = 0;
    }
    if (ret == 1) {
        ret = we_init_aesgcm_meth(we_aes256_gcm_ciph);
    }

    /* Cleanup */
    if (ret == 0 && we_aes128_gcm_ciph != NULL) {
        EVP_CIPHER_meth_free(we_aes128_gcm_ciph);
        we_aes128_gcm_ciph = NULL;
    }
    if (ret == 0 && we_aes256_gcm_ciph != NULL) {
        EVP_CIPHER_meth_free(we_aes256_gcm_ciph);
        we_aes256_gcm_ciph = NULL;
    }
    return ret;
}

#endif /* WE_HAVE_AESGM */

/** List of supported cipher algorithms as numeric ids. */
static const int we_cipher_nids[] = {
#ifdef WE_HAVE_AESGCM
    NID_aes_128_gcm,
    NID_aes_256_gcm,
#endif
};


/**
 * Returns the list of ciphers supported or the cipher method for the algorithm.
 *
 * @param  e       [in]   Engine object.
 * @param  cipher  [out]  Cipher method for algorithm.
 *                        When NULL, return list of algorithms.
 * @param  nids    [out]  List of supported cipher algorithms.
 * @param  nid     [in]   Cipher algorithm required.
 * @return  When cipher is NULL, the number of NIDs returned.<br>
 *          When cipher is not NULL, 1 on success and 0 when algorithm not
 *          supported.
 */
static int we_ciphers(ENGINE *e, const EVP_CIPHER **cipher, const int **nids,
                      int nid)
{
    int ret = 1;

    (void)e;

    if (cipher == NULL) {
        /* Return a list of supported NIDs (Numerical IDentifiers) */
        *nids = we_cipher_nids;
        ret = (sizeof(we_cipher_nids)) / sizeof(*we_cipher_nids);
    }
    else {
        switch (nid) {
#ifdef WE_HAVE_AESGCM
        case NID_aes_128_gcm:
            *cipher = we_aes128_gcm_ciph;
            break;
        case NID_aes_256_gcm:
            *cipher = we_aes256_gcm_ciph;
            break;
#endif
        default:
            *cipher = NULL;
            ret = 0;
            break;
        }
    }

    return ret;
}

#ifdef WE_HAVE_ECC
/*
 * ECC
 */

/**
 * Get the curve id for the curve name (NID).
 *
 * @param  curveNme  [in]   OpenSSL curve name.
 * @param  curveId   [out]  Curve id corresponding to the group.
 * @returns  1 on success and 0 when group is not recognized.
 */
static int we_ec_get_curve_id(int curveName, int *curveId)
{
    int ret = 1;

    switch (curveName) {
#ifdef WE_HAVE_EC_P256
        case NID_X9_62_prime256v1:
            WOLFENGINE_MSG("Set P-256");
            *curveId = ECC_SECP256R1;
            break;
#endif
#ifdef WE_HAVE_EC_P384
        case NID_secp384r1:
            WOLFENGINE_MSG("Set P-384");
            *curveId = ECC_SECP384R1;
            break;
#endif
        default:
            ret = 0;
            break;
    }

    return ret;
}

/**
 * Set private key from the EC key into wolfSSL ECC key.
 *
 * @param  key      [in]  wolfSSL ECC key.
 * @param  curveId  [in]  wolfSSL curve identifier.
 * @param  ecKey    [in]  OpenSSL EC key.
 * @returns  1 on success and 0 no failure.
 */
static int we_ec_set_private(ecc_key *key, int curveId, const EC_KEY *ecKey)
{
    int ret = 1;
    size_t privLen = 0;
    unsigned char* privBuf = NULL;

    /* Get the EC key private key as binary data. */
    privLen = EC_KEY_priv2buf(ecKey, &privBuf);
    if (privLen <= 0) {
        ret = 0;
    }
    /* Import private key. */
    if (ret == 1) {
        ret = wc_ecc_import_private_key_ex(privBuf, privLen, NULL, 0, key,
                                           curveId) == 0;
    }

    if (privLen > 0) {
        /* Zeroize and free private key data. */
        OPENSSL_clear_free(privBuf, privLen);
    }

    return ret;
}

/**
 * Set public key from the EC key into wolfSSL ECC key.
 *
 * @param  key      [in]  wolfSSL ECC key.
 * @param  curveId  [in]  wolfSSL curve identifier.
 * @param  ecKey    [in]  OpenSSL EC key.
 * @returns  1 on success and 0 no failure.
 */
static int we_ec_set_public(ecc_key *key, int curveId, EC_KEY *ecKey)
{
    int ret = 1;
    size_t pubLen;
    unsigned char* pubBuf = NULL;
    unsigned char* x;
    unsigned char* y;

    /* Get the EC key public key as and uncompressed point. */
    pubLen = EC_KEY_key2buf(ecKey, POINT_CONVERSION_UNCOMPRESSED, &pubBuf,
                            NULL);
    if (pubLen <= 0) {
        ret = 0;
    }

    /* Import public key. */
    if (ret == 1) {
        /* 0x04, x, y - x and y are equal length. */
        x = pubBuf + 1;
        y = x + ((pubLen - 1) / 2);
        ret = wc_ecc_import_unsigned(key, x, y, NULL, curveId) == 0;
    }

    OPENSSL_free(pubBuf);

    return ret;
}

#ifdef WE_HAVE_EVP_PKEY
/**
 * Data required to complete an ECC operation.
 */
typedef struct we_Ecc
{
    /* wolfSSL ECC key structure to hold private/public key. */
    ecc_key        key;
    /* wolfSSL curve id for key. */
    int            curveId;
    /* OpenSSL curve name */
    int            curveName;
#ifdef WE_HAVE_ECDSA
    /* Digest method - stored but not used. */
    EVP_MD        *md;
#endif
#ifdef WE_HAVE_ECDH
    /* Peer's public key encoded in binary - uncompressed. */
    unsigned char *peerKey;
    /* Length of peer's encoded public key. */
    int            peerKeyLen;
#endif
#ifdef WE_HAVE_ECKEYGEN
    EC_GROUP      *group;
#endif
    /* Indicates private key has been set into wolfSSL structure. */
    int            privKeySet:1;
    /* Indicates public key has been set into wolfSSL structure. */
    int            pubKeySet:1;
} we_Ecc;

/**
 * Initialize and set the data required to complete an EC operations.
 *
 * @param  ctx  [in]  Public key context of operation.
 * @returns  1 on success and 0 on failure.
 */
static int we_ec_init(EVP_PKEY_CTX *ctx)
{
    int ret;
    we_Ecc *ecc;

    WOLFENGINE_MSG("ECC - Init");

    ret = (ecc = OPENSSL_zalloc(sizeof(we_Ecc))) != NULL;
    if (ret == 1) {
        ret = wc_ecc_init(&ecc->key) == 0;
    }
#if !defined(HAVE_FIPS) || \
    (defined(HAVE_FIPS_VERSION) && HAVE_FIPS_VERSION != 2)
    if (ret == 1) {
        ret = wc_ecc_set_rng(&ecc->key, &we_globalRng) == 0;
    }
#endif /* !HAVE_FIPS || (HAVE_FIPS_VERSION && HAVE_FIPS_VERSION != 2) */
    if (ret == 1) {
        EVP_PKEY_CTX_set_data(ctx, ecc);
    }

    if (ret == 0 && ecc != NULL) {
        OPENSSL_free(ecc);
    }

    return ret;
}

#ifdef WE_HAVE_ECKEYGEN
#ifdef WE_HAVE_EC_P256
/**
 * Initialize and set the data required to complete an EC P-256 operations.
 *
 * @param  ctx  [in]  Public key context of operation.
 * @returns  1 on success and 0 on failure.
 */
static int we_ec_p256_init(EVP_PKEY_CTX *ctx)
{
    int ret;
    we_Ecc *ecc;

    WOLFENGINE_MSG("ECC - Init");

    ret = (ecc = OPENSSL_zalloc(sizeof(we_Ecc))) != NULL;
    if (ret == 1) {
        ret = wc_ecc_init(&ecc->key) == 0;
    }
    if (ret == 1) {
        EVP_PKEY_CTX_set_data(ctx, ecc);
        ecc->curveId = ECC_SECP256R1;
        ecc->curveName = NID_X9_62_prime256v1;
        ecc->group = EC_GROUP_new_by_curve_name(ecc->curveName);
        if (ecc->group == NULL)
            ret = 0;
    }

    if (ret == 0 && ecc != NULL) {
        OPENSSL_free(ecc);
    }

    return ret;
}
#endif

#ifdef WE_HAVE_EC_P384
/**
 * Initialize and set the data required to complete an EC P-384 operations.
 *
 * @param  ctx  [in]  Public key context of operation.
 * @returns  1 on success and 0 on failure.
 */
static int we_ec_p384_init(EVP_PKEY_CTX *ctx)
{
    int ret;
    we_Ecc *ecc;

    WOLFENGINE_MSG("ECC - Init");

    ret = (ecc = OPENSSL_zalloc(sizeof(we_Ecc))) != NULL;
    if (ret == 1) {
        ret = wc_ecc_init(&ecc->key) == 0;
    }
    if (ret == 1) {
        EVP_PKEY_CTX_set_data(ctx, ecc);
        ecc->curveId = ECC_SECP384R1;
        ecc->curveName = NID_secp384r1;
        ecc->group = EC_GROUP_new_by_curve_name(ecc->curveName);
        if (ecc->group == NULL)
            ret = 0;
    }

    if (ret == 0 && ecc != NULL) {
        OPENSSL_free(ecc);
    }

    return ret;
}

#endif
#endif

/**
 * Copy the EVP public key method rom/to EVP public key contexts.
 *
 * @param  dst  [in]  Destination public key context.
 * @param  src  [in]  Source public key context.
 * @returns  1 on success and 0 on failure.
 */
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
static int we_ec_copy(EVP_PKEY_CTX *dst, const EVP_PKEY_CTX *src)
#else
static int we_ec_copy(EVP_PKEY_CTX *dst, EVP_PKEY_CTX *src)
#endif
{
    int ret = 1;

    (void)src;

    WOLFENGINE_MSG("ECC - Copy");

    if (EVP_PKEY_CTX_get_data(dst) != NULL) {
        ret = we_ec_init(dst) == 0;
    }

    return ret;
}

/**
 * Clean up the ECC operation data.
 *
 * @param  ctx  [in]  Public key context of operation.
 */
static void we_ec_cleanup(EVP_PKEY_CTX *ctx)
{
    we_Ecc *ecc = (we_Ecc *)EVP_PKEY_CTX_get_data(ctx);

    WOLFENGINE_MSG("ECC - Cleanup");

    if (ecc != NULL) {
#ifdef WE_HAVE_ECKEYGEN
        EC_GROUP_free(ecc->group);
        ecc->group = NULL;
#endif
#ifdef WE_HAVE_ECDH
        OPENSSL_free(ecc->peerKey);
        ecc->peerKey = NULL;
#endif
        wc_ecc_free(&ecc->key);
        OPENSSL_free(ecc);
        EVP_PKEY_CTX_set_data(ctx, NULL);
    }
}

/**
 * Get the EC key and curve id from the EVP public key.
 *
 * @param  ctx      [in]   EVP public key context
 * @param  ecKey    [out]  OpenSSL EC key in context.
 * @param  ecc      [in]   wolfengine ECC object.
 * @returns  1 on success and 0 when group is not recognized.
 */
static int we_ec_get_ec_key(EVP_PKEY_CTX *ctx, EC_KEY **ecKey, we_Ecc *ecc)
{
    int ret;
    EVP_PKEY *pkey;
    const EC_GROUP *group;

    ret = (pkey = EVP_PKEY_CTX_get0_pkey(ctx)) != NULL;
    if (ret == 1) {
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
        ret = (*ecKey = (EC_KEY*)EVP_PKEY_get0_EC_KEY(pkey)) != NULL;
#else
        ret = (*ecKey = EVP_PKEY_get0_EC_KEY(pkey)) != NULL;
#endif
    }
    if (ret == 1) {
        ret = (group = EC_KEY_get0_group(*ecKey)) != NULL;
    }
    if (ret == 1) {
        ret = we_ec_get_curve_id(EC_GROUP_get_curve_name(group),
                                  &ecc->curveId);
    }

    return ret;
}

#ifdef WE_HAVE_ECDSA
/**
 * Sign data with a private EC key.
 *
 * @param  ctx     [in]      Public key context of operation.
 * @param  sig     [in]      Buffer to hold signature data.
 *                           NULL indicates length of signature requested.
 * @param  sigLen  [in/out]  Length of signature buffer.
 * @param  tbs     [in]      To Be Signed data.
 * @param  tbsLen  [in]      Length of To Be Signed data.
 * @returns  1 on success and 0 on failure.
 */
static int we_ecdsa_sign(EVP_PKEY_CTX *ctx, unsigned char *sig, size_t *sigLen,
                         const unsigned char *tbs, size_t tbsLen)
{
    int ret;
    word32 outLen;
    we_Ecc *ecc;
    EC_KEY *ecKey = NULL;

    WOLFENGINE_MSG("ECDSA - Sign");

    ret = (ecc = (we_Ecc *)EVP_PKEY_CTX_get_data(ctx)) != NULL;
    if (ret == 1 && !ecc->privKeySet) {
        ret = we_ec_get_ec_key(ctx, &ecKey, ecc);
        if (ret == 1) {
            ret = we_ec_set_private(&ecc->key, ecc->curveId, ecKey);
        }
        if (ret == 1) {
            ecc->privKeySet = 1;
        }
    }

    if (ret == 1 && sig == NULL) {
        /* Return signature size in bytes. */
        *sigLen = wc_ecc_sig_size(&ecc->key);
    }
    if (ret == 1 && sig != NULL) {
        outLen = *sigLen;
        ret = wc_ecc_sign_hash(tbs, tbsLen, sig, &outLen, &we_globalRng,
                               &ecc->key) == 0;
        if (ret == 1) {
            /* Return actual size. */
            *sigLen = outLen;
        }
    }

    return ret;
}

/**
 * Verify data with a public EC key.
 *
 * @param  ctx     [in]  Public key context of operation.
 * @param  sig     [in]  Signature data.
 * @param  sigLen  [in]  Length of signature data.
 * @param  tbs     [in]  To Be Signed data.
 * @param  tbsLen  [in]  Length of To Be Signed data.
 * @returns  1 on success and 0 on failure.
 */
static int we_ecdsa_verify(EVP_PKEY_CTX *ctx, const unsigned char *sig,
                           size_t sigLen, const unsigned char *tbs,
                           size_t tbsLen)
{
    int ret;
    we_Ecc *ecc;
    EC_KEY *ecKey = NULL;
    int res;

    WOLFENGINE_MSG("ECDSA - Verify");

    ret = (ecc = (we_Ecc *)EVP_PKEY_CTX_get_data(ctx)) != NULL;
    if (ret == 1 && !ecc->pubKeySet) {
        ret = we_ec_get_ec_key(ctx, &ecKey, ecc);
        if (ret == 1) {
            ret = we_ec_set_public(&ecc->key, ecc->curveId, ecKey);
        }
        if (ret == 1) {
            ecc->pubKeySet = 1;
        }
    }
    if (ret == 1) {
        ret = wc_ecc_verify_hash(sig, sigLen, tbs, tbsLen, &res,
                                 &ecc->key) == 0;
    }
    if (ret == 1) {
        /* Verification result is 1 on success and 0 on failure. */
        ret = res; 
    }

    return ret;
}
#endif /* WE_HAVE_ECDSA */

#ifdef WE_HAVE_ECKEYGEN
/**
 * Generate an ECC key.
 *
 * @param  ctx   [in]  Public key context of operation.
 * @param  pkey  [in]  EVP public key to hold result.
 * @returns  1 on success and 0 on failure.
 */
static int we_ec_keygen(EVP_PKEY_CTX *ctx, EVP_PKEY *pkey)
{
    int ret = 1;
    we_Ecc *ecc;
    EC_KEY *ecKey = NULL;
    EVP_PKEY *ctxPkey;
    int len = 0;
    unsigned char *buf = NULL;
    unsigned char *d = NULL;

    WOLFENGINE_MSG("ECC - Key Gen");

    ret = (ecc = (we_Ecc *)EVP_PKEY_CTX_get_data(ctx)) != NULL;
    if (ret == 1) {
        len = wc_ecc_get_curve_size_from_id(ecc->curveId);

        ctxPkey = EVP_PKEY_CTX_get0_pkey(ctx);
        /* May be NULL */

        ret = (ecKey = EC_KEY_new()) != NULL;
    }

    if (ret == 1) {
        ret = EVP_PKEY_assign_EC_KEY(pkey, ecKey);
        if (ret == 0) {
            EC_KEY_free(ecKey);
        }
    }

    if (ret == 1) {
        if (ctxPkey != NULL) {
            ret = EVP_PKEY_copy_parameters(pkey, ctxPkey);
        }
        else {
            ret = EC_KEY_set_group(ecKey, ecc->group);
        }
    }

    if (ret == 1) {
        ret = wc_ecc_make_key_ex(&we_globalRng, len, &ecc->key,
                                 ecc->curveId) == 0;
    }
    if (ret == 1) {
        ecc->privKeySet = 1;
        ecc->pubKeySet = 1;

        /* Now set key into an OpenSSL EC key. */
        ret = (buf = OPENSSL_malloc(len * 3 + 1)) != NULL;
    }
    if (ret == 1) {
        unsigned char *x = buf + 1;
        unsigned char *y = x + len;
        word32 xLen = len;
        word32 yLen = len;
        word32 dLen = len;

        d = y + len;
        ret = wc_ecc_export_private_raw(&ecc->key, x, &xLen, y, &yLen, d,
                                        &dLen) == 0;
    }
    if (ret == 1) {
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
        ret = (ecKey = (EC_KEY*)EVP_PKEY_get0_EC_KEY(pkey)) != NULL;
#else
        ret = (ecKey = EVP_PKEY_get0_EC_KEY(pkey)) != NULL;
#endif
    }
    if (ret == 1) {
        buf[0] = ECC_POINT_UNCOMP;
        ret = EC_KEY_oct2key(ecKey, buf, len * 2 + 1, NULL);
    }
    if (ret == 1) {
        ret = EC_KEY_oct2priv(ecKey, d, len);
    }

    if (buf != NULL) {
        OPENSSL_clear_free(buf, len * 3 + 1);
    }

    return ret;
}
#endif /* WE_HAVE_ECKEYGEN */

#ifdef WE_HAVE_ECDH
/**
 * Derive a secret from the private key and peer key in the public key context.
 *
 * @param  ctx     [in]      Public key context of operation.
 * @param  key     [in]      Buffer to hold secret/key.
 *                           NULL indicates that only length is returned.
 * @param  keyLen  [in/out]  Length og the secret/key buffer.
 * @returns  1 on success and 0 on failure.
 */
static int we_ecdh_derive(EVP_PKEY_CTX *ctx, unsigned char *key, size_t *keyLen)
{
    int ret = 1;
    we_Ecc *ecc;
    EC_KEY *ecKey = NULL;
    word32 len = *keyLen;
    ecc_key peer;

    WOLFENGINE_MSG("ECDH - Derive");

    ret = (ecc = (we_Ecc *)EVP_PKEY_CTX_get_data(ctx)) != NULL;
    if (ret == 1 && !ecc->privKeySet) {
        /* Set the private key. */
        ret = we_ec_get_ec_key(ctx, &ecKey, ecc);
        if (ret == 1) {
            ret = we_ec_set_private(&ecc->key, ecc->curveId, ecKey);
        }
        if (ret == 1) {
            ecc->privKeySet = 1;
        }
    }

    if (ret == 1 && key == NULL) {
        *keyLen = wc_ecc_get_curve_size_from_id(ecc->curveId);
    }
    if (ret == 1 && key != NULL) {
        /* 0x04, x, y - x and y are equal length. */
        unsigned char *x = ecc->peerKey + 1;
        unsigned char *y = x + ((ecc->peerKeyLen - 1) / 2);

        /* Create a new wolfSSL ECC key and set peer's public key. */
        ret = wc_ecc_init(&peer) == 0;
        if (ret == 1) {
            ret = wc_ecc_import_unsigned(&peer, x, y, NULL, ecc->curveId) == 0;
            if (ret == 1) {
                ret = wc_ecc_shared_secret(&ecc->key, &peer, key, &len) == 0;
            }
            if (ret == 1) {
                *keyLen = len;
            }

            /* Free the temporary peer key. */
            wc_ecc_free(&ecc->key);
        }
    }

    return ret;
}
#endif /* WE_HAVE_ECDH */

/**
 * Extra operations for working with ECC.
 * Supported operations include:
 *  - EVP_PKEY_CTRL_MD: set the method used when digesting.
 *
 * @param  ctx   [in]  Public key context of operation.
 * @param  type  [in]  Type of operation to perform.
 * @param  num   [in]  Integer parameter.
 * @param  ptr   [in]  Pointer parameter.
 * @returns  1 on success and 0 on failure.
 */
static int we_ec_ctrl(EVP_PKEY_CTX *ctx, int type, int num, void *ptr)
{
    int ret = 1;
    we_Ecc *ecc;
    EVP_PKEY *peerKey;
    EC_KEY *ecPeerKey = NULL;

    (void)num;
    (void)ptr;

    WOLFENGINE_MSG("ECC - Ctrl");

    ecc = (we_Ecc *)EVP_PKEY_CTX_get_data(ctx);
    if (ecc == NULL)
        ret = 0;

    if (ret == 1) {
        switch (type) {
    #ifdef WE_HAVE_ECDSA
            case EVP_PKEY_CTRL_MD:
                ecc->md = ptr;
                break;

            case EVP_PKEY_CTRL_DIGESTINIT:
                break;
    #endif

    #ifdef WE_HAVE_ECKEYGEN
            case EVP_PKEY_CTRL_EC_PARAMGEN_CURVE_NID:
                ecc->curveName = num;
                ret = we_ec_get_curve_id(num, &ecc->curveId);
                if (ret == 1) {
                    EC_GROUP_free(ecc->group);
                    ecc->group = EC_GROUP_new_by_curve_name(ecc->curveName);
                    ret = ecc->group != NULL;
                }
                break;
    #endif

    #ifdef WE_HAVE_ECDH
            case EVP_PKEY_CTRL_PEER_KEY:
                peerKey = (EVP_PKEY *)ptr;
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
                ret = (ecPeerKey = (EC_KEY*)EVP_PKEY_get0_EC_KEY(peerKey)) !=
                                                                           NULL;
#else
                ret = (ecPeerKey = EVP_PKEY_get0_EC_KEY(peerKey)) != NULL;
#endif
                if (ret == 1) {
                    OPENSSL_free(ecc->peerKey);
                    /* Get the EC key public key as and uncompressed point. */
                    ecc->peerKeyLen = EC_KEY_key2buf(ecPeerKey,
                        POINT_CONVERSION_UNCOMPRESSED, &ecc->peerKey, NULL);
                    if (ecc->peerKeyLen <= 0) {
                        ret = 0;
                    }
                }
                break;
    #endif

            default:
                ret = 0;
                break;
        }
    }

    return ret;
}

/** EVP public key method - EC using wolfSSL for the implementation. */
static EVP_PKEY_METHOD *we_ec_method = NULL;
#ifdef WE_HAVE_ECKEYGEN
#ifdef WE_HAVE_EC_P256
/** EVP public key method - EC P-256 using wolfSSL for the implementation. */
static EVP_PKEY_METHOD *we_ec_p256_method = NULL;
#endif
#ifdef WE_HAVE_EC_P384
/** EVP public key method - EC P-384 using wolfSSL for the implementation. */
static EVP_PKEY_METHOD *we_ec_p384_method = NULL;
#endif
#endif

/**
 * Initialize the ECC method.
 *
 * @return  1 on success and 0 on failure.
 */
static int we_init_ecc_meths()
{
    int ret;

    ret = (we_ec_method = EVP_PKEY_meth_new(EVP_PKEY_EC, 0)) != NULL;
    if (ret == 1) {
        EVP_PKEY_meth_set_init(we_ec_method, we_ec_init);
        EVP_PKEY_meth_set_copy(we_ec_method, we_ec_copy);
        EVP_PKEY_meth_set_cleanup(we_ec_method, we_ec_cleanup);

#ifdef WE_HAVE_ECDSA
        EVP_PKEY_meth_set_sign(we_ec_method, NULL, we_ecdsa_sign);
        EVP_PKEY_meth_set_verify(we_ec_method, NULL, we_ecdsa_verify);
#endif
#ifdef WE_HAVE_ECKEYGEN
        EVP_PKEY_meth_set_keygen(we_ec_method, NULL, we_ec_keygen);
#endif
#ifdef WE_HAVE_ECDH
        EVP_PKEY_meth_set_derive(we_ec_method, NULL, we_ecdh_derive);
#endif

        EVP_PKEY_meth_set_ctrl(we_ec_method, we_ec_ctrl, NULL);
    }

#ifdef WE_HAVE_ECKEYGEN
#ifdef WE_HAVE_EC_P256
    ret = (we_ec_p256_method = EVP_PKEY_meth_new(EVP_PKEY_EC, 0)) != NULL;
    if (ret == 1) {
        EVP_PKEY_meth_set_init(we_ec_p256_method, we_ec_p256_init);
        EVP_PKEY_meth_set_copy(we_ec_p256_method, we_ec_copy);
        EVP_PKEY_meth_set_cleanup(we_ec_p256_method, we_ec_cleanup);

        EVP_PKEY_meth_set_keygen(we_ec_p256_method, NULL, we_ec_keygen);

        EVP_PKEY_meth_set_ctrl(we_ec_p256_method, we_ec_ctrl, NULL);
    }
#endif
#ifdef WE_HAVE_EC_P384
    ret = (we_ec_p384_method = EVP_PKEY_meth_new(EVP_PKEY_EC, 0)) != NULL;
    if (ret == 1) {
        EVP_PKEY_meth_set_init(we_ec_p384_method, we_ec_p384_init);
        EVP_PKEY_meth_set_copy(we_ec_p384_method, we_ec_copy);
        EVP_PKEY_meth_set_cleanup(we_ec_p384_method, we_ec_cleanup);

        EVP_PKEY_meth_set_keygen(we_ec_p384_method, NULL, we_ec_keygen);

        EVP_PKEY_meth_set_ctrl(we_ec_p384_method, we_ec_ctrl, NULL);
    }
#endif
#endif

    if (ret == 0 && we_ec_method != NULL) {
        EVP_PKEY_meth_free(we_ec_method);
        we_ec_method = NULL;
    }

    return ret;
}

#endif /* WE_HAVE_ECC */

#ifdef WE_HAVE_EVP_PKEY

/**
 * Returns the list of public keys supported or the public key method for the
 * id.
 *
 * @param  e     [in]   Engine object.
 * @param  pkey  [out]  Public key method for id.
 *                      When NULL, return list of ids.
 * @param  nids  [out]  List of supported public key ids.
 * @param  nid   [in]   Public key id requested.
 * @return  When pkey is NULL, the number of NIDs returned.<br>
 *          When pkey is not NULL, 1 on success and 0 when algorithm not
 *          supported.
 */
static int we_pkey(ENGINE *e, EVP_PKEY_METHOD **pkey, const int **nids,
                         int nid)
{
    int ret = 1;

    (void)e;

    if (pkey == NULL) {
        /* Return a list of supported nids */
        *nids = we_pkey_nids;
        ret = (sizeof(we_pkey_nids)) / sizeof(*we_pkey_nids);
    }
    else {
        switch (nid) {
        case NID_X9_62_id_ecPublicKey:
            *pkey = we_ec_method;
            break;
#ifdef WE_HAVE_ECKEYGEN
#ifdef WE_HAVE_EC_P256
        case NID_X9_62_prime256v1:
            *pkey = we_ec_p256_method;
            break;
#endif
#ifdef WE_HAVE_EC_P384
        case NID_secp384r1:
            *pkey = we_ec_p384_method;
            break;
#endif
#endif /* WE_HAVE_ECKEYGEN */
        default:
            *pkey = NULL;
            ret = 0;
            break;
        }
    }

    return ret;
}
#endif /* WE_HAVE_EVP_PKEY */

#ifdef WE_HAVE_EC_KEY
static EC_KEY_METHOD *we_ec_key_method = NULL;

static int we_ec_key_keygen(EC_KEY *key)
{
    int ret = 1;
    int curveId;
    ecc_key ecc;
    int len = 0;
    unsigned char *buf = NULL;
    unsigned char *d = NULL;

    WOLFENGINE_MSG("EC - Key Generation");

    ret = we_ec_get_curve_id(EC_GROUP_get_curve_name(EC_KEY_get0_group(key)),
                             &curveId);
    if (ret == 1) {
        len = wc_ecc_get_curve_size_from_id(curveId);

        ret = wc_ecc_init(&ecc) == 0;
    }
    if (ret == 1) {
        ret = wc_ecc_make_key_ex(&we_globalRng, len, &ecc, curveId) == 0;
    }
    if (ret == 1) {
        /* Now set key into an OpenSSL EC key. */
        ret = (buf = OPENSSL_malloc(len * 3 + 1)) != NULL;
    }
    if (ret == 1) {
        unsigned char *x = buf + 1;
        unsigned char *y = x + len;
        word32 xLen = len;
        word32 yLen = len;
        word32 dLen = len;

        d = y + len;
        ret = wc_ecc_export_private_raw(&ecc, x, &xLen, y, &yLen, d,
                                        &dLen) == 0;
    }
    if (ret == 1) {
        buf[0] = ECC_POINT_UNCOMP;
        ret = EC_KEY_oct2key(key, buf, len * 2 + 1, NULL);
    }
    if (ret == 1) {
        ret = EC_KEY_oct2priv(key, d, len);
    }

    if (buf != NULL) {
        OPENSSL_clear_free(buf, len * 3 + 1);
    }

    return ret;
}

static int we_ec_key_compute_key(unsigned char **psec, size_t *pseclen,
                                 const EC_POINT *pub_key, const EC_KEY *ecdh)
{
    int ret;
    ecc_key key;
    ecc_key peer;
    ecc_key *pKey = NULL;
    ecc_key *pPeer = NULL;
    const EC_GROUP *group;
    int curveId;
    word32 len;
    int peerKeyLen;
    unsigned char* peerKey = NULL;
    unsigned char* secret = NULL;

    WOLFENGINE_MSG("ECDH - Compute Key");

    group = EC_KEY_get0_group(ecdh);
    ret = we_ec_get_curve_id(EC_GROUP_get_curve_name(group), &curveId);
    if (ret == 1) {
        peerKeyLen = EC_POINT_point2buf(group, pub_key,
                                        POINT_CONVERSION_UNCOMPRESSED, &peerKey,
                                        NULL);
        ret = peerKey != NULL;
    }
    if (ret == 1) {
        len = wc_ecc_get_curve_size_from_id(curveId);

        ret = (secret = OPENSSL_malloc(len)) != NULL;
    }
    if (ret == 1) {
        ret = wc_ecc_init(&key) == 0;
    }
#if !defined(HAVE_FIPS) || \
    (defined(HAVE_FIPS_VERSION) && HAVE_FIPS_VERSION != 2)
    if (ret == 1) {
        ret = wc_ecc_set_rng(&key, &we_globalRng) == 0;
    }
#endif /* !HAVE_FIPS || (HAVE_FIPS_VERSION && HAVE_FIPS_VERSION != 2) */
    if (ret == 1) {
        pKey = &key;

        ret = we_ec_set_private(pKey, curveId, ecdh);
    }
    if (ret == 1) {
        /* Create a new wolfSSL ECC key and set peer's public key. */
        ret = wc_ecc_init(&peer) == 0;
    }
    if (ret == 1) {
        unsigned char *x = peerKey + 1;
        unsigned char *y = x + ((peerKeyLen - 1) / 2);

        pPeer = &peer;

        ret = wc_ecc_import_unsigned(pPeer, x, y, NULL, curveId) == 0;
    }
    if (ret == 1) {
        ret = wc_ecc_shared_secret(pKey, pPeer, secret, &len) == 0;
    }
    if (ret == 1) {
        *psec = secret;
        *pseclen = len;
    }
    else {
        OPENSSL_free(secret);
    }
    OPENSSL_free(peerKey);
    wc_ecc_free(pPeer);
    wc_ecc_free(pKey);

    return ret;
}

static int we_ec_key_sign(int type, const unsigned char *dgst, int dLen,
                          unsigned char *sig, unsigned int *sigLen,
                          const BIGNUM *kinv, const BIGNUM *r, EC_KEY *ecKey)
{
    int ret;
    ecc_key key;
    ecc_key *pKey = NULL;
    const EC_GROUP *group;
    int curveId;
    word32 outLen;

    WOLFENGINE_MSG("ECDSA - Sign");

    (void)type;
    (void)kinv;
    (void)r;

    group = EC_KEY_get0_group(ecKey);
    ret = we_ec_get_curve_id(EC_GROUP_get_curve_name(group), &curveId);
    if (ret == 1) {
        ret = wc_ecc_init(&key) == 0;
    }
    if (ret == 1) {
        pKey = &key;

        ret = we_ec_set_private(&key, curveId, ecKey);
    }

    if (ret == 1 && sig == NULL) {
        /* Return signature size in bytes. */
        *sigLen = wc_ecc_sig_size(&key);
    }
    if (ret == 1 && sig != NULL) {
        outLen = *sigLen;
        ret = wc_ecc_sign_hash(dgst, dLen, sig, &outLen, &we_globalRng,
                               &key) == 0;
        if (ret == 1) {
            /* Return actual size. */
            *sigLen = outLen;
        }
    }

    wc_ecc_free(pKey);

    return ret;
}

static int we_ec_key_verify(int type, const unsigned char *dgst, int dLen,
                            const unsigned char *sig, int sigLen, EC_KEY *ecKey)
{
    int ret;
    int res;
    ecc_key key;
    ecc_key *pKey = NULL;
    const EC_GROUP *group;
    int curveId;

    WOLFENGINE_MSG("ECDSA - Verify");

    (void)type;

    group = EC_KEY_get0_group(ecKey);
    ret = we_ec_get_curve_id(EC_GROUP_get_curve_name(group), &curveId);
    if (ret == 1) {
        ret = wc_ecc_init(&key) == 0;
    }
    if (ret == 1) {
        pKey = &key;

        ret = we_ec_set_public(&key, curveId, ecKey);
    }
    if (ret == 1) {
        ret = wc_ecc_verify_hash(sig, sigLen, dgst, dLen, &res, &key) == 0;
    }
    if (ret == 1) {
        /* Verification result is 1 on success and 0 on failure. */
        ret = res; 
    }

    wc_ecc_free(pKey);

    return ret;
}

/**
 * Initialize the ECC method.
 *
 * @return  1 on success and 0 on failure.
 */
static int we_init_ec_key_meths()
{
    int ret;

    ret = (we_ec_key_method = EC_KEY_METHOD_new(NULL)) != NULL;
    if (ret == 1) {
        EC_KEY_METHOD_set_keygen(we_ec_key_method, we_ec_key_keygen);
        EC_KEY_METHOD_set_compute_key(we_ec_key_method, we_ec_key_compute_key);
        EC_KEY_METHOD_set_sign(we_ec_key_method, we_ec_key_sign, NULL, NULL);
        EC_KEY_METHOD_set_verify(we_ec_key_method, we_ec_key_verify, NULL);
    }

    return ret;
}

static const EC_KEY_METHOD *we_ec(void)
{
    return we_ec_key_method;
}
#endif /* WE_HAVE_EC_KEY */
#endif /* WE_HAVE_ECC */

/**
 * Initialize all wolfengine global data.
 * This includes:
 *  - Global random
 *  - SHA-256 method
 *  - AES128-GCM method
 *  - AES256-GCM method
 *  - EC method
 *
 * @param  e  [in]  Engine object.
 * @returns  1 on success and 0 on failure.
 */
static int wolfengine_init(ENGINE *e)
{
    int ret = 1;

    (void)e;

#if defined(WE_HAVE_ECC) || defined(WE_HAVE_AESGCM)
    ret = we_init_random();
#endif
#ifdef WE_HAVE_SHA256
    if (ret == 1) {
        ret = we_init_sha256_meth();
    }
#endif
#ifdef WE_HAVE_SHA384
    if (ret == 1) {
        ret = we_init_sha384_meth();
    }
#endif
#ifdef WE_HAVE_SHA512
    if (ret == 1) {
        ret = we_init_sha512_meth();
    }
#endif
#ifdef WE_HAVE_AESGCM
    if (ret == 1) {
        ret = we_init_aesgcm_meths();
    }
#endif
#ifdef WE_HAVE_ECC
#ifdef WE_HAVE_EVP_PKEY
    if (ret == 1) {
        ret = we_init_ecc_meths();
    }
#endif
#ifdef WE_HAVE_EC_KEY
    if (ret == 1) {
        ret = we_init_ec_key_meths();
    }
#endif
#endif

    return ret;
}

/**
 * Destroy all data allocated by wolfengine.
 *
 * @param  e  [in]  Engine object.
 * @returns  1 for success always.
 */
static int wolfengine_destroy(ENGINE *e)
{
    WOLFENGINE_MSG("Destroy");

    (void)e;

#ifdef WE_HAVE_ECC
    /* we_ec_method is freed by OpenSSL_cleanup(). */
#ifdef WE_HAVE_EC_KEY
    EC_KEY_METHOD_free(we_ec_key_method);
    we_ec_key_method = NULL;
#endif
#endif
#ifdef WE_HAVE_AESGCM
    EVP_CIPHER_meth_free(we_aes128_gcm_ciph);
    we_aes128_gcm_ciph = NULL;
    EVP_CIPHER_meth_free(we_aes256_gcm_ciph);
    we_aes256_gcm_ciph = NULL;
#endif
#ifdef WE_HAVE_SHA256
    EVP_MD_meth_free(we_sha256_md);
    we_sha256_md = NULL;
#endif
#ifdef WE_HAVE_SHA384
    EVP_MD_meth_free(we_sha384_md);
    we_sha384_md = NULL;
#endif
#ifdef WE_HAVE_SHA512
    EVP_MD_meth_free(we_sha512_md);
    we_sha512_md = NULL;
#endif
#if defined(WE_HAVE_ECC) || defined(WE_HAVE_AESGCM)
    if (we_globalRngInited) {
        wc_FreeRng(&we_globalRng);
        we_globalRngInited = 0;
    }
#endif

    return 1;
}

/**
 * Bind the wolfengine into an engine object.
 *
 * @param  e   [in]  Engine object.
 * @param  id  [in]  Library name or identifier.
 * @returns  1 on success and 0 on failure.
 */
static int wolfengine_bind(ENGINE *e, const char *id)
{
    int ret = 1;

    WOLFENGINE_MSG("Bind");

    if (XSTRNCMP(id, wolfengine_lib, XSTRLEN(wolfengine_lib)) != 0)
        ret = 0;

    if (ret == 1) {
        ret = ENGINE_set_id(e, wolfengine_id);
    }
    if (ret == 1) {
        ret = wolfengine_init(e);
    }
    if (ret == 1 && ENGINE_set_name(e, wolfengine_name) == 0) {
        ret = 0;
    }
    if (ret == 1 && ENGINE_set_digests(e, we_digests) == 0) {
        ret = 0;
    }
    if (ret == 1 && ENGINE_set_ciphers(e, we_ciphers) == 0) {
        ret = 0;
    }
#ifdef WE_HAVE_EVP_PKEY
    if (ret == 1 && ENGINE_set_pkey_meths(e, we_pkey) == 0) {
        ret = 0;
    }
#endif
#ifdef WE_HAVE_EC_KEY
    if (ret == 1 && ENGINE_set_EC(e, we_ec()) == 0) {
        ret = 0;
    }
#endif
    if (ret == 1 && ENGINE_set_destroy_function(e, wolfengine_destroy) == 0) {
        ret = 0;
    }

    return ret;
}

/** Define implementation of common bind function in OpenSSL engines. */
IMPLEMENT_DYNAMIC_BIND_FN(wolfengine_bind)
/** Define implementation of common checking function in OpenSSL engines. */
IMPLEMENT_DYNAMIC_CHECK_FN()

