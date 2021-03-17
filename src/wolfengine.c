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

#include "wolfengine.h"


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
#ifdef WE_HAVE_RSA
    NID_rsaEncryption,
#endif
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

/**
 * Get the public key types supported as ids.
 *
 * @param nids [out]  Public key nids.
 * @returns  Number of NIDs in list.
 */
int we_pkey_get_nids(const int **nids)
{
    *nids = we_pkey_nids;
    return (sizeof(we_pkey_nids)) / sizeof(*we_pkey_nids);
}
#endif /* WE_HAVE_EVP_PKEY || WE_USE_HASH */

#if defined(WE_HAVE_ECC) || defined(WE_HAVE_AESGCM) || defined(WE_HAVE_RSA)

/*
 * Random number generator
 */

/* Global random number generator. */
static WC_RNG we_globalRng;
/* Pointer to global random number generator. */
WC_RNG* we_rng = &we_globalRng;
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

#endif /* WE_HAVE_ECC || WE_HAVE_AESGCM || WE_HAVE_RSA */

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
#ifdef WE_HAVE_SHA3_224
    NID_sha3_224,
#endif
#ifdef WE_HAVE_SHA3_256
    NID_sha3_256,
#endif
#ifdef WE_HAVE_SHA3_384
    NID_sha3_384,
#endif
#ifdef WE_HAVE_SHA3_512
    NID_sha3_512,
#endif
};

/**
 * Convert an OpenSSL hash NID to a wolfCrypt hash OID.
 *
 * @param  nid  [in]  OpenSSL NID to convert.
 * @return  Returns the OID if a NID -> OID mapping exists and a negative value
 *          if it doesn't.
 */
int we_nid_to_wc_hash_oid(int nid)
{
    int hashType = WC_HASH_TYPE_NONE;

    switch (nid) {
#ifdef WE_HAVE_SHA256
        case NID_sha256:
            hashType = WC_HASH_TYPE_SHA256;
            break;
#endif
#ifdef WE_HAVE_SHA384
        case NID_sha384:
            hashType = WC_HASH_TYPE_SHA384;
            break;
#endif
#ifdef WE_HAVE_SHA512
        case NID_sha512:
            hashType = WC_HASH_TYPE_SHA512;
            break;
#endif
#ifdef WE_HAVE_SHA3_224
        case NID_sha3_224:
            hashType = WC_HASH_TYPE_SHA3_224;
            break;
#endif
#ifdef WE_HAVE_SHA3_256
        case NID_sha3_256:
            hashType = WC_HASH_TYPE_SHA3_256;
            break;
#endif
#ifdef WE_HAVE_SHA3_384
        case NID_sha3_384:
            hashType = WC_HASH_TYPE_SHA3_384;
            break;
#endif
#ifdef WE_HAVE_SHA3_512
        case NID_sha3_512:
            hashType = WC_HASH_TYPE_SHA3_512;
            break;
        default:
            break;
#endif
    }

    return wc_HashGetOID(hashType);
}

/*
 * Digests
 */

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
#ifdef WE_HAVE_SHA3_224
        case NID_sha3_224:
            *digest = we_sha3_224_md;
            break;
#endif
#ifdef WE_HAVE_SHA3_256
        case NID_sha3_256:
            *digest = we_sha3_256_md;
            break;
#endif
#ifdef WE_HAVE_SHA3_384
        case NID_sha3_384:
            *digest = we_sha3_384_md;
            break;
#endif
#ifdef WE_HAVE_SHA3_512
        case NID_sha3_512:
            *digest = we_sha3_512_md;
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


/** List of supported cipher algorithms as numeric ids. */
static const int we_cipher_nids[] = {
#ifdef WE_HAVE_AESGCM
    NID_aes_128_gcm,
    NID_aes_256_gcm,
#endif
};


/*
 * Ciphers
 */

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

#if defined(WE_HAVE_ECC) && defined(WE_HAVE_EC_KEY)
static const EC_KEY_METHOD *we_ec(void)
{
    return we_ec_key_method;
}
#endif

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
        ret = we_pkey_get_nids(nids);
    }
    else {
        switch (nid) {
#ifdef WE_HAVE_RSA
        case NID_rsaEncryption:
            *pkey = we_rsa_pkey_method;
            break;
#endif /* WE_HAVE_RSA */
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
#ifdef WE_HAVE_SHA3_224
    if (ret == 1) {
        ret = we_init_sha3_224_meth();
    }
#endif
#ifdef WE_HAVE_SHA3_256
    if (ret == 1) {
        ret = we_init_sha3_256_meth();
    }
#endif
#ifdef WE_HAVE_SHA3_384
    if (ret == 1) {
        ret = we_init_sha3_384_meth();
    }
#endif
#ifdef WE_HAVE_SHA3_512
    if (ret == 1) {
        ret = we_init_sha3_512_meth();
    }
#endif
#ifdef WE_HAVE_AESGCM
    if (ret == 1) {
        ret = we_init_aesgcm_meths();
    }
#endif
#ifdef WE_HAVE_RSA
#ifdef WE_HAVE_EVP_PKEY
    if (ret == 1) {
        ret = we_init_rsa_pkey_meth();
    }
#endif /* WE_HAVE_EVP_PKEY */
#endif /* WE_HAVE_RSA */
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
#ifdef WE_HAVE_SHA3_224
    EVP_MD_meth_free(we_sha3_224_md);
    we_sha3_224_md = NULL;
#endif
#ifdef WE_HAVE_SHA3_256
    EVP_MD_meth_free(we_sha3_256_md);
    we_sha3_256_md = NULL;
#endif
#ifdef WE_HAVE_SHA3_384
    EVP_MD_meth_free(we_sha3_384_md);
    we_sha3_384_md = NULL;
#endif
#ifdef WE_HAVE_SHA3_512
    EVP_MD_meth_free(we_sha3_512_md);
    we_sha3_512_md = NULL;
#endif
#if defined(WE_HAVE_ECC) || defined(WE_HAVE_AESGCM) || defined(WE_HAVE_RSA)
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

