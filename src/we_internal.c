/* we_internal.c
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

#include <wolfengine/we_wolfengine.h>
#include <wolfengine/we_internal.h>

/** Engine bound to. */
static ENGINE *bound = NULL;

#if defined(WE_HAVE_EVP_PKEY) || defined(WE_USE_HASH)
/** List of public key types supported as ids. */
static const int we_pkey_nids[] = {
#ifdef WE_HAVE_HMAC
    NID_hmac,
#endif /* WE_HAVE_HMAC */
#ifdef WE_HAVE_CMAC
    NID_cmac,
    NID_wolfengine_cmac,
#endif /* WE_HAVE_CMAC */
#ifdef WE_HAVE_TLS1_PRF
    NID_tls1_prf,
#endif /* WE_HAVE_TLS1_PRF */
#ifdef WE_HAVE_HKDF
    NID_hkdf,
#endif /* WE_HAVE_HKDF */
#ifdef WE_HAVE_RSA
    NID_rsaEncryption,
#endif
#ifdef WE_HAVE_DH
    NID_dhKeyAgreement,
#endif
#ifdef WE_HAVE_ECC
    NID_X9_62_id_ecPublicKey,
#ifdef WE_HAVE_ECKEYGEN
#ifdef WE_HAVE_EC_P192
    NID_X9_62_prime192v1,
#endif
#ifdef WE_HAVE_EC_P224
    NID_secp224r1,
#endif
#ifdef WE_HAVE_EC_P256
    NID_X9_62_prime256v1,
#endif
#ifdef WE_HAVE_EC_P384
    NID_secp384r1,
#endif
#ifdef WE_HAVE_EC_P521
    NID_secp521r1,
#endif
#endif
#endif
};

static const int we_pkey_asn1_nids[] = {
#ifdef WE_HAVE_HMAC
    NID_hmac,
#endif /* WE_HAVE_HMAC */
#ifdef WE_HAVE_CMAC
    NID_cmac,
    NID_wolfengine_cmac,
#endif /* WE_HAVE_CMAC */
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

/**
 * Get the public key ASN.1 types supported as ids.
 *
 * @param nids [out]  Public key ASN.1 nids.
 * @returns  Number of NIDs in list.
 */
int we_pkey_asn1_get_nids(const int **nids)
{
    *nids = we_pkey_asn1_nids;
    return (sizeof(we_pkey_asn1_nids)) / sizeof(*we_pkey_asn1_nids);
}
#endif /* WE_HAVE_EVP_PKEY || WE_USE_HASH */

#if defined(WE_HAVE_ECC) || defined(WE_HAVE_AESGCM) || defined(WE_HAVE_RSA) || \
    defined(WE_HAVE_RANDOM) || defined(WE_HAVE_DH)

/*
 * Random number generator
 */

/* Global random number generator. */
static WC_RNG we_globalRng;
/* Pointer to global random number generator. */
WC_RNG* we_rng = &we_globalRng;
/* Global RNG has been initialized. */
static int we_globalRngInited = 0;
#ifndef WE_SINGLE_THREADED
/* Mutex for protecting use of global random number generator. */
wolfSSL_Mutex we_global_rng_mutex;
/* Pointer to mutex for protecting use of global random number generator.*/
wolfSSL_Mutex* we_rng_mutex = &we_global_rng_mutex;
#endif

/**
 * Initialize the global random number generator object.
 *
 * @returns  1 on success and 0 on failure.
 */
static int we_init_random()
{
    int ret = 1;
    int rc;

    WOLFENGINE_ENTER(WE_LOG_ENGINE, "we_init_random");

    if (!we_globalRngInited) {
        rc = wc_InitRng(&we_globalRng);
        if (rc != 0) {
            WOLFENGINE_ERROR_FUNC(WE_LOG_ENGINE, "wc_InitRng", rc);
            ret = 0;
        }
    #ifndef WE_SINGLE_THREADED
        if (ret == 1) {
            rc = wc_InitMutex(&we_global_rng_mutex);
            if (rc != 0) {
                wc_FreeRng(&we_globalRng);
                WOLFENGINE_ERROR_FUNC(WE_LOG_ENGINE, "wc_InitRng", rc);
                ret = 0;
            }
        }
    #endif
        if (ret == 1) {
            we_globalRngInited = 1;
        }
    }

    WOLFENGINE_LEAVE(WE_LOG_ENGINE, "we_init_random", ret);

    return ret;
}

/**
 * Free the global random number generator object.
 */
static void we_final_random()
{
    WOLFENGINE_ENTER(WE_LOG_ENGINE, "we_final_random");

    if (we_globalRngInited) {
    #ifndef WE_SINGLE_THREADED
        wc_FreeMutex(&we_global_rng_mutex);
    #endif
        wc_FreeRng(&we_globalRng);
        we_globalRngInited = 0;
    }

    WOLFENGINE_LEAVE(WE_LOG_ENGINE, "we_final_random", 1);
}

#endif /* WE_HAVE_ECC || WE_HAVE_AESGCM || WE_HAVE_RSA */

/** List of supported digest algorithms. */
static const int we_digest_nids[] = {
#ifdef WE_HAVE_SHA1
    NID_sha1,
#endif
#ifdef WE_HAVE_SHA224
    NID_sha224,
#endif
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
 * @returns  Hash type corresponding to the NID or WC_HASH_TYPE_NONE
 *           when not supported.
 */
enum wc_HashType we_nid_to_wc_hash_type(int nid)
{
    enum wc_HashType hashType = WC_HASH_TYPE_NONE;
    char errBuff[WOLFENGINE_MAX_LOG_WIDTH];

    WOLFENGINE_ENTER(WE_LOG_ENGINE, "we_nid_to_wc_hash_type");

    switch (nid) {
#ifndef NO_MD5
        case NID_md5:
            hashType = WC_HASH_TYPE_MD5;
            break;
#endif
#ifdef WE_HAVE_SHA1
        case NID_sha1:
            hashType = WC_HASH_TYPE_SHA;
            break;
#endif
#ifdef WE_HAVE_SHA224
        case NID_sha224:
            hashType = WC_HASH_TYPE_SHA224;
            break;
#endif
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
#endif
        default:
            XSNPRINTF(errBuff, sizeof(errBuff), "Unsupported hash type NID: %d",
                      nid);
            WOLFENGINE_ERROR_MSG(WE_LOG_ENGINE, errBuff);
            break;
    }

    WOLFENGINE_LEAVE(WE_LOG_ENGINE, "we_nid_to_wc_hash_type", hashType);

    return hashType;
}

/**
 * Convert an OpenSSL hash NID to a wolfCrypt hash OID.
 *
 * @param  nid  [in]  OpenSSL NID to convert.
 * @return  Returns the OID if a NID -> OID mapping exists and a negative value
 *          if it doesn't.
 */
int we_nid_to_wc_hash_oid(int nid) {
    enum wc_HashType hashType = we_nid_to_wc_hash_type(nid);
    int ret;

    WOLFENGINE_ENTER(WE_LOG_ENGINE, "we_nid_to_wc_hash_oid");

    ret = wc_HashGetOID(hashType);
    if (ret < 0) {
        WOLFENGINE_ERROR_FUNC(WE_LOG_ENGINE, "wc_HashGetOID", ret);
    }

    WOLFENGINE_LEAVE(WE_LOG_ENGINE, "we_nid_to_wc_hash_oid", ret);

    return ret;
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
    char errBuff[WOLFENGINE_MAX_LOG_WIDTH];

    WOLFENGINE_ENTER(WE_LOG_ENGINE, "we_digests");

    (void)e;

    if (digest == NULL) {
        /* Return a list of supported NIDs (Numerical IDentifiers) */
        *nids = we_digest_nids;
        ret = (sizeof(we_digest_nids)) / sizeof(*we_digest_nids);
    }
    else {
        switch (nid) {
#ifdef WE_HAVE_SHA1
        case NID_sha1:
            *digest = we_sha1_md;
            break;
#endif
#ifdef WE_HAVE_SHA224
        case NID_sha224:
            *digest = we_sha224_md;
            break;
#endif
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
            XSNPRINTF(errBuff, sizeof(errBuff), "Unsupported digest NID: %d",
                      nid);
            WOLFENGINE_ERROR_MSG(WE_LOG_ENGINE, errBuff);
            *digest = NULL;
            ret = 0;
            break;
        }
    }

    WOLFENGINE_LEAVE(WE_LOG_ENGINE, "we_digests", ret);

    return ret;
}


/** List of supported cipher algorithms as numeric ids. */
static const int we_cipher_nids[] = {
#ifdef WE_HAVE_DES3CBC
    NID_des_ede3_cbc,
#endif
#ifdef WE_HAVE_AESECB
    NID_aes_128_ecb,
    NID_aes_192_ecb,
    NID_aes_256_ecb,
#endif
#ifdef WE_HAVE_AESCBC
    NID_aes_128_cbc,
    NID_aes_192_cbc,
    NID_aes_256_cbc,
    NID_aes_128_cbc_hmac_sha256,
    NID_aes_256_cbc_hmac_sha256,
#endif
#ifdef WE_HAVE_AESCTR
    NID_aes_128_ctr,
    NID_aes_192_ctr,
    NID_aes_256_ctr,
#endif
#ifdef WE_HAVE_AESGCM
    NID_aes_128_gcm,
    NID_aes_192_gcm,
    NID_aes_256_gcm,
#endif
#ifdef WE_HAVE_AESCCM
    NID_aes_128_ccm,
    NID_aes_192_ccm,
    NID_aes_256_ccm,
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
    char errBuff[WOLFENGINE_MAX_LOG_WIDTH];

    (void)e;

    WOLFENGINE_ENTER(WE_LOG_ENGINE, "we_ciphers");

    if (cipher == NULL) {
        /* Return a list of supported NIDs (Numerical IDentifiers) */
        *nids = we_cipher_nids;
        ret = (sizeof(we_cipher_nids)) / sizeof(*we_cipher_nids);
    }
    else {
        switch (nid) {
#ifdef WE_HAVE_DES3CBC
        case NID_des_ede3_cbc:
            *cipher = we_des3_cbc_ciph;
            break;
#endif
#ifdef WE_HAVE_AESECB
        case NID_aes_128_ecb:
            *cipher = we_aes128_ecb_ciph;
            break;
        case NID_aes_192_ecb:
            *cipher = we_aes192_ecb_ciph;
            break;
        case NID_aes_256_ecb:
            *cipher = we_aes256_ecb_ciph;
            break;
#endif
#ifdef WE_HAVE_AESCBC
        case NID_aes_128_cbc:
            *cipher = we_aes128_cbc_ciph;
            break;
        case NID_aes_192_cbc:
            *cipher = we_aes192_cbc_ciph;
            break;
        case NID_aes_256_cbc:
            *cipher = we_aes256_cbc_ciph;
            break;
        case NID_aes_128_cbc_hmac_sha256:
            *cipher = we_aes128_cbc_hmac_ciph;
            break;
        case NID_aes_256_cbc_hmac_sha256:
            *cipher = we_aes256_cbc_hmac_ciph;
            break;
#endif
#ifdef WE_HAVE_AESCTR
        case NID_aes_128_ctr:
            *cipher = we_aes128_ctr_ciph;
            break;
        case NID_aes_192_ctr:
            *cipher = we_aes192_ctr_ciph;
            break;
        case NID_aes_256_ctr:
            *cipher = we_aes256_ctr_ciph;
            break;
#endif
#ifdef WE_HAVE_AESGCM
        case NID_aes_128_gcm:
            *cipher = we_aes128_gcm_ciph;
            break;
        case NID_aes_192_gcm:
            *cipher = we_aes192_gcm_ciph;
            break;
        case NID_aes_256_gcm:
            *cipher = we_aes256_gcm_ciph;
            break;
#endif
#ifdef WE_HAVE_AESCCM
        case NID_aes_128_ccm:
            *cipher = we_aes128_ccm_ciph;
            break;
        case NID_aes_192_ccm:
            *cipher = we_aes192_ccm_ciph;
            break;
        case NID_aes_256_ccm:
            *cipher = we_aes256_ccm_ciph;
            break;
#endif
        default:
            XSNPRINTF(errBuff, sizeof(errBuff), "Unsupported cipher NID: %d",
                      nid);
            WOLFENGINE_ERROR_MSG(WE_LOG_ENGINE, errBuff);

            *cipher = NULL;
            ret = 0;
            break;
        }
    }

    WOLFENGINE_LEAVE(WE_LOG_ENGINE, "we_ciphers", ret);

    return ret;
}

#if defined(WE_HAVE_ECC) && defined(WE_HAVE_EC_KEY)
static const EC_KEY_METHOD *we_ec(void)
{
    return we_ec_key_method;
}
#endif

#if defined(WE_HAVE_EVP_PKEY)
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
    char errBuff[WOLFENGINE_MAX_LOG_WIDTH];

    (void)e;

    WOLFENGINE_ENTER(WE_LOG_ENGINE, "we_pkey");

    if (pkey == NULL) {
        /* Return a list of supported nids */
        ret = we_pkey_get_nids(nids);
        WOLFENGINE_MSG(WE_LOG_ENGINE, "Returning %d supported public key NIDs",
                       ret);
    }
    else {
        switch (nid) {
#ifdef WE_HAVE_HMAC
        case NID_hmac:
            *pkey = we_hmac_pkey_method;
            break;
#endif /* WE_HAVE_HMAC */
#ifdef WE_HAVE_CMAC
        case NID_cmac:
            *pkey = we_cmac_pkey_method;
            break;
        case NID_wolfengine_cmac:
            *pkey = we_cmac_we_pkey_method;
            break;
#endif /* WE_HAVE_CMAC */
#ifdef WE_HAVE_TLS1_PRF
        case NID_tls1_prf:
            *pkey = we_tls1_prf_method;
            break;
#endif /* WE_HAVE_TLS1_PRF */
#ifdef WE_HAVE_HKDF
        case NID_hkdf:
            *pkey = we_hkdf_method;
            break;
#endif /* WE_HAVE_HKDF */
#ifdef WE_HAVE_RSA
        case NID_rsaEncryption:
            *pkey = we_rsa_pkey_method;
            break;
#endif /* WE_HAVE_RSA */
#ifdef WE_HAVE_DH
        case NID_dhKeyAgreement:
            *pkey = we_dh_pkey_method;
            break;
#endif /* WE_HAVE_DH */
#ifdef WE_HAVE_ECC
        case NID_X9_62_id_ecPublicKey:
            *pkey = we_ec_method;
            break;
#endif /* WE_HAVE_ECC */
#ifdef WE_HAVE_ECKEYGEN
#ifdef WE_HAVE_EC_P192
        case NID_X9_62_prime192v1:
            *pkey = we_ec_p192_method;
            break;
#endif
#ifdef WE_HAVE_EC_P224
        case NID_secp224r1:
            *pkey = we_ec_p224_method;
            break;
#endif
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
#ifdef WE_HAVE_EC_P521
        case NID_secp521r1:
            *pkey = we_ec_p521_method;
            break;
#endif
#endif /* WE_HAVE_ECKEYGEN */
        default:
            XSNPRINTF(errBuff, sizeof(errBuff), "we_pkey: Unsupported public "
                      "key NID: %d", nid);
            WOLFENGINE_ERROR_MSG(WE_LOG_ENGINE, errBuff);

            *pkey = NULL;
            ret = 0;
            break;
        }
    }

    WOLFENGINE_LEAVE(WE_LOG_ENGINE, "we_pkey", ret);

    return ret;
}

static int we_pkey_asn1(ENGINE *e, EVP_PKEY_ASN1_METHOD **pkey,
                        const int **nids, int nid)
{
    int ret = 1;
    char errBuff[WOLFENGINE_MAX_LOG_WIDTH];

    (void)e;

    if (pkey == NULL) {
        /* Return a list of supported nids */
        ret = we_pkey_asn1_get_nids(nids);
    }
    else {
        switch (nid) {
#ifdef WE_HAVE_HMAC
        case NID_hmac:
            *pkey = we_hmac_pkey_asn1_method;
            break;
#endif /* WE_HAVE_HMAC */
#ifdef WE_HAVE_CMAC
        case NID_cmac:
            *pkey = we_cmac_pkey_asn1_method;
            break;
        case NID_wolfengine_cmac:
            *pkey = we_cmac_we_pkey_asn1_method;
            break;
#endif /* WE_HAVE_CMAC */
        default:
            XSNPRINTF(errBuff, sizeof(errBuff), "we_pkey: Unsupported public "
                      "key ASN1 NID: %d", nid);
            WOLFENGINE_ERROR_MSG(WE_LOG_ENGINE, errBuff);

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
 *  - SHA-2 methods
 *  - SHA-3 methods
 *  - DES3-CBC methods
 *  - AES-EBC methods
 *  - AES-CBC methods
 *  - AES-CTR methods
 *  - AES-GCM methods
 *  - AES-CCM methods
 *  - RSA method
 *  - EC methods
 *
 * @param  e  [in]  Engine object.
 * @returns  1 on success and 0 on failure.
 */
static int wolfengine_init(ENGINE *e)
{
    int ret = 1;

    (void)e;

    WOLFENGINE_ENTER(WE_LOG_ENGINE, "wolfengine_init");

#if defined(WE_HAVE_ECC) || defined(WE_HAVE_AESGCM) || defined(WE_HAVE_RSA) || \
    defined(WE_HAVE_DH) || defined(WE_HAVE_RANDOM)
    ret = we_init_random();
#endif
#ifdef WE_HAVE_SHA1
    if (ret == 1) {
        ret = we_init_sha_meth();
    }
#endif
#ifdef WE_HAVE_SHA224
    if (ret == 1) {
        ret = we_init_sha224_meth();
    }
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
#ifdef WE_HAVE_DES3CBC
    if (ret == 1) {
        ret = we_init_des3cbc_meths();
    }
#endif
#ifdef WE_HAVE_AESECB
    if (ret == 1) {
        ret = we_init_aesecb_meths();
    }
#endif
#ifdef WE_HAVE_AESCBC
    if (ret == 1) {
        ret = we_init_aescbc_meths();
    }
    if (ret == 1) {
        ret = we_init_aescbc_hmac_meths();
    }
#endif
#ifdef WE_HAVE_AESCTR
    if (ret == 1) {
        ret = we_init_aesctr_meths();
    }
#endif
#ifdef WE_HAVE_AESGCM
    if (ret == 1) {
        ret = we_init_aesgcm_meths();
    }
#endif
#ifdef WE_HAVE_AESCCM
    if (ret == 1) {
        ret = we_init_aesccm_meths();
    }
#endif
#ifdef WE_HAVE_HMAC
    if (ret == 1) {
        ret = we_init_hmac_pkey_meth();
    }
    if (ret == 1) {
        ret = we_init_hmac_pkey_asn1_meth();
    }
#endif /* WE_HAVE_HMAC */
#ifdef WE_HAVE_CMAC
    if (ret == 1) {
        ret = we_init_cmac_pkey_meth();
    }
    if (ret == 1) {
        ret = we_init_cmac_pkey_asn1_meth();
    }
#endif /* WE_HAVE_CMAC */
#ifdef WE_HAVE_TLS1_PRF
#ifdef WE_HAVE_EVP_PKEY
    if (ret == 1) {
        ret = we_init_tls1_prf_meth();
    }
#endif /* WE_HAVE_EVP_PKEY */
#endif /* WE_HAVE_TLS1_PRF */
#ifdef WE_HAVE_HKDF
#ifdef WE_HAVE_EVP_PKEY
    if (ret == 1) {
        ret = we_init_hkdf_meth();
    }
#endif /* WE_HAVE_EVP_PKEY */
#endif /* WE_HAVE_HKDF */
#ifdef WE_HAVE_DH
#ifdef WE_HAVE_EVP_PKEY
    if (ret == 1) {
        ret = we_init_dh_pkey_meth();
    }
#endif /* WE_HAVE_EVP_PKEY */
    if (ret == 1) {
        ret = we_init_dh_meth();
    }
#endif /* WE_HAVE_DH */
#ifdef WE_HAVE_RSA
    if (ret == 1) {
        ret = we_init_rsa_meth();
    }
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
#if OPENSSL_VERSION_NUMBER < 0x10100000L
#if defined(WE_HAVE_ECDH)
    if (ret == 1) {
        ret = we_init_ecdh_meth();
    }
#endif /* WE_HAVE_ECDH */
#endif /* OPENSSL_VERSION_NUMBER < 0x10100000L */
#ifdef WE_HAVE_ECDSA
#if OPENSSL_VERSION_NUMBER <= 0x100020ffL
    if (ret == 1) {
        we_init_ecdsa_meth();
    }
#endif
#endif

#endif

    WOLFENGINE_LEAVE(WE_LOG_ENGINE, "wolfengine_init", ret);

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
    WOLFENGINE_ENTER(WE_LOG_ENGINE, "wolfengine_destroy");

    (void)e;

#ifdef WE_HAVE_DH
    DH_meth_free(we_dh_method);
    we_dh_method = NULL;
#endif
#ifdef WE_HAVE_RSA
    RSA_meth_free(we_rsa_method);
    we_rsa_method = NULL;
#endif /* WE_HAVE_RSA */
#ifdef WE_HAVE_ECC
    /* we_ec_method is freed by OpenSSL_cleanup(). */
#ifdef WE_HAVE_EC_KEY
    EC_KEY_METHOD_free(we_ec_key_method);
    we_ec_key_method = NULL;
#endif
#endif
#ifdef WE_HAVE_DES3CBC
    EVP_CIPHER_meth_free(we_des3_cbc_ciph);
    we_des3_cbc_ciph = NULL;
#endif
#ifdef WE_HAVE_AESECB
    EVP_CIPHER_meth_free(we_aes128_ecb_ciph);
    we_aes128_ecb_ciph = NULL;
    EVP_CIPHER_meth_free(we_aes192_ecb_ciph);
    we_aes192_ecb_ciph = NULL;
    EVP_CIPHER_meth_free(we_aes256_ecb_ciph);
    we_aes256_ecb_ciph = NULL;
#endif
#ifdef WE_HAVE_AESCBC
    EVP_CIPHER_meth_free(we_aes128_cbc_ciph);
    we_aes128_cbc_ciph = NULL;
    EVP_CIPHER_meth_free(we_aes192_cbc_ciph);
    we_aes192_cbc_ciph = NULL;
    EVP_CIPHER_meth_free(we_aes256_cbc_ciph);
    we_aes256_cbc_ciph = NULL;

    EVP_CIPHER_meth_free(we_aes128_cbc_hmac_ciph);
    we_aes128_cbc_hmac_ciph = NULL;
    EVP_CIPHER_meth_free(we_aes256_cbc_hmac_ciph);
    we_aes256_cbc_hmac_ciph = NULL;
#endif
#ifdef WE_HAVE_AESCTR
    EVP_CIPHER_meth_free(we_aes128_ctr_ciph);
    we_aes128_ctr_ciph = NULL;
    EVP_CIPHER_meth_free(we_aes192_ctr_ciph);
    we_aes192_ctr_ciph = NULL;
    EVP_CIPHER_meth_free(we_aes256_ctr_ciph);
    we_aes256_ctr_ciph = NULL;
#endif
#ifdef WE_HAVE_AESGCM
    EVP_CIPHER_meth_free(we_aes128_gcm_ciph);
    we_aes128_gcm_ciph = NULL;
    EVP_CIPHER_meth_free(we_aes192_gcm_ciph);
    we_aes192_gcm_ciph = NULL;
    EVP_CIPHER_meth_free(we_aes256_gcm_ciph);
    we_aes256_gcm_ciph = NULL;
#endif
#ifdef WE_HAVE_AESCCM
    EVP_CIPHER_meth_free(we_aes128_ccm_ciph);
    we_aes128_ccm_ciph = NULL;
    EVP_CIPHER_meth_free(we_aes192_ccm_ciph);
    we_aes192_ccm_ciph = NULL;
    EVP_CIPHER_meth_free(we_aes256_ccm_ciph);
    we_aes256_ccm_ciph = NULL;
#endif
#ifdef WE_HAVE_SHA1
    EVP_MD_meth_free(we_sha1_md);
    we_sha1_md = NULL;
#endif
#ifdef WE_HAVE_SHA224
    EVP_MD_meth_free(we_sha224_md);
    we_sha224_md = NULL;
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
    we_final_random();
#endif

    bound = NULL;

    WOLFENGINE_LEAVE(WE_LOG_ENGINE, "wolfengine_destroy", 1);

    return 1;
}

#define WOLFENGINE_CMD_ENABLE_DEBUG          ENGINE_CMD_BASE
#define WOLFENGINE_CMD_SET_LOG_LEVEL         (ENGINE_CMD_BASE + 1)
#define WOLFENGINE_CMD_SET_LOG_COMPONENTS    (ENGINE_CMD_BASE + 2)
#define WOLFENGINE_CMD_SET_LOGGING_CB        (ENGINE_CMD_BASE + 3)

/**
 * wolfEngine control command list.
 *
 * Note that these control commands are specific to the engine itself, not
 * necessarily underlying algorithm behavior (unless otherwise stated).
 *
 * This list must be ordered in an increasing order, by command number. The
 * list must also be NULL terminated, ending with an array element that is
 * set to NULL/0 entries.
 *
 * COMMAND DESCRIPTIONS:
 *
 * enable_debug - Enable/disable wolfEngine debug logging, must also
 *                have defined WOLFENGINE_DEBUG or used --enable-debug.
 *                (1 = enable, 0 = disable)
 *
 * log_level    - Set wolfEngine logging level. Input is bitmask of levels
 *                from we_logging.h wolfEngine_LogType enum. Default wolfEngine
 *                log level, if not set, logs error, enter/leave, and info.
 *
 * log_components - Set wolfEngine components to be included in log messages.
 *                  Input is bitmask of levels from we_logging.h
 *                  wolfEngine_LogComponents enum. Default wolfEngine component
 *                  selection logs all components unless set by application.
 *
 * INTERNAL COMMANDS (not listed here, as not NUMERIC, STRING, or NO_INPUT):
 * "set_logging_cb" - Sets the wolfEngine loggging callback, function pointer
 *                    passed in must match wolfEngine_Logging_cb prototype
 *                    from we_logging.h.
 *
 */
static ENGINE_CMD_DEFN wolfengine_cmd_defns[] = {

    { WOLFENGINE_CMD_ENABLE_DEBUG,
      "enable_debug",
      "Enable wolfEngine debug logging (1=enable, 0=disable)",
      ENGINE_CMD_FLAG_NUMERIC },
    { WOLFENGINE_CMD_SET_LOG_LEVEL,
      "log_level",
      "Set wolfEngine logging level (bitmask from wolfEngine_LogType)",
      ENGINE_CMD_FLAG_NUMERIC },
    { WOLFENGINE_CMD_SET_LOG_COMPONENTS,
      "log_components",
      "Set components to be logged by wolfEngine "
          "(bitmask from wolfEngine_LogComponents)",
      ENGINE_CMD_FLAG_NUMERIC },
    { WOLFENGINE_CMD_SET_LOGGING_CB,
      "set_logging_cb",
      "Set wolfEngine logging callback",
      ENGINE_CMD_FLAG_INTERNAL },

    /* last element MUST be NULL/0 entry, do not remove */
    {0, NULL, NULL, 0}
};

/**
 * wolfEngine control command handler.
 *
 * Depending on the control command being given to the engine,
 * the command number (cmd) can be associated with either an integer (i),
 * data pointer (p), or function pointer (f). Any or all of (i), (p), or (f)
 * may be NULL depending on the control command.
 *
 * @param e   [IN]  Engine object.
 * @param cmd [IN]  Engine command.
 * @param i   [IN]  Integer input for ctrl command.
 * @param p   [IN]  Pointer to data for ctrl command.
 * @param f   [IN]  Function pointer for ctrl command.
 * @returns 1 on success and 0 on failure.
 */
static int wolfengine_ctrl(ENGINE* e, int cmd, long i, void* p,
                           void (*f) (void))
{
    int ret = 1;
    char errBuff[WOLFENGINE_MAX_LOG_WIDTH];

    (void)e;
    (void)p;

    WOLFENGINE_ENTER(WE_LOG_ENGINE, "wolfengine_ctrl");

    switch (cmd) {
        case ENGINE_CTRL_SET_LOGSTREAM:
            if (wolfEngine_Debugging_ON() < 0) {
                ret = 0;
            }
            break;
        case WOLFENGINE_CMD_ENABLE_DEBUG:
            if (i > 0) {
                if (wolfEngine_Debugging_ON() < 0) {
                    ret = 0;
                }
            } else {
                wolfEngine_Debugging_OFF();
            }
            break;
        case WOLFENGINE_CMD_SET_LOG_LEVEL:
            if (wolfEngine_SetLogLevel((int)i) < 0) {
                WOLFENGINE_ERROR_MSG(WE_LOG_ENGINE,
                                     "Failed to set logging level");
                ret = 0;
            }
            break;
        case WOLFENGINE_CMD_SET_LOG_COMPONENTS:
            if (wolfEngine_SetLogComponents((int)i) < 0) {
                WOLFENGINE_ERROR_MSG(WE_LOG_ENGINE,
                                     "Failed to set log components");
                ret = 0;
            }
            break;
        case WOLFENGINE_CMD_SET_LOGGING_CB:
            /* if f is NULL, resets logging back to default */
            if (wolfEngine_SetLoggingCb((wolfEngine_Logging_cb)f) != 0) {
                WOLFENGINE_ERROR_MSG(WE_LOG_ENGINE, 
                        "Error registering wolfEngine logging callback");
                ret = 0;
            } else {
                WOLFENGINE_MSG(WE_LOG_ENGINE,
                               "wolfEngine user logging callback registered");
            }
            break;
        default:
            XSNPRINTF(errBuff, sizeof(errBuff), "Unsupported ctrl type %d",
                      cmd);
            WOLFENGINE_ERROR_MSG(WE_LOG_ENGINE, errBuff);
            ret = 0;
    }

    WOLFENGINE_LEAVE(WE_LOG_ENGINE, "wolfengine_ctrl", ret);

    return ret;
}

#ifdef WE_HAVE_RSA
/**
 * Return the RSA method.
 *
 * @return  Pointer to the RSA method.
 */
static const RSA_METHOD *we_rsa(void)
{
    return we_rsa_method;
}
#endif /* WE_HAVE_RSA */

#if OPENSSL_VERSION_NUMBER < 0x10100000L
#if defined(WE_HAVE_ECC) && defined(WE_HAVE_ECDH)
/**
 * Return the ECDH method.
 *
 * @return  Pointer to the ECDH method.
 */
static const ECDH_METHOD *we_ecdh(void)
{
    return we_ecdh_method;
}
#endif /* WE_HAVE_ECC && WE_HAVE_ECDH */
#endif /* OPENSSL_VERSION_NUMBER < 0x10100000L */

#ifdef WE_HAVE_ECDSA
#if OPENSSL_VERSION_NUMBER <= 0x100020ffL
/**
 * Return the ECDSA method.
 *
 * @return  Pointer to the ECDSA method.
 */
static const ECDSA_METHOD *we_ecdsa(void)
{
    return we_ecdsa_method;
}
#endif
#endif /* WE_HAVE_ECDSA */

/**
 * Bind the wolfengine into an engine object.
 *
 * @param  e   [in]  Engine object.
 * @param  id  [in]  Library name or identifier.
 * @returns  1 on success and 0 on failure.
 */
int wolfengine_bind(ENGINE *e, const char *id)
{
    int ret = 1;

    WOLFENGINE_ENTER(WE_LOG_ENGINE, "wolfengine_bind");

    if ((id != NULL) &&
                 (XSTRNCMP(id, wolfengine_lib, XSTRLEN(wolfengine_lib)) != 0)) {
        ret = 0;
    }

    if ((ret == 1) && (bound != NULL)) {
        /* Don't add methods a second time. */
        ret = 0;
    }

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
#ifdef WE_HAVE_RANDOM
    if (ret == 1 && ENGINE_set_RAND(e, we_random_method) == 0) {
        ret = 0;
    }
#endif
#ifdef WE_HAVE_RSA
    if (ret == 1 && ENGINE_set_RSA(e, we_rsa()) == 0) {
        ret = 0;
    }
#endif
#ifdef WE_HAVE_DH
    if (ret == 1 && ENGINE_set_DH(e, we_dh_method) == 0) {
        ret = 0;
    }
#endif /* WE_HAVE_DH */
#ifdef WE_HAVE_ECDSA
#if OPENSSL_VERSION_NUMBER <= 0x100020ffL
    if (ret == 1 && ENGINE_set_ECDSA(e, we_ecdsa()) == 0) {
        ret = 0;
    }
#endif
#endif
#if defined(WE_HAVE_EVP_PKEY)
    if (ret == 1 && ENGINE_set_pkey_meths(e, we_pkey) == 0) {
        ret = 0;
    }
    if (ret == 1 && ENGINE_set_pkey_asn1_meths(e, we_pkey_asn1) == 0) {
        ret = 0;
    }
#endif
#ifdef WE_HAVE_EC_KEY
    if (ret == 1 && ENGINE_set_EC(e, we_ec()) == 0) {
        ret = 0;
    }
#endif /* WE_HAVE_EC_KEY */
#if OPENSSL_VERSION_NUMBER < 0x10100000L
#if defined(WE_HAVE_ECC) && defined(WE_HAVE_ECDH)
    if (ret == 1 && ENGINE_set_ECDH(e, we_ecdh()) == 0) {
        ret = 0;
    }
#endif /* WE_HAVE_ECC && WE_HAVE_ECDH */
#endif /* OPENSSL_VERSION_NUMBER < 0x10100000L */
    if (ret == 1 && ENGINE_set_destroy_function(e, wolfengine_destroy) == 0) {
        ret = 0;
    }
    if (ret == 1 && ENGINE_set_cmd_defns(e, wolfengine_cmd_defns) == 0) {
        ret = 0;
    }
    if (ret == 1 && ENGINE_set_ctrl_function(e, wolfengine_ctrl) == 0) {
        ret = 0;
    }

    if (ret == 1) {
        /* Successfully bound the methods to the engine. */
        bound = e;
    }

    WOLFENGINE_LEAVE(WE_LOG_ENGINE, "wolfengine_bind", ret);

    return ret;
}
