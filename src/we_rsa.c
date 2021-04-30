/* we_rsa.c
 *
 * Copyright (C) 2019-2021 wolfSSL Inc.
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

#include <wolfengine/we_internal.h>

#ifdef WE_HAVE_RSA

/* Maximum DER digest size, taken from wolfSSL. Sum of the maximum size of the
   encoded digest, algorithm tag, and sequence tag. */
#define MAX_DER_DIGEST_SZ 98
/* The default RSA key/modulus size in bits. */
#define DEFAULT_KEY_BITS 2048
/* The default RSA public exponent, e. */
#define DEFAULT_PUB_EXP WC_RSA_EXPONENT

/* wolfCrypt FIPS does not have these defined */
#ifndef RSA_PSS_SALT_LEN_DEFAULT
    #define RSA_PSS_SALT_LEN_DEFAULT -1
#endif

/**
 * Data required to complete an RSA operation.
 */
typedef struct we_Rsa
{
    /** wolfSSL structure for holding RSA key data. */
    RsaKey key;
#ifndef WE_SINGLE_THREADED
    /** Random number generator for RSA operations. */
    WC_RNG rng;
#endif
    /** Stored by control command EVP_PKEY_CTRL_MD. */
    const EVP_MD *md;
    /** Stored by string control command "rsa_mgf1_md". */
    const EVP_MD *mdMGF1;
    /** Padding mode */
    int padMode;
    /** The public exponent ("e"). */
    long pubExp;
    /** The key/modulus size in bits. */
    int bits;
    /** Length of salt to use with PSS. */
    int saltLen;
    /** Indicates private key has been set into wolfSSL structure. */
    int privKeySet:1;
    /** Indicates public key has been set into wolfSSL structure. */
    int pubKeySet:1;
} we_Rsa;


/** RSA direct method - RSA using wolfSSL for the implementation. */
RSA_METHOD *we_rsa_method = NULL;


/**
 * Check that the key size is allowed. For FIPS, 1024-bit keys can only be used
 * to verify; they can't be generated or used to sign.
 *
 * @param  size       [in]  Key size in bits.
 * @param  allow1024  [in]  Whether to allow 1024-bit keys for this check. In
 *                          FIPS mode, 1024-bit keys aren't allowed for signing
 *                          (private encrypt) or key generation.
 * @returns  1 if the key size is allowed, 0 if it isn't.
 */
static int we_check_rsa_key_size(int size, int allow1024) {
    int ret = 0;
    char errBuff[WOLFENGINE_MAX_LOG_WIDTH];

#if defined(HAVE_FIPS) || defined(HAVE_FIPS_VERSION)
    if (fipsChecks == 1) {
        ret = size == 2048 || size == 3072 || size == 4096;
        if (allow1024 == 1) {
            ret |= size == 1024;
        }
    }
    else 
#endif /* HAVE_FIPS || HAVE_FIPS_VERSION */
    {
        (void)allow1024;
        ret = size >= RSA_MIN_SIZE && size <= RSA_MAX_SIZE;

        if (ret == 0) {
            XSNPRINTF(errBuff, sizeof(errBuff), "RSA key size %d not allowed.",
                      size);
            WOLFENGINE_ERROR_MSG(WE_LOG_PK, errBuff);
        }
    }

    return ret;
}

/**
 * Convert an OpenSSL hash NID to a wolfSSL MGF1 algorithm.
 *
 * @param  nid  [in]  OpenSSL hash NID to convert.
 * @returns  wolfSSL MGF1 algorithm or WC_MGF1NONE on failure.
 */
static int we_mgf_from_hash(int nid)
{
    int mgf;

    switch (nid) {
        case NID_sha1:
            mgf = WC_MGF1SHA1;
            break;
        case NID_sha224:
            mgf = WC_MGF1SHA224;
            break;
        case NID_sha256:
            mgf = WC_MGF1SHA256;
            break;
        case NID_sha384:
            mgf = WC_MGF1SHA384;
            break;
        case NID_sha512:
            mgf = WC_MGF1SHA512;
            break;
        default:
            mgf = WC_MGF1NONE;
            break;
    }

    return mgf;
}

/**
 * Convert the PSS salt length from OpenSSL value to a wolfSSL value.
 *
 * @param  saltLen   [in]  Salt length.
 * @param  md        [in]  Digest to use with PSS.
 * @param  key       [in]  RSA key to use with PSS.
 * @param  signing   [in]  Whether operation is for signing.
 * @return  Salt length for wolfSSL.
 */
static int we_pss_salt_len_to_wc(int saltLen, const EVP_MD *md, RsaKey *key,
                                 int signing)
{
    (void)md;
    (void)key;
    (void)signing;

#if OPENSSL_VERSION_NUMBER >= 0x10101000L
    if (saltLen < 0) {
        if (saltLen == RSA_PSS_SALTLEN_DIGEST) {
            saltLen = RSA_PSS_SALT_LEN_DEFAULT;
        }
        if (saltLen == RSA_PSS_SALTLEN_MAX) {
        #ifndef WOLFSSL_PSS_SALT_LEN_DISCOVER
            saltLen = EVP_MD_size(md);
        #else
            saltLen = RSA_PSS_SALT_LEN_DISCOVER;
        #endif
        }
        if (saltLen == RSA_PSS_SALTLEN_AUTO) {
        #ifndef WOLFSSL_PSS_LONG_SALT
            saltLen = EVP_MD_size(md);
        #else
            if (signing) {
                saltLen = wc_RsaEncryptSize(key) - EVP_MD_size(md) - 2;
            }
            else {
                saltLen = RSA_PSS_SALT_LEN_DISCOVER;
            }
        #endif
        }
    }
#endif

    return saltLen;
}

/**
 * Set the public key in a we_Rsa structure.
 *
 * @param  ctx     [in]  Public key context of operation.
 * @param  rsa     [in]  RSA structure to hold public key.
 * @returns  1 on success and 0 on failure.
 */
static int we_rsa_set_public_key(RSA *rsaKey, we_Rsa *engineRsa)
{
    int ret = 1;
    int rc = 0;
    unsigned char *pubDer = NULL;
    int pubDerLen = 0;
    word32 idx = 0;

    WOLFENGINE_ENTER(WE_LOG_PK, "we_rsa_set_public_key");
    WOLFENGINE_MSG_VERBOSE(WE_LOG_PK, "ARGS [rsaKey = %p, engineRsa = %p]",
                           rsaKey, engineRsa);

    /* DER encoded public key with OpenSSL. */
    pubDerLen = i2d_RSAPublicKey(rsaKey, &pubDer);
    if (pubDerLen == 0) {
        WOLFENGINE_ERROR_FUNC(WE_LOG_PK, "i2d_RSAPublicKey", pubDerLen);
        ret = 0;
    }

    if (ret == 1) {
        /* Decode public key DER data into wolfSSL object. */
        rc = wc_RsaPublicKeyDecode(pubDer, &idx, &engineRsa->key,
                                   pubDerLen);
        if (rc != 0) {
            WOLFENGINE_ERROR_FUNC(WE_LOG_PK, "wc_RsaPublicKeyDecode", rc);
            ret = 0;
        }
    }

    if (ret == 1) {
        WOLFENGINE_MSG(WE_LOG_PK, "Imported RSA public key to RsaKey struct");
        /* Ensure this only happens once. */
        engineRsa->pubKeySet = 1;
    }

    if (pubDer != NULL) {
        /* Dispose of DER encoding memory. */
        OPENSSL_free(pubDer);
    }

    WOLFENGINE_LEAVE(WE_LOG_PK, "we_rsa_set_public_key", ret);

    return ret;
}

/**
 * Set the private key in a we_Rsa structure.
 *
 * @param  ctx     [in]  Public key context of operation.
 * @param  rsa     [in]  RSA structure to hold private key.
 * @returns  1 on success and 0 on failure.
 */
static int we_rsa_set_private_key(RSA *rsaKey, we_Rsa *engineRsa)
{
    int ret = 1;
    int rc = 0;
    unsigned char *privDer = NULL;
    int privDerLen = 0;
    word32 idx = 0;

    WOLFENGINE_ENTER(WE_LOG_PK, "we_rsa_set_private_key");
    WOLFENGINE_MSG_VERBOSE(WE_LOG_PK, "ARGS (rsaKey = %p, engineRsa = %p]",
                           rsaKey, engineRsa);

    /* DER encoded private key with OpenSSL. */
    privDerLen = i2d_RSAPrivateKey(rsaKey, &privDer);
    if (privDerLen == 0) {
        WOLFENGINE_ERROR_FUNC(WE_LOG_PK, "i2d_RSAPrivateKey", privDerLen);
        ret = 0;
    }

    if (ret == 1) {
        /* Decode private key DER data into wolfSSL object. */
        rc = wc_RsaPrivateKeyDecode(privDer, &idx, &engineRsa->key,
                                    privDerLen);
        if (rc != 0) {
            WOLFENGINE_ERROR_FUNC(WE_LOG_PK, "wc_RsaPrivateKeyDecode", rc);
            ret = 0;
        }
    }

    if (ret == 1) {
        WOLFENGINE_MSG(WE_LOG_PK, "Imported RSA private key into "
                       "RsaKey struct");
        /* Ensure this only happens once. */
        engineRsa->privKeySet = 1;
    }

    if (privDer != NULL) {
        /* Dispose safely of DER encoded private key. */
        OPENSSL_clear_free(privDer, privDerLen);
    }

    WOLFENGINE_LEAVE(WE_LOG_PK, "we_rsa_set_private_key", ret);

    return ret;
}

/**
 * Initialize and set the data required to complete an RSA operation.
 *
 * @param  rsa  [in]  RSA context of operation.
 * @returns  1 on success and 0 on failure.
 */
static int we_rsa_init(RSA *rsa)
{
    int ret = 1;
    int rc = 0;
    we_Rsa *engineRsa;

    WOLFENGINE_ENTER(WE_LOG_PK, "we_rsa_init");
    WOLFENGINE_MSG_VERBOSE(WE_LOG_PK, "ARGS [rsa = %p]", rsa);

    /* Allocate memory for internal RSA object. */
    engineRsa = (we_Rsa *)OPENSSL_zalloc(sizeof(we_Rsa));
    if (engineRsa == NULL) {
        WOLFENGINE_ERROR_FUNC_NULL(WE_LOG_PK, "OPENSSL_zalloc", engineRsa);
        ret = 0;
    }

    if (ret == 1) {
    #if OPENSSL_VERSION_NUMBER >= 0x10101000L
        engineRsa->saltLen = RSA_PSS_SALTLEN_AUTO;
    #else
        engineRsa->saltLen = RSA_PSS_SALT_LEN_DEFAULT;
    #endif

        /* Initialize wolfSSL RSA key. */
        rc = wc_InitRsaKey(&engineRsa->key, NULL);
        if (rc != 0) {
            WOLFENGINE_ERROR_FUNC(WE_LOG_PK, "wc_InitRsaKey", rc);
            ret = 0;
        }
    }

#ifndef WE_SINGLE_THREADED
    if (ret == 1) {
        rc = wc_InitRng(&engineRsa->rng);
        if (rc != 0) {
            ret = 0;
        }
    }
#endif
#ifdef WC_RSA_BLINDING
    if (ret == 1) {
        /* Set RNG for use when performing private operations or generating
         * random padding. */
    #ifndef WE_SINGLE_THREADED
        rc = wc_RsaSetRNG(&engineRsa->key, &engineRsa->rng);
    #else
        rc = wc_RsaSetRNG(&engineRsa->key, we_rng);
    #endif
        if (rc != 0) {
            WOLFENGINE_ERROR_FUNC(WE_LOG_PK, "wc_RsaSetRNG", rc);
            ret = 0;
        }
    }
#endif /* WC_RSA_BLINDING */

    if (ret == 1) {
        /* OpenSSL's default RSA_METHOD uses SHA-1 for OAEP padding. We mirror
         * that default here. */
        engineRsa->md = EVP_sha1();
        /* Store the internal RSA object in the extra data.
         * Index is able to be defined by user. */
        rc = RSA_set_ex_data(rsa, WE_RSA_EX_DATA_IDX, engineRsa);
        if (rc != 1) {
            WOLFENGINE_ERROR_FUNC(WE_LOG_PK, "RSA_set_ex_data", rc);
            ret = 0;
        }
    }

    if ((ret == 0) && (engineRsa != NULL)) {
        /* Disopse of the wolfSSL RSA key, RNG and internal object on failure.
         */
    #ifndef WE_SINGLE_THREADED
        wc_FreeRng(&engineRsa->rng);
    #endif
        wc_FreeRsaKey(&engineRsa->key);
        OPENSSL_free(engineRsa);
    }

    return ret;
}

/**
 * Clean up the RSA operation data.
 *
 * @param  rsa  [in]  RSA context of operation.
 * @returns  1 on success and 0 on failure.
 */
static int we_rsa_finish(RSA *rsa)
{
    we_Rsa *engineRsa;

    WOLFENGINE_ENTER(WE_LOG_PK, "we_rsa_finish");
    WOLFENGINE_MSG_VERBOSE(WE_LOG_PK, "ARGS [rsa = %p]", rsa);

    /* Retrieve internal RSA object from extra data. */
    engineRsa = (we_Rsa *)RSA_get_ex_data(rsa, WE_RSA_EX_DATA_IDX);
    if (engineRsa != NULL) {
        /* Remove reference to internal RSA object. */
        RSA_set_ex_data(rsa, WE_RSA_EX_DATA_IDX, NULL);
        /* Dispose of the wolfSSL RNG, RSA key and internal object. */
    #ifndef WE_SINGLE_THREADED
        wc_FreeRng(&engineRsa->rng);
    #endif
        wc_FreeRsaKey(&engineRsa->key);
        OPENSSL_free(engineRsa);
    }

    WOLFENGINE_LEAVE(WE_LOG_PK, "we_rsa_finish", 1);

    return 1;
}

/**
 * Perform an RSA public encryption operation.
 *
 * @param  fromLen  [in]   Length of buffer to encrypt.
 * @param  from     [in]   Buffer to encrypt.
 * @param  to       [out]  Buffer to place ciphertext in.
 * @param  rsa      [in]   Internal RSA object.
 * @returns  Length of ciphertext on success and -1 on failure.
 */
static int we_rsa_pub_enc_int(size_t fromLen, const unsigned char *from,
                              size_t toLen, unsigned char *to, we_Rsa *rsa)
{
    int ret;
    const EVP_MD *mdMGF1 = NULL;
#ifndef WE_SINGLE_THREADED
    WC_RNG *rng = &rsa->rng;
#else
    WC_RNG *rng = we_rng;
#endif
    char errBuff[WOLFENGINE_MAX_LOG_WIDTH];

    WOLFENGINE_ENTER(WE_LOG_PK, "we_rsa_pub_enc_int");
    WOLFENGINE_MSG_VERBOSE(WE_LOG_PK, "ARGS [fromLen = %zu, from = %p, "
                           "toLen = %zu, to = %p, rsa = %p]", fromLen,
                           from, toLen, to, rsa);

    switch (rsa->padMode) {
        case RSA_PKCS1_PADDING:
            WOLFENGINE_MSG(WE_LOG_PK, "padMode: RSA_PKCS1_PADDING");
            /* PKCS#1 v1.5 padding using block type 2. */
            ret = wc_RsaPublicEncrypt(from, (word32)fromLen, to, (word32)toLen,
                    &rsa->key, rng);
            if (ret < 0) {
                WOLFENGINE_ERROR_FUNC(WE_LOG_PK, "wc_RsaPublicEncrypt", ret);
                ret = -1;
            }
            break;
        case RSA_PKCS1_OAEP_PADDING:
            WOLFENGINE_MSG(WE_LOG_PK, "padMode: RSA_PKCS1_OAEP_PADDING");
            /* OAEP padding using SHA-1, MGF1. */
            if (rsa->md == NULL) {
                WOLFENGINE_ERROR_MSG(WE_LOG_PK, "Digest not set");
                ret = -1;
            }
            else {
                mdMGF1 = rsa->mdMGF1 != NULL ? rsa->mdMGF1 : rsa->md;
                ret = wc_RsaPublicEncrypt_ex(from, (word32)fromLen, to,
                    (word32)toLen, &rsa->key, rng, WC_RSA_OAEP_PAD,
                    we_nid_to_wc_hash_type(EVP_MD_type(rsa->md)),
                    we_mgf_from_hash(EVP_MD_type(mdMGF1)), NULL, 0);
                if (ret < 0) {
                    WOLFENGINE_ERROR_FUNC(WE_LOG_PK, "wc_RsaPublicEncrypt_ex",
                                          ret);
                    ret = -1;
                }
            }
            break;
        case RSA_NO_PADDING:
            WOLFENGINE_MSG(WE_LOG_PK, "padMode: RSA_NO_PADDING");
            /* Raw public encrypt - no padding. */
            ret = wc_RsaPublicEncrypt_ex(from, (word32)fromLen, to,
                    (word32)toLen, &rsa->key, rng, WC_RSA_NO_PAD,
                    WC_HASH_TYPE_NONE, 0, NULL, 0);
            if (ret < 0) {
                WOLFENGINE_ERROR_FUNC(WE_LOG_PK, "wc_RsaPublicEncrypt_ex",
                                      ret);
                ret = -1;
            }
            break;
        default:
            /* Unsupported padding mode for RSA encrpytion. */
            XSNPRINTF(errBuff, sizeof(errBuff), "Unknown padding mode:  %d",
                      rsa->padMode);
            WOLFENGINE_ERROR_MSG(WE_LOG_PK, errBuff);
            ret = -1;
    }

    WOLFENGINE_LEAVE(WE_LOG_PK, "we_rsa_pub_enc_int", ret);

    return ret;
}

/**
 * Perform an RSA public encryption operation.
 *
 * @param  fromLen  [in]   Length of buffer to encrypt.
 * @param  from     [in]   Buffer to encrypt.
 * @param  to       [out]  Buffer to place ciphertext in.
 * @param  rsa      [in]   RSA context of operation.
 * @param  padding  [in]   Type of padding to use.
 * @returns  Length of ciphertext on success and -1 on failure.
 */
static int we_rsa_pub_enc(int fromLen, const unsigned char *from,
                          unsigned char *to, RSA *rsa, int padding)
{
    int ret = 1;
    int rc = 0;
    we_Rsa *engineRsa = NULL;
    int keySize = 0;

    WOLFENGINE_ENTER(WE_LOG_PK, "we_rsa_pub_enc");
    WOLFENGINE_MSG_VERBOSE(WE_LOG_PK, "ARGS [fromLen = %d, from = %p, "
                           "to = %p, rsa = %p, padding = %d]", fromLen,
                           from, to, rsa, padding);

    /* Validate parameters. */
    if (fromLen < 0) {
        WOLFENGINE_ERROR_MSG(WE_LOG_PK, "Negative input buffer length.");
        ret = -1;
    }

    if (ret == 1) {
        keySize = RSA_size(rsa) * 8;
        rc = we_check_rsa_key_size(keySize, 1);
        if (rc != 1) {
            WOLFENGINE_ERROR_FUNC(WE_LOG_PK, "we_check_rsa_key_size", rc);
            ret = -1;
        }
    }

    if (ret == 1) {
        /* Retrieve the internal RSA object from extra data. */
        engineRsa = (we_Rsa *)RSA_get_ex_data(rsa, WE_RSA_EX_DATA_IDX);
        if (engineRsa == NULL) {
            WOLFENGINE_ERROR_FUNC_NULL(WE_LOG_PK, "RSA_get_ex_data", engineRsa);
            ret = -1;
        }
    }

    /* Set public key into wolfSSL RSA key if not done already. */
    if ((ret == 1) && (!engineRsa->pubKeySet)) {
        rc = we_rsa_set_public_key(rsa, engineRsa);
        if (rc == 0) {
            WOLFENGINE_ERROR_FUNC(WE_LOG_PK, "we_rsa_set_public_key", rc);
            ret = -1;
        }
    }

    if (ret == 1) {
        /* Store the padding mode (PKEY variant has it set) and encrypt. */
        engineRsa->padMode = padding;
        /* Output size is always the length of the prime. */
        ret = we_rsa_pub_enc_int(fromLen, from, RSA_size(rsa), to, engineRsa);
        if (ret == -1) {
            WOLFENGINE_ERROR_FUNC(WE_LOG_PK, "we_rsa_pub_enc_int", ret);
        }
    }

    WOLFENGINE_LEAVE(WE_LOG_PK, "we_rsa_pub_enc", ret);

    return ret;
}

/**
 * Perform an RSA private decryption operation.
 *
 * @param  fromLen  [in]   Length of buffer to decrypt.
 * @param  from     [in]   Buffer to decrypt.
 * @param  to       [out]  Buffer to place plaintext in.
 * @param  rsa      [in]   Internal RSA object.
 * @returns  Length of plaintext on success and -1 on failure.
 */
static int we_rsa_priv_dec_int(size_t fromLen, const unsigned char *from,
                               size_t toLen, unsigned char *to, we_Rsa *rsa)
{
    int ret;
    const EVP_MD *mdMGF1 = NULL;
    char errBuff[WOLFENGINE_MAX_LOG_WIDTH];

    WOLFENGINE_ENTER(WE_LOG_PK, "we_rsa_priv_dec_int");
    WOLFENGINE_MSG_VERBOSE(WE_LOG_PK, "ARGS [fromLen = %zu, from = %p, "
                           "toLen = %zu, to = %p, rsa = %p]", fromLen,
                           from, toLen, to, rsa);

    switch (rsa->padMode) {
        case RSA_PKCS1_PADDING:
            WOLFENGINE_MSG(WE_LOG_PK, "padMode: RSA_PKCS1_PADDING");
            if (to == NULL) {
                ret = (int)fromLen;
            }
            else {
                /* PKCS#1 v1.5 padding using block type 2. */
                ret = wc_RsaPrivateDecrypt(from, (word32)fromLen, to,
                        (word32)toLen, &rsa->key);
                if (ret < 0) {
                    WOLFENGINE_ERROR_FUNC(WE_LOG_PK, "wc_RsaPrivateDecrypt",
                                          ret);
                    ret = -1;
                }
            }
            break;
        case RSA_PKCS1_OAEP_PADDING:
            WOLFENGINE_MSG(WE_LOG_PK, "padMode: RSA_PKCS1_OAEP_PADDING");
            /* PKCS#1 OAEP padding. */
            if (rsa->md == NULL) {
                WOLFENGINE_ERROR_MSG(WE_LOG_PK, "Digest not set");
                ret = -1;
            }
            else if (to == NULL) {
                ret = (int)fromLen;
            }
            else {
                mdMGF1 = rsa->mdMGF1 != NULL ? rsa->mdMGF1 : rsa->md;
                ret = wc_RsaPrivateDecrypt_ex(from, (word32)fromLen, to,
                    (word32)toLen, &rsa->key, WC_RSA_OAEP_PAD,
                    we_nid_to_wc_hash_type(EVP_MD_type(rsa->md)),
                    we_mgf_from_hash(EVP_MD_type(mdMGF1)), NULL, 0);
                if (ret < 0) {
                    WOLFENGINE_ERROR_FUNC(WE_LOG_PK, "wc_RsaPrivateDecrypt_ex",
                                          ret);
                    ret = -1;
                }
            }
            break;
        case RSA_NO_PADDING:
            WOLFENGINE_MSG(WE_LOG_PK, "padMode: RSA_NO_PADDING");
            /* Raw private decrypt - no padding. */
            ret = wc_RsaPrivateDecrypt_ex(from, (word32)fromLen, to,
                    (word32)toLen, &rsa->key, WC_RSA_NO_PAD, WC_HASH_TYPE_NONE,
                    0, NULL, 0);
            if (ret < 0) {
                WOLFENGINE_ERROR_FUNC(WE_LOG_PK, "wc_RsaPrivateDecrypt_ex",
                                      ret);
                ret = -1;
            }
            break;
        default:
            /* Unsupported padding mode for RSA decryption. */
            WOLFENGINE_ERROR_MSG(WE_LOG_PK,
                                 "we_rsa_priv_dec: unknown padding");
            XSNPRINTF(errBuff, sizeof(errBuff), "Unknown padding: %d",
                      rsa->padMode);
            WOLFENGINE_ERROR_MSG(WE_LOG_PK, errBuff);
            ret = -1;
    }

    WOLFENGINE_LEAVE(WE_LOG_PK, "we_rsa_priv_dec_int", ret);

    return ret;
}

/**
 * Perform an RSA private decryption operation.
 *
 * @param  fromLen  [in]   Length of buffer to decrypt.
 * @param  from     [in]   Buffer to decrypt.
 * @param  to       [out]  Buffer to place plaintext in.
 * @param  rsa      [in]   RSA context of operation.
 * @param  padding  [in]   Type of padding to use.
 * @returns  Length of plaintext on success and -1 on failure.
 */
static int we_rsa_priv_dec(int fromLen, const unsigned char *from,
                           unsigned char *to, RSA *rsa, int padding)
{
    int ret = 1;
    int rc = 0;
    we_Rsa *engineRsa = NULL;
    int keySize = 0;

    WOLFENGINE_ENTER(WE_LOG_PK, "we_rsa_priv_dec");
    WOLFENGINE_MSG_VERBOSE(WE_LOG_PK, "ARGS [fromLen = %d, from = %p, "
                           "to = %p, rsa = %p, padding = %d]",
                           fromLen, from, to, rsa, padding);

    /* Validate parameters. */
    if (fromLen < 0) {
        WOLFENGINE_ERROR_MSG(WE_LOG_PK, "Negative input buffer length.");
        ret = -1;
    }

    if (ret == 1) {
        keySize = RSA_size(rsa) * 8;
        rc = we_check_rsa_key_size(keySize, 1);
        if (rc != 1) {
            WOLFENGINE_ERROR_FUNC(WE_LOG_PK, "we_check_rsa_key_size", rc);
            ret = -1;
        }
    }

    if (ret == 1) {
        /* Retrieve the internal RSA object from extra data. */
        engineRsa = (we_Rsa *)RSA_get_ex_data(rsa, WE_RSA_EX_DATA_IDX);
        if (engineRsa == NULL) {
            WOLFENGINE_ERROR_FUNC_NULL(WE_LOG_PK, "RSA_get_ex_data", engineRsa);
            ret = -1;
        }
    }

    /* Set private key into wolfSSL RSA key if not done already. */
    if ((ret == 1) && (!engineRsa->privKeySet)) {
        rc = we_rsa_set_private_key(rsa, engineRsa);
        if (rc == 0) {
            WOLFENGINE_ERROR_FUNC(WE_LOG_PK, "we_rsa_set_private_key", rc);
            ret = -1;
        }
    }

    if (ret == 1) {
        /* Store the padding mode (PKEY variant has it set) and decrypt. */
        engineRsa->padMode = padding;
        /* Maximum output size is the length of the prime.
         * Actual plaintext length returned. */
        ret = we_rsa_priv_dec_int(fromLen, from, RSA_size(rsa), to, engineRsa);
        if (ret == -1) {
            WOLFENGINE_ERROR_FUNC(WE_LOG_PK, "we_rsa_priv_dec_int", ret);
        }
    }

    WOLFENGINE_LEAVE(WE_LOG_PK, "we_rsa_priv_dec", ret);

    return ret;
}

/**
 * Internal function for performing an RSA private encryption operation.
 *
 * @param  fromLen  [in]   Length of buffer to encrypt.
 * @param  from     [in]   Buffer to encrypt.
 * @param  toLen    [in]   Size of ciphertext buffer.
 * @param  to       [out]  Buffer to place ciphertext in.
 * @param  key      [in]   RSA key to use.
 * @param  padding  [in]   Type of padding to use.
 * @returns  Length of ciphertext on success and -1 on failure.
 */
static int we_rsa_priv_enc_int(size_t fromLen, const unsigned char *from,
                               size_t toLen, unsigned char *to, we_Rsa *rsa)
{
    int ret = 1;
    unsigned int tLen = (unsigned int)toLen;
    const EVP_MD *mdMGF1;
#ifndef WE_SINGLE_THREADED
    WC_RNG *rng = &rsa->rng;
#else
    WC_RNG *rng = we_rng;
#endif
    char errBuff[WOLFENGINE_MAX_LOG_WIDTH];

    WOLFENGINE_ENTER(WE_LOG_PK, "we_rsa_priv_enc_int");
    WOLFENGINE_MSG_VERBOSE(WE_LOG_PK, "ARGS [fromLen = %zu, from = %p, "
                           "toLen = %zu, to = %p, rsa = %p]", fromLen, from,
                           toLen, to, rsa);

    switch (rsa->padMode) {
        case RSA_PKCS1_PADDING:
            WOLFENGINE_MSG(WE_LOG_PK, "padMode: RSA_PKCS1_PADDING");
            /* PKCS#1 v1.5 padding using block type 1. */
            ret = wc_RsaSSL_Sign(from, (word32)fromLen, to, (word32)toLen,
                    &rsa->key, rng);
            if (ret < 0) {
                WOLFENGINE_ERROR_FUNC(WE_LOG_PK, "wc_RsaSSL_Sign", ret);
                ret = -1;
            }
            break;
        case RSA_NO_PADDING:
            WOLFENGINE_MSG(WE_LOG_PK, "padMode: RSA_NO_PADDING");
            /* Raw private encrypt - no padding. */
            ret = wc_RsaDirect((byte*)from, (unsigned int)fromLen, to, &tLen,
                               &rsa->key, RSA_PRIVATE_ENCRYPT, rng);
            if (ret < 0) {
                WOLFENGINE_ERROR_FUNC(WE_LOG_PK, "wc_RsaDirect", ret);
                ret = -1;
            }
            break;
        case RSA_PKCS1_PSS_PADDING:
            WOLFENGINE_MSG(WE_LOG_PK, "padMode: RSA_PSS_PADDING");
            /* PKCS#1 PSS padding. */
            if (rsa->md == NULL) {
                WOLFENGINE_ERROR_MSG(WE_LOG_PK, "Digest not set");
                ret = -1;
            }
            else {
                /* Convert salt length into wolfCrypt value. */
                int wc_saltLen = we_pss_salt_len_to_wc(rsa->saltLen, rsa->md,
                    &rsa->key, 1);
                if (wc_saltLen >= 0) {
                    rsa->saltLen = wc_saltLen;
                }
                /* When MGF1 digest is not specified, use signing digest. */
                mdMGF1 = rsa->mdMGF1 != NULL ? rsa->mdMGF1 : rsa->md;
                ret = wc_RsaPSS_Sign_ex(from, (word32)fromLen, to,
                    (word32)toLen, we_nid_to_wc_hash_type(EVP_MD_type(rsa->md)),
                    we_mgf_from_hash(EVP_MD_type(mdMGF1)), wc_saltLen,
                    &rsa->key, rng);
                if (ret < 0) {
                    WOLFENGINE_ERROR_FUNC(WE_LOG_PK, "wc_RsaPSS_Sign_ex", ret);
                    ret = -1;
                }
            }
            break;
        default:
            /* Unsupported padding mode for RSA private encryption. */
            WOLFENGINE_ERROR_MSG(WE_LOG_PK,
                                 "we_rsa_priv_enc_int: unknown padding");
            XSNPRINTF(errBuff, sizeof(errBuff), "Unknown padding mode: %d",
                      rsa->padMode);
            WOLFENGINE_ERROR_MSG(WE_LOG_PK, errBuff);
            ret = -1;
    }

    WOLFENGINE_LEAVE(WE_LOG_PK, "we_rsa_priv_enc_int", ret);

    return ret;
}

/**
 * Perform an RSA private encryption operation.
 *
 * @param  fromLen  [in]   Length of buffer to encrypt.
 * @param  from     [in]   Buffer to encrypt.
 * @param  to       [out]  Buffer to place ciphertext in.
 * @param  rsa      [in]   RSA context of operation.
 * @param  padding  [in]   Type of padding to use.
 * @returns  Length of ciphertext on success and -1 on failure.
 */
static int we_rsa_priv_enc(int fromLen, const unsigned char *from,
                           unsigned char *to, RSA *rsa, int padding)
{
    int ret = 1;
    int rc = 0;
    we_Rsa *engineRsa = NULL;
    int keySize = 0;

    WOLFENGINE_ENTER(WE_LOG_PK, "we_rsa_priv_enc");
    WOLFENGINE_MSG_VERBOSE(WE_LOG_PK, "ARGS [fromLen = %d, from = %p, "
                           "to = %p, rsa = %p, padding = %d]", fromLen, from,
                           to, rsa, padding);

    /* Validate parameters. */
    if (fromLen < 0) {
        WOLFENGINE_ERROR_MSG(WE_LOG_PK, "Negative input buffer length.");
        ret = -1;
    }

    if (ret == 1) {
        keySize = RSA_size(rsa) * 8;
        rc = we_check_rsa_key_size(keySize, 0);
        if (rc != 1) {
            WOLFENGINE_ERROR_FUNC(WE_LOG_PK, "we_check_rsa_key_size", rc);
            ret = -1;
        }
    }

    if (ret == 1) {
        /* Retrieve the internal RSA object from extra data. */
        engineRsa = (we_Rsa *)RSA_get_ex_data(rsa, WE_RSA_EX_DATA_IDX);
        if (engineRsa == NULL) {
            WOLFENGINE_ERROR_FUNC_NULL(WE_LOG_PK, "RSA_get_ex_data", engineRsa);
            ret = -1;
        }
    }

    /* Set private key into wolfSSL RSA key if not done already. */
    if ((ret == 1) && (!engineRsa->privKeySet)) {
        rc = we_rsa_set_private_key(rsa, engineRsa);
        if (rc == 0) {
            WOLFENGINE_ERROR_FUNC(WE_LOG_PK, "we_rsa_set_private_key", rc);
            ret = -1;
        }
    }

    if (ret == 1) {
        /* Store the padding mode (PKEY variant has it set) and private
         * encrypt. */
        engineRsa->padMode = padding;
    #if OPENSSL_VERSION_NUMBER >= 0x10101000L
        if ((padding == RSA_PKCS1_PADDING) &&
                                      (EVP_MD_size(engineRsa->md) != fromLen)) {
            WOLFENGINE_ERROR_MSG(WE_LOG_PK, "Digest length invalid");
            ret = -1;
        }
    #endif
    }
    if (ret == 1) {
        /* Output size is always the length of the prime. */
        ret = we_rsa_priv_enc_int(fromLen, from, RSA_size(rsa), to, engineRsa);
        if (ret == -1) {
            WOLFENGINE_ERROR_FUNC(WE_LOG_PK, "we_rsa_priv_enc_int", ret);
        }
    }

    WOLFENGINE_LEAVE(WE_LOG_PK, "we_rsa_priv_enc", ret);

    return ret;
}

/**
 * Internal function for performing an RSA public decryption operation.
 *
 * @param  fromLen  [in]   Length of buffer to decrypt.
 * @param  from     [in]   Buffer to decrypt.
 * @param  toLen    [in]   Size of plaintext buffer.
 * @param  to       [out]  Buffer to place plaintext in.
 * @param  key      [in]   RSA key to use.
 * @param  padding  [in]   Type of padding to use.
 * @returns  Length of plaintext on success and -1 on failure.
 */
static int we_rsa_pub_dec_int(size_t fromLen, const unsigned char *from,
                              size_t toLen, unsigned char *to, we_Rsa *rsa)
{
    int ret = 1;
    unsigned int tLen = (unsigned int)toLen;
    const EVP_MD *mdMGF1;
#ifndef WE_SINGLE_THREADED
    WC_RNG *rng = &rsa->rng;
#else
    WC_RNG *rng = we_rng;
#endif
    char errBuff[WOLFENGINE_MAX_LOG_WIDTH];

    WOLFENGINE_ENTER(WE_LOG_PK, "we_rsa_pub_dec_int");
    WOLFENGINE_MSG_VERBOSE(WE_LOG_PK, "ARGS [fromLen = %zu, from = %p, "
                           "toLen = %zu, to = %p, rsa = %p]", fromLen, from,
                           toLen, to, rsa);

    /* Check input length doesn't exceed the prime length. */
    if (fromLen > (size_t)wc_RsaEncryptSize(&rsa->key)) {
        WOLFENGINE_ERROR_MSG(WE_LOG_PK, "Decrypt buffer too big");
        ret = -1;
    }

    if (ret == 1) {
        switch (rsa->padMode) {
            case RSA_PKCS1_PADDING:
                WOLFENGINE_MSG(WE_LOG_PK, "padMode: RSA_PKCS1_PADDING");
                /* PKCS #1 v1.5 padding using block type 1. */
                ret = wc_RsaSSL_Verify(from, (word32)fromLen, to, (word32)toLen,
                        &rsa->key);
                if (ret < 0) {
                    WOLFENGINE_ERROR_FUNC(WE_LOG_PK, "wc_RsaSSL_Verify", ret);
                    ret = -1;
                }
                break;
            case RSA_NO_PADDING:
                WOLFENGINE_MSG(WE_LOG_PK, "padMode: RSA_NO_PADDING");
                ret = wc_RsaDirect((byte*)from, (unsigned int)fromLen, to,
                    &tLen, &rsa->key, RSA_PUBLIC_DECRYPT, rng);
                if (ret < 0) {
                    WOLFENGINE_ERROR_FUNC(WE_LOG_PK, "wc_RsaDirect", ret);
                    ret = -1;
                }
                break;
            case RSA_PKCS1_PSS_PADDING:
                WOLFENGINE_MSG(WE_LOG_PK, "padMode: RSA_PKCS1_PSS_PADDING");
                /* PKCS #1 PSS padding. */
                if (rsa->md == NULL) {
                    WOLFENGINE_ERROR_MSG(WE_LOG_PK, "Digest not set");
                    ret = -1;
                }
                else {
                    int hash;
                    int mgf1;
                    int wc_saltLen;

                    hash = we_nid_to_wc_hash_type(EVP_MD_type(rsa->md));
                    /* When MGF1 digest is not specified, use verify digest. */
                    mdMGF1 = rsa->mdMGF1 != NULL ? rsa->mdMGF1 : rsa->md;
                    mgf1 = we_mgf_from_hash(EVP_MD_type(mdMGF1));
                    /* Convert salt length into wolfCrypt value. */
                    wc_saltLen = we_pss_salt_len_to_wc(rsa->saltLen, rsa->md,
                        &rsa->key, 0);

                    ret = wc_RsaPSS_Verify_ex((byte*)from, (word32)fromLen, to,
                        (word32)toLen, hash, mgf1, wc_saltLen, &rsa->key);
                    if (ret < 0) {
                        WOLFENGINE_ERROR_FUNC(WE_LOG_PK, "wc_RsaPSS_Verify_ex",
                                              ret);
                        ret = -1;
                    }
                }
                break;
            default:
                /* Unsupported padding mode for RSA public decryption. */
                XSNPRINTF(errBuff, sizeof(errBuff), "Unknown padding mode: %d",
                          rsa->padMode);
                WOLFENGINE_ERROR_MSG(WE_LOG_PK, errBuff);
                ret = -1;
        }
    }

    WOLFENGINE_LEAVE(WE_LOG_PK, "we_rsa_pub_dec_int", ret);

    return ret;
}

/**
 * Perform an RSA public decryption operation.
 *
 * @param  fromLen  [in]   Length of buffer to decrypt.
 * @param  from     [in]   Buffer to decrypt.
 * @param  to       [out]  Buffer to place plaintext in.
 * @param  rsa      [in]   RSA context of operation.
 * @param  padding  [in]   Type of padding to use.
 * @returns  Length of plaintext on success and -1 on failure.
 */
static int we_rsa_pub_dec(int fromLen, const unsigned char *from,
                          unsigned char *to, RSA *rsa, int padding)
{
    int ret = 1;
    int rc = 0;
    we_Rsa *engineRsa = NULL;
    int keySize = 0;

    WOLFENGINE_ENTER(WE_LOG_PK, "we_rsa_pub_dec");
    WOLFENGINE_MSG_VERBOSE(WE_LOG_PK, "ARGS [fromLen = %d, from = %p, to = %p, "
                           "rsa = %p, padding = %d]", fromLen, from, to,
                           rsa, padding);

    /* Validate parameters. */
    if (fromLen < 0) {
        WOLFENGINE_ERROR_MSG(WE_LOG_PK, "Negative input buffer length.");
        ret = -1;
    }

    if (ret == 1) {
        keySize = RSA_size(rsa) * 8;
        rc = we_check_rsa_key_size(keySize, 1);
        if (rc != 1) {
            WOLFENGINE_ERROR_FUNC(WE_LOG_PK, "we_check_rsa_key_size", rc);
            ret = -1;
        }
    }

    if (ret == 1) {
        /* Retrieve the internal RSA object from extra data. */
        engineRsa = (we_Rsa *)RSA_get_ex_data(rsa, WE_RSA_EX_DATA_IDX);
        if (engineRsa == NULL) {
            WOLFENGINE_ERROR_FUNC_NULL(WE_LOG_PK, "RSA_get_ex_data", engineRsa);
            ret = -1;
        }
    }

    /* Set public key into wolfSSL RSA key if not done already. */
    if ((ret == 1) && (!engineRsa->pubKeySet)) {
        rc = we_rsa_set_public_key(rsa, engineRsa);
        if (rc == 0) {
            WOLFENGINE_ERROR_FUNC(WE_LOG_PK, "we_rsa_set_public_key", rc);
            ret = -1;
        }
    }

    if (ret == 1) {
        /* Store the padding mode (PKEY variant has it set) and public
         * decrypt. */
        engineRsa->padMode = padding;
        /* Maximum output size is the length of the prime.
         * Actual plaintext length returned. */
        ret = we_rsa_pub_dec_int(fromLen, from, RSA_size(rsa), to, engineRsa);
        if (ret == -1) {
            WOLFENGINE_ERROR_FUNC(WE_LOG_PK, "we_rsa_pub_dec_int", ret);
        }
    }

    WOLFENGINE_LEAVE(WE_LOG_PK, "we_rsa_pub_dec", ret);

    return ret;
}

/**
 * Export the wolfSSL RSA key into an OpenSSL RSA key.
 *
 * @param  wolfKey  [in]  wolfSSL key.
 * @param  osslKey  [in]  OpenSSL key.
 * @returns  1 on success and 0 on failure.
 */
static int we_convert_rsa(RsaKey *wolfKey, RSA **osslKey)
{
    int ret = 1;
    int derLen = 0;
    unsigned char *der = NULL;
    const unsigned char *derPtr = NULL;
    RSA *decodedRsa = NULL;

    WOLFENGINE_ENTER(WE_LOG_PK, "we_convert_rsa");
    WOLFENGINE_MSG_VERBOSE(WE_LOG_PK, "ARGS [wolfKey = %p, osslKey = %p]",
                           wolfKey, osslKey);

    /* Get the length of the DER encoded private key. */
    derLen = wc_RsaKeyToDer(wolfKey, NULL, 0);
    if (derLen <= 0) {
        WOLFENGINE_ERROR_FUNC(WE_LOG_PK, "wc_RsaKeyToDer", derLen);
        ret = 0;
    }

    if (ret == 1) {
        /* Allocate memory to store encoded private key. */
        der = (unsigned char *)OPENSSL_malloc(derLen);
        if (der == NULL) {
            WOLFENGINE_ERROR_FUNC_NULL(WE_LOG_PK, "OPENSSL_malloc", der);
            ret = 0;
        }
    }

    if (ret == 1) {
        /* DER encode the private key. */
        derLen = wc_RsaKeyToDer(wolfKey, der, derLen);
        if (derLen <= 0) {
            WOLFENGINE_ERROR_FUNC(WE_LOG_PK, "wc_RsaKeyToDer", derLen);
            ret = 0;
        }
    }

    if (ret == 1) {
        /* The pointer passed to d2i_RSAPrivateKey will get advanced to the
         * end of the buffer, so we save the original pointer in order to free
         * the buffer later.
         */
        derPtr = (const unsigned char *)der;
        /* Decode into RSA key - will allocate a new key if osslKey is pointing
         * to NULL. */
        decodedRsa = d2i_RSAPrivateKey(osslKey, &derPtr, derLen);
        if (decodedRsa == NULL) {
            WOLFENGINE_ERROR_FUNC_NULL(WE_LOG_PK, "d2i_RSAPrivateKey",
                                       decodedRsa);
            ret = 0;
        }
    }

    if (der != NULL) {
        /* Dispose safely of DER encoded private key. */
        OPENSSL_clear_free(der, derLen);
    }

    WOLFENGINE_LEAVE(WE_LOG_PK, "we_convert_rsa", ret);

    return ret;
}

/**
 * Internal RSA key generation.
 *
 * @param  rsa      [in,out]  Internal RSA key to generate with.
 * @param  osslKey  [in,out]  OpenSSL RSA key to put key into.
 *                            When NULL, a new key is allocated.
 * @param  bits     [in]      Number of bits in prime to generate.
 * @param  e        [in]      Public exponent to generate with.
 * @returns  1 on success and 0 on failure.
 */
static int we_rsa_keygen_int(we_Rsa *rsa, RSA **osslKey, int bits, long e)
{
    int ret = 1;
    int rc = 0;
#ifndef WE_SINGLE_THREADED
    WC_RNG *rng = &rsa->rng;
#else
    WC_RNG *rng = we_rng;
#endif

    WOLFENGINE_ENTER(WE_LOG_PK, "we_rsa_pkey_keygen");
    WOLFENGINE_MSG_VERBOSE(WE_LOG_PK, "ARGS [rsa = %p, osslKey = %p, "
                           "bits = %d, e = %ld]", rsa, osslKey, bits, e);

    /* Validate parameters. */
    if (rsa == NULL) {
        WOLFENGINE_ERROR_MSG(WE_LOG_PK, "we_rsa_keygen_int: rsa NULL");
        ret = 0;
    }
    if (ret == 1 && osslKey == NULL) {
        WOLFENGINE_ERROR_MSG(WE_LOG_PK, "we_rsa_keygen_int: osslKey NULL");
        ret = 0;
    }
    if (ret == 1) {
        rc = we_check_rsa_key_size(bits, 0);
        if (rc != 1) {
            WOLFENGINE_ERROR_FUNC(WE_LOG_PK, "we_check_rsa_key_size", rc);
            ret = 0;
        }
    }

    if (ret == 1) {
        /* Generate and RSA key with wolfSSL. */
        rc = wc_MakeRsaKey(&rsa->key, bits, e, rng);
        if (rc != 0) {
            WOLFENGINE_ERROR_FUNC(WE_LOG_PK, "wc_MakeRsaKey", rc);
            ret = 0;
        }
    }

    if (ret == 1) {
        /* Convert the wolfSSL RSA key to and OpenSSL RSA key. */
        rc = we_convert_rsa(&rsa->key, osslKey);
        if (rc != 1) {
            WOLFENGINE_ERROR_FUNC(WE_LOG_PK, "we_convert_rsa", rc);
            ret = 0;
        }
    }

    WOLFENGINE_LEAVE(WE_LOG_PK, "we_rsa_keygen_int", ret);

    return ret;
}

/**
 * Generate an RSA key with a prime of a set length and the specified exponent.
 *
 * wolfSSL only supports exponents that fit in a 'long'.
 *
 * @param  osslKey  [in,out]  OpenSSL RSA key.
 * @param  bits     [in]      Number of bits in prime to generate.
 * @param  eBn      [in]      Public exponent as a big number.
 * @returns  1 on success and 0 on failure.
 */
static int we_rsa_keygen(RSA *osslKey, int bits, BIGNUM *eBn, BN_GENCB *cb)
{
    int ret = 1;
    int rc = 0;
    we_Rsa *engineRsa = NULL;
    long e = 0;

    (void)cb; /* Callback not supported, yet. */

    WOLFENGINE_ENTER(WE_LOG_PK, "we_rsa_keygen");
    WOLFENGINE_MSG_VERBOSE(WE_LOG_PK, "ARGS [osslKey = %p, bits = %d, "
                           "eBn = %p, cb = %p]", osslKey, bits, eBn, cb);

    /* Retrieve the internal RSA object from extra data. */
    engineRsa = (we_Rsa *)RSA_get_ex_data(osslKey, WE_RSA_EX_DATA_IDX);
    if (engineRsa == NULL) {
        WOLFENGINE_ERROR_FUNC_NULL(WE_LOG_PK, "RSA_get_ex_data", engineRsa);
        ret = 0;
    }

    if (ret == 1) {
        /* Get the bottom word of the big number. */
        e = (long)BN_get_word(eBn);
        /* Check for positive value overflowing signed number or 0. */
        if (e <= 0) {
            WOLFENGINE_ERROR_FUNC(WE_LOG_PK, "BN_get_word", (int)e);
            ret = 0;
        }
    }

    if (ret == 1) {
        /* Generate the RSA key with wolfSSL and put into OpenSSL key. */
        rc = we_rsa_keygen_int(engineRsa, &osslKey, bits, e);
        if (rc != 1) {
            WOLFENGINE_ERROR_FUNC(WE_LOG_PK, "we_rsa_keygen_int", rc);
            ret = 0;
        }
    }

    WOLFENGINE_LEAVE(WE_LOG_PK, "we_rsa_keygen", ret);

    return ret;
}

/**
 * Initialize the RSA method.
 *
 * @return  1 on success and 0 on failure.
 */
int we_init_rsa_meth(void)
{
    int ret = 1;

    WOLFENGINE_ENTER(WE_LOG_PK, "we_init_rsa_meth");

    we_rsa_method = RSA_meth_new("wolfengine_rsa", 0);
    if (we_rsa_method == NULL) {
        WOLFENGINE_ERROR_FUNC_NULL(WE_LOG_PK, "RSA_meth_new", we_rsa_method);
        ret = 0;
    }

    if (ret == 1) {
        RSA_meth_set_init(we_rsa_method, we_rsa_init);
        RSA_meth_set_finish(we_rsa_method, we_rsa_finish);
        RSA_meth_set_pub_enc(we_rsa_method, we_rsa_pub_enc);
        RSA_meth_set_pub_dec(we_rsa_method, we_rsa_pub_dec);
        RSA_meth_set_priv_enc(we_rsa_method, we_rsa_priv_enc);
        RSA_meth_set_priv_dec(we_rsa_method, we_rsa_priv_dec);
        RSA_meth_set_keygen(we_rsa_method, we_rsa_keygen);
    }
    /* No failures to cause method to be be invalid. */

    WOLFENGINE_LEAVE(WE_LOG_PK, "we_init_rsa_meth", ret);

    return ret;
}

#ifdef WE_HAVE_EVP_PKEY

/** EVP public key method - RSA using wolfSSL for the implementation. */
EVP_PKEY_METHOD *we_rsa_pkey_method = NULL;

/**
 * Initialize and set the data required to complete an RSA operation.
 *
 * @param  ctx  [in]  Public key context of operation.
 * @returns  1 on success and 0 on failure.
 */
static int we_rsa_pkey_init(EVP_PKEY_CTX *ctx)
{
    int ret = 1;
    int rc = 0;
    we_Rsa *rsa;

    WOLFENGINE_ENTER(WE_LOG_PK, "we_rsa_pkey_init");
    WOLFENGINE_MSG_VERBOSE(WE_LOG_PK, "ARGS [ctx = %p]", ctx);

    /* Allocate an internal RSA object. */
    rsa = (we_Rsa *)OPENSSL_zalloc(sizeof(we_Rsa));
    if (rsa == NULL) {
        WOLFENGINE_ERROR_FUNC_NULL(WE_LOG_PK, "OPENSSL_zalloc", rsa);
        ret = 0;
    }

    if (ret == 1) {
    #if OPENSSL_VERSION_NUMBER >= 0x10101000L
        rsa->saltLen = RSA_PSS_SALTLEN_AUTO;
    #else
        rsa->saltLen = RSA_PSS_SALT_LEN_DEFAULT;
    #endif

        /* Initialize the wolfSSL RSA key. */
        rc = wc_InitRsaKey(&rsa->key, NULL);
        if (rc != 0) {
            WOLFENGINE_ERROR_FUNC(WE_LOG_PK, "wc_InitRsaKey", rc);
            ret = 0;
        }
    }

#ifndef WE_SINGLE_THREADED
    if (ret == 1) {
        rc = wc_InitRng(&rsa->rng);
        if (rc != 0) {
            WOLFENGINE_ERROR_FUNC(WE_LOG_PK, "wc_InitRng", rc);
            ret = 0;
        }
    }
#endif

    if (ret == 1) {
        /* Set defaults. */
        rsa->padMode = RSA_PKCS1_PADDING;
        rsa->pubExp = DEFAULT_PUB_EXP;
        rsa->bits = DEFAULT_KEY_BITS;
        /* Store the internal RSA object in the context. */
        EVP_PKEY_CTX_set_data(ctx, rsa);
    }

    if ((ret == 0) && (rsa != NULL)) {
        /* Dispose of the wolfSSL RSA key, RNG and internal object on failure.
         */
#ifndef WE_SINGLE_THREADED
        wc_FreeRng(&rsa->rng);
#endif
        wc_FreeRsaKey(&rsa->key);
        OPENSSL_free(rsa);
    }

    WOLFENGINE_LEAVE(WE_LOG_PK, "we_rsa_pkey_init", ret);

    return ret;
}

/**
 * Clean up the RSA operation data.
 *
 * @param  ctx  [in]  Public key context of operation.
 */
static void we_rsa_pkey_cleanup(EVP_PKEY_CTX *ctx)
{
    /* Get the internal RSA object. */
    we_Rsa *rsa = (we_Rsa *)EVP_PKEY_CTX_get_data(ctx);

    WOLFENGINE_ENTER(WE_LOG_PK, "we_rsa_pkey_cleanup");
    WOLFENGINE_MSG_VERBOSE(WE_LOG_PK, "ARGS [ctx = %p]", ctx);

    if (rsa != NULL) {
        /* Remove reference to internal RSA object. */
        EVP_PKEY_CTX_set_data(ctx, NULL);
        /* Free the wolfSSL RSA key. */
    #ifndef WE_SINGLE_THREADED
        wc_FreeRng(&rsa->rng);
    #endif
        wc_FreeRsaKey(&rsa->key);
        OPENSSL_free(rsa);
    }

    WOLFENGINE_LEAVE(WE_LOG_PK, "we_rsa_pkey_cleanup", 1);
}

/**
 * Copy the EVP public key method from/to EVP public key contexts.
 *
 * @param  dst  [in]  Destination public key context.
 * @param  src  [in]  Source public key context.
 * @returns  1 on success and 0 on failure.
 */
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
static int we_rsa_pkey_copy(EVP_PKEY_CTX *dst, const EVP_PKEY_CTX *src)
#else
static int we_rsa_pkey_copy(EVP_PKEY_CTX *dst, EVP_PKEY_CTX *src)
#endif
{
    int ret = 1;
    int rc;
    we_Rsa *rsaDst = NULL;
    we_Rsa *rsaSrc = NULL;

    WOLFENGINE_ENTER(WE_LOG_PK, "we_rsa_pkey_copy");
    WOLFENGINE_MSG_VERBOSE(WE_LOG_PK, "ARGS [dst = %p, src = %p]", dst, src);

    /* Initialize the internal RSA object. */
    rc = we_rsa_pkey_init(dst);
    if (rc != 1) {
        WOLFENGINE_ERROR_FUNC(WE_LOG_PK, "we_rsa_pkey_init", rc);
        ret = 0;
    }
    if (ret == 1) {
        /* Get the internal RSA object for destination context. */
        rsaDst = (we_Rsa *)EVP_PKEY_CTX_get_data(dst);
        if (rsaDst == NULL) {
            WOLFENGINE_ERROR_FUNC_NULL(WE_LOG_PK,
                                       "EVP_PKEY_CTX_get_data(rsaDst)", rsaDst);
            ret = 0;
        }
    }
    if (ret == 1) {
        /* Get the internal RSA object for source context. */
        rsaSrc = (we_Rsa *)EVP_PKEY_CTX_get_data(src);
        if (rsaSrc == NULL) {
            WOLFENGINE_ERROR_FUNC_NULL(WE_LOG_PK,
                                       "EVP_PKEY_CTX_get_data(rsaSrc)", rsaDst);
            ret = 0;
        }
    }
    if (ret == 1) {
        /* Copy the parameter fields. */
        rsaDst->md = rsaSrc->md;
        rsaDst->mdMGF1 = rsaSrc->mdMGF1;
        rsaDst->padMode = rsaSrc->padMode;
        rsaDst->pubExp = rsaSrc->pubExp;
        rsaDst->bits = rsaSrc->bits;
        rsaDst->saltLen = rsaSrc->saltLen;
        /* Don't copy wolfSSL RSA key.
         * No public key or private key set. */
    }

    WOLFENGINE_LEAVE(WE_LOG_PK, "we_rsa_pkey_copy", ret);

    return ret;
}

/**
 * Generate an RSA key.
 *
 * @param  ctx   [in]   Public key context of operation.
 * @param  pkey  [out]  EVP public key to hold result.
 * @returns  1 on success and 0 on failure.
 */
static int we_rsa_pkey_keygen(EVP_PKEY_CTX *ctx, EVP_PKEY *pkey)
{
    int ret = 1;
    int rc = 0;
    we_Rsa *engineRsa = NULL;
    RSA *rsa = NULL;

    WOLFENGINE_ENTER(WE_LOG_PK, "we_rsa_pkey_keygen");
    WOLFENGINE_MSG_VERBOSE(WE_LOG_PK, "ARGS [ctx = %p, pkey = %p]", ctx, pkey);

    /* Get the internal RSA object. */
    engineRsa = (we_Rsa *)EVP_PKEY_CTX_get_data(ctx);
    if (engineRsa == NULL) {
        WOLFENGINE_ERROR_FUNC_NULL(WE_LOG_PK, "EVP_PKEY_CTX_get_data",
                                   engineRsa);
        ret = 0;
    }

    if (ret == 1) {
        /* Generate an RSA key using wolfSSL and copy into OpenSSL RSA key. */
        rc = we_rsa_keygen_int(engineRsa, &rsa, engineRsa->bits,
                               engineRsa->pubExp);
        if (rc == 0) {
            WOLFENGINE_ERROR_FUNC(WE_LOG_PK, "we_rsa_keygen_int", rc);
            ret = 0;
        }
    }

    if (ret == 1) {
        /* Assign the generated key into the EVP PKEY. */
        ret = EVP_PKEY_assign_RSA(pkey, rsa);
        if (ret == 0) {
            WOLFENGINE_ERROR_FUNC(WE_LOG_PK, "EVP_PKEY_assign_RSA", ret);
        }
    }

    WOLFENGINE_LEAVE(WE_LOG_PK, "we_rsa_pkey_keygen", ret);

    return ret;
}

/**
 * Extra operations for working with RSA.
 * Supported operations include:
 *  - EVP_PKEY_CTRL_RSA_PADDING: set the padding mode.
 *  - EVP_PKEY_CTRL_GET_RSA_PADDING: get the padding mode.
 *  - EVP_PKEY_CTRL_MD: set the digest method for sign/verify.
 *  - EVP_PKEY_CTRL_GET_MD: get the digest method for sign/verify.
 *  - EVP_PKEY_CTRL_RSA_OAEP_MD: set the digest method for OAEP label.
 *  - EVP_PKEY_CTRL_GET_RSA_OAEP_MD: get the digest method for OAEP label.
 *  - EVP_PKEY_CTRL_RSA_KEYGEN_BITS: set the key size in bits.
 *  - EVP_PKEY_CTRL_RSA_KEYGEN_PUBEXP: set the public exponent, "e."
 *  - EVP_PKEY_CTRL_RSA_PSS_SALTLEN: set the salt length for PSS padding.
 *  - EVP_PKEY_CTRL_GET_RSA_PSS_SALTLEN:  get the salt length for PSS padding.
 *  - EVP_PKEY_CTRL_RSA_MGF1_MD: Set the MGF1 digest to use for OAEP, PSS.
 *  - EVP_PKEY_CTRL_GET_RSA_MGF1_MD: Get the MGF1 digest used for OAEP, PSS.
 *
 * @param  ctx   [in]  Public key context of operation.
 * @param  type  [in]  Type of operation to perform.
 * @param  num   [in]  Integer parameter.
 * @param  ptr   [in]  Pointer parameter.
 * @returns  1 on success and 0 on failure.
 */
static int we_rsa_pkey_ctrl(EVP_PKEY_CTX *ctx, int type, int num, void *ptr)
{
    int ret = 1;
    we_Rsa *rsa = NULL;
    BIGNUM* bn = NULL;
    long e;
    char errBuff[WOLFENGINE_MAX_LOG_WIDTH];

    WOLFENGINE_ENTER(WE_LOG_PK, "we_rsa_pkey_ctrl");
    WOLFENGINE_MSG_VERBOSE(WE_LOG_PK, "ARGS [ctx = %p, type = %d, num = %d, "
                           "ptr = %p]", ctx, type, num, ptr);

    /* Get the internal RSA object. */
    rsa = (we_Rsa *)EVP_PKEY_CTX_get_data(ctx);
    if (rsa == NULL) {
        WOLFENGINE_ERROR_FUNC_NULL(WE_LOG_PK, "EVP_PKEY_CTX_get_data", rsa);
        ret = 0;
    }

    if (ret == 1) {
        switch (type) {
            case EVP_PKEY_CTRL_RSA_PADDING:
                WOLFENGINE_MSG(WE_LOG_PK, "type: EVP_PKEY_CTRL_RSA_PADDING");
                /* num  [in]  RSA padding mode. */
                /* Validate parameter - padding mode. */
                if (num != RSA_PKCS1_PADDING &&
                    num != RSA_PKCS1_PSS_PADDING &&
                    num != RSA_PKCS1_OAEP_PADDING &&
                    num != RSA_NO_PADDING)
                {
                    WOLFENGINE_ERROR_MSG(WE_LOG_PK,
                                         "Unsupported RSA padding mode.");
                    ret = 0;
                }
                else {
                    rsa->padMode = num;
                    if (rsa->md == NULL && (num == RSA_PKCS1_OAEP_PADDING ||
                        num == RSA_PKCS1_PSS_PADDING)) {
                       /* Default to SHA-1 as the message digest for OAEP and
                          PSS padding. */
                       rsa->md = EVP_sha1();
                    }
                }
                break;
            case EVP_PKEY_CTRL_GET_RSA_PADDING:
                WOLFENGINE_MSG(WE_LOG_PK,
                               "type: EVP_PKEY_CTRL_GET_RSA_PADDING");
                /* ptr  [out]  RSA padding mode. */
                *(int *)ptr = rsa->padMode;
                break;
            case EVP_PKEY_CTRL_MD:
                WOLFENGINE_MSG(WE_LOG_PK, "type: EVP_PKEY_CTRL_MD");
                /* ptr  [in]  Signing/verification digest. */
                rsa->md = (EVP_MD*)ptr;
                break;
            case EVP_PKEY_CTRL_GET_MD:
                WOLFENGINE_MSG(WE_LOG_PK, "type: EVP_PKEY_CTRL_GET_MD");
                /* ptr  [out]  Signing/verification digest. */
                *(const EVP_MD **)ptr = rsa->md;
                break;
            case EVP_PKEY_CTRL_RSA_OAEP_MD:
                WOLFENGINE_MSG(WE_LOG_PK, "type: EVP_PKEY_CTRL_RSA_OAEP_MD");
                /* ptr [in]  EVP digest to use in OAEP padding. */
                if (rsa->padMode != RSA_PKCS1_OAEP_PADDING) {
                    WOLFENGINE_ERROR_MSG(WE_LOG_PK, "Can't use "
                        "EVP_PKEY_CTRL_RSA_OAEP_MD when padding mode "
                        "isn't OAEP.");
                    ret = 0;
                }
                else {
                    rsa->md = (const EVP_MD *)ptr;
                }
                break;
            case EVP_PKEY_CTRL_GET_RSA_OAEP_MD:
                WOLFENGINE_MSG(WE_LOG_PK,
                               "type: EVP_PKEY_CTRL_GET_RSA_OAEP_MD");
                /* ptr [out]  EVP digest used in OAEP padding. */
                if (rsa->padMode != RSA_PKCS1_OAEP_PADDING) {
                    WOLFENGINE_ERROR_MSG(WE_LOG_PK, "Can't use "
                        "EVP_PKEY_CTRL_GET_RSA_OAEP_MD when padding mode "
                        "isn't OAEP.");
                    ret = 0;
                }
                else {
                    *(const EVP_MD **)ptr = rsa->md;
                }
                break;
#if OPENSSL_VERSION_NUMBER >= 0x1010100fL
            case EVP_PKEY_CTRL_RSA_KEYGEN_PRIMES:
                WOLFENGINE_MSG(WE_LOG_PK,
                               "type: EVP_PKEY_CTRL_RSA_KEYGEN_PRIMES");
                /* num  [in]  Number of primes. */
                if (num != 2) {
                    /* wolfCrypt can only do key generation with 2 primes. */
                    WOLFENGINE_ERROR_MSG(WE_LOG_PK,
                        "wolfCrypt does not support multi-prime RSA.");
                    ret = 0;
                }
                break;
#endif
            case EVP_PKEY_CTRL_RSA_KEYGEN_BITS:
                WOLFENGINE_MSG(WE_LOG_PK,
                               "type: EVP_PKEY_CTRL_RSA_KEYGEN_BITS");
                /* num  [in]  Size of the prime to generate in bits. */
                ret = we_check_rsa_key_size(num, 0);
                if (ret != 1) {
                    WOLFENGINE_ERROR_FUNC(WE_LOG_PK, "we_check_rsa_key_size",
                                          ret);
                }
                else {
                    rsa->bits = num;
                    ret = 1;
                }
                break;
            case EVP_PKEY_CTRL_RSA_KEYGEN_PUBEXP:
                WOLFENGINE_MSG(WE_LOG_PK,
                               "type: EVP_PKEY_CTRL_RSA_KEYGEN_PUBEXP");
                /* ptr  [in]  Big number holding public exponent. */
                bn = (BIGNUM*)ptr;
                /* Get the bottom word of the big number. */
                e = (long)BN_get_word(bn);
                /* Check for positive value overflowing signed number. */
                if (e < 0) {
                    WOLFENGINE_ERROR_MSG(WE_LOG_PK,
                                         "RSA public exponent too large.");
                    ret = 0;
                }
                /* Public exponent must have inverse. */
                if ((ret == 1) && (e == 0)) {
                    WOLFENGINE_ERROR_MSG(WE_LOG_PK,
                                         "RSA public exponent is 0.");
                    ret = 0;
                }
                if (ret == 1) {
                    rsa->pubExp = (int)e;
                }
                break;
            case EVP_PKEY_CTRL_RSA_PSS_SALTLEN:
                WOLFENGINE_MSG(WE_LOG_PK,
                               "type: EVP_PKEY_CTRL_RSA_PSS_SALTLEN");
                /* num  [in]  Salt length for PSS.  */
                /* Only useful when padding mode is PSS. */
                if (rsa->padMode != RSA_PKCS1_PSS_PADDING) {
                    WOLFENGINE_ERROR_MSG(WE_LOG_PK, "Can't set PSS salt length "
                                         "when padding mode isn't PSS.");
                    ret = 0;
                }
                /* Store salt length to use with RSA-PSS. */
                rsa->saltLen = num;
                break;
            case EVP_PKEY_CTRL_GET_RSA_PSS_SALTLEN:
                WOLFENGINE_MSG(WE_LOG_PK,
                               "type: EVP_PKEY_CTRL_GET_RSA_PSS_SALTLEN");
                /* ptr  [out]  Salt length for PSS.  */
                /* Only useful when padding mode is PSS. */
                if (rsa->padMode != RSA_PKCS1_PSS_PADDING) {
                    WOLFENGINE_ERROR_MSG(WE_LOG_PK, "Can't get PSS salt length "
                                         "when padding mode isn't PSS.");
                    ret = 0;
                }
                if (ret == 1) {
                    /* Get the salt length to use with RSA-PSS. */
            #if OPENSSL_VERSION_NUMBER >= 0x10101000L
                #ifndef WOLFSSL_PSS_LONG_SALT
                    /* rsa_ameth.c:rsa_ctx_to_pss() defaults to max size when
                     * RSA_PSS_SALTLEN_AUTO. No long salt means maximum salt
                     * size is the digest size.
                     */
                    if (rsa->saltLen == RSA_PSS_SALTLEN_AUTO) {
                        *(int *)ptr = EVP_MD_size(rsa->md);
                    }
                    else
                #endif
            #endif
                    {
                        *(int *)ptr = rsa->saltLen;
                    }
                }
                break;
            case EVP_PKEY_CTRL_RSA_MGF1_MD:
                WOLFENGINE_MSG(WE_LOG_PK, "type: EVP_PKEY_CTRL_RSA_MGF1_MD");
                /* ptr  [in]  Digest to use with MGF1 in OAEP/PSS. */
                /* Only useful when padding mode is OAEP/PSS. */
                if (rsa->padMode != RSA_PKCS1_OAEP_PADDING &&
                    rsa->padMode != RSA_PKCS1_PSS_PADDING) {
                    WOLFENGINE_ERROR_MSG(WE_LOG_PK, "Can't set MGF1 digest "
                                         "when padding mode isn't OAEP or "
                                         "PSS.");
                    ret = 0;
                }
                else {
                    rsa->mdMGF1 = (const EVP_MD *)ptr;
                }
                break;
            case EVP_PKEY_CTRL_GET_RSA_MGF1_MD:
                WOLFENGINE_MSG(WE_LOG_PK,
                               "type: EVP_PKEY_CTRL_GET_RSA_MGF1_MD");
                /* ptr  [out]  Digest to use with MGF1 in OAEP/PSS. */
                /* Only useful when padding mode is OAEP/PSS. */
                if (rsa->padMode != RSA_PKCS1_OAEP_PADDING &&
                    rsa->padMode != RSA_PKCS1_PSS_PADDING) {
                    WOLFENGINE_ERROR_MSG(WE_LOG_PK, "Can't get MGF1 digest "
                                         "when padding mode isn't OAEP or "
                                         "PSS.");
                    ret = 0;
                }
                else {
                    /* When MGF1 digest not set then the sign/verify digest
                     * will be used so return it in that case.
                     */
                    if (rsa->mdMGF1 != NULL) {
                        *(const EVP_MD **)ptr = rsa->mdMGF1;
                    }
                    else {
                        *(const EVP_MD **)ptr = rsa->md;
                    }
                }
                break;

            case EVP_PKEY_CTRL_DIGESTINIT:
                WOLFENGINE_MSG(WE_LOG_PK, "type: EVP_PKEY_CTRL_DIGESTINIT");
                /* Nothing to do. */
                break;
            case EVP_PKEY_CTRL_PKCS7_SIGN:
                WOLFENGINE_MSG(WE_LOG_PK, "type: EVP_PKEY_CTRL_PKCS7_SIGN");
                /* Nothing to do. */
                break;
            case EVP_PKEY_CTRL_CMS_SIGN:
                WOLFENGINE_MSG(WE_LOG_PK, "type: EVP_PKEY_CTRL_CMS_SIGN");
                /* Nothing to do. */
                break;

            case EVP_PKEY_CTRL_PKCS7_ENCRYPT:
            case EVP_PKEY_CTRL_PKCS7_DECRYPT:
            case EVP_PKEY_CTRL_CMS_DECRYPT:
            case EVP_PKEY_CTRL_CMS_ENCRYPT:
                if (rsa->padMode == RSA_PKCS1_PSS_PADDING) {
                    WOLFENGINE_ERROR_MSG(WE_LOG_PK, "PKCS7/CMS not with PSS");
                    ret = 0;
                }
                break;
            case EVP_PKEY_CTRL_RSA_OAEP_LABEL:
                WOLFENGINE_MSG(WE_LOG_PK, "type: EVP_PKEY_CTRL_RSA_OAEP_LABEL");
                /* Not needed - seed created internally. */
                break;
            case EVP_PKEY_CTRL_GET_RSA_OAEP_LABEL:
                WOLFENGINE_MSG(WE_LOG_PK,
                               "type: EVP_PKEY_CTRL_GET_RSA_OAEP_LABEL");
                /* Not needed - seed created internally. */
                *(unsigned char **)ptr = NULL;
                ret = 0;
                break;

            default:
                /* Unsupported control type. */
                XSNPRINTF(errBuff, sizeof(errBuff), "Unsupported ctrl type %d",
                          type);
                WOLFENGINE_ERROR_MSG(WE_LOG_PK, errBuff);
                ret = 0;
                break;
        }
    }

    WOLFENGINE_LEAVE(WE_LOG_PK, "we_rsa_pkey_ctrl", ret);

    return ret;
}

/**
 * Extra operations for working with RSA.
 * Supported operations include:
 *  - "rsa_padding_mode": set the padding mode
 *  - "rsa_pss_saltlen": set RSA-PSS salt length to use
 *  - "rsa_keygen_bits": set size of RSA keys to generate in bits
 *  - "rsa_mgf1_md": set the RSA-PSS MGF1 hash to use
 *
 * @param  ctx   [in]  Public key context of operation.
 * @param  type  [in]  Type of operation to perform.
 * @param  num   [in]  Integer parameter.
 * @param  ptr   [in]  Pointer parameter.
 * @returns  1 on success and 0 on failure.
 */
static int we_rsa_pkey_ctrl_str(EVP_PKEY_CTX *ctx, const char *type,
                                const char *value)
{
    int ret = 1;
    we_Rsa *rsa = NULL;
    char errBuff[WOLFENGINE_MAX_LOG_WIDTH];
    int bits = 0;

    WOLFENGINE_ENTER(WE_LOG_PK, "we_rsa_pkey_ctrl_str");
    WOLFENGINE_MSG_VERBOSE(WE_LOG_PK, "ARGS [ctx = %p, type = %p, value = %p]",
                           ctx, type, value);

    /* Get the internal RSA object. */
    rsa = (we_Rsa *)EVP_PKEY_CTX_get_data(ctx);
    if (rsa == NULL) {
        WOLFENGINE_ERROR_FUNC_NULL(WE_LOG_PK, "EVP_PKEY_CTX_get_data", rsa);
        ret = 0;
    }

    if ((ret == 1) && (XSTRNCMP(type, "rsa_padding_mode", 17) == 0)) {
        /* Padding mode. */
        if (XSTRNCMP(value, "none", 5) == 0) {
            rsa->padMode = RSA_NO_PADDING;
        }
        else if (XSTRNCMP(value, "pkcs1", 6) == 0) {
            rsa->padMode = RSA_PKCS1_PADDING;
        }
        else if (XSTRNCMP(value, "oaep", 5) == 0) {
            rsa->padMode = RSA_PKCS1_OAEP_PADDING;
        }
        else if (XSTRNCMP(value, "pss", 4) == 0) {
            rsa->padMode = RSA_PKCS1_PSS_PADDING;
        }
        else {
            ret = 0;
        }
        if ((ret == 1) && (rsa->md == NULL) &&
            ((rsa->padMode == RSA_PKCS1_OAEP_PADDING) ||
             (rsa->padMode == RSA_PKCS1_PSS_PADDING))) {
           /* Default to SHA-1 as the message digest for OAEP and PSS padding.
            */
           rsa->md = EVP_sha1();
        }
    }
    else if ((ret == 1) && (XSTRNCMP(type, "rsa_pss_saltlen", 16) == 0)) {
        /* RSA-PSS salt length. */
        if (rsa->padMode != RSA_PKCS1_PSS_PADDING) {
            ret = 0;
        }
    #if OPENSSL_VERSION_NUMBER >= 0x10101000L
        else if (XSTRNCMP(value, "digest", 7) == 0) {
            rsa->saltLen = RSA_PSS_SALTLEN_DIGEST;
        }
        else if (XSTRNCMP(value, "max", 4) == 0) {
            rsa->saltLen = RSA_PSS_SALTLEN_MAX;
        }
        else if (XSTRNCMP(value, "auto", 5) == 0) {
        #if OPENSSL_VERSION_NUMBER >= 0x10101000L
            rsa->saltLen = RSA_PSS_SALTLEN_AUTO;
        #else
            rsa->saltLen = RSA_PSS_SALT_LEN_DEFAULT;
        #endif
        }
    #endif
        else {
            rsa->saltLen = XATOI(value);
        }
    }
    else if ((ret == 1) && (XSTRNCMP(type, "rsa_keygen_bits", 16) == 0)) {
        /* Size, in bits, of RSA key to generate. */
        bits = XATOI(value);
        ret = we_check_rsa_key_size(bits, 0);
        if (ret != 1) {
            WOLFENGINE_ERROR_FUNC(WE_LOG_PK, "we_check_rsa_key_size", ret);
            ret = -2;
        }
        else {
            rsa->bits = bits;
        }
    }
    else if ((ret == 1) && (XSTRNCMP(type, "rsa_mgf1_md", 12) == 0)) {
        if ((rsa->padMode != RSA_PKCS1_OAEP_PADDING) &&
            (rsa->padMode != RSA_PKCS1_PSS_PADDING)) {
            WOLFENGINE_ERROR_MSG(WE_LOG_PK, "Setting MGF1 and not PSS or OAEP");
            ret = -2;
        }
        if (ret == 1) {
            /* Digest to use with MGF in RSA-PSS. */
            rsa->mdMGF1 = EVP_get_digestbyname(value);
            if (rsa->mdMGF1 == NULL) {
                ret = 0;
            }
        }
    }
    else if ((ret == 1) && (XSTRNCMP(type, "rsa_oaep_md", 12) == 0)) {
        if (rsa->padMode != RSA_PKCS1_OAEP_PADDING) {
            WOLFENGINE_ERROR_MSG(WE_LOG_PK, "Setting MD and not OAEP");
            ret = -2;
        }
        if (ret == 1) {
            /* Digest to use in RSA-OAEP. */
            rsa->md = EVP_get_digestbyname(value);
            if (rsa->md == NULL) {
                ret = 0;
            }
        }
    }
    else {
        /* Unsupported string. */
        XSNPRINTF(errBuff, sizeof(errBuff), "Unsupported ctrl string: %s",
                  type);
        WOLFENGINE_ERROR_MSG(WE_LOG_PK, errBuff);
        ret = 0;
    }

    return ret;
}

/**
 * Encode a digest in DER format.
 *
 * @param  md            [in]   EVP_MD structure containing the hash type.
 * @param  digest        [in]   Buffer holding the digest.
 * @param  digestLen     [in]   Length of digest buffer.
 * @param  encodedDigest [out]  Buffer containing encoded digest. If NULL,
                                memory will be allocated and caller must free.
 * @returns Length of encoded digest on success and 0 on failure.
 */
static int we_der_encode_digest(const EVP_MD *md, const unsigned char *digest,
                                size_t digestLen, unsigned char **encodedDigest)
{
    int ret = 1;
    int hashOID = 0;

    WOLFENGINE_ENTER(WE_LOG_PK, "we_der_encode_digest");
    WOLFENGINE_MSG_VERBOSE(WE_LOG_PK, "ARGS [md = %p, digest = %p, "
                           "digestLen = %zu, encodedDigest = %p]", md,
                           digest, digestLen, encodedDigest);

    /* Allocate a buffer if not passed in. */
    if (*encodedDigest == NULL) {
        *encodedDigest = (unsigned char *)OPENSSL_malloc(MAX_DER_DIGEST_SZ);
        if (*encodedDigest == NULL) {
            WOLFENGINE_ERROR_FUNC_NULL(WE_LOG_PK, "OPENSSL_malloc",
                                       *encodedDigest);
            ret = 0;
        }
    }

#if OPENSSL_VERSION_NUMBER >= 0x10100000L
    /* SSL signatures are not encoded. */
    if ((ret == 1) && (md == EVP_md5_sha1())) {
        XMEMCPY(*encodedDigest, digest, digestLen);
        ret = (int)digestLen;
    }
    else
#endif
    if (ret == 1) {
        /* Map digest to wolfSSL value for encode function. */
        hashOID = we_nid_to_wc_hash_oid(EVP_MD_type(md));
        if (hashOID <= 0) {
            /* Digest not supported. */
            WOLFENGINE_ERROR_FUNC(WE_LOG_PK, "we_nid_to_wc_hash_oid", hashOID);
            ret = 0;
        }

        if (ret == 1) {
            /* Encode digest with ASN.1 - includes hash algorithm. */
            ret = wc_EncodeSignature(*encodedDigest, digest, (word32)digestLen,
                                     hashOID);
            if (ret == 0) {
                WOLFENGINE_ERROR_FUNC(WE_LOG_PK, "wc_EncodeSignature", ret);
            }
        }
    }

    WOLFENGINE_LEAVE(WE_LOG_PK, "we_der_encode_digest", ret);

    return ret;
}

/**
 * Sign data with a private RSA key.
 *
 * @param  ctx     [in]      Private key context of operation.
 * @param  sig     [in]      Buffer to hold signature data.
 *                           NULL indicates length of signature requested.
 * @param  sigLen  [in/out]  Length of signature buffer.
 * @param  tbs     [in]      To Be Signed data.
 * @param  tbsLen  [in]      Length of To Be Signed data.
 * @returns  1 on success and 0 on failure.
 */
static int we_rsa_pkey_sign(EVP_PKEY_CTX *ctx, unsigned char *sig,
                            size_t *sigLen, const unsigned char *tbs,
                            size_t tbsLen)
{
    int ret = 1;
    we_Rsa *rsa = NULL;
    EVP_PKEY *pkey = NULL;
    RSA *rsaKey = NULL;
    unsigned char *encodedDigest = NULL;
    int encodedDigestLen = 0;
    int len;
    int actualSigLen = 0;
    int keySize = 0;

    WOLFENGINE_ENTER(WE_LOG_PK, "we_rsa_pkey_sign");
    WOLFENGINE_MSG_VERBOSE(WE_LOG_PK, "ARGS [ctx = %p, sig = %p, sigLen = %p, "
                           "tbs = %p, tbsLen = %zu]", ctx, sig, sigLen, tbs,
                           tbsLen);

    /* Get the internal RSA object. */
    rsa = (we_Rsa *)EVP_PKEY_CTX_get_data(ctx);
    if (rsa == NULL) {
        WOLFENGINE_ERROR_FUNC_NULL(WE_LOG_PK, "EVP_PKEY_CTX_get_data", rsa);
        ret = 0;
    }

    /* Set up private key */
    if ((ret == 1) && (!rsa->privKeySet)) {
        /* OpenSSL RSA key in EVP PKEY associated with context. */
        pkey = EVP_PKEY_CTX_get0_pkey(ctx);
        if (pkey == NULL) {
            WOLFENGINE_ERROR_FUNC_NULL(WE_LOG_PK, "EVP_PKEY_CTX_get0_pkey",
                                       pkey);
            ret = 0;
        }
        if (ret == 1) {
            /* Get OpenSSL RSA key containing private key. */
            rsaKey = (RSA*)EVP_PKEY_get0_RSA(pkey);
            if (rsaKey == NULL) {
                WOLFENGINE_ERROR_FUNC_NULL(WE_LOG_PK, "EVP_PKEY_get0_RSA",
                                           rsaKey);
                ret = 0;
            }
        }
        if (ret == 1) {
            keySize = RSA_size(rsaKey) * 8;
            ret = we_check_rsa_key_size(keySize, 0);
            if (ret != 1) {
                WOLFENGINE_ERROR_FUNC(WE_LOG_PK, "we_check_rsa_key_size", ret);
            }
        }
        if (ret == 1) {
            /* Set the private key into the internal RSA key. */
            ret = we_rsa_set_private_key(rsaKey, rsa);
            if (ret == 0) {
                WOLFENGINE_ERROR_FUNC(WE_LOG_PK, "we_rsa_set_private_key", ret);
            }
        }
    }

    if ((ret == 1) && (sig == NULL)) {
        /* Only determining signature size this call. */
        len = wc_RsaEncryptSize(&rsa->key);
        if (len <= 0) {
            WOLFENGINE_ERROR_FUNC(WE_LOG_PK, "wc_SignatureGetSize", (int)len);
            ret = 0;
        }
        else {
            /* Return signature size in bytes. */
            *sigLen = len;
        }
    }

    if ((ret == 1) && (sig != NULL)) {
    #if OPENSSL_VERSION_NUMBER >= 0x10101000L
        if ((rsa->md != NULL) && (rsa->padMode == RSA_PKCS1_PADDING) &&
                                     ((size_t)EVP_MD_size(rsa->md) != tbsLen)) {
            WOLFENGINE_ERROR_MSG(WE_LOG_PK, "Digest length invalid");
            ret = -1;
        }
    #endif
        if ((ret == 1) && (rsa->md != NULL) &&
                                          (rsa->padMode == RSA_PKCS1_PADDING)) {
            /* In this case, OpenSSL expects a proper PKCS #1 v1.5
             * signature. */
            encodedDigestLen = we_der_encode_digest(rsa->md, tbs, tbsLen,
                                                    &encodedDigest);
            if (encodedDigestLen == 0) {
                WOLFENGINE_ERROR_FUNC(WE_LOG_PK, "we_der_encode_digest",
                                      encodedDigestLen);
                ret = 0;
            }
            else {
                /* Encoded digest is now the ToBeSigned data. */
                tbs = encodedDigest;
                tbsLen = encodedDigestLen;
            }
        }
        if (ret == 1) {
            /* Pad and private encrypt. */
            actualSigLen = we_rsa_priv_enc_int(tbsLen, tbs, *sigLen, sig, rsa);
            if (actualSigLen == -1) {
                WOLFENGINE_ERROR_FUNC(WE_LOG_PK, "we_rsa_priv_enc_int",
                                      actualSigLen);
                ret = 0;
            }
            else {
                /* Return length of signature generated. */
                *sigLen = actualSigLen;
            }
        }
    }

    if (encodedDigest != NULL) {
        OPENSSL_free(encodedDigest);
    }

    WOLFENGINE_LEAVE(WE_LOG_PK, "we_rsa_pkey_sign", ret);

    return ret;
}

/**
 * Verify data with a public RSA key.
 *
 * @param  ctx     [in]  Public key context of operation.
 * @param  sig     [in]  Signature data.
 * @param  sigLen  [in]  Length of signature data.
 * @param  tbs     [in]  To Be Signed data.
 * @param  tbsLen  [in]  Length of To Be Signed data.
 * @returns  1 on success and 0 on failure.
 */
static int we_rsa_pkey_verify(EVP_PKEY_CTX *ctx, const unsigned char *sig,
                         size_t sigLen, const unsigned char *tbs,
                         size_t tbsLen)
{
    int ret = 1;
    int rc = 0;
    we_Rsa *rsa = NULL;
    EVP_PKEY *pkey = NULL;
    RSA *rsaKey = NULL;
    unsigned char *decryptedSig = NULL;
    unsigned char *encodedDigest = NULL;
    int encodedDigestLen = 0;
    int keySize = 0;

    WOLFENGINE_ENTER(WE_LOG_PK, "we_rsa_pkey_verify");
    WOLFENGINE_MSG_VERBOSE(WE_LOG_PK, "ARGS [ctx = %p, sig = %p, sigLen = %zu, "
                           "tbs = %p, tbsLen = %zu]", ctx, sig, sigLen,
                           tbs, tbsLen);

    /* Get the internal RSA object. */
    rsa = (we_Rsa *)EVP_PKEY_CTX_get_data(ctx);
    if (rsa == NULL) {
        WOLFENGINE_ERROR_FUNC_NULL(WE_LOG_PK, "EVP_PKEY_CTX_get_data", rsa);
        ret = 0;
    }

    /* Set up public key */
    if ((ret == 1) && (!rsa->pubKeySet)) {
        /* OpenSSL RSA key in EVP PKEY associated with context. */
        pkey = EVP_PKEY_CTX_get0_pkey(ctx);
        if (pkey == NULL) {
            WOLFENGINE_ERROR_FUNC_NULL(WE_LOG_PK, "EVP_PKEY_CTX_get0_pkey",
                                       pkey);
            ret = 0;
        }
        if (ret == 1) {
            /* Get OpenSSL RSA key containing public key. */
            rsaKey = (RSA*)EVP_PKEY_get0_RSA(pkey);
            if (rsaKey == NULL) {
                WOLFENGINE_ERROR_FUNC_NULL(WE_LOG_PK, "EVP_PKEY_get0_RSA",
                                           rsaKey);
                ret = 0;
            }
        }
        if (ret == 1) {
            keySize = RSA_size(rsaKey) * 8;
            rc = we_check_rsa_key_size(keySize, 1);
            if (rc != 1) {
                WOLFENGINE_ERROR_FUNC(WE_LOG_PK, "we_check_rsa_key_size", rc);
                ret = 0;
            }
        }
        if (ret == 1) {
            /* Set the public key into the internal RSA key. */
            ret = we_rsa_set_public_key(rsaKey, rsa);
            if (ret == 0) {
                WOLFENGINE_ERROR_FUNC(WE_LOG_PK, "we_rsa_set_public_key", ret);
            }
        }
    }

    if (ret == 1) {
        /* Decrypted signature will same size or smaller than the signature. */
        decryptedSig = (unsigned char *)OPENSSL_malloc(sigLen);
        if (decryptedSig == NULL) {
            WOLFENGINE_ERROR_FUNC_NULL(WE_LOG_PK, "OPENSSL_malloc",
                                       decryptedSig);
            ret = 0;
        }
    }
    if ((ret == 1) && (rsa->md != NULL) &&
                                     (rsa->padMode == RSA_PKCS1_PADDING) &&
                                     ((size_t)EVP_MD_size(rsa->md) != tbsLen)) {
        WOLFENGINE_ERROR_MSG(WE_LOG_PK, "Digest length invalid");
        ret = -1;
    }

    if (ret == 1) {
        /* Unpad and public decrypt. */
        rc = we_rsa_pub_dec_int(sigLen, sig, sigLen, decryptedSig, rsa);
        if (rc == -1) {
            WOLFENGINE_ERROR_FUNC(WE_LOG_PK, "we_rsa_pub_dec_int", rc);
            ret = 0;
        }
    }

    if ((ret == 1) && (rsa->padMode == RSA_PKCS1_PSS_PADDING)) {
        /* Convert salt length into wolfCrypt value. */
        int wc_saltLen = we_pss_salt_len_to_wc(rsa->saltLen, rsa->md,
            &rsa->key, 0);
        /* Verify call in we_rsa_pub_dec_int only decrypts - this actually
           checks padding. */
        rc = wc_RsaPSS_CheckPadding_ex(tbs, (word32)tbsLen, decryptedSig, rc,
            we_nid_to_wc_hash_type(EVP_MD_type(rsa->md)), wc_saltLen, 0);
        if (rc != 0) {
            WOLFENGINE_ERROR_FUNC(WE_LOG_PK, "wc_RsaPSS_CheckPadding_ex", rc);
            ret = 0;
        }
    }
    else if (ret == 1) {
        if ((rsa->md != NULL) && (rsa->padMode == RSA_PKCS1_PADDING)) {
            /* In this case, we have a proper DER-encoded signature, not
             * just arbitrary signed data, so we must compare with the
             * encoded digest. */
            encodedDigestLen = we_der_encode_digest(rsa->md, tbs, tbsLen,
                                                    &encodedDigest);
            if (encodedDigestLen == 0) {
                WOLFENGINE_ERROR_FUNC(WE_LOG_PK, "we_der_encode_digest",
                                      encodedDigestLen);
                ret = 0;
            }
            else {
                /* Encoded digest is now the ToBeSigned data. */
                tbs = encodedDigest;
                tbsLen = encodedDigestLen;
            }
        }
        if ((ret == 1) && (tbsLen != (size_t)rc)) {
            WOLFENGINE_ERROR_MSG(WE_LOG_PK, "Encoding different size");
            ret = 0;
        }
        if (ret == 1) {
            /* Compare encoded with encoded to avoid parsing issues. */
            rc = XMEMCMP(tbs, decryptedSig, tbsLen);
            if (rc != 0) {
                WOLFENGINE_ERROR_FUNC(WE_LOG_PK, "XMEMCMP", rc);
                ret = 0;
            }
        }
    }

    /* Dispose of allocated data. */
    if (decryptedSig != NULL) {
        OPENSSL_free(decryptedSig);
    }
    if (encodedDigest != NULL) {
        OPENSSL_free(encodedDigest);
    }

    return ret;
}

/**
 * Encrypt data with a public RSA key.
 *
 * @param  ctx         [in]  Public key context of operation.
 * @param  ciphertext  [in]  Encrypted data.
 * @param  cipherLen   [in]  Length of encrypted data.
 * @param  plaintext   [in]  Data to be encrypted.
 * @param  plainLen    [in]  Length of data to be encrypted.
 * @returns  1 on success and 0 on failure.
 */
static int we_rsa_pkey_encrypt(EVP_PKEY_CTX *ctx, unsigned char *ciphertext,
    size_t *cipherLen, const unsigned char *plaintext, size_t plainLen)
{
    int ret = 1;
    int rc;
    we_Rsa *rsa = NULL;
    EVP_PKEY *pkey = NULL;
    RSA *rsaKey = NULL;
    int keySize = 0;

    WOLFENGINE_ENTER(WE_LOG_PK, "we_rsa_pkey_encrypt");
    WOLFENGINE_MSG_VERBOSE(WE_LOG_PK, "ARGS [ctx = %p, ciphertext = %p, "
                           "cipherLen = %p, plaintext = %p, plainLen = %zu]",
                           ctx, ciphertext, cipherLen, plaintext, plainLen);

    /* Get the internal RSA object. */
    rsa = (we_Rsa *)EVP_PKEY_CTX_get_data(ctx);
    if (rsa == NULL) {
        WOLFENGINE_ERROR_FUNC_NULL(WE_LOG_PK, "EVP_PKEY_CTX_get_data", rsa);
        ret = 0;
    }

    if (ret == 1) {
        /* Get the RSA PKEY. */
        pkey = EVP_PKEY_CTX_get0_pkey(ctx);
        if (pkey == NULL) {
            WOLFENGINE_ERROR_FUNC_NULL(WE_LOG_PK, "EVP_PKEY_CTX_get0_pkey",
                                       pkey);
            ret = 0;
        }
    }
    if (ret == 1) {
        /* Get the RSA key for size or setting internal RSA public key. */
        rsaKey = (RSA*)EVP_PKEY_get0_RSA(pkey);
        if (rsaKey == NULL) {
            WOLFENGINE_ERROR_FUNC_NULL(WE_LOG_PK, "EVP_PKEY_get0_RSA", rsaKey);
            ret = 0;
        }
    }
    if (ret == 1) {
        keySize = RSA_size(rsaKey) * 8;
        rc = we_check_rsa_key_size(keySize, 1);
        if (rc != 1) {
            WOLFENGINE_ERROR_FUNC(WE_LOG_PK, "we_check_rsa_key_size", rc);
            ret = 0;
        }
    }

    if ((ret == 1) && (ciphertext == NULL)) {
        /* Only return the length when no output buffer passed in. */
        *cipherLen = RSA_size(rsaKey);
    }
    else if (ret == 1) {
        /* Set up public key */
        if (!rsa->pubKeySet) {
            ret = we_rsa_set_public_key(rsaKey, rsa);
            if (ret == 0) {
                WOLFENGINE_ERROR_FUNC(WE_LOG_PK, "we_rsa_set_public_key", ret);
            }
        }

        if (ret == 1) {
            /* Perform encryption operation. */
            rc = we_rsa_pub_enc_int(plainLen, plaintext, *cipherLen, ciphertext,
                                    rsa);
            if (rc == -1) {
                WOLFENGINE_ERROR_FUNC(WE_LOG_PK, "we_rsa_pub_enc_int", rc);
                ret = 0;
            }
            else {
                /* Return actual encrypted size. */
                *cipherLen = rc;
            }
        }
    }

    WOLFENGINE_LEAVE(WE_LOG_PK, "we_rsa_pkey_encrypt", ret);

    return ret;
}

/**
 * Decrypt ciphertext with a private RSA key.
 *
 * @param  ctx         [in]      Private key context of operation.
 * @param  plaintext   [in]      Buffer to hold decrypted data.
 *                               NULL indicates length of signature requested.
 * @param  plainLen    [in/out]  Length of decrypted data.
 * @param  ciphertext  [in]      Data to be decrypted.
 * @param  cipherLen   [in]      Length of encrypted data.
 * @returns  1 on success and 0 on failure.
 */
static int we_rsa_pkey_decrypt(EVP_PKEY_CTX *ctx, unsigned char *plaintext,
    size_t *plainLen, const unsigned char *ciphertext, size_t cipherLen)
{
    int ret = 1;
    int rc = 0;
    we_Rsa *rsa = NULL;
    EVP_PKEY *pkey = NULL;
    RSA *rsaKey = NULL;
    int keySize = 0;

    WOLFENGINE_ENTER(WE_LOG_PK, "we_rsa_pkey_decrypt");
    WOLFENGINE_MSG_VERBOSE(WE_LOG_PK, "ctx = %p, plaintext = %p, "
                           "plainLen = %p, ciphertext = %p, cipherLen = %zu]",
                           ctx, plaintext, plainLen, ciphertext, cipherLen);

    /* Get the internal RSA object. */
    rsa = (we_Rsa *)EVP_PKEY_CTX_get_data(ctx);
    if (rsa == NULL) {
        WOLFENGINE_ERROR_FUNC_NULL(WE_LOG_PK, "EVP_PKEY_CTX_get_data", rsa);
        ret = 0;
    }

    if ((ret == 1) && (!rsa->privKeySet)) {
        /* Get the RSA PKEY. */
        pkey = EVP_PKEY_CTX_get0_pkey(ctx);
        if (pkey == NULL) {
            WOLFENGINE_ERROR_FUNC_NULL(WE_LOG_PK, "EVP_PKEY_CTX_get0_pkey",
                                       pkey);
            ret = 0;
        }
        if (ret == 1) {
            /* Get the RSA key for size or setting internal RSA private key. */
            rsaKey = (RSA*)EVP_PKEY_get0_RSA(pkey);
            if (rsaKey == NULL) {
                WOLFENGINE_ERROR_FUNC_NULL(WE_LOG_PK, "EVP_PKEY_get0_RSA",
                                           rsaKey);
                ret = 0;
            }
        }
        if (ret == 1) {
            keySize = RSA_size(rsaKey) * 8;
            rc = we_check_rsa_key_size(keySize, 1);
            if (rc != 1) {
                WOLFENGINE_ERROR_FUNC(WE_LOG_PK, "we_check_rsa_key_size", rc);
                ret = 0;
            }
        }
        if (ret == 1) {
            /* Set up private key */
            ret = we_rsa_set_private_key(rsaKey, rsa);
            if (ret == 0) {
                WOLFENGINE_ERROR_FUNC(WE_LOG_PK, "we_rsa_set_private_key", ret);
            }
        }
    }

#ifdef WC_RSA_BLINDING
    /* Always need RNG. */
    if (ret == 1) {
    #ifndef WE_SINGLE_THREADED
        rc = wc_RsaSetRNG(&rsa->key, &rsa->rng);
    #else
        rc = wc_RsaSetRNG(&rsa->key, we_rng);
    #endif
        if (rc != 0) {
            WOLFENGINE_ERROR_FUNC(WE_LOG_PK, "wc_RsaSetRNG", rc);
            ret = 0;
        }
    }
#endif

    if (ret == 1) {
        /* Perform decryption operation. */
        rc = we_rsa_priv_dec_int(cipherLen, ciphertext, *plainLen, plaintext,
                                 rsa);
        if (rc == -1) {
            WOLFENGINE_ERROR_FUNC(WE_LOG_PK, "we_rsa_priv_dec_int", rc);
            ret = 0;
        }
        else {
            /* Return the plaintext length. */
            *plainLen = rc;
        }
    }

    WOLFENGINE_LEAVE(WE_LOG_PK, "we_rsa_pkey_decrypt", ret);

    return ret;
}

/**
 * Initialize the RSA method for use with the EVP_PKEY API.
 *
 * @return  1 on success and 0 on failure.
 */
int we_init_rsa_pkey_meth(void)
{
    int ret = 1;

    /* Create a new method object. */
    we_rsa_pkey_method = EVP_PKEY_meth_new(EVP_PKEY_RSA, 0);
    if (we_rsa_pkey_method == NULL) {
        WOLFENGINE_ERROR_FUNC_NULL(WE_LOG_PK, "EVP_PKEY_meth_new",
                                   we_rsa_pkey_method);
        ret = 0;
    }

    if (ret == 1) {
        /* Set the implementations using public APIs. */
        EVP_PKEY_meth_set_init(we_rsa_pkey_method, we_rsa_pkey_init);
        EVP_PKEY_meth_set_sign(we_rsa_pkey_method, NULL, we_rsa_pkey_sign);
        EVP_PKEY_meth_set_verify(we_rsa_pkey_method, NULL, we_rsa_pkey_verify);
        EVP_PKEY_meth_set_encrypt(we_rsa_pkey_method, NULL,
                                  we_rsa_pkey_encrypt);
        EVP_PKEY_meth_set_decrypt(we_rsa_pkey_method, NULL,
                                  we_rsa_pkey_decrypt);
        EVP_PKEY_meth_set_cleanup(we_rsa_pkey_method, we_rsa_pkey_cleanup);
        EVP_PKEY_meth_set_ctrl(we_rsa_pkey_method, we_rsa_pkey_ctrl,
                               we_rsa_pkey_ctrl_str);
        EVP_PKEY_meth_set_copy(we_rsa_pkey_method, we_rsa_pkey_copy);
        EVP_PKEY_meth_set_keygen(we_rsa_pkey_method, NULL, we_rsa_pkey_keygen);
    }
    /* No failures to cause method to be be invalid. */

    return ret;
}

#endif /* WE_HAVE_EVP_PKEY */

#endif /* WE_HAVE_RSA */
