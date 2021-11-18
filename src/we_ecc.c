/* we_ecc.c
 *
 * Copyright (C) 2019-2021 wolfSSL Inc.
 *
 * This file is part of wolfengine.
 *
 * wolfengine is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
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
#include <wolfengine/we_wolfengine.h>

#ifdef WE_HAVE_ECC

/*
 * Macros
 * ------
 * WE_ECC_USE_GLOBAL_RNG:
 *     Use the global wolfEngine RNG when an RNG is needed, as opposed to a
 *     local one.
 */

/**
 * Check that the curve is allowed. For FIPS, P-192 isn't allowed for ECDH, key
 * gen or signing, only verifying.
 *
 * @param  curveId  [in]  The wolfSSL curve ID.
 * @returns  1 if the curve is allowed, 0 if it isn't.
 */
static int we_ecc_check_curve_usage(int curveId) {
    int ret = 1;

    (void) curveId;

    WOLFENGINE_ENTER(WE_LOG_PK, "we_ecc_check_curve_usage");

    if ((wolfEngine_GetFipsChecks() & WE_FIPS_CHECK_P192) &&
        (curveId == ECC_SECP192R1)) {
        ret = 0;
        WOLFENGINE_ERROR_MSG(WE_LOG_PK, "P-192 isn't allowed in FIPS mode.");
    }

    WOLFENGINE_LEAVE(WE_LOG_PK, "we_ecc_check_curve_usage", ret);

    return ret;
}

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
    char errBuff[WOLFENGINE_MAX_LOG_WIDTH];

    WOLFENGINE_ENTER(WE_LOG_PK, "we_ec_get_curve_id");
    WOLFENGINE_MSG_VERBOSE(WE_LOG_PK, "ARGS [curveName = %d, curveId = %p]",
                           curveName, curveId);

    switch (curveName) {
#ifdef WE_HAVE_EC_P192
        case NID_X9_62_prime192v1:
            WOLFENGINE_MSG(WE_LOG_PK, "Set P-192");
            *curveId = ECC_SECP192R1;
            break;
#endif
#ifdef WE_HAVE_EC_P224
        case NID_secp224r1:
            WOLFENGINE_MSG(WE_LOG_PK, "Set P-224");
            *curveId = ECC_SECP224R1;
            break;
#endif
#ifdef WE_HAVE_EC_P256
        case NID_X9_62_prime256v1:
            WOLFENGINE_MSG(WE_LOG_PK, "Set P-256");
            *curveId = ECC_SECP256R1;
            break;
#endif
#ifdef WE_HAVE_EC_P384
        case NID_secp384r1:
            WOLFENGINE_MSG(WE_LOG_PK, "Set P-384");
            *curveId = ECC_SECP384R1;
            break;
#endif
#ifdef WE_HAVE_EC_P521
        case NID_secp521r1:
            WOLFENGINE_MSG(WE_LOG_PK, "Set P-521");
            *curveId = ECC_SECP521R1;
            break;
#endif
        default:
            XSNPRINTF(errBuff, sizeof(errBuff), "Unsupported ECC curve name: "
                      "%d.", curveName);
            WOLFENGINE_ERROR_MSG(WE_LOG_PK, errBuff);
            ret = 0;
            break;
    }

    WOLFENGINE_LEAVE(WE_LOG_PK, "we_ec_get_curve_id", ret);

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
    int ret = 1, rc;
    size_t privLen = 0;
    unsigned char* privBuf = NULL;

    WOLFENGINE_ENTER(WE_LOG_PK, "we_ec_set_private");
    WOLFENGINE_MSG_VERBOSE(WE_LOG_PK, "ARGS [key = %p, curveId = %p, "
                           "ecKey = %p]", key, curveId, ecKey);

    /* Get the EC key private key as binary data. */
    privLen = EC_KEY_priv2buf(ecKey, &privBuf);
    if (privLen <= 0) {
        WOLFENGINE_ERROR_FUNC(WE_LOG_PK, "EC_KEY_priv2buf", (int)privLen);
        ret = 0;
    }
    /* Import private key. */
    if (ret == 1) {
        WOLFENGINE_MSG(WE_LOG_PK, "Importing EC private key into ecc_key");
        rc = wc_ecc_import_private_key_ex(privBuf, (word32)privLen, NULL, 0,
                                          key, curveId);
        if (rc != 0) {
            WOLFENGINE_ERROR_FUNC(WE_LOG_PK,
                                  "wc_ecc_import_private_key_ex", rc);
            ret = 0;
        }
    }

    if (privLen > 0) {
        /* Zeroize and free private key data. */
        OPENSSL_clear_free(privBuf, privLen);
    }

    WOLFENGINE_LEAVE(WE_LOG_PK, "we_ec_set_private", ret);

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
    int ret = 1, rc;
    size_t pubLen;
    unsigned char* pubBuf = NULL;
    unsigned char* x;
    unsigned char* y;

    WOLFENGINE_ENTER(WE_LOG_PK, "we_ec_set_public");
    WOLFENGINE_MSG_VERBOSE(WE_LOG_PK, "ARGS [key = %p, curveId = %d, "
                           "ecKey = %p]", key, curveId, ecKey);

    /* Get the EC key public key as and uncompressed point. */
    pubLen = EC_KEY_key2buf(ecKey, POINT_CONVERSION_UNCOMPRESSED, &pubBuf,
                            NULL);
    if (pubLen <= 0) {
        WOLFENGINE_ERROR_FUNC(WE_LOG_PK, "EC_KEY_key2buf", (int)pubLen);
        ret = 0;
    }

    /* Import public key. */
    if (ret == 1) {
        WOLFENGINE_MSG(WE_LOG_PK, "Importing public key into ecc_key");
        /* 0x04, x, y - x and y are equal length. */
        x = pubBuf + 1;
        y = x + ((pubLen - 1) / 2);
        rc = wc_ecc_import_unsigned(key, x, y, NULL, curveId);
        if (rc != 0) {
            WOLFENGINE_ERROR_FUNC(WE_LOG_PK, "wc_ecc_import_unsigned", rc);
            ret = 0;
        }
    }

    OPENSSL_free(pubBuf);

    WOLFENGINE_LEAVE(WE_LOG_PK, "we_ec_set_public", ret);

    return ret;
}

/**
 * Export the key from the wolfSSL EC key object into OpenSSL EC_KEY object.
 *
 * @param  ecc  [in]      wolfSSL ECC Key.
 * @param  len  [in]      Length of modulus.
 * @param  key  [in/out]  OpenSSL EC_KEY oject.
 * @returns  1 on success and 0 no failure.
 */
static int we_ec_export_key(ecc_key *ecc, int len, EC_KEY *key)
{
    int ret, rc;
    unsigned char *buf = NULL;
    unsigned char *d = NULL;

    WOLFENGINE_ENTER(WE_LOG_PK, "we_ec_export_key");

    /* Allocate buffer to hold private and public key data. */
    ret = (buf = (unsigned char *)OPENSSL_malloc(len * 3 + 1)) != NULL;
    if (ret == 1) {
        unsigned char *x = buf + 1;
        unsigned char *y = x + len;
        word32 xLen = len;
        word32 yLen = len;
        word32 dLen = len;

        d = y + len;
        /* Export public and private key data. */
        rc = wc_ecc_export_private_raw(ecc, x, &xLen, y, &yLen, d, &dLen);
        if (rc != 0) {
            WOLFENGINE_ERROR_FUNC(WE_LOG_PK, "wc_ecc_export_private", rc);
            ret = 0;
        }
    }
    if (ret == 1) {
        /* Import public key. */
        buf[0] = ECC_POINT_UNCOMP;
        ret = EC_KEY_oct2key(key, buf, len * 2 + 1, NULL);
        if (ret == 0) {
            WOLFENGINE_ERROR_FUNC(WE_LOG_PK, "EC_KEY_oct2key", ret);
        }
    }
    if (ret == 1) {
        /* Import private key. */
        ret = EC_KEY_oct2priv(key, d, len);
        if (ret == 0) {
            WOLFENGINE_ERROR_FUNC(WE_LOG_PK, "EC_KEY_oct2priv", ret);
        }
    }

    if (buf != NULL) {
        OPENSSL_clear_free(buf, len * 3 + 1);
    }

    WOLFENGINE_LEAVE(WE_LOG_PK, "we_ec_export_key", ret);

    return ret;
}

#ifdef WE_HAVE_EVP_PKEY
/**
 * Data required to complete an ECC operation.
 */
typedef struct we_Ecc
{
    /** wolfSSL ECC key structure to hold private/public key. */
    ecc_key        key;
#ifndef WE_ECC_USE_GLOBAL_RNG
    /** wolfSSL random number generator. */
    WC_RNG         rng;
#endif
    /** wolfSSL curve id for key. */
    int            curveId;
    /** OpenSSL curve name */
    int            curveName;
#ifdef WE_HAVE_ECDSA
    /** Digest method - stored but not used. */
    EVP_MD        *md;
#endif
#ifdef WE_HAVE_ECDH
    /** Peer's public key encoded in binary - uncompressed. */
    unsigned char *peerKey;
    /** Length of peer's encoded public key. */
    int            peerKeyLen;
#endif
#ifdef WE_HAVE_ECKEYGEN
    /** OpenSSL group indicating EC parameters. */
    EC_GROUP      *group;
#endif
    /** Indicates private key has been set into wolfSSL structure. */
    int            privKeySet:1;
    /** Indicates public key has been set into wolfSSL structure. */
    int            pubKeySet:1;
#ifdef WE_HAVE_ECDH
    /** Use co-factor with ECDH operation. */
    int            coFactor:1;
    /** Type of KDF to use with ECDH derivation. */
    int            kdfType;
    /** Digest method to use with KDF. */
    const EVP_MD  *kdfMd;
    /** Output length of KDF. */
    int            kdfOutLen;
    /** KDF UKM. */
    unsigned char *kdfUkm;
    /** Length of KDF UKN. */
    int            kdfUkmLen;
#endif
} we_Ecc;

/**
 * Initialize and set the data required to complete an EC operation.
 *
 * @param  ctx  [in]  Public key context of operation.
 * @returns  1 on success and 0 on failure.
 */
static int we_ec_init(EVP_PKEY_CTX *ctx)
{
    int ret, rc;
    we_Ecc *ecc;
    int keyInited = 0;

    WOLFENGINE_ENTER(WE_LOG_PK, "we_ec_init");
    WOLFENGINE_MSG_VERBOSE(WE_LOG_PK, "ARGS [ctx = %p]", ctx);

    /* Allocate a new internal EC object. */
    ret = (ecc = (we_Ecc*)OPENSSL_zalloc(sizeof(we_Ecc))) != NULL;
    if (ret == 1) {
        /* Initialize the wolfSSL key object. */
        WOLFENGINE_MSG(WE_LOG_PK, "Initializing wolfCrypt ecc_key "
                       "structure: %p", &ecc->key);
#ifdef WE_HAVE_ECDH
        ecc->kdfType = EVP_PKEY_ECDH_KDF_NONE;
#endif

        rc = wc_ecc_init(&ecc->key);
        if (rc == 0) {
            keyInited = 1;
        }
        else {
            WOLFENGINE_ERROR_FUNC(WE_LOG_PK, "wc_ecc_init", rc);
            ret = 0;
        }
    }
#ifndef WE_ECC_USE_GLOBAL_RNG
    if (ret == 1) {
        rc = wc_InitRng(&ecc->rng);
        if (rc != 0) {
            ret = 0;
        }
    }
#endif
#if !defined(HAVE_FIPS) || \
    (defined(HAVE_FIPS_VERSION) && HAVE_FIPS_VERSION != 2)
    if (ret == 1) {
        /* Set the random number generator for use in EC operations. */
#ifndef WE_ECC_USE_GLOBAL_RNG
        rc = wc_ecc_set_rng(&ecc->key, &ecc->rng);
#else
        rc = wc_ecc_set_rng(&ecc->key, we_rng);
#endif
        if (rc != 0) {
            WOLFENGINE_ERROR_FUNC(WE_LOG_PK, "wc_ecc_set_rng", rc);
            ret = 0;
        }
    }
#endif /* !HAVE_FIPS || (HAVE_FIPS_VERSION && HAVE_FIPS_VERSION != 2) */
    if (ret == 1) {
        /* Set this key object to be returned when performing operations. */
        EVP_PKEY_CTX_set_data(ctx, ecc);
    }

    if (ret == 0 && ecc != NULL) {
#ifndef WE_ECC_USE_GLOBAL_RNG
        wc_FreeRng(&ecc->rng);
#endif
        /* Make sure wolfSSL EC key is freed if initialized. */
        if (keyInited) {
            wc_ecc_free(&ecc->key);
        }
        /* Failed - free allocated data. */
        OPENSSL_free(ecc);
    }

    WOLFENGINE_LEAVE(WE_LOG_PK, "we_ec_init", ret);

    return ret;
}

#ifdef WE_HAVE_ECKEYGEN

#ifdef WE_HAVE_EC_P192
/**
 * Initialize and set the data required to complete an EC P-192 operation.
 *
 * @param  ctx  [in]  Public key context of operation.
 * @returns  1 on success and 0 on failure.
 */
static int we_ec_p192_init(EVP_PKEY_CTX *ctx)
{
    int ret;
    we_Ecc *ecc;

    WOLFENGINE_ENTER(WE_LOG_PK, "we_ec_p192_init");
    WOLFENGINE_MSG_VERBOSE(WE_LOG_PK, "ARGS [ctx = %p]", ctx);

    /* Create the internal EC object in context. */
    ret = we_ec_init(ctx);
    if (ret == 1) {
        /* Get the internal EC object. */
        ecc = (we_Ecc *)EVP_PKEY_CTX_get_data(ctx);
        /* Setup P-192 curve. */
        ecc->curveId = ECC_SECP192R1;
        ecc->curveName = NID_X9_62_prime192v1;
        ecc->group = EC_GROUP_new_by_curve_name(ecc->curveName);
        if (ecc->group == NULL) {
            /* Failed - free allocated data. */
            WOLFENGINE_ERROR_FUNC_NULL(WE_LOG_PK, "EC_GROUP_new_by_curve_name",
                                       ecc->group);
        #ifndef WE_ECC_USE_GLOBAL_RNG
            wc_FreeRng(&ecc->rng);
        #endif
            wc_ecc_free(&ecc->key);
            OPENSSL_free(ecc);
            ret = 0;
        }
    }

    WOLFENGINE_LEAVE(WE_LOG_PK, "we_ec_p192_init", ret);

    return ret;
}
#endif
#ifdef WE_HAVE_EC_P224
/**
 * Initialize and set the data required to complete an EC P-224 operation.
 *
 * @param  ctx  [in]  Public key context of operation.
 * @returns  1 on success and 0 on failure.
 */
static int we_ec_p224_init(EVP_PKEY_CTX *ctx)
{
    int ret;
    we_Ecc *ecc;

    WOLFENGINE_ENTER(WE_LOG_PK, "we_ec_p224_init");
    WOLFENGINE_MSG_VERBOSE(WE_LOG_PK, "ARGS [ctx = %p]", ctx);

    /* Create the internal EC object in context. */
    ret = we_ec_init(ctx);
    if (ret == 1) {
        /* Get the internal EC object. */
        ecc = (we_Ecc *)EVP_PKEY_CTX_get_data(ctx);
        /* Setup P-224 curve. */
        ecc->curveId = ECC_SECP224R1;
        ecc->curveName = NID_secp224r1;
        ecc->group = EC_GROUP_new_by_curve_name(ecc->curveName);
        if (ecc->group == NULL) {
            /* Failed - free allocated data. */
            WOLFENGINE_ERROR_FUNC_NULL(WE_LOG_PK, "EC_GROUP_new_by_curve_name",
                                       ecc->group);
        #ifndef WE_ECC_USE_GLOBAL_RNG
            wc_FreeRng(&ecc->rng);
        #endif
            wc_ecc_free(&ecc->key);
            OPENSSL_free(ecc);
            ret = 0;
        }
    }

    WOLFENGINE_LEAVE(WE_LOG_PK, "we_ec_p224_init", ret);

    return ret;
}
#endif

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

    WOLFENGINE_ENTER(WE_LOG_PK, "we_ec_p256_init");
    WOLFENGINE_MSG_VERBOSE(WE_LOG_PK, "ARGS [ctx = %p]", ctx);

    /* Create the internal EC object in context. */
    ret = we_ec_init(ctx);
    if (ret == 1) {
        /* Get the internal EC object. */
        ecc = (we_Ecc *)EVP_PKEY_CTX_get_data(ctx);
        /* Setup P-256 curve. */
        ecc->curveId = ECC_SECP256R1;
        ecc->curveName = NID_X9_62_prime256v1;
        ecc->group = EC_GROUP_new_by_curve_name(ecc->curveName);
        if (ecc->group == NULL) {
            /* Failed - free allocated data. */
            WOLFENGINE_ERROR_FUNC_NULL(WE_LOG_PK, "EC_GROUP_new_by_curve_name",
                                       ecc->group);
        #ifndef WE_ECC_USE_GLOBAL_RNG
            wc_FreeRng(&ecc->rng);
        #endif
            wc_ecc_free(&ecc->key);
            OPENSSL_free(ecc);
            ret = 0;
        }
    }

    WOLFENGINE_LEAVE(WE_LOG_PK, "we_ec_p256_init", ret);

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

    WOLFENGINE_ENTER(WE_LOG_PK, "we_ec_p384_init");
    WOLFENGINE_MSG_VERBOSE(WE_LOG_PK, "ARGS [ctx = %p]", ctx);

    /* Create the internal EC object in context. */
    ret = we_ec_init(ctx);
    if (ret == 1) {
        /* Get the internal EC object. */
        ecc = (we_Ecc *)EVP_PKEY_CTX_get_data(ctx);
        /* Setup P-384 curve. */
        ecc->curveId = ECC_SECP384R1;
        ecc->curveName = NID_secp384r1;
        ecc->group = EC_GROUP_new_by_curve_name(ecc->curveName);
        if (ecc->group == NULL) {
            /* Failed - free allocated data. */
            WOLFENGINE_ERROR_FUNC_NULL(WE_LOG_PK, "EC_GROUP_new_by_curve_name",
                                       ecc->group);
        #ifndef WE_ECC_USE_GLOBAL_RNG
            wc_FreeRng(&ecc->rng);
        #endif
            wc_ecc_free(&ecc->key);
            OPENSSL_free(ecc);
            ret = 0;
        }
    }

    WOLFENGINE_LEAVE(WE_LOG_PK, "we_ec_p384_init", ret);

    return ret;
}

#endif

#ifdef WE_HAVE_EC_P521
/**
 * Initialize and set the data required to complete an EC P-521 operations.
 *
 * @param  ctx  [in]  Public key context of operation.
 * @returns  1 on success and 0 on failure.
 */
static int we_ec_p521_init(EVP_PKEY_CTX *ctx)
{
    int ret;
    we_Ecc *ecc;

    WOLFENGINE_ENTER(WE_LOG_PK, "we_ec_p521_init");
    WOLFENGINE_MSG_VERBOSE(WE_LOG_PK, "ARGS [ctx = %p]", ctx);

    /* Create the internal EC object in context. */
    ret = we_ec_init(ctx);
    if (ret == 1) {
        /* Get the internal EC object. */
        ecc = (we_Ecc *)EVP_PKEY_CTX_get_data(ctx);
        /* Setup P-521 curve. */
        ecc->curveId = ECC_SECP521R1;
        ecc->curveName = NID_secp521r1;
        ecc->group = EC_GROUP_new_by_curve_name(ecc->curveName);
        if (ecc->group == NULL) {
            /* Failed - free allocated data. */
            WOLFENGINE_ERROR_FUNC_NULL(WE_LOG_PK, "EC_GROUP_new_by_curve_name",
                                       ecc->group);
        #ifndef WE_ECC_USE_GLOBAL_RNG
            wc_FreeRng(&ecc->rng);
        #endif
            wc_ecc_free(&ecc->key);
            OPENSSL_free(ecc);
            ret = 0;
        }
    }

    WOLFENGINE_LEAVE(WE_LOG_PK, "we_ec_p521_init", ret);

    return ret;
}

#endif
#endif

/**
 * Copy the EVP public key method from/to EVP public key contexts.
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
    WOLFENGINE_ENTER(WE_LOG_PK, "we_ec_copy");

    /* Nothing to copy as src is empty. */
    (void)src;
    (void)dst;

    WOLFENGINE_LEAVE(WE_LOG_PK, "we_ec_copy", 1);

    return 1;
}

/**
 * Clean up the ECC operation data.
 *
 * @param  ctx  [in]  Public key context of operation.
 */
static void we_ec_cleanup(EVP_PKEY_CTX *ctx)
{
    we_Ecc *ecc;

    WOLFENGINE_ENTER(WE_LOG_PK, "we_ec_cleanup");
    WOLFENGINE_MSG_VERBOSE(WE_LOG_PK, "ARGS [ctx = %p]", ctx);

    ecc = (we_Ecc *)EVP_PKEY_CTX_get_data(ctx);
    if (ecc != NULL) {
#ifdef WE_HAVE_ECKEYGEN
        EC_GROUP_free(ecc->group);
        ecc->group = NULL;
#endif
#ifdef WE_HAVE_ECDH
        OPENSSL_free(ecc->peerKey);
        ecc->peerKey = NULL;
#endif
#ifndef WE_ECC_USE_GLOBAL_RNG
        wc_FreeRng(&ecc->rng);
#endif
        wc_ecc_free(&ecc->key);
        OPENSSL_free(ecc);
        EVP_PKEY_CTX_set_data(ctx, NULL);
    }

    WOLFENGINE_LEAVE(WE_LOG_PK, "we_ec_cleanup", 1);
}

#if defined(WE_HAVE_ECDSA) || defined(WE_HAVE_ECDH)
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

    WOLFENGINE_ENTER(WE_LOG_PK, "we_ec_get_ec_key");
    WOLFENGINE_MSG_VERBOSE(WE_LOG_PK, "ARGS [ctx = %p, ecKey = %p, ecc = %p]",
                           ctx, ecKey, ecc);

    /* Get the EVP_PKEY object performing operation with. */
    ret = (pkey = EVP_PKEY_CTX_get0_pkey(ctx)) != NULL;
    if (ret == 1) {
        /* Get the EC_KEY object performing operation with. */
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
        ret = (*ecKey = (EC_KEY*)EVP_PKEY_get0_EC_KEY(pkey)) != NULL;
#else
        ret = (*ecKey = EVP_PKEY_get0_EC_KEY(pkey)) != NULL;
#endif
    }
    if (ret == 1) {
        /* Retrieve group parameters to setup curve in wolfSSL object. */
        group = EC_KEY_get0_group(*ecKey);
        if (group == NULL) {
            WOLFENGINE_ERROR_FUNC_NULL(WE_LOG_PK, "EC_KEY_get0_group",
                                       (EC_GROUP*)group);
            ret = 0;
        }
    }
    if (ret == 1) {
        /* Set the curve id into internal EC key object. */
        ret = we_ec_get_curve_id(EC_GROUP_get_curve_name(group),
                                  &ecc->curveId);
    }

    WOLFENGINE_LEAVE(WE_LOG_PK, "we_ec_get_ec_key", ret);

    return ret;
}
#endif

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
static int we_pkey_ecdsa_sign(EVP_PKEY_CTX *ctx, unsigned char *sig, size_t *sigLen,
                         const unsigned char *tbs, size_t tbsLen)
{
    int ret, rc;
    word32 outLen;
    we_Ecc *ecc;
    EC_KEY *ecKey = NULL;

    WOLFENGINE_ENTER(WE_LOG_PK, "we_ecdsa_sign");
    WOLFENGINE_MSG_VERBOSE(WE_LOG_PK, "ARGS [ctx = %p, sig = %p, sigLen = %p, "
                           "tbs = %p, tbsLen = %zu]", ctx, sig, sigLen,
                           tbs, tbsLen);

    /* Get the internal EC key object. */
    ret = (ecc = (we_Ecc *)EVP_PKEY_CTX_get_data(ctx)) != NULL;
    if (ret == 1 && !ecc->privKeySet) {
        /* Get the OpenSSL EC_KEY object and set curve id. */
        ret = we_ec_get_ec_key(ctx, &ecKey, ecc);
        if (ret == 1) {
            /* Set private key in wolfSSL object. */
            ret = we_ec_set_private(&ecc->key, ecc->curveId, ecKey);
        }
        if (ret == 1) {
            /* Only do this once as private will not change. */
            ecc->privKeySet = 1;
        }
    }

    if (ret == 1 && (rc = we_ecc_check_curve_usage(ecc->curveId)) != 1) {
        WOLFENGINE_ERROR_FUNC(WE_LOG_PK, "we_ecc_check_curve_usage", rc);
        ret = 0;
    }

    if (ret == 1 && sig == NULL) {
        /* Return signature size in bytes. */
        *sigLen = wc_ecc_sig_size(&ecc->key);
        WOLFENGINE_MSG(WE_LOG_PK, "sig is NULL, returning size: %zu", *sigLen);
    }
    if (ret == 1 && sig != NULL) {
        /* Sign the data with wolfSSL EC key object. */
        outLen = (word32)*sigLen;
#ifndef WE_ECC_USE_GLOBAL_RNG
        rc = wc_ecc_sign_hash(tbs, (word32)tbsLen, sig, &outLen, &ecc->rng,
                              &ecc->key);
#else
#ifndef WE_SINGLE_THREADED
        rc = wc_LockMutex(we_rng_mutex);
        if (rc != 0) {
            WOLFENGINE_ERROR_FUNC(WE_LOG_PK, "wc_LockMutex", rc);
            ret = 0;
        }
        else
#endif /* !WE_SINGLE_THREADED */
        {
            rc = wc_ecc_sign_hash(tbs, (word32)tbsLen, sig, &outLen, we_rng,
                                  &ecc->key);
        #ifndef WE_SINGLE_THREADED
            wc_UnLockMutex(we_rng_mutex);
        #endif
        }
#endif /* !WE_ECC_USE_GLOBAL_RNG */
        if (ret == 1 && rc != 0) {
            WOLFENGINE_ERROR_FUNC(WE_LOG_PK, "wc_ecc_sign_hash", rc);
            ret = 0;
        }
        if (ret == 1) {
            WOLFENGINE_MSG_VERBOSE(WE_LOG_PK, "Signature generated:");
            WOLFENGINE_BUFFER(WE_LOG_PK, sig, outLen);
            /* Return actual size. */
            *sigLen = outLen;
        }
    }

    WOLFENGINE_LEAVE(WE_LOG_PK, "we_ecdsa_sign", ret);

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
static int we_pkey_ecdsa_verify(EVP_PKEY_CTX *ctx, const unsigned char *sig,
                           size_t sigLen, const unsigned char *tbs,
                           size_t tbsLen)
{
    int ret, rc;
    we_Ecc *ecc;
    EC_KEY *ecKey = NULL;
    int res;

    WOLFENGINE_ENTER(WE_LOG_PK, "we_ecdsa_verify");
    WOLFENGINE_MSG_VERBOSE(WE_LOG_PK, "ARGS [ctx = %p, sig = %p, sigLen = %zu, "
                           "tbs = %p, tbsLen = %zu]", ctx, sig, sigLen,
                           tbs, tbsLen);

    /* Get the internal EC key object. */
    ret = (ecc = (we_Ecc *)EVP_PKEY_CTX_get_data(ctx)) != NULL;
    if (ret == 1 && !ecc->pubKeySet) {
        /* Get the OpenSSL EC_KEY object and set curve id. */
        ret = we_ec_get_ec_key(ctx, &ecKey, ecc);
        if (ret == 1) {
            /* Set the public key into the wolfSSL object. */
            ret = we_ec_set_public(&ecc->key, ecc->curveId, ecKey);
        }
        if (ret == 1) {
            /* Only do this once as public will not change. */
            ecc->pubKeySet = 1;
        }
    }
    /* wolfSSL FIPS is not checking SEQUENCE length. */
    if ((ret == 1) && (sig[0] == 0x30)) {
        size_t len;
        int o = 1;

        /* Check for indefinite length - length not specified. */
        if (sig[o] == 0x80) {
            WOLFENGINE_ERROR_MSG(WE_LOG_PK, "Signature has indefinite length");
            ret = 0;
        }
        /* Check for multi-byte length. */
        else if (sig[o] > 0x80) {
            byte cnt = (sig[o++]) & 0x7f;
            len = 0;
            while ((cnt--) > 0) {
                len <<= 8;
                len += sig[o++];
            }
        }
        /* Length in byte. */
        else {
            len = sig[o++];
        }
        /* Check signature length is:
         *     SEQUENCE header length + SQUENCE data length */
        if ((ret == 1) && (o + len != sigLen)) {
            WOLFENGINE_ERROR_MSG(WE_LOG_PK, "Signature length invalid");
            ret = 0;
        }
    }
    if (ret == 1) {
        /* Verify the signature with the data using wolfSSL. */
        rc = wc_ecc_verify_hash(sig, (word32)sigLen, tbs, (word32)tbsLen, &res,
                                &ecc->key);
        if (rc != 0) {
            WOLFENGINE_ERROR_FUNC(WE_LOG_PK, "wc_ecc_verify_hash", rc);
            ret = 0;
        }
    }
    if (ret == 1) {
        /* Verification result is 1 on success and 0 on failure. */
        ret = res;

        if (ret == 1) {
            WOLFENGINE_MSG(WE_LOG_PK, "Verified ECDSA signature");
        }
        else {
            WOLFENGINE_MSG(WE_LOG_PK, "Failed to verify ECDSA signature");
        }
    }

    WOLFENGINE_LEAVE(WE_LOG_PK, "we_ecdsa_verify", ret);

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
    int ret = 1, rc;
    we_Ecc *ecc;
    EC_KEY *ecKey = NULL;
    EVP_PKEY *ctxPkey;
    int len = 0;

    WOLFENGINE_ENTER(WE_LOG_PK, "we_ec_keygen");
    WOLFENGINE_MSG_VERBOSE(WE_LOG_PK, "ARGS [ctx = %p, pkey = %p]",
                           ctx, pkey);

    /* Get the internal EC key object. */
    ret = (ecc = (we_Ecc *)EVP_PKEY_CTX_get_data(ctx)) != NULL;
    if (ret == 1) {
        ctxPkey = EVP_PKEY_CTX_get0_pkey(ctx);
        if (ecc->group == NULL) {
            /* If both the group stored and the pkey is null then the curve
             * group is unknown */
            if (ctxPkey == NULL) {
                WOLFENGINE_ERROR_MSG(WE_LOG_PK, "Keygen with no group set");
                ret = 0;

            }
        }
    }

    if (ret == 1 && ecc->group == NULL) {
        const EC_GROUP *group;
        EC_KEY *tmp;

        /* set group from the ctx pkey */
        tmp = EVP_PKEY_get0_EC_KEY(ctxPkey);
        if (tmp == NULL) {
            WOLFENGINE_ERROR_FUNC_NULL(WE_LOG_PK, "EVP_PKEY_get0_EC_KEY", tmp);
            ret = 0;
        }

        if (ret == 1) {
            group = EC_KEY_get0_group(tmp);
            if (group == NULL) {
                WOLFENGINE_ERROR_FUNC_NULL(WE_LOG_PK, "EC_KEY_get0_group",
                        group);
                ret = 0;
            }
        }

        if (ret == 1) {
            ecc->group = EC_GROUP_dup(group);
            if (ecc->group == NULL) {
                WOLFENGINE_ERROR_FUNC_NULL(WE_LOG_PK, "EC_GROUP_dup",
                        ecc->group);
                ret = 0;
            }
        }

        if (ret == 1) {
            ret = we_ec_get_curve_id(EC_GROUP_get_curve_name(group),
                             &ecc->curveId);
            if (ret != 1) {
                WOLFENGINE_ERROR_FUNC(WE_LOG_PK, "wc_ecc_get_curve_id", ret);
            }
        }
    }

    if (ret == 1) {
        ret = we_ecc_check_curve_usage(ecc->curveId);
        if (ret != 1) {
            WOLFENGINE_ERROR_FUNC(WE_LOG_PK, "we_ecc_check_curve_usage", ret);
        }
    }

    if (ret == 1) {
        len = wc_ecc_get_curve_size_from_id(ecc->curveId);
        if (len < 0) {
            WOLFENGINE_ERROR_FUNC(WE_LOG_PK,
                                  "wc_ecc_get_curve_size_from_id", len);
        }

        /* New OpenSSL EC_KEY object to hold new key. */
        ret = (ecKey = EC_KEY_new()) != NULL;
    }

    if (ret == 1) {
        /* EVP_PKEY object needs an EC_KEY object. */
        ret = EVP_PKEY_assign_EC_KEY(pkey, ecKey);
        if (ret == 0) {
            WOLFENGINE_ERROR_FUNC(WE_LOG_PK, "EVP_PKEY_assign_EC_KEY", ret);
            EC_KEY_free(ecKey);
        }
    }

    if (ret == 1) {
        if (ctxPkey != NULL) {
            /* Get group from context into object. */
            ret = EVP_PKEY_copy_parameters(pkey, ctxPkey);
        }
        else {
            /* Set group from internal EC objects group. */
            ret = EC_KEY_set_group(ecKey, ecc->group);
        }
    }

    if (ret == 1) {
        /* Generate a new EC key with wolfSSL. */
#ifndef WE_ECC_USE_GLOBAL_RNG
        rc = wc_ecc_make_key_ex(&ecc->rng, len, &ecc->key, ecc->curveId);
#else
#ifndef WE_SINGLE_THREADED
        rc = wc_LockMutex(we_rng_mutex);
        if (rc != 0) {
            WOLFENGINE_ERROR_FUNC(WE_LOG_PK, "wc_LockMutex", rc);
            ret = 0;
        }
        else
#endif /* !WE_SINGLE_THREADED */
        {
            rc = wc_ecc_make_key_ex(we_rng, len, &ecc->key, ecc->curveId);
        #ifndef WE_SINGLE_THREADED
            wc_UnLockMutex(we_rng_mutex);
        #endif
        }
#endif /* !WE_ECC_USE_GLOBAL_RNG */
        if (ret == 1 && rc != 0) {
            WOLFENGINE_ERROR_FUNC(WE_LOG_PK, "wc_ecc_make_key_ex", rc);
            ret = 0;
        }
    }
    if (ret == 1) {
        WOLFENGINE_MSG(WE_LOG_PK, "Generated EC key");
        /* Private key and public key in wolfSSL object. */
        ecc->privKeySet = 1;
        ecc->pubKeySet = 1;

        /* Export new key into EC_KEY object. */
        ret = we_ec_export_key(&ecc->key, len, ecKey);
    }

    WOLFENGINE_LEAVE(WE_LOG_PK, "we_ec_keygen", ret);

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
    int ret = 1, rc;
    we_Ecc *ecc;
    EC_KEY *ecKey = NULL;
    word32 len;
    ecc_key peer;

    WOLFENGINE_ENTER(WE_LOG_PK, "we_ecdh_derive");
    WOLFENGINE_MSG_VERBOSE(WE_LOG_PK, "ARGS [ctx = %p, key = %p, keyLen = %p]",
                           ctx, key, keyLen);

    /* Get the internal EC key object. */
    ret = (ecc = (we_Ecc *)EVP_PKEY_CTX_get_data(ctx)) != NULL;

    if (ret == 1) {
        ret = we_ecc_check_curve_usage(ecc->curveId);
        if (ret != 1) {
            WOLFENGINE_ERROR_FUNC(WE_LOG_PK, "we_ecc_check_curve_usage", ret);
        }
    }

    if ((ret == 1) && (!ecc->privKeySet)) {
        /* Get the OpenSSL EC_KEY object and set curve id. */
        ret = we_ec_get_ec_key(ctx, &ecKey, ecc);
        if (ret == 1) {
            /* Set private key in wolfSSL object. */
            ret = we_ec_set_private(&ecc->key, ecc->curveId, ecKey);
        }
        if (ret == 1) {
            /* Only do this once as private will not change. */
            ecc->privKeySet = 1;
        }
    }

    if ((ret == 1) && (key == NULL)) {
        if (ecc->kdfType == EVP_PKEY_ECDH_KDF_NONE) {
            /* Return secret size in bytes. */
            rc = wc_ecc_get_curve_size_from_id(ecc->curveId);
            if (rc < 0) {
                WOLFENGINE_ERROR_FUNC(WE_LOG_PK,
                                      "wc_ecc_get_curve_size_from_id", rc);
            }
            else {
                *keyLen = (size_t)rc;
                WOLFENGINE_MSG(WE_LOG_PK,
                    "key is NULL, returning secret size: %d", *keyLen);
            }
        }
        else {
            *keyLen = ecc->kdfOutLen;
        }
    }
    if ((ret == 1) && (key != NULL)) {
        /* Create a new wolfSSL ECC key and set peer's public key. */
        rc = wc_ecc_init(&peer);
        if (rc != 0) {
            WOLFENGINE_ERROR_FUNC(WE_LOG_PK, "wc_ecc_init", rc);
            ret = 0;
        }
        else {
            /* Format of peer's public key point:
             *   0x04 | x | y - x and y ordinates are equal length.
             */
            unsigned char *x = ecc->peerKey + 1;
            unsigned char *y = x + ((ecc->peerKeyLen - 1) / 2);

            /* Import public key into wolfSSL object. */
            rc = wc_ecc_import_unsigned(&peer, x, y, NULL, ecc->curveId);
            if (rc != 0) {
                WOLFENGINE_ERROR_FUNC(WE_LOG_PK, "wc_ecc_import_unsigned", rc);
                ret = 0;
            }

            if (ret == 1) {
            #if defined(WE_ECC_USE_GLOBAL_RNG) && defined(ECC_TIMING_RESISTANT) \
                && !defined(WE_SINGLE_THREADED)
                rc = wc_LockMutex(we_rng_mutex);
                if (rc != 0) {
                    WOLFENGINE_ERROR_FUNC(WE_LOG_PK, "wc_LockMutex", rc);
                    ret = 0;
                }
                else
            #endif
                {
                    if (ecc->kdfType == EVP_PKEY_ECDH_KDF_NONE) {
                        len = (word32)*keyLen;
                        /* Calculate shared secret using wolfSSL. */
                        rc = wc_ecc_shared_secret(&ecc->key, &peer, key, &len);
                        if (rc != 0) {
                            WOLFENGINE_ERROR_FUNC(WE_LOG_PK,
                                                  "wc_ecc_shared_secret", rc);
                            ret = 0;
                        }
                    }
                    else {
                        /* Maximum output size supported for curves supported. */
                        unsigned char out[72];

                        /* Get buffer length. */
                        len = (word32)sizeof(out);
                        /* Calculate shared secret using wolfSSL. */
                        rc = wc_ecc_shared_secret(&ecc->key, &peer, out, &len);
                        if (rc != 0) {
                            WOLFENGINE_ERROR_FUNC(WE_LOG_PK,
                                                  "wc_ecc_shared_secret", rc);
                            ret = 0;
                        }
                        if (ret == 1) {
                            /* Get wolfCrypt hash algorithm to use. */
                            enum wc_HashType hash =
                                we_nid_to_wc_hash_type(EVP_MD_type(ecc->kdfMd));
                            /* KDF secret to key. */
                            rc = wc_X963_KDF(hash, out, len, ecc->kdfUkm,
                                             ecc->kdfUkmLen, key, (word32)*keyLen);
                            if (rc != 0) {
                                WOLFENGINE_ERROR_FUNC(WE_LOG_PK, "wc_X963_KDF", rc);
                                ret = 0;
                            }
                        }
                    }
                }
            #if defined(WE_ECC_USE_GLOBAL_RNG) && defined(ECC_TIMING_RESISTANT) \
                && !defined(WE_SINGLE_THREADED)
                wc_UnLockMutex(we_rng_mutex);
            #endif
            }
            if (ret == 1) {
                /* Return length of secret. */
                WOLFENGINE_MSG(WE_LOG_PK, "Generated shared secret (%d bytes)",
                            len);
                *keyLen = len;
            }

            /* Free the temporary peer key. */
            wc_ecc_free(&peer);
        }
    }

    WOLFENGINE_LEAVE(WE_LOG_PK, "we_ecdh_derive", ret);

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
#ifdef WE_HAVE_ECDH
    EVP_PKEY *peerKey;
    EC_KEY *ecPeerKey = NULL;
#endif
    char errBuff[WOLFENGINE_MAX_LOG_WIDTH];

    (void)num;
    (void)ptr;

    WOLFENGINE_ENTER(WE_LOG_PK, "we_ec_ctrl");
    WOLFENGINE_MSG_VERBOSE(WE_LOG_PK, "ARGS [ctx = %p, type = %d, num = %d, "
                           "ptr = %p]", ctx, type, num, ptr);

    ecc = (we_Ecc *)EVP_PKEY_CTX_get_data(ctx);
    if (ecc == NULL) {
        WOLFENGINE_ERROR_FUNC_NULL(WE_LOG_PK, "EVP_PKEY_CTX_get_data", ecc);
        ret = 0;
    }

    if (ret == 1) {
        switch (type) {
        #ifdef WE_HAVE_ECDSA
            /* Keep a copy of the digest object. */
            case EVP_PKEY_CTRL_MD:
                WOLFENGINE_MSG(WE_LOG_PK, "received type: EVP_PKEY_CTRL_MD");
                if ((EVP_MD_type((const EVP_MD *)ptr) != NID_sha1) &&
                    (EVP_MD_type((const EVP_MD *)ptr) != NID_ecdsa_with_SHA1) &&
                    (EVP_MD_type((const EVP_MD *)ptr) != NID_sha224) &&
                    (EVP_MD_type((const EVP_MD *)ptr) != NID_sha256) &&
                    (EVP_MD_type((const EVP_MD *)ptr) != NID_sha384) &&
                    (EVP_MD_type((const EVP_MD *)ptr) != NID_sha512)) {
                    XSNPRINTF(errBuff, sizeof(errBuff), "Invalid digest: %d",
                              EVP_MD_type((const EVP_MD *)ptr));
                    WOLFENGINE_ERROR_MSG(WE_LOG_PK, errBuff);
                    ret = 0;
                }
                else {
                    ecc->md = (EVP_MD*)ptr;
                }
                break;

            case EVP_PKEY_CTRL_DIGESTINIT:
                /* Nothing to do. */
                WOLFENGINE_MSG(WE_LOG_PK,
                               "received type: EVP_PKEY_CTRL_DIGEST");
                break;

            case EVP_PKEY_CTRL_PKCS7_SIGN:
                /* Nothing to do. */
                WOLFENGINE_MSG(WE_LOG_PK,
                               "received type: EVP_PKEY_CTRL_PKCS7_SIGN");
                break;

            case EVP_PKEY_CTRL_CMS_SIGN:
                /* Nothing to do. */
                WOLFENGINE_MSG(WE_LOG_PK,
                               "received type: EVP_PKEY_CTRL_CMS_SIGN");
                break;
        #endif

        #ifdef WE_HAVE_ECKEYGEN
            /* Set the group to use. */
            case EVP_PKEY_CTRL_EC_PARAMGEN_CURVE_NID:
                WOLFENGINE_MSG(WE_LOG_PK, 
                        "received type: EVP_PKEY_CTRL_EC_PARAMGEN_CURVE_NID");
                ecc->curveName = num;
                /* Get wolfSSL EC id from NID. */
                ret = we_ec_get_curve_id(num, &ecc->curveId);
                if (ret == 1) {
                    /* Replace the EC_GROUP object. */
                    EC_GROUP_free(ecc->group);
                    ecc->group = EC_GROUP_new_by_curve_name(ecc->curveName);
                    ret = ecc->group != NULL;
                }
                break;
        #endif

        #ifdef WE_HAVE_ECDH
            /* Set the peer key (public key from peer). */
            case EVP_PKEY_CTRL_PEER_KEY:
                WOLFENGINE_MSG(WE_LOG_PK,
                               "received type: EVP_PKEY_CTRL_PEER_KEY");
                peerKey = (EVP_PKEY *)ptr;
                /* Get the OpenSSL EC_KEY object. */
            #if OPENSSL_VERSION_NUMBER >= 0x30000000L
                ret = (ecPeerKey = (EC_KEY*)EVP_PKEY_get0_EC_KEY(peerKey)) !=
                                                                           NULL;
            #else
                ret = (ecPeerKey = EVP_PKEY_get0_EC_KEY(peerKey)) != NULL;
            #endif
                if (ret == 1) {
                    /* Replace the peerKey data. */
                    OPENSSL_free(ecc->peerKey);
                    /* Get the EC key public key as an uncompressed point. */
                    ecc->peerKeyLen = (int)EC_KEY_key2buf(ecPeerKey,
                        POINT_CONVERSION_UNCOMPRESSED, &ecc->peerKey, NULL);
                    if (ecc->peerKeyLen <= 0) {
                        WOLFENGINE_ERROR_MSG(WE_LOG_PK, "Peer key len <= 0");
                        ret = 0;
                    }
                }
                break;

            case EVP_PKEY_CTRL_EC_ECDH_COFACTOR:
                if (num == -2) {
                    ret = ecc->coFactor;
                }
                else {
                    ecc->coFactor = (num == 1);
                }
                break;

            case EVP_PKEY_CTRL_EC_KDF_TYPE:
                if (num == -2) {
                    ret = ecc->kdfType;
                }
                else if ((num == EVP_PKEY_ECDH_KDF_NONE) ||
                         (num == EVP_PKEY_ECDH_KDF_X9_63)) {
                    ecc->kdfType = num;
                }
                else {
                    XSNPRINTF(errBuff, sizeof(errBuff), "Invalid KDF type %d",
                               num);
                    WOLFENGINE_ERROR_MSG(WE_LOG_PK, errBuff);
                    ret = 0;
                }
                break;

            case EVP_PKEY_CTRL_EC_KDF_MD:
                ecc->kdfMd = (const EVP_MD *)ptr;
                break;
            case EVP_PKEY_CTRL_GET_EC_KDF_MD:
                *(const EVP_MD **)ptr = ecc->kdfMd;
                break;

            case EVP_PKEY_CTRL_EC_KDF_OUTLEN:
                ecc->kdfOutLen = num;
                break;
            case EVP_PKEY_CTRL_GET_EC_KDF_OUTLEN:
                ret = ecc->kdfOutLen;
                break;

            case EVP_PKEY_CTRL_EC_KDF_UKM:
                OPENSSL_free(ecc->kdfUkm);
                ecc->kdfUkm = (unsigned char *)ptr;
                if (ecc->kdfUkm != NULL) {
                    ecc->kdfUkmLen = num;
                }
                else {
                    ecc->kdfUkmLen = 0;
                }
                break;
            case EVP_PKEY_CTRL_GET_EC_KDF_UKM:
                *(unsigned char **)ptr = ecc->kdfUkm;
                ret = ecc->kdfUkmLen;
                break;
        #endif

            /* Unsupported type. */
            default:
                XSNPRINTF(errBuff, sizeof(errBuff), "Unsupported ctrl type %d",
                          type);
                WOLFENGINE_ERROR_MSG(WE_LOG_PK, errBuff);
                ret = 0;
                break;
        }
    }

    WOLFENGINE_LEAVE(WE_LOG_PK, "we_ec_ctrl", ret);

    return ret;
}

/**
 * Extra operations for working with ECC.
 * Supported operations include:
 *  - "ecdh_cofactor_mode": whether to perform ECDH with cofactor.
 *
 * @param  ctx   [in]  Public key context of operation.
 * @param  type  [in]  String representation of value.
 * @returns  1 on success and 0 on failure.
 */
static int we_ec_ctrl_str(EVP_PKEY_CTX *ctx, const char *type,
                          const char *value)
{
    int ret = 1;
    char errBuff[WOLFENGINE_MAX_LOG_WIDTH];
    we_Ecc *ecc;

    ecc = (we_Ecc *)EVP_PKEY_CTX_get_data(ctx);
    if (ecc == NULL) {
        WOLFENGINE_ERROR_FUNC_NULL(WE_LOG_PK, "EVP_PKEY_CTX_get_data", ecc);
        ret = 0;
    }

    if (ret == 1) {
        if (XSTRNCMP(type, "ecdh_cofactor_mode", 19) == 0) {
            WOLFENGINE_MSG(WE_LOG_PK, "received type: ecdh_cofactor_mode");
            ecc->coFactor = (XATOI(value) == 1);
        }
        else if (XSTRNCMP(type, "ecdh_kdf_md", 19) == 0) {
            ecc->kdfMd = EVP_get_digestbyname(value);
            WOLFENGINE_MSG(WE_LOG_PK, "received type: ecdh_kdf_md");
            if (ecc->kdfMd == NULL) {
                XSNPRINTF(errBuff, sizeof(errBuff), "Invalid digest %s", value);
                WOLFENGINE_ERROR_MSG(WE_LOG_PK, errBuff);
                ret = 0;
            }
        }
        else {
            XSNPRINTF(errBuff, sizeof(errBuff), "Unsupported ctrl string %s",
                      type);
            WOLFENGINE_ERROR_MSG(WE_LOG_PK, errBuff);
            ret = 0;
        }
    }

    return ret;
}

#if OPENSSL_VERSION_NUMBER >= 0x10101000L
/**
 * Used to set the group
 *
 * @param  ctx   [in]  Public key context of operation.
 * @param  pkey  [in]  Key to set parameters in
 * @returns  1 on success and 0 on failure.
 */
static int wc_ec_paramgen(EVP_PKEY_CTX *ctx, EVP_PKEY *pkey)
{
    EC_KEY *key = NULL;
    we_Ecc *ecc = NULL;
    int ret = 1;
    WOLFENGINE_ENTER(WE_LOG_PK, "we_ec_paramgen");

    ecc = (we_Ecc *)EVP_PKEY_CTX_get_data(ctx);
    if (ecc == NULL) {
        WOLFENGINE_ERROR_FUNC_NULL(WE_LOG_PK, "EVP_PKEY_CTX_get_data", ecc);
        ret = 0;
    }

    if (ret == 1 && ecc->group == NULL) {
        WOLFENGINE_ERROR_MSG(WE_LOG_PK, "group not set!");
        ret = 0;
    }

    if (ret == 1) {
        ret = we_ec_get_curve_id(EC_GROUP_get_curve_name(ecc->group),
                             &ecc->curveId);
        if (ret != 1) {
            WOLFENGINE_ERROR_FUNC(WE_LOG_PK, "we_ec_get_curve_id", ret);
        }
    }

    if (ret == 1) {
        key = EC_KEY_new();
        if (key == NULL) {
            WOLFENGINE_ERROR_FUNC_NULL(WE_LOG_PK, "EC_KEY_new", key);
            ret = 0;
        }
    }

    if (ret == 1) {
        ret = EC_KEY_set_group(key, ecc->group);
        if (ret == 0) {
            WOLFENGINE_ERROR_FUNC(WE_LOG_PK, "EC_KEY_set_group", ret);
            EC_KEY_free(key);
        }
    }

    if (ret == 1) {
        ret = EVP_PKEY_assign_EC_KEY(pkey, key);
        if (ret == 0) {
            WOLFENGINE_ERROR_FUNC(WE_LOG_PK, "EVP_PKEY_assign_EC_KEY", ret);
            EC_KEY_free(key);
        }
    }

    return ret;
}
#endif


/** EVP public key method - EC using wolfSSL for the implementation. */
EVP_PKEY_METHOD *we_ec_method = NULL;
#ifdef WE_HAVE_ECKEYGEN
#ifdef WE_HAVE_EC_P192
/** EVP public key method - EC P-192 using wolfSSL for the implementation. */
EVP_PKEY_METHOD *we_ec_p192_method = NULL;
#endif
#ifdef WE_HAVE_EC_P224
/** EVP public key method - EC P-224 using wolfSSL for the implementation. */
EVP_PKEY_METHOD *we_ec_p224_method = NULL;
#endif
#ifdef WE_HAVE_EC_P256
/** EVP public key method - EC P-256 using wolfSSL for the implementation. */
EVP_PKEY_METHOD *we_ec_p256_method = NULL;
#endif
#ifdef WE_HAVE_EC_P384
/** EVP public key method - EC P-384 using wolfSSL for the implementation. */
EVP_PKEY_METHOD *we_ec_p384_method = NULL;
#endif
#ifdef WE_HAVE_EC_P521
/** EVP public key method - EC P-521 using wolfSSL for the implementation. */
EVP_PKEY_METHOD *we_ec_p521_method = NULL;
#endif
#endif

/**
 * Initialize the ECC method.
 *
 * @return  1 on success and 0 on failure.
 */
int we_init_ecc_meths(void)
{
    int ret = 1;

    WOLFENGINE_ENTER(WE_LOG_PK, "we_init_ecc_meths");

    we_ec_method = EVP_PKEY_meth_new(EVP_PKEY_EC, 0);
    if (we_ec_method == NULL) {
        WOLFENGINE_ERROR_FUNC_NULL(WE_LOG_PK,
                                   "EVP_PKEY_meth_new", we_ec_method);
        ret = 0;
    }
    else {
        EVP_PKEY_meth_set_init(we_ec_method, we_ec_init);
        EVP_PKEY_meth_set_copy(we_ec_method, we_ec_copy);
        EVP_PKEY_meth_set_cleanup(we_ec_method, we_ec_cleanup);

#if OPENSSL_VERSION_NUMBER >= 0x10101000L
        /* used in TLS 1.3 connections */
        EVP_PKEY_meth_set_paramgen(we_ec_method, NULL, wc_ec_paramgen);
#endif
#ifdef WE_HAVE_ECDSA
        EVP_PKEY_meth_set_sign(we_ec_method, NULL, we_pkey_ecdsa_sign);
        EVP_PKEY_meth_set_verify(we_ec_method, NULL, we_pkey_ecdsa_verify);
#endif
#ifdef WE_HAVE_ECKEYGEN
        EVP_PKEY_meth_set_keygen(we_ec_method, NULL, we_ec_keygen);
#endif
#ifdef WE_HAVE_ECDH
        EVP_PKEY_meth_set_derive(we_ec_method, NULL, we_ecdh_derive);
#endif

        EVP_PKEY_meth_set_ctrl(we_ec_method, we_ec_ctrl, we_ec_ctrl_str);
    }

#ifdef WE_HAVE_ECKEYGEN
#ifdef WE_HAVE_EC_P192
    if (ret == 1) {
        we_ec_p192_method = EVP_PKEY_meth_new(EVP_PKEY_EC, 0);
        if (we_ec_p192_method == NULL) {
            WOLFENGINE_ERROR_FUNC_NULL(WE_LOG_PK, "EVP_PKEY_meth_new",
                                       we_ec_p192_method);
            ret = 0;
        }
        else {
            EVP_PKEY_meth_set_init(we_ec_p192_method, we_ec_p192_init);
            EVP_PKEY_meth_set_copy(we_ec_p192_method, we_ec_copy);
            EVP_PKEY_meth_set_cleanup(we_ec_p192_method, we_ec_cleanup);

            EVP_PKEY_meth_set_keygen(we_ec_p192_method, NULL, we_ec_keygen);

            EVP_PKEY_meth_set_ctrl(we_ec_p192_method, we_ec_ctrl,
                                   we_ec_ctrl_str);
        }
    }
#endif
#ifdef WE_HAVE_EC_P224
    if (ret == 1) {
        we_ec_p224_method = EVP_PKEY_meth_new(EVP_PKEY_EC, 0);
        if (we_ec_p224_method == NULL) {
            WOLFENGINE_ERROR_FUNC_NULL(WE_LOG_PK, "EVP_PKEY_meth_new",
                                       we_ec_p224_method);
            ret = 0;
        }
        else {
            EVP_PKEY_meth_set_init(we_ec_p224_method, we_ec_p224_init);
            EVP_PKEY_meth_set_copy(we_ec_p224_method, we_ec_copy);
            EVP_PKEY_meth_set_cleanup(we_ec_p224_method, we_ec_cleanup);

            EVP_PKEY_meth_set_keygen(we_ec_p224_method, NULL, we_ec_keygen);

            EVP_PKEY_meth_set_ctrl(we_ec_p224_method, we_ec_ctrl,
                                   we_ec_ctrl_str);
        }
    }
#endif
#ifdef WE_HAVE_EC_P256
    if (ret == 1) {
        we_ec_p256_method = EVP_PKEY_meth_new(EVP_PKEY_EC, 0);
        if (we_ec_p256_method == NULL) {
            WOLFENGINE_ERROR_FUNC_NULL(WE_LOG_PK, "EVP_PKEY_meth_new",
                                       we_ec_p256_method);
            ret = 0;
        }
        else {
            EVP_PKEY_meth_set_init(we_ec_p256_method, we_ec_p256_init);
            EVP_PKEY_meth_set_copy(we_ec_p256_method, we_ec_copy);
            EVP_PKEY_meth_set_cleanup(we_ec_p256_method, we_ec_cleanup);

            EVP_PKEY_meth_set_keygen(we_ec_p256_method, NULL, we_ec_keygen);

            EVP_PKEY_meth_set_ctrl(we_ec_p256_method, we_ec_ctrl,
                                   we_ec_ctrl_str);
        }
    }
#endif
#ifdef WE_HAVE_EC_P384
    if (ret == 1) {
        we_ec_p384_method = EVP_PKEY_meth_new(EVP_PKEY_EC, 0);
        if (we_ec_p384_method == NULL) {
            WOLFENGINE_ERROR_FUNC_NULL(WE_LOG_PK, "EVP_PKEY_meth_new",
                                       we_ec_p384_method);
            ret = 0;
        }
        else {
            EVP_PKEY_meth_set_init(we_ec_p384_method, we_ec_p384_init);
            EVP_PKEY_meth_set_copy(we_ec_p384_method, we_ec_copy);
            EVP_PKEY_meth_set_cleanup(we_ec_p384_method, we_ec_cleanup);

            EVP_PKEY_meth_set_keygen(we_ec_p384_method, NULL, we_ec_keygen);

            EVP_PKEY_meth_set_ctrl(we_ec_p384_method, we_ec_ctrl,
                                   we_ec_ctrl_str);
        }
    }
#endif
#ifdef WE_HAVE_EC_P521
    if (ret == 1) {
        we_ec_p521_method = EVP_PKEY_meth_new(EVP_PKEY_EC, 0);
        if (we_ec_p521_method == NULL) {
            WOLFENGINE_ERROR_FUNC_NULL(WE_LOG_PK, "EVP_PKEY_meth_new",
                                       we_ec_p521_method);
            ret = 0;
        }
        else {
            EVP_PKEY_meth_set_init(we_ec_p521_method, we_ec_p521_init);
            EVP_PKEY_meth_set_copy(we_ec_p521_method, we_ec_copy);
            EVP_PKEY_meth_set_cleanup(we_ec_p521_method, we_ec_cleanup);

            EVP_PKEY_meth_set_keygen(we_ec_p521_method, NULL, we_ec_keygen);

            EVP_PKEY_meth_set_ctrl(we_ec_p521_method, we_ec_ctrl,
                                   we_ec_ctrl_str);
        }
    }
#endif
#endif

    if (ret == 0) {
        if (we_ec_method != NULL) {
            EVP_PKEY_meth_free(we_ec_method);
            we_ec_method = NULL;
        }
#ifdef WE_HAVE_ECKEYGEN
#ifdef WE_HAVE_EC_P192
        if (we_ec_p192_method != NULL) {
            EVP_PKEY_meth_free(we_ec_p192_method);
            we_ec_p192_method = NULL;
        }
#endif
#ifdef WE_HAVE_EC_P224
        if (we_ec_p224_method != NULL) {
            EVP_PKEY_meth_free(we_ec_p224_method);
            we_ec_p224_method = NULL;
        }
#endif
#ifdef WE_HAVE_EC_P256
        if (we_ec_p256_method != NULL) {
            EVP_PKEY_meth_free(we_ec_p256_method);
            we_ec_p256_method = NULL;
        }
#endif
#ifdef WE_HAVE_EC_P384
        if (we_ec_p384_method != NULL) {
            EVP_PKEY_meth_free(we_ec_p384_method);
            we_ec_p384_method = NULL;
        }
#endif
#ifdef WE_HAVE_EC_P521
        if (we_ec_p521_method != NULL) {
            EVP_PKEY_meth_free(we_ec_p521_method);
            we_ec_p521_method = NULL;
        }
#endif
#endif
    }

    WOLFENGINE_LEAVE(WE_LOG_PK, "we_init_ecc_meths", ret);

    return ret;
}

#endif /* WE_HAVE_EVP_PKEY */

#ifdef WE_HAVE_EC_KEY
/* Method for using wolfSSL thorugh the EC_KEY API. */
EC_KEY_METHOD *we_ec_key_method = NULL;

/**
 * Generate an EC key for the group specified in key object.
 *
 * @param  key  [in/out]  Elliptic curve key object.
 * @erturns 1 on success and 0 on faulure.
 */
static int we_ec_key_keygen(EC_KEY *key)
{
    int ret = 1, rc;
    int curveId;
    ecc_key ecc;
    ecc_key* pEcc = NULL;
#ifndef WE_ECC_USE_GLOBAL_RNG
    WC_RNG rng;
    WC_RNG *pRng = NULL;
#else
    WC_RNG *pRng = we_rng;
#endif
    int len = 0;

    WOLFENGINE_ENTER(WE_LOG_PK, "we_ec_key_keygen");
    WOLFENGINE_MSG_VERBOSE(WE_LOG_PK, "ARGS [key = %p]", key);

    /* Get the wolfSSL EC curve id for the group. */
    ret = we_ec_get_curve_id(EC_GROUP_get_curve_name(EC_KEY_get0_group(key)),
                             &curveId);

    if (ret == 1 && (rc = we_ecc_check_curve_usage(curveId)) != 1) {
        WOLFENGINE_ERROR_FUNC(WE_LOG_PK, "we_ecc_check_curve_usage", rc);
        ret = 0;
    }

    if (ret == 1) {
        len = wc_ecc_get_curve_size_from_id(curveId);
        if (len < 0) {
            WOLFENGINE_ERROR_FUNC(WE_LOG_PK,
                                  "wc_ecc_get_curve_size_from_id", len);
            ret = 0;

        }
        else {
            /* Initialize a wolfSSL EC key object. */
            rc = wc_ecc_init(&ecc);
            if (rc != 0) {
                WOLFENGINE_ERROR_FUNC(WE_LOG_PK, "wc_ecc_init", rc);
                ret = 0;
            }
        }
    }
#ifndef WE_ECC_USE_GLOBAL_RNG
    if (ret == 1) {
        rc = wc_InitRng(&rng);
        if (rc != 0) {
            ret = 0;
        }
        else {
            pRng = &rng;
        }
    }
#endif
    if (ret == 1) {
        pEcc = &ecc;

        /* Generate key. */
#if defined(WE_ECC_USE_GLOBAL_RNG) && !defined(WE_SINGLE_THREADED)
        rc = wc_LockMutex(we_rng_mutex);
        if (rc != 0) {
            WOLFENGINE_ERROR_FUNC(WE_LOG_PK, "wc_LockMutex", rc);
            ret = 0;
        }
        else
#endif
        {
            rc = wc_ecc_make_key_ex(pRng, len, &ecc, curveId);
        #if defined(WE_ECC_USE_GLOBAL_RNG) && !defined(WE_SINGLE_THREADED)
            wc_UnLockMutex(we_rng_mutex);
        #endif
            if (rc != 0) {
                WOLFENGINE_ERROR_FUNC(WE_LOG_PK, "wc_ecc_make_key_ex", rc);
                ret = 0;
            }
        }
    }
    if (ret == 1) {
        WOLFENGINE_MSG(WE_LOG_PK, "Generated EC key");
        /* Export new key into EC_KEY object. */
        ret = we_ec_export_key(&ecc, len, key);
    }

#ifndef WE_ECC_USE_GLOBAL_RNG
    wc_FreeRng(pRng);
#endif
    wc_ecc_free(pEcc);

    WOLFENGINE_LEAVE(WE_LOG_PK, "we_ec_key_keygen", ret);

    return ret;
}
#endif /* WE_HAVE_EC_KEY */
#if defined(WE_HAVE_EC_KEY) || defined(WE_HAVE_ECDH)

/**
 * Compute the EC secret for ECDH using wolfSSL.
 *
 * @param  psec     [out]  Pointer to buffer holding secret. Allocated with
 *                         OPENSSL_malloc().
 * @param  pseclen  [out]  Pointer to length of secret.
 * @param  pub_key  [in]   Public EC point from peer.
 * @param  ecdh     [in]   EC KEY with private key.
 * @returns  1 on success, 0 on failure.
 */
static int we_ec_key_compute_key(unsigned char **psec, size_t *pseclen,
                                 const EC_POINT *pub_key, const EC_KEY *ecdh)
{
    int ret, rc;
    ecc_key key;
    ecc_key peer;
#if !defined(HAVE_FIPS) || \
    (defined(HAVE_FIPS_VERSION) && HAVE_FIPS_VERSION != 2)
#ifndef WE_ECC_USE_GLOBAL_RNG
    WC_RNG rng;
    WC_RNG *pRng = NULL;
#else
    WC_RNG *pRng = we_rng;
#endif
#endif
    ecc_key *pKey = NULL;
    ecc_key *pPeer = NULL;
    const EC_GROUP *group;
    int curveId;
    word32 len;
    int peerKeyLen = 0;
    unsigned char* peerKey = NULL;
    unsigned char* secret = NULL;

    WOLFENGINE_ENTER(WE_LOG_PK, "we_ec_key_compute_key");
    WOLFENGINE_MSG_VERBOSE(WE_LOG_PK, "ARGS [psec = %p, pseclen = %p, "
                           "pub_key = %p, ecdh = %p]", psec, pseclen,
                           pub_key, ecdh);

    /* Get wolfSSL curve id for EC group. */
    group = EC_KEY_get0_group(ecdh);
    ret = we_ec_get_curve_id(EC_GROUP_get_curve_name(group), &curveId);
    if (ret == 1 && (rc = we_ecc_check_curve_usage(curveId)) != 1) {
        WOLFENGINE_ERROR_FUNC(WE_LOG_PK, "we_ecc_check_curve_usage", rc);
        ret = 0;
    }
    if (ret == 1) {
        peerKeyLen = (int)EC_POINT_point2buf(group, pub_key,
                                             POINT_CONVERSION_UNCOMPRESSED,
                                             &peerKey, NULL);
        ret = peerKey != NULL;
    }
    if (ret == 1) {
        rc = wc_ecc_get_curve_size_from_id(curveId);
        if (rc < 0) {
            WOLFENGINE_ERROR_FUNC(WE_LOG_PK,
                                  "wc_ecc_get_curve_size_from_id", rc);
            ret = 0;
        }
        else {
            len = (word32)rc;
        }
    }
    if (ret == 1) {
        /* Allocate the buffer to hold secret. Freed externally. */
        ret = (secret = (unsigned char *)OPENSSL_malloc(len)) != NULL;
    }
    if (ret == 1) {
        /* Initialize the wolfSSL private key object. */
        rc = wc_ecc_init(&key);
        if (rc != 0) {
            WOLFENGINE_ERROR_FUNC(WE_LOG_PK, "wc_ecc_init", rc);
            ret = 0;
        }
    }
#if !defined(HAVE_FIPS) || \
    (defined(HAVE_FIPS_VERSION) && HAVE_FIPS_VERSION != 2)
#ifndef WE_ECC_USE_GLOBAL_RNG
    if (ret == 1) {
        rc = wc_InitRng(&rng);
        if (rc != 0) {
            WOLFENGINE_ERROR_FUNC(WE_LOG_PK, "wc_InitRng", rc);
            ret = 0;
        }
        else {
            pRng = &rng;
        }
    }
#endif
    if (ret == 1) {
        /* Set RNG for side-channel resistant code. */
        rc = wc_ecc_set_rng(&key, pRng);
        if (rc != 0) {
            WOLFENGINE_ERROR_FUNC(WE_LOG_PK, "wc_ecc_set_rng", rc);
            ret = 0;
        }
    }
#endif /* !HAVE_FIPS || (HAVE_FIPS_VERSION && HAVE_FIPS_VERSION != 2) */
    if (ret == 1) {
        pKey = &key;

        /* Set private key into wolfSSL key object. */
        ret = we_ec_set_private(pKey, curveId, ecdh);
    }
    if (ret == 1) {
        /* Initialize wolfSSL ECC key for peer's public key. */
        rc = wc_ecc_init(&peer);
        if (rc != 0) {
            WOLFENGINE_ERROR_FUNC(WE_LOG_PK, "wc_ecc_init", rc);
            ret = 0;
        }
    }
    if (ret == 1) {
        unsigned char *x = peerKey + 1;
        unsigned char *y = x + ((peerKeyLen - 1) / 2);

        pPeer = &peer;

        /* Import the public point into wolfSSL key object. */
        rc = wc_ecc_import_unsigned(pPeer, x, y, NULL, curveId);
        if (rc != 0) {
            WOLFENGINE_ERROR_FUNC(WE_LOG_PK, "wc_ecc_import_unsigned", rc);
            ret = 0;
        }
    }
    if (ret == 1) {
    #if defined(WE_ECC_USE_GLOBAL_RNG) && defined(ECC_TIMING_RESISTANT) \
        && !defined(WE_SINGLE_THREADED)
        rc = wc_LockMutex(we_rng_mutex);
        if (rc != 0) {
            WOLFENGINE_ERROR_FUNC(WE_LOG_PK, "wc_LockMutex", rc);
            ret = 0;
        }
        else
    #endif
        {
            /* Calculate shared secret. */
            rc = wc_ecc_shared_secret(pKey, pPeer, secret, &len);
            if (rc != 0) {
                WOLFENGINE_ERROR_FUNC(WE_LOG_PK, "wc_ecc_shared_secret", rc);
                ret = 0;
            }
        }
    #if defined(WE_ECC_USE_GLOBAL_RNG) && defined(ECC_TIMING_RESISTANT) \
        && !defined(WE_SINGLE_THREADED)
        wc_UnLockMutex(we_rng_mutex);
    #endif
    }
    if (ret == 1) {
        WOLFENGINE_MSG(WE_LOG_PK, "Calculated ECDH shared secret");
        *psec = secret;
        *pseclen = len;
    }
    else {
        OPENSSL_free(secret);
    }
    OPENSSL_free(peerKey);
#if !defined(HAVE_FIPS) || \
    (defined(HAVE_FIPS_VERSION) && HAVE_FIPS_VERSION != 2)
#ifndef WE_ECC_USE_GLOBAL_RNG
    wc_FreeRng(pRng);
#endif
#endif
    wc_ecc_free(pPeer);
    wc_ecc_free(pKey);

    WOLFENGINE_LEAVE(WE_LOG_PK, "we_ec_key_compute_key", ret);

    return ret;
}
#endif /* WE_HAVE_EC_KEY || WE_HAVE_ECDH */

#if defined(WE_HAVE_ECDSA) || defined(WE_HAVE_EC_KEY)

/** ECDSA Sign
 *
 * This function is set as a callback in both:
 *     EC_KEY_METHOD_set_sign() - used by OpenSSL 1.1.1 for ECDSA_do_sign_ex()
 *     ECDSA_METHOD_set_sign()  - used by OpenSSL 1.0.2 for ECDSA_do_sign()
 *
 * @param  d        [in]   Pointer to digest buffer
 * @param  dlen     [in]   Digest length.
 * @param  kinv     [in]   Precomputed kinv (Not supported)
 * @param  rp       [in]   Precomputed r    (Not supported)
 * @param  key      [in]   EC Key
 * @return  pointer to allocated ECDSA_SIG
 * @return  NULL on failure.
 */
static ECDSA_SIG* we_ecdsa_do_sign_ex(const unsigned char *d, int dlen,
                    const BIGNUM *kinv, const BIGNUM *rp, EC_KEY *key)
{
    ECDSA_SIG *sig = NULL;
    ecc_key we_key;
#ifndef WE_ECC_USE_GLOBAL_RNG
    WC_RNG rng;
    WC_RNG *pRng = NULL;
#else
    WC_RNG *pRng = we_rng;
#endif
    int curveId = 0;
    mp_int sig_r, sig_s;
    int r_size, s_size;
    unsigned char *r_bin = NULL, *s_bin = NULL;
    BIGNUM* rBN = NULL;
    BIGNUM* sBN = NULL;
    int err = 0, rc;

    WOLFENGINE_ENTER(WE_LOG_PK, "we_ecdsa_do_sign_ex");
    WOLFENGINE_MSG_VERBOSE(WE_LOG_PK, "ARGS [d = %p, dlen = %d, kinv = %p, "
                           "rp = %p, key = %p]", d, dlen, kinv, rp, key);

    if (kinv != NULL || rp != NULL) {
        WOLFENGINE_ERROR_MSG(WE_LOG_PK, "we_ecdsa_do_sign_ex() does not "
                             "support kinv or rp BIGNUM arguments, must be "
                             "passed as NULL");
        return NULL;
    }

    if (d == NULL || key == NULL) {
        WOLFENGINE_MSG(WE_LOG_PK, "we_ecdsa_do_sign_ex Bad arguments");
        return NULL;
    }

    if ((rc = we_ec_get_curve_id(EC_GROUP_get_curve_name(
                                 EC_KEY_get0_group(key)), &curveId)) == 0) {
        WOLFENGINE_ERROR_FUNC(WE_LOG_PK, "we_ec_get_curve_id", rc);
        return NULL;
    }

    if ((rc = we_ecc_check_curve_usage(curveId)) == 0) {
        WOLFENGINE_ERROR_FUNC(WE_LOG_PK, "we_ecc_check_curve_usage", rc);
        return NULL;
    }

#ifndef WE_ECC_USE_GLOBAL_RNG
    rc = wc_InitRng(&rng);
    if (rc != 0) {
        err = 1;
    }
    else {
        pRng = &rng;
    }

    if (err == 0)
#endif
    {
        rc = mp_init(&sig_r);
        if (rc != MP_OKAY) {
            WOLFENGINE_ERROR_FUNC(WE_LOG_PK, "mp_init(sig_r)", rc);
            err = 1;
        }
    }
    if (err == 0) {
        rc = mp_init(&sig_s);
        if (rc != MP_OKAY) {
            WOLFENGINE_ERROR_FUNC(WE_LOG_PK, "mp_init(sig_s)", rc);
            err = 1;
        }
    }

    /* Initialize a wolfSSL key object. */
    if (err == 0) {
        rc = wc_ecc_init(&we_key);
        if (rc != 0) {
            WOLFENGINE_ERROR_FUNC(WE_LOG_PK, "wc_ecc_init", rc);
            err = 1;
        }
    }

    /* Set private key from EC_KEY into ecc_key */
    if (err == 0) {
        rc = we_ec_set_private(&we_key, curveId, key);
        if (rc != 1) {
            WOLFENGINE_ERROR_FUNC(WE_LOG_PK, "we_ec_set_private", rc);
            err = 1;
        }
    }

    if (err == 0) {
        rc = mp_init_multi(&sig_r, &sig_s, NULL, NULL, NULL, NULL);
        if (rc != MP_OKAY) {
            WOLFENGINE_ERROR_FUNC(WE_LOG_PK, "mp_init_multi", rc);
            err = 1;
        }
    }

    /* Sign hash with ECDSA */
    if (err == 0) {
#if defined(WE_ECC_USE_GLOBAL_RNG) && !defined(WE_SINGLE_THREADED)
        rc = wc_LockMutex(we_rng_mutex);
        if (rc != 0) {
            WOLFENGINE_ERROR_FUNC(WE_LOG_PK, "wc_LockMutex", rc);
            err = 1;
        }
        else
#endif
        {
            rc = wc_ecc_sign_hash_ex(d, dlen, pRng, &we_key, &sig_r, &sig_s);
        #if defined(WE_ECC_USE_GLOBAL_RNG) && !defined(WE_SINGLE_THREADED)
            wc_UnLockMutex(we_rng_mutex);
        #endif
            if (rc != MP_OKAY) {
                WOLFENGINE_ERROR_FUNC(WE_LOG_PK, "wc_ecc_sign_hash_ex", rc);
                err = 1;
            }
        }
    }

    if (err == 0) {
        WOLFENGINE_MSG(WE_LOG_PK, "Generated ECDSA signature");
        r_size = mp_unsigned_bin_size(&sig_r);
        s_size = mp_unsigned_bin_size(&sig_s);
        if (r_size == 0 || s_size == 0) {
            WOLFENGINE_ERROR_MSG(WE_LOG_PK, "Invalid r/s parameter size");
            err = 1;
        }
    }

    if (err == 0) {
        r_bin = OPENSSL_malloc(r_size);
        s_bin = OPENSSL_malloc(s_size);
        if (r_bin == NULL || s_bin == NULL) {
            WOLFENGINE_ERROR_MSG(WE_LOG_PK,
                                 "OPENSSL_malloc error during r/s conversion");
            err = 1;
        }
    }

    if (err == 0) {
        sig = ECDSA_SIG_new();
        if (sig == NULL) {
            WOLFENGINE_ERROR_FUNC_NULL(WE_LOG_PK, "ECDSA_SIG_new", sig);
            err = 1;
        }
    }

    if (err == 0) {
        rc = mp_to_unsigned_bin(&sig_r, r_bin);
        if (rc != MP_OKAY) {
            WOLFENGINE_ERROR_FUNC(WE_LOG_PK, "mp_to_unsigned_bin(r_bin)", rc);
            err = 1;
        }
        rc = mp_to_unsigned_bin(&sig_s, s_bin);
        if (rc != MP_OKAY) {
            WOLFENGINE_ERROR_FUNC(WE_LOG_PK, "mp_to_unsigned_bin(s_bin)", rc);
            err = 1;
        }
    }

    if (err == 0) {
        rBN = BN_bin2bn(r_bin, r_size, rBN);
        sBN = BN_bin2bn(s_bin, s_size, sBN);
        if (rBN == NULL || sBN == NULL) {
            WOLFENGINE_ERROR_FUNC_NULL(WE_LOG_PK, "BN_bin2bn", NULL);
            err = 1;
        } else {
            rc = ECDSA_SIG_set0(sig, rBN, sBN);
            if (rc != 1) {
                WOLFENGINE_ERROR_FUNC(WE_LOG_PK, "ECDSA_SIG_set0", rc);
                err = 1;
            }
        }
    }

    if (r_bin != NULL) {
        OPENSSL_free(r_bin);
    }
    if (s_bin != NULL) {
        OPENSSL_free(s_bin);
    }

    mp_free(&sig_r);
    mp_free(&sig_s);
    wc_ecc_free(&we_key);
#ifndef WE_ECC_USE_GLOBAL_RNG
    wc_FreeRng(pRng);
#endif

    if (err != 0) {
        /* in error state, free ECDSA_SIG before returning */
        if (sig != NULL) {
            ECDSA_SIG_free(sig);
        }
        sig = NULL;
    }

    return sig;
}

/** Setup parameters for ECDSA_sign
 *
 * This function is intentionally a stub, as wolfEngine does not support
 * usage of "kinv" and "r" parameters with ECDSA_METHOD.
 *
 * @return 0 for Error
 */
static int we_ecdsa_sign_setup(EC_KEY *eckey, BN_CTX *ctx,
                               BIGNUM **kinv, BIGNUM **r)
{
    (void)eckey;
    (void)ctx;
    (void)kinv;
    (void)r;

    WOLFENGINE_ENTER(WE_LOG_PK, "we_ecdsa_sign_setup");
    WOLFENGINE_ERROR_MSG(WE_LOG_PK, "wolfEngine does not support usage of "
                         "'kinv' and 'r' parameters with ECDSA_METHOD");
    WOLFENGINE_LEAVE(WE_LOG_PK, "we_ecdsa_sign_setup", 0);

    return 0;
}

/** ECDSA Verify signature
 *
 * This function is set as a callback in both:
 *     EC_KEY_METHOD_set_verify() - used by OpenSSL 1.1.1 for ECDSA_do_verify()
 *     ECDSA_METHOD_set_verify()  - used by OpenSSL 1.0.2 for ECDSA_do_verify()
 *
 * @param  d        [in]   Pointer to digest buffer
 * @param  dlen     [in]   Digest length.
 * @param  sig      [in]   pointer to the signature to verify
 * @param  key      [in]   EC Key
 * @return  1 for a valid signature, 0 for an invalid signature and -1 on error.
 */
static int we_ecdsa_do_verify(const unsigned char *d, int dlen,
                            const ECDSA_SIG *sig, EC_KEY *key)
{
    ecc_key we_key;
    int curveId = 0;
    int ret = 1, rc;

    int sigDerSz = 0;
    unsigned char* sigDer = NULL;
    unsigned char* sigDerPtr = NULL;

    /* start out with invalid signature (0) */
    int check_sig = 0;

    WOLFENGINE_ENTER(WE_LOG_PK,"we_ecdsa_do_verify");
    WOLFENGINE_MSG_VERBOSE(WE_LOG_PK, "ARGS [d = %p, dlen = %d, sig = %p, "
                           "key = %p]", d, dlen, sig, key);

    if (d == NULL || sig == NULL || key == NULL) {
        WOLFENGINE_MSG(WE_LOG_PK,"we_ecdsa_do_verify Bad arguments");
        return WOLFENGINE_FATAL_ERROR;
    }

    if ((rc = we_ec_get_curve_id(
        EC_GROUP_get_curve_name(EC_KEY_get0_group(key)), &curveId)) != 1) {
        WOLFENGINE_ERROR_FUNC(WE_LOG_PK,"we_ec_get_curve_id", rc);
        ret = -1;
    }
    if (ret == 1) {
        rc = wc_ecc_init(&we_key);
        if (rc != 0) {
            WOLFENGINE_ERROR_FUNC(WE_LOG_PK,"wc_ecc_init", rc);
            ret = -1;
        }
    }
    if (ret == 1) {
        rc = we_ec_set_public(&we_key, curveId, key);
        if (rc != 1) {
            WOLFENGINE_ERROR_FUNC(WE_LOG_PK,"we_ec_set_public", rc);
            ret = -1;
        }
    }

    if (ret == 1) {
        /* get expected DER sig size, allocate space for DER */
        sigDerSz = i2d_ECDSA_SIG(sig, NULL);
        if (sigDerSz == 0) {
            WOLFENGINE_ERROR_FUNC(WE_LOG_PK, "i2d_ECDSA_SIG(NULL)", sigDerSz);
            ret = -1;
        } else {
            sigDer = (unsigned char*)OPENSSL_malloc(sigDerSz);
            if (sigDer == NULL) {
                WOLFENGINE_ERROR_FUNC_NULL(WE_LOG_PK, "OPENSSL_malloc", sigDer);
                ret = -1;
            }
        }
    }

    if (ret == 1) {
        /* convert sig from ECDSA_SIG to DER */
        sigDerPtr = sigDer; /* i2d_ECDSA_SIG advances sigDerPtr */
        sigDerSz = i2d_ECDSA_SIG(sig, &sigDerPtr);
        if (sigDerSz == 0) {
            WOLFENGINE_ERROR_FUNC(WE_LOG_PK, "i2d_ECDSA_SIG", sigDerSz);
            ret = -1;
        }
    }

    if (ret == 1) {
        rc = wc_ecc_verify_hash(sigDer, sigDerSz, d, dlen, &check_sig, &we_key);
        if (rc != 0) {
            WOLFENGINE_ERROR_FUNC(WE_LOG_PK, "wc_ecc_verify_hash", rc);
            ret = -1;
        }
    }

    if (ret == 1) {
        /* Verification result is 1 on success and 0 on failure */
        if (check_sig == 0) {
            WOLFENGINE_MSG(WE_LOG_PK, "Failed to verify ECDSA signature");
            ret = 0;   /* invalid signature, no other errors */
        }
        else {
            WOLFENGINE_MSG(WE_LOG_PK, "Successfully verified ECDSA signature");
        }
    }

    wc_ecc_free(&we_key);
    if (sigDer != NULL) {
        OPENSSL_free(sigDer);
    }

    WOLFENGINE_LEAVE(WE_LOG_PK, "we_ecdsa_do_verify", ret);

    return ret;
}

#endif /* WE_HAVE_ECDSA | WE_HAVE_EC_KEY */

#ifdef WE_HAVE_EC_KEY
/**
 * Sign data with a private EC key.
 *
 * @param  type    [in]      Type of EC key. Ignored.
 * @param  dgst    [in]      Digest to be signed.
 * @param  dLen    [in]      Length of digest.
 * @param  sig     [in]      Buffer to hold signature data.
 *                           NULL indicates length of signature requested.
 * @param  sigLen  [in/out]  Length of signature buffer.
 * @param  kInv    [in]      Big number holding inverse of k. Ignored.
 * @param  r       [in]      Big number holding an r sig value. Ignored.
 * @parma  ecKey   [in]      EC key object.
 * @returns  1 on success and 0 on failure.
 */
static int we_ec_key_sign(int type, const unsigned char *dgst, int dLen,
                          unsigned char *sig, unsigned int *sigLen,
                          const BIGNUM *kinv, const BIGNUM *r, EC_KEY *ecKey)
{
    int ret, rc;
    ecc_key key;
    ecc_key *pKey = NULL;
#ifndef WE_ECC_USE_GLOBAL_RNG
    WC_RNG rng;
    WC_RNG *pRng = NULL;
#else
    WC_RNG *pRng = we_rng;
#endif
    const EC_GROUP *group;
    int curveId;
    word32 outLen;

    WOLFENGINE_ENTER(WE_LOG_PK, "we_ec_key_sign");
    WOLFENGINE_MSG_VERBOSE(WE_LOG_PK, "ARGS [type = %d, dgst = %p, dLen = %d, "
                           "sig = %p, sigLen = %p, kinv = %p, r = %p, "
                           "ecKey = %p]", type, dgst, dLen, sig, sigLen,
                           kinv, r, ecKey);
    (void)type;
    (void)kinv;
    (void)r;

    /* Get wolfSSL curve id for EC group. */
    group = EC_KEY_get0_group(ecKey);
    ret = we_ec_get_curve_id(EC_GROUP_get_curve_name(group), &curveId);
    if (ret == 1 && (rc = we_ecc_check_curve_usage(curveId)) != 1) {
        WOLFENGINE_ERROR_FUNC(WE_LOG_PK, "we_ecc_check_curve_usage", rc);
        ret = 0;
    }
    if (ret == 1) {
        /* Initialize a wolfSSL key object. */
        rc = wc_ecc_init(&key);
        if (rc != 0) {
            WOLFENGINE_ERROR_FUNC(WE_LOG_PK, "we_ecc_init", rc);
            ret = 0;
        }
    }
    if (ret == 1) {
        pKey = &key;

#ifndef WE_ECC_USE_GLOBAL_RNG
        rc = wc_InitRng(&rng);
        if (rc != 0) {
            ret = 0;
        }
        else {
            pRng = &rng;
        }
    }
    if (ret == 1) {
#endif
        /* Set private key into wolfSSL key object. */
        ret = we_ec_set_private(&key, curveId, ecKey);
    }

    if (ret == 1 && sig == NULL) {
        /* Return signature size in bytes. */
        *sigLen = wc_ecc_sig_size(&key);
        WOLFENGINE_MSG(WE_LOG_PK, "sig is NULL, returning size: %zu", *sigLen);
    }
    if (ret == 1 && sig != NULL) {
        /* Sign hash with wolfSSL. */
        outLen = *sigLen;
#if defined(WE_ECC_USE_GLOBAL_RNG) && !defined(WE_SINGLE_THREADED)
        rc = wc_LockMutex(we_rng_mutex);
        if (rc != 0) {
            WOLFENGINE_ERROR_FUNC(WE_LOG_PK, "wc_LockMutex", rc);
            ret = 0;
        }
        else
#endif
        {
            rc = wc_ecc_sign_hash(dgst, dLen, sig, &outLen, pRng, &key);
        #if defined(WE_ECC_USE_GLOBAL_RNG) && !defined(WE_SINGLE_THREADED)
            wc_UnLockMutex(we_rng_mutex);
        #endif
            if (rc != 0) {
                WOLFENGINE_ERROR_FUNC(WE_LOG_PK, "wc_ecc_sign_hash", rc);
                ret = 0;
            }
            if (ret == 1) {
                /* Return actual size. */
                *sigLen = outLen;
                WOLFENGINE_MSG_VERBOSE(WE_LOG_PK, "Generated ECDSA signature:");
                WOLFENGINE_BUFFER(WE_LOG_PK, sig, *sigLen);
            }
        }
    }

#ifndef WE_ECC_USE_GLOBAL_RNG
    wc_FreeRng(pRng);
#endif
    wc_ecc_free(pKey);

    WOLFENGINE_LEAVE(WE_LOG_PK, "we_ec_key_sign", ret);

    return ret;
}


/**
 * Verify data with a public EC key.
 *
 * @param  type    [in]  Type of EC key. Ignored.
 * @param  dgst    [in]  Digest to be verified.
 * @param  dLen    [in]  Length of digest.
 * @param  sig     [in]  Signature data.
 * @param  sigLen  [in]  Length of signature data.
 * @returns  1 on success and 0 on failure.
 */
static int we_ec_key_verify(int type, const unsigned char *dgst, int dLen,
                            const unsigned char *sig, int sigLen, EC_KEY *ecKey)
{
    int ret, rc;
    int res;
    ecc_key key;
    ecc_key *pKey = NULL;
    const EC_GROUP *group;
    int curveId;

    WOLFENGINE_ENTER(WE_LOG_PK, "we_ec_key_verify");
    WOLFENGINE_MSG_VERBOSE(WE_LOG_PK, "ARGS [type = %d, dgst = %p, dLen = %d, "
                           "sig = %p, sigLen = %d, ecKey = %p]", type, dgst,
                           dLen, sig, sigLen, ecKey);
    (void)type;

    /* Get wolfSSL curve id for EC group. */
    group = EC_KEY_get0_group(ecKey);
    ret = we_ec_get_curve_id(EC_GROUP_get_curve_name(group), &curveId);
    if (ret == 1) {
        /* Initialize a wolfSSL key object. */
        rc = wc_ecc_init(&key);
        if (rc != 0) {
            WOLFENGINE_ERROR_FUNC(WE_LOG_PK, "wc_ecc_init", rc);
            ret = 0;
        }
    }
    if (ret == 1) {
        pKey = &key;

        /* Set public key into wolfSSL key object. */
        ret = we_ec_set_public(&key, curveId, ecKey);
    }
    if (ret == 1) {
        /* Verify hash with wolfSSL. */
        rc = wc_ecc_verify_hash(sig, sigLen, dgst, dLen, &res, &key);
        if (rc != 0) {
            WOLFENGINE_ERROR_FUNC(WE_LOG_PK, "wc_ecc_verify_hash", rc);
            ret = 0;
        }
    }
    if (ret == 1) {
        /* Verification result is 1 on success and 0 on failure. */
        ret = res;

        if (ret == 1) {
            WOLFENGINE_MSG(WE_LOG_PK, "Successfully verified ECDSA signature");
        }
        else {
            WOLFENGINE_MSG(WE_LOG_PK, "Failed to verify ECDSA signature");
        }
    }

    wc_ecc_free(pKey);

    WOLFENGINE_LEAVE(WE_LOG_PK, "we_ec_key_verify", ret);

    return ret;
}

/**
 * Initialize the ECC method.
 *
 * @return  1 on success and 0 on failure.
 */
int we_init_ec_key_meths(void)
{
    int ret = 1;

    WOLFENGINE_ENTER(WE_LOG_PK, "we_init_ec_key_meths");

    we_ec_key_method = EC_KEY_METHOD_new(NULL);
    if (we_ec_key_method == NULL) {
        WOLFENGINE_ERROR_FUNC_NULL(WE_LOG_PK,
                                   "EC_KEY_METHOD_new", we_ec_key_method);
        ret = 0;
    }
    else {
        EC_KEY_METHOD_set_keygen(we_ec_key_method, we_ec_key_keygen);
        EC_KEY_METHOD_set_compute_key(we_ec_key_method, we_ec_key_compute_key);
        EC_KEY_METHOD_set_sign(we_ec_key_method, we_ec_key_sign,
                               we_ecdsa_sign_setup, we_ecdsa_do_sign_ex);
        EC_KEY_METHOD_set_verify(we_ec_key_method, we_ec_key_verify,
                                 we_ecdsa_do_verify);
    }

    WOLFENGINE_LEAVE(WE_LOG_PK, "we_init_ec_key_meths", ret);

    return ret;
}
#endif /* WE_HAVE_EC_KEY */

#if OPENSSL_VERSION_NUMBER < 0x10100000L
#ifdef WE_HAVE_ECDH

/** ECDH method - ECDH using wolfSSL for the implementation. */
ECDH_METHOD *we_ecdh_method = NULL;

/*  struct ecdh_method is originally defined in openssl/crypt/ecdh/ecdh_locl.h.
 *  However, the file is not installed along with openssl installation.
 *  ECDH_METHOD_new function is not provided in openssl/ecdh.h.
 */
struct ecdh_method {
    const char *name;
    int (*compute_key) (void *key, size_t outlen, const EC_POINT *pub_key,
                        EC_KEY *ecdh, void *(*KDF) (const void *in,
                                                    size_t inlen, void *out,
                                                    size_t *outlen));

    int flags;
    char *app_data;
};

/**
 * Compute shared secret with a private-key and a peer's public-key.
 * If key-derivation function is given, calls it with shared secret.
 *
 * @param  out     [in]  buffer to hold computed key.
 * @param  outlen  [in]  size of out buffer.
 * @param  pub_key [in]  peer's public key.
 * @param  ecdh    [in]  private key.
 * @param  KDF     [in]  Key-derivation function pointer
 * @returns the number of key bytes in buffer out on success and -1 on failure.
 */
static int we_ecdh_compute_key(void* out, size_t outlen,
                                const EC_POINT* pub_key, EC_KEY* ecdh,
                                void*(*KDF)(const void*in, size_t inlen,
                                    void*out, size_t* outlen))
{
    int  ret = 1;

    unsigned char* secret = NULL;
    size_t secretLen = 0;

    WOLFENGINE_ENTER(WE_LOG_KE, "we_ecdh_compute_key");
    WOLFENGINE_MSG_VERBOSE(WE_LOG_PK, "ARGS [out = %p, outlen = %zu, "
                           "pub_key = %p, ecdh = %p]", out, outlen,
                           pub_key, ecdh);

    if (out == NULL || outlen == 0 || pub_key == NULL || ecdh == NULL ) {
        WOLFENGINE_ERROR_MSG(WE_LOG_KE,
                             "we_ecdh_compute_key() bad function arguments");
        ret = -1;
    }

    if (ret != -1) {
        ret = we_ec_key_compute_key(&secret, &secretLen, pub_key,
                                                (const EC_KEY*)ecdh);
        if (ret == 0) {
            WOLFENGINE_ERROR_FUNC(WE_LOG_KE,
                                        "we_ec_key_compute_key", ret);
            ret = -1;
        }
    }
    if (ret != -1) {
        if (KDF) {
            if (KDF(secret, secretLen, out, &outlen)) {
                ret = (int)outlen;
            }
            else {
                WOLFENGINE_ERROR_FUNC(WE_LOG_KE, "KDF", ret);
                ret = -1;
            }
        }
        else {
            XMEMCPY(out, secret, MIN(outlen, secretLen));
            ret = MIN((int)outlen, (int)secretLen);
        }
    }

    if (secret != NULL) {
        OPENSSL_free(secret);
    }

    WOLFENGINE_LEAVE(WE_LOG_KE, "we_ecdh_compute_key", ret);
    return ret;
}

/**
 * Initialize the ECDH_METHOD structure.
 *
 * @return  1 on success and 0 on failure.
 */
int we_init_ecdh_meth(void)
{
    int ret = 1;

    WOLFENGINE_ENTER(WE_LOG_KE, "we_init_ecdh_meth");
    we_ecdh_method = (ECDH_METHOD*)OPENSSL_zalloc(sizeof(ECDH_METHOD));
    if (we_ecdh_method == NULL) {
        WOLFENGINE_ERROR_FUNC_NULL(WE_LOG_KE, "OPENSSL_zalloc",
                                            we_ecdh_method);
        ret = 0;
    }

    if (ret == 1) {
        we_ecdh_method->compute_key = we_ecdh_compute_key;
    }

    if (ret == 0 && we_ecdh_method != NULL) {
        OPENSSL_free(we_ecdh_method);
        we_ecdh_method = NULL;
    }

    WOLFENGINE_LEAVE(WE_LOG_KE, "we_init_ecdh_meth", ret);
    return ret;
}
#endif /* WE_HAVE_ECDH */
#endif /* OPENSSL_VERSION_NUMBER < 0x10100000L */

#ifdef WE_HAVE_ECDSA
#if OPENSSL_VERSION_NUMBER < 0x10100000L

/** ECDSA method - ECDSA using wolfSSL for the implementation. */
ECDSA_METHOD *we_ecdsa_method = NULL;

/**
 * Initialize the ECDSA method for use with the ECDSA API.
 *
 * @return  1 on success and 0 on failure.
 */
int we_init_ecdsa_meth(void)
{
    int ret = 1;

    we_ecdsa_method = ECDSA_METHOD_new(NULL);
    if (we_ecdsa_method == NULL) {
        WOLFENGINE_ERROR_FUNC_NULL(WE_LOG_PK,
                                    "ECDSA_METHOD_new", we_ecdsa_method);
        ret = 0;
    }

    if (ret == 1) {
        ECDSA_METHOD_set_sign(we_ecdsa_method, we_ecdsa_do_sign_ex);
        ECDSA_METHOD_set_sign_setup(we_ecdsa_method, we_ecdsa_sign_setup);
        ECDSA_METHOD_set_verify(we_ecdsa_method, we_ecdsa_do_verify);
    }

    if (ret == 0 && we_ecdsa_method != NULL) {
        ECDSA_METHOD_free(we_ecdsa_method);
        we_ecdsa_method = NULL;
    }

    return ret;
}

#endif /* OPENSSL_VERSION_NUMBER <= 0x100020ffL */
#endif /* WE_HAVE_ECDSA */

#endif /* WE_HAVE_ECC */
