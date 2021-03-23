/* ecc.c
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

#include "internal.h"

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
        ret = wc_ecc_import_private_key_ex(privBuf, (word32)privLen, NULL, 0,
                                           key, curveId) == 0;
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
    int ret;
    unsigned char *buf = NULL;
    unsigned char *d = NULL;

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
        ret = wc_ecc_export_private_raw(ecc, x, &xLen, y, &yLen, d, &dLen) == 0;
    }
    if (ret == 1) {
        /* Import public key. */
        buf[0] = ECC_POINT_UNCOMP;
        ret = EC_KEY_oct2key(key, buf, len * 2 + 1, NULL);
    }
    if (ret == 1) {
        /* Import private key. */
        ret = EC_KEY_oct2priv(key, d, len);
    }

    if (buf != NULL) {
        OPENSSL_clear_free(buf, len * 3 + 1);
    }

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
    /* OpenSSL group indicating EC parameters. */
    EC_GROUP      *group;
#endif
    /* Indicates private key has been set into wolfSSL structure. */
    int            privKeySet:1;
    /* Indicates public key has been set into wolfSSL structure. */
    int            pubKeySet:1;
} we_Ecc;

/**
 * Initialize and set the data required to complete an EC operation.
 *
 * @param  ctx  [in]  Public key context of operation.
 * @returns  1 on success and 0 on failure.
 */
static int we_ec_init(EVP_PKEY_CTX *ctx)
{
    int ret;
    we_Ecc *ecc;
    int keyInited = 0;

    WOLFENGINE_MSG("ECC - Init");

    /* Allocate a new internal EC object. */
    ret = (ecc = (we_Ecc*)OPENSSL_zalloc(sizeof(we_Ecc))) != NULL;
    if (ret == 1) {
        /* Initialize the wolfSSL key object. */
        ret = wc_ecc_init(&ecc->key) == 0;
        if (ret == 1) {
            keyInited = 1;
        }
    }
#if !defined(HAVE_FIPS) || \
    (defined(HAVE_FIPS_VERSION) && HAVE_FIPS_VERSION != 2)
    if (ret == 1) {
        /* Set the random number generator for use in EC operations. */
        ret = wc_ecc_set_rng(&ecc->key, we_rng) == 0;
    }
#endif /* !HAVE_FIPS || (HAVE_FIPS_VERSION && HAVE_FIPS_VERSION != 2) */
    if (ret == 1) {
        /* Set this key object to be returned when performing operations. */
        EVP_PKEY_CTX_set_data(ctx, ecc);
    }

    if (ret == 0 && ecc != NULL) {
        /* Make sure wolfSSL EC key is freed if initialized. */
        if (keyInited) {
            wc_ecc_free(&ecc->key);
        }
        /* Failed - free allocated data. */
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

    WOLFENGINE_MSG("ECC - Init P256");

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
            wc_ecc_free(&ecc->key);
            OPENSSL_free(ecc);
            ret = 0;
        }
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

    WOLFENGINE_MSG("ECC - Init P384");

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
            wc_ecc_free(&ecc->key);
            OPENSSL_free(ecc);
            ret = 0;
        }
    }

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
    WOLFENGINE_MSG("ECC - Copy");

    /* Nothing to copy as src is empty. */
    (void)src;
    (void)dst;

    return 1;
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
        ret = (group = EC_KEY_get0_group(*ecKey)) != NULL;
    }
    if (ret == 1) {
        /* Set the curve id into internal EC key object. */
        ret = we_ec_get_curve_id(EC_GROUP_get_curve_name(group),
                                  &ecc->curveId);
    }

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
static int we_ecdsa_sign(EVP_PKEY_CTX *ctx, unsigned char *sig, size_t *sigLen,
                         const unsigned char *tbs, size_t tbsLen)
{
    int ret;
    word32 outLen;
    we_Ecc *ecc;
    EC_KEY *ecKey = NULL;

    WOLFENGINE_MSG("ECDSA - Sign");

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

    if (ret == 1 && sig == NULL) {
        /* Return signature size in bytes. */
        *sigLen = wc_ecc_sig_size(&ecc->key);
    }
    if (ret == 1 && sig != NULL) {
        /* Sign the data with wolfSSL EC key object. */
        outLen = (word32)*sigLen;
        ret = wc_ecc_sign_hash(tbs, (word32)tbsLen, sig, &outLen, we_rng,
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
    if (ret == 1) {
        /* Verify the signature with the data using wolfSSL. */
        ret = wc_ecc_verify_hash(sig, (word32)sigLen, tbs, (word32)tbsLen, &res,
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

    WOLFENGINE_MSG("ECC - Key Gen");

    /* Get the internal EC key object. */
    ret = (ecc = (we_Ecc *)EVP_PKEY_CTX_get_data(ctx)) != NULL;
    if (ret == 1) {
        len = wc_ecc_get_curve_size_from_id(ecc->curveId);

        ctxPkey = EVP_PKEY_CTX_get0_pkey(ctx);
        /* May be NULL */

        /* New OpenSSL EC_KEY object to hold new key. */
        ret = (ecKey = EC_KEY_new()) != NULL;
    }

    if (ret == 1) {
        /* EVP_PKEY object needs an EC_KEY object. */
        ret = EVP_PKEY_assign_EC_KEY(pkey, ecKey);
        if (ret == 0) {
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
        ret = wc_ecc_make_key_ex(we_rng, len, &ecc->key, ecc->curveId) == 0;
    }
    if (ret == 1) {
        /* Private key and public key in wolfSSL object. */
        ecc->privKeySet = 1;
        ecc->pubKeySet = 1;

        /* Export new key into EC_KEY object. */
        ret = we_ec_export_key(&ecc->key, len, ecKey);
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
    word32 len = (word32)*keyLen;
    ecc_key peer;

    WOLFENGINE_MSG("ECDH - Derive");

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

    if (ret == 1 && key == NULL) {
        /* Return secret size in bytes. */
        *keyLen = wc_ecc_get_curve_size_from_id(ecc->curveId);
    }
    if (ret == 1 && key != NULL) {
        /* Create a new wolfSSL ECC key and set peer's public key. */
        ret = wc_ecc_init(&peer) == 0;
        if (ret == 1) {
            /* Format of peer's public key point:
             *   0x04 | x | y - x and y ordinates are equal length.
             */
            unsigned char *x = ecc->peerKey + 1;
            unsigned char *y = x + ((ecc->peerKeyLen - 1) / 2);

            /* Import public key into wolfSSL object. */
            ret = wc_ecc_import_unsigned(&peer, x, y, NULL, ecc->curveId) == 0;
            if (ret == 1) {
                /* Calculate shared secret using wolfSSL. */
                ret = wc_ecc_shared_secret(&ecc->key, &peer, key, &len) == 0;
            }
            if (ret == 1) {
                /* Return length of secret. */
                *keyLen = len;
            }

            /* Free the temporary peer key. */
            wc_ecc_free(&peer);
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
#ifdef WE_HAVE_ECDH
    EVP_PKEY *peerKey;
    EC_KEY *ecPeerKey = NULL;
#endif

    (void)num;
    (void)ptr;

    WOLFENGINE_MSG("ECC - Ctrl");

    ecc = (we_Ecc *)EVP_PKEY_CTX_get_data(ctx);
    if (ecc == NULL)
        ret = 0;

    if (ret == 1) {
        switch (type) {
        #ifdef WE_HAVE_ECDSA
            /* Keep a copy of the digest object. */
            case EVP_PKEY_CTRL_MD:
                ecc->md = (EVP_MD*)ptr;
                break;

            /* Initialize digest. */
            case EVP_PKEY_CTRL_DIGESTINIT:
                break;
        #endif

        #ifdef WE_HAVE_ECKEYGEN
            /* Set the group to use. */
            case EVP_PKEY_CTRL_EC_PARAMGEN_CURVE_NID:
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
                        ret = 0;
                    }
                }
                break;
        #endif

            /* Unsupported type. */
            default:
                ret = 0;
                break;
        }
    }

    return ret;
}

/** EVP public key method - EC using wolfSSL for the implementation. */
EVP_PKEY_METHOD *we_ec_method = NULL;
#ifdef WE_HAVE_ECKEYGEN
#ifdef WE_HAVE_EC_P256
/** EVP public key method - EC P-256 using wolfSSL for the implementation. */
EVP_PKEY_METHOD *we_ec_p256_method = NULL;
#endif
#ifdef WE_HAVE_EC_P384
/** EVP public key method - EC P-384 using wolfSSL for the implementation. */
EVP_PKEY_METHOD *we_ec_p384_method = NULL;
#endif
#endif

/**
 * Initialize the ECC method.
 *
 * @return  1 on success and 0 on failure.
 */
int we_init_ecc_meths(void)
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
    int ret = 1;
    int curveId;
    ecc_key ecc;
    ecc_key* pEcc = NULL;
    int len = 0;

    WOLFENGINE_MSG("EC - Key Generation");

    /* Get the wolfSSL EC curve id for the group. */
    ret = we_ec_get_curve_id(EC_GROUP_get_curve_name(EC_KEY_get0_group(key)),
                             &curveId);
    if (ret == 1) {
        len = wc_ecc_get_curve_size_from_id(curveId);

        /* Initialize a wolfSSL EC key object. */
        ret = wc_ecc_init(&ecc) == 0;
    }
    if (ret == 1) {
        pEcc = &ecc;

        /* Generate key. */
        ret = wc_ecc_make_key_ex(we_rng, len, &ecc, curveId) == 0;
    }
    if (ret == 1) {
        /* Export new key into EC_KEY object. */
        ret = we_ec_export_key(&ecc, len, key);
    }

    wc_ecc_free(pEcc);

    return ret;
}

/**
 * Compute the EC secret for ECDH using wolfSSL.
 *
 * @param  psec     [out]  Pointer to buffer holding secret. Allocated with
 *                         OPENSSL_malloc().
 * @param  pseclen  [out]  Pointer to length of secret.
 * @param  pub_key  [in]   Public EC point from peer.
 * @param  ecdh     [in]   EC KEY with private key.
 */
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

    /* Get wolfSSL curve id for EC group. */
    group = EC_KEY_get0_group(ecdh);
    ret = we_ec_get_curve_id(EC_GROUP_get_curve_name(group), &curveId);
    if (ret == 1) {
        peerKeyLen = (int)EC_POINT_point2buf(group, pub_key,
                                             POINT_CONVERSION_UNCOMPRESSED,
                                             &peerKey, NULL);
        ret = peerKey != NULL;
    }
    if (ret == 1) {
        len = wc_ecc_get_curve_size_from_id(curveId);

        /* Allocate the buffer to hold secret. Freed externally. */
        ret = (secret = (unsigned char *)OPENSSL_malloc(len)) != NULL;
    }
    if (ret == 1) {
        /* Initialize the wolfSSL private key object. */
        ret = wc_ecc_init(&key) == 0;
    }
#if !defined(HAVE_FIPS) || \
    (defined(HAVE_FIPS_VERSION) && HAVE_FIPS_VERSION != 2)
    if (ret == 1) {
        /* Set RNG for side-channel resistant code. */
        ret = wc_ecc_set_rng(&key, we_rng) == 0;
    }
#endif /* !HAVE_FIPS || (HAVE_FIPS_VERSION && HAVE_FIPS_VERSION != 2) */
    if (ret == 1) {
        pKey = &key;

        /* Set private key into wolfSSL key object. */
        ret = we_ec_set_private(pKey, curveId, ecdh);
    }
    if (ret == 1) {
        /* Initialize wolfSSL ECC key for peer's public key. */
        ret = wc_ecc_init(&peer) == 0;
    }
    if (ret == 1) {
        unsigned char *x = peerKey + 1;
        unsigned char *y = x + ((peerKeyLen - 1) / 2);

        pPeer = &peer;

        /* Import the public point into wolfSSL key object. */
        ret = wc_ecc_import_unsigned(pPeer, x, y, NULL, curveId) == 0;
    }
    if (ret == 1) {
        /* Calculate shared secret. */
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

    /* Get wolfSSL curve id for EC group. */
    group = EC_KEY_get0_group(ecKey);
    ret = we_ec_get_curve_id(EC_GROUP_get_curve_name(group), &curveId);
    if (ret == 1) {
        /* Initialize a wolfSSL key object. */
        ret = wc_ecc_init(&key) == 0;
    }
    if (ret == 1) {
        pKey = &key;

        /* Set private key into wolfSSL key object. */
        ret = we_ec_set_private(&key, curveId, ecKey);
    }

    if (ret == 1 && sig == NULL) {
        /* Return signature size in bytes. */
        *sigLen = wc_ecc_sig_size(&key);
    }
    if (ret == 1 && sig != NULL) {
        /* Sign hash with wolfSSL. */
        outLen = *sigLen;
        ret = wc_ecc_sign_hash(dgst, dLen, sig, &outLen, we_rng, &key) == 0;
        if (ret == 1) {
            /* Return actual size. */
            *sigLen = outLen;
        }
    }

    wc_ecc_free(pKey);

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
    int ret;
    int res;
    ecc_key key;
    ecc_key *pKey = NULL;
    const EC_GROUP *group;
    int curveId;

    WOLFENGINE_MSG("ECDSA - Verify");

    (void)type;

    /* Get wolfSSL curve id for EC group. */
    group = EC_KEY_get0_group(ecKey);
    ret = we_ec_get_curve_id(EC_GROUP_get_curve_name(group), &curveId);
    if (ret == 1) {
        /* Initialize a wolfSSL key object. */
        ret = wc_ecc_init(&key) == 0;
    }
    if (ret == 1) {
        pKey = &key;

        /* Set public key into wolfSSL key object. */
        ret = we_ec_set_public(&key, curveId, ecKey);
    }
    if (ret == 1) {
        /* Verify hash with wolfSSL. */
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
int we_init_ec_key_meths(void)
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

#endif /* WE_HAVE_EC_KEY */
#endif /* WE_HAVE_ECC */

