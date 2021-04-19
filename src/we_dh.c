/* we_dh.c
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

#ifdef WE_HAVE_DH

#define DEFAULT_PRIME_LEN 1024

/**
 * Data required to complete DH operations.
 */
typedef struct we_Dh
{
    /** wolfSSL structure for holding DH key data. */
    DhKey key;
#ifndef WE_SINGLE_THREADED
    /** wolfSSL random number generator. */
    WC_RNG rng;
#endif
    /** Length of prime ("p") in bits. */
    int primeLen;
    /** Byte buffer containing the value of group prime "q". */
    unsigned char *q;
    /** Length of "q" in bytes. */
    int qLen;
} we_Dh;

/** DH key method - DH using wolfSSL for the implementation. */
DH_METHOD *we_dh_method = NULL;


/* Dispose of internal DH object.
 *
 * Assumes that engineDh is not NULL.
 *
 * @param  engineDh  [in]  Internal DH object.
 */
static void we_dh_free_int(we_Dh *engineDh)
{
    WOLFENGINE_ENTER(WE_LOG_KE, "we_dh_free_int");

    /* Dispose of cached q used when checking public key. */
    if (engineDh->q != NULL) {
        OPENSSL_free(engineDh->q);
    }
    /* Free the wolfSSL key, RNG and internal DH object. */
#ifndef WE_SINGLE_THREADED
    wc_FreeRng(&engineDh->rng);
#endif
    wc_FreeDhKey(&engineDh->key);
    OPENSSL_free(engineDh);

    WOLFENGINE_LEAVE(WE_LOG_KE, "we_dh_free_int", 1);
}

/**
 * Initialize internal DH object.
 *
 * @param  dh  [out]  Internal DH object.
 * @returns  1 on success and 0 on failure.
 */
static int we_dh_init_int(we_Dh **dh)
{
    int ret = 1;
    int rc;
    we_Dh *engineDh;

    WOLFENGINE_ENTER(WE_LOG_KE, "we_dh_init_int");

    /* Allocate memory for internal DH object. */
    engineDh = (we_Dh *)OPENSSL_zalloc(sizeof(we_Dh));
    if (engineDh == NULL) {
        WOLFENGINE_ERROR_FUNC_NULL(WE_LOG_KE, "OPENSSL_zalloc", engineDh);
        ret = 0;
    }

    if (ret == 1) {
        WOLFENGINE_MSG(WE_LOG_KE, "Initializing wolfCrypt DhKey structure: %p",
                       &engineDh->key);
        /* Initialize the wolfSSL DH key. */
        rc = wc_InitDhKey(&engineDh->key);
        if (rc != 0) {
            WOLFENGINE_ERROR_FUNC(WE_LOG_KE, "wc_InitDhKey", rc);
            ret = 0;
        }
        /* Set the default prime length for parameter generation. */
        engineDh->primeLen = DEFAULT_PRIME_LEN;
        WOLFENGINE_MSG(WE_LOG_KE, "Setting DH prime length to %d",
                       DEFAULT_PRIME_LEN);
    }

#ifndef WE_SINGLE_THREADED
    if (ret == 1) {
        /* Initialize the random number generator for use in key and parameter
         * generation. */
        rc = wc_InitRng(&engineDh->rng);
        if (rc != 0) {
            WOLFENGINE_ERROR_FUNC(WE_LOG_KE, "wc_InitRng", rc);
            ret = 0;
        }
    }
#endif

    if ((ret == 0) && (engineDh != NULL)) {
        /* Free the wolfSSL key, RNG and internal DH object. */
        we_dh_free_int(engineDh);
        engineDh = NULL;
    }

    /* Return the internal DH object. */
    *dh = engineDh;

    WOLFENGINE_LEAVE(WE_LOG_KE, "we_dh_init_int", ret);

    return ret;
}

/**
 * Initialize and set the data required to complete DH operations.
 *
 * @param  dh  [in/out]  DH data structure.
 * @returns  1 on success and 0 on failure.
 */
static int we_dh_init(DH *dh)
{
    int ret;
    int rc;
    we_Dh *engineDh;

    WOLFENGINE_ENTER(WE_LOG_KE, "we_dh_init");
    WOLFENGINE_MSG_VERBOSE(WE_LOG_KE, "ARGS [dh = %p]", dh);

    /* Allocate and initialize the internal DH object. */
    ret = we_dh_init_int(&engineDh);
    if (ret == 1) {
        /* Store internal DH object in extra data. */
        rc = DH_set_ex_data(dh, WE_DH_EX_DATA_IDX, engineDh);
        if (rc != 1) {
            WOLFENGINE_ERROR_FUNC(WE_LOG_KE, "DH_set_ex_data", rc);
            ret = 0;
        }
    }

    if ((ret == 0) && (engineDh != NULL)) {
        /* Dispose of internal DH object. */
        we_dh_free_int(engineDh);
    }

    WOLFENGINE_LEAVE(WE_LOG_KE, "we_dh_init", ret);

    return ret;
}

/**
 * Clean up the DH data.
 *
 * @param  dh  [in]  DH data structure.
 * @returns  1 on success and 0 on failure.
 */
static int we_dh_finish(DH *dh)
{
    int ret = 1;
    we_Dh *engineDh = NULL;

    WOLFENGINE_ENTER(WE_LOG_KE, "we_dh_finish");
    WOLFENGINE_MSG_VERBOSE(WE_LOG_KE, "ARGS [dh = %p]", dh);

    /* Get the internal DH object. */
    engineDh = (we_Dh *)DH_get_ex_data(dh, WE_DH_EX_DATA_IDX);
    if (engineDh == NULL) {
        WOLFENGINE_ERROR_FUNC_NULL(WE_LOG_KE, "DH_get_ex_data", engineDh);
        ret = 0;
    }

    if (ret == 1) {
        /* Dispose of internal DH object now DH object finished. */
        we_dh_free_int(engineDh);
    }

    WOLFENGINE_LEAVE(WE_LOG_KE, "we_dh_finish", ret);

    return ret;
}

/**
 * Encode an OpenSSL big number into an allocated byte array.
 *
 * @param  n     [in]   OpenSSL big number.
 * @param  pBuf  [out]  Buffer holding encoding.
 * @param  pLen  [out]  Length of data in buffer.
 * @returns  1 on success and 0 on failure.
 */
static int we_dh_bignum_to_bin(const BIGNUM *n, unsigned char **pBuf, int *pLen)
{
    int ret = 1;
    unsigned char *buf;
    int len;

    WOLFENGINE_ENTER(WE_LOG_KE, "we_dh_bignum_to_bin");

    /* Allocate buffer large enough to hold encoding. */
    buf = (unsigned char *)OPENSSL_malloc(BN_num_bytes(n));
    if (buf == NULL) {
        WOLFENGINE_ERROR_FUNC_NULL(WE_LOG_KE, "OPENSSL_malloc(buf)", buf);
        ret = 0;
    }

    if (ret == 1) {
        /* Encode big number into buffer. */
        len = BN_bn2bin(n, buf);
        if (len <= 0) {
            WOLFENGINE_ERROR_FUNC(WE_LOG_KE, "BN_bn2bin(len)", len);
            ret = 0;
        }
    }

    if (ret == 1) {
        /* Return buffer and length. */
        *pBuf = buf;
        *pLen = len;
    }

    /* Dispose of allocated buffer on error. */
    if ((ret == 0) && (buf != NULL)) {
        OPENSSL_free(buf);
    }

    WOLFENGINE_LEAVE(WE_LOG_KE, "we_dh_bignum_to_bin", ret);

    return ret;
}

/**
 * Take the p and g parameters from dh and convert and store them in the DhKey
 * owned by engineDh.
 *
 * Also retrieves the q parameter if set and caches it in engineDh.
 *
 * @param  dh        [in]   OpenSSL DH data structure.
 * @param  engineDh  [out]  wolfEngine DH object holding wolfSSL DhKey.
 * @returns  1 on success and 0 on failure.
 */
static int we_dh_set_parameters(const DH *dh, we_Dh *engineDh)
{
    int ret = 1;
    int rc;
    unsigned char *pBuf = NULL;
    int pBufLen = 0;
    unsigned char *gBuf = NULL;
    int gBufLen = 0;
    unsigned char *qBuf = NULL;
    int qBufLen = 0;

    WOLFENGINE_ENTER(WE_LOG_KE, "we_dh_set_parameters");
    WOLFENGINE_MSG_VERBOSE(WE_LOG_KE, "ARGS [dh = %p, engineDh = %p]",
                           dh, engineDh);

    /* Get p in byte array. */
    ret = we_dh_bignum_to_bin(DH_get0_p(dh), &pBuf, &pBufLen);
    if (ret == 1) {
        /* Get g in byte array. */
        ret = we_dh_bignum_to_bin(DH_get0_g(dh), &gBuf, &gBufLen);
    }
    /* Get q in byte array if set. */
    if ((ret == 1) && (DH_get0_q(dh) != NULL)) {
        ret = we_dh_bignum_to_bin(DH_get0_q(dh), &qBuf, &qBufLen);
        if (ret == 1) {
            /* Dispose of previously cached q. */
            if (engineDh->q != NULL) {
                OPENSSL_free(engineDh->q);
            }
            /* Cache q for checking public key. */
            engineDh->q = qBuf;
            engineDh->qLen = qBufLen;
        }
    }

    if (ret == 1) {
        /* Set p, g and q parameters into wolfSSL DH key. */
        rc = wc_DhSetKey_ex(&engineDh->key, pBuf, pBufLen, gBuf, gBufLen, qBuf,
                            qBufLen);
        if (rc != 0) {
            WOLFENGINE_ERROR_FUNC(WE_LOG_KE, "wc_DhSetKey_ex", rc);
            ret = 0;
        }
        else {
            WOLFENGINE_MSG_VERBOSE(WE_LOG_KE, "Set DH parameters");
        }
    }

    /* Dispose of allocated buffers.
     * q byte array cached in internal DH object for checking public key. */
    if (gBuf != NULL)
        OPENSSL_free(gBuf);
    if (pBuf != NULL)
        OPENSSL_free(pBuf);

    WOLFENGINE_LEAVE(WE_LOG_KE, "we_dh_set_parameters", ret);

    return ret;
}

/**
 * Internal function to generate a DH key pair.
 *
 * @param  dh        [in/out]  OpenSSL DH data to store result in. Also holds
 *                             parameters.
 * @param  engineDh  [in]      wolfEngine DH data. Holds DhKey used for key
 *                             generation.
 * @returns  1 on success and 0 on failure.
 */
static int we_dh_generate_key_int(DH *dh, we_Dh *engineDh)
{
    int ret = 1;
    int rc;
    unsigned char *priv = NULL;
    unsigned int privLen = 0;
    unsigned char *pub = NULL;
    unsigned int pubLen = 0;
    BIGNUM *privBn = NULL;
    BIGNUM *pubBn = NULL;
#ifndef WE_SINGLE_THREADED
    WC_RNG *pRng = &engineDh->rng;
#else
    WC_RNG *pRng = we_rng;
#endif

    WOLFENGINE_ENTER(WE_LOG_KE, "we_dh_generate_key_int");
    WOLFENGINE_MSG_VERBOSE(WE_LOG_KE, "ARGS [dh = %p, engineDh = %p]",
                           dh, engineDh);

    /* Public key is no larger than the prime. */
    pubLen = BN_num_bytes(DH_get0_p(dh));
    if (DH_get_length(dh) != 0) {
        /* Convert bits to bytes - add some so buffer is big enough. */
        privLen = (unsigned int)(DH_get_length(dh) / 8 + 8);
    }
    else {
        privLen = pubLen;
    }

    /* Set parameters in engineDh. */
    rc = we_dh_set_parameters(dh, engineDh);
    if (rc != 1) {
        WOLFENGINE_ERROR_FUNC(WE_LOG_KE, "we_dh_set_parameters", rc);
        ret = 0;
    }

    if (ret == 1) {
        /* Allocate memory for public key when generated. */
        pub = (unsigned char*)OPENSSL_malloc(pubLen);
        if (pub == NULL) {
            WOLFENGINE_ERROR_FUNC_NULL(WE_LOG_KE, "OPENSSL_malloc", pub);
            ret = 0;
        }
    }
    if (ret == 1) {
        /* Allocate memory for private key when generated. */
        priv = (unsigned char*)OPENSSL_malloc(privLen);
        if (priv == NULL) {
            WOLFENGINE_ERROR_FUNC_NULL(WE_LOG_KE, "OPENSSL_malloc", priv);
            ret = 0;
        }
    }

    if (ret == 1) {
        /* Generate public/private key pair with wolfSSL. */
        rc = wc_DhGenerateKeyPair(&engineDh->key, pRng, priv, &privLen, pub,
                                  &pubLen);
        if (rc != 0) {
            WOLFENGINE_ERROR_FUNC(WE_LOG_KE, "wc_DhGenerateKeyPair", rc);
            ret = 0;
        }
    }

    if (ret == 1) {
        WOLFENGINE_MSG(WE_LOG_KE, "Generated DH key pair");
        /* Convert private key byte array into a new OpenSSL big number. */
        privBn = BN_bin2bn(priv, privLen, NULL);
        if (privBn == NULL) {
            WOLFENGINE_ERROR_FUNC_NULL(WE_LOG_KE, "BN_bin2bn", privBn);
            ret = 0;
        }
    }

    if (ret == 1) {
        /* Convert public key byte array into a new OpenSSL big number. */
        pubBn = BN_bin2bn(pub, pubLen, NULL);
        if (pubBn == NULL) {
            WOLFENGINE_ERROR_FUNC_NULL(WE_LOG_KE, "BN_bin2bn", pubBn);
            ret = 0;
        }
    }

    if (ret == 1) {
        /* Assign the big numbers in OpenSSL DH object. */
        rc = DH_set0_key(dh, pubBn, privBn);
        if (rc != 1) {
            WOLFENGINE_ERROR_FUNC(WE_LOG_KE, "DH_set0_key", rc);
            ret = 0;
        }
        else {
            /* Big numbers not to be freed - assigned to DH object. */
            privBn = NULL;
            pubBn = NULL;
        }
    }

    /* Dispose of allocate memory securely. */
    if (pubBn != NULL) {
        BN_free(pubBn);
    }
    if (privBn != NULL) {
        BN_clear_free(privBn);
    }
    if (priv != NULL) {
        OPENSSL_clear_free(priv, privLen);
    }
    if (pub != NULL) {
        OPENSSL_free(pub);
    }

    WOLFENGINE_LEAVE(WE_LOG_KE, "we_dh_generate_key_int", ret);

    return ret;
}

/**
 * Generate DH private and public keys using the parameters in dh and store
 * them in dh.
 *
 * @param  dh  [in/out]  DH data structure.
 * @returns  1 on success and 0 on failure.
 */
static int we_dh_generate_key(DH *dh)
{
    int ret = 1;
    we_Dh *engineDh = NULL;

    WOLFENGINE_ENTER(WE_LOG_KE, "we_dh_generate_key");
    WOLFENGINE_MSG_VERBOSE(WE_LOG_KE, "ARGS [dh = %p]", dh);

    /* Retrieve the internal DH object. */
    engineDh = (we_Dh *)DH_get_ex_data(dh, WE_DH_EX_DATA_IDX);
    if (engineDh == NULL) {
        WOLFENGINE_ERROR_FUNC_NULL(WE_LOG_KE, "DH_get_ex_data", engineDh);
        ret = 0;
    }

    if (ret == 1) {
        /* Generate the DH public/private key pair. */
        ret = we_dh_generate_key_int(dh, engineDh);
        if (ret == 0) {
            WOLFENGINE_ERROR_FUNC(WE_LOG_KE, "we_dh_generate_key_int", ret);
        }
    }

    WOLFENGINE_LEAVE(WE_LOG_KE, "we_dh_generate_key", ret);

    return ret;
}

/**
 * Internal function for computing a DH shared secret.
 *
 * @param  engineDh  [in]      wolfEngine DH data.
 * @param  secret    [out]     Buffer holding the shared secret.
 * @param  secret    [in.out]  Length of secret buffer on input, length of
                               secret written on output.
 * @param  pubKey    [in]      Peer's public key.
 * @param  dh        [in]      DH data structure.
 * @returns  1 on success and 0 on failure.
 */
static int we_dh_compute_key_int(we_Dh *engineDh, unsigned char *secret,
                                 size_t *secretLen, const BIGNUM *pubKey,
                                 DH *dh)
{
    int ret = 1;
    int rc;
    unsigned char *pubBuf = NULL;
    int pubLen = 0;
    unsigned char *privBuf = NULL;
    int privLen = 0;
    unsigned int secLen = 0;

    WOLFENGINE_ENTER(WE_LOG_KE, "we_dh_compute_key_int");
    WOLFENGINE_MSG_VERBOSE(WE_LOG_KE, "ARGS [engineDh = %p, secret = %p, "
                           "secretLen = %p, pubKey = %p, dh = %p]",
                           engineDh, secret, secretLen, pubKey, dh);

    /* Set parameters into engineDH. */
    rc = we_dh_set_parameters(dh, engineDh);
    if (rc != 1) {
        WOLFENGINE_ERROR_FUNC(WE_LOG_KE, "we_dh_set_parameters", rc);
        ret = 0;
    }

    if (ret == 1) {
        /* Convert peer's public key to a byte array. */
        ret = we_dh_bignum_to_bin(pubKey, &pubBuf, &pubLen);
    }
    if (ret == 1) {
        WOLFENGINE_MSG(WE_LOG_KE, "Set DH parameters into DH struct");
        /* Check the public key is valid. */
        rc = wc_DhCheckPubKey_ex(&engineDh->key, pubBuf, pubLen, engineDh->q,
                                 engineDh->qLen);
        if (rc != 0) {
            WOLFENGINE_ERROR_FUNC(WE_LOG_KE, "wc_DhCheckPubKey", rc);
            ret = 0;
        }
        else {
            WOLFENGINE_MSG(WE_LOG_KE, "Validated DH public key");
        }
    }

    if (ret == 1) {
        /* Convert our private key to a byte array. */
        ret = we_dh_bignum_to_bin(DH_get0_priv_key(dh), &privBuf, &privLen);
    }

    if (ret == 1) {
        /* Set length of secret buffer into appropriate typed variable. */
        secLen = (unsigned int)*secretLen;
        /* Calculate the secret. */
        rc = wc_DhAgree(&engineDh->key, secret, &secLen, privBuf, privLen,
                         pubBuf, pubLen);
        if (rc != 0) {
            WOLFENGINE_ERROR_FUNC(WE_LOG_KE, "wc_DhAgree", rc);
            ret = 0;
        }
        else {
            WOLFENGINE_MSG(WE_LOG_KE, "Generated DH shared secret");
            /* Return the secret length. */
            *secretLen = secLen;
        }
    }

    /* Dispose of allocated data securely. */
    if (pubBuf != NULL) {
        OPENSSL_free(pubBuf);
    }
    if (privBuf != NULL) {
        OPENSSL_clear_free(privBuf, privLen);
    }

    WOLFENGINE_LEAVE(WE_LOG_KE, "we_dh_compute_key_int", ret);

    return ret;
}

/**
 * Compute a DH shared secret using the private key in dh and the peer's public
 * key in pubKey. Store the result in secret.
 *
 * @param  secret  [out]  Buffer holding the shared secret.
 * @param  pubKey  [in]   Peer's public key.
 * @param  dh      [in]   DH data structure.
 * @returns  Length of shared secret on success and -1 on failure.
 */
static int we_dh_compute_key(unsigned char *secret, const BIGNUM *pubKey,
                             DH *dh)
{
    int ret = 1;
    we_Dh *engineDh = NULL;
    size_t secretLen = 0;

    WOLFENGINE_ENTER(WE_LOG_KE, "we_compute_key");
    WOLFENGINE_MSG_VERBOSE(WE_LOG_KE, "ARGS [secret = %p, pubKey = %p, "
                           "dh = %p]", secret, pubKey, dh);

    /* Retrieve internal DH object. */
    engineDh = (we_Dh *)DH_get_ex_data(dh, WE_DH_EX_DATA_IDX);
    if (engineDh == NULL) {
        WOLFENGINE_ERROR_FUNC_NULL(WE_LOG_KE, "DH_get_ex_data", engineDh);
        ret = -1;
    }

    if (ret == 1) {
        /* Get maximim secret size. 'secret' assumed to be large enough. */
        secretLen = DH_size(dh);
        /* Compute the secret from peer's public key. */
        ret = we_dh_compute_key_int(engineDh, secret, &secretLen, pubKey, dh);
        if (ret == 0) {
            WOLFENGINE_ERROR_FUNC(WE_LOG_KE, "we_dh_compute_key_int", ret);
            ret = -1;
        }
        else {
            WOLFENGINE_MSG(WE_LOG_KE, "Generated secret, len = %d", secretLen);
            /* Return the size of the calculated secret. */
            ret = (int)secretLen;
        }
    }

    WOLFENGINE_LEAVE(WE_LOG_KE, "we_compute_key", ret);
    (void)ret;

    return ret;
}

/**
 * Take DH parameters from a wolfSSL DhKey and store them in an OpenSSL DH.
 *
 * @param  wolfDh   [in]   The wolfSSL DhKey to take the parameters from.
 * @param  osslDh   [out]  The OpenSSL DH to store the parameters in.
 * @returns  1 on success and 0 on failure.
 */
static int we_dh_convert_params(DhKey *wolfDh, DH *osslDh)
{
    int ret = 1;
    int rc;
    BIGNUM *pBn = NULL;
    BIGNUM *qBn = NULL;
    BIGNUM *gBn = NULL;
    unsigned char *p = NULL;
    unsigned int pLen = 0;
    unsigned char *g = NULL;
    unsigned int gLen = 0;
    unsigned char *q = NULL;
    unsigned int qLen = 0;

    WOLFENGINE_ENTER(WE_LOG_KE, "we_dh_convert_params");
    WOLFENGINE_MSG_VERBOSE(WE_LOG_KE, "ARGS [wolfDh = %p, osslDh = %p]",
                           wolfDh, osslDh);

    /* Call with NULL for the buffers to get required lengths. */
    rc = wc_DhExportParamsRaw(wolfDh, NULL, &pLen, NULL, &qLen, NULL, &gLen);
    if (rc != LENGTH_ONLY_E) {
        WOLFENGINE_ERROR_FUNC(WE_LOG_KE, "wc_DhExportParamsRaw", rc);
        ret = 0;
    }

    if (ret == 1) {
        /* Allocate buffer for prime. */
        p = (unsigned char*)OPENSSL_malloc(pLen);
        if (p == NULL) {
            WOLFENGINE_ERROR_FUNC_NULL(WE_LOG_KE, "OPENSSL_malloc(p)", p);
            ret = 0;
        }
    }
    if (ret == 1) {
        /* Allocate buffer for group prime. */
        q = (unsigned char*)OPENSSL_malloc(qLen);
        if (q == NULL) {
            WOLFENGINE_ERROR_FUNC_NULL(WE_LOG_KE, "OPENSSL_malloc(q)", q);
            ret = 0;
        }
    }
    if (ret == 1) {
        /* Allocate buffer for generator. */
        g = (unsigned char*)OPENSSL_malloc(pLen);
        if (g == NULL) {
            WOLFENGINE_ERROR_FUNC_NULL(WE_LOG_KE, "OPENSSL_malloc(g)", g);
            ret = 0;
        }
    }
    if (ret == 1) {
        WOLFENGINE_MSG(WE_LOG_KE, "Exporting raw DH params from DhKey struct");
        /* With buffers allocated, write the parameters. */
        rc = wc_DhExportParamsRaw(wolfDh, p, &pLen, q, &qLen, g, &gLen);
        if (rc != 0) {
            WOLFENGINE_ERROR_FUNC(WE_LOG_KE, "wc_DhExportParamsRaw", rc);
            ret = 0;
        }
    }

    /* Convert the parameter byte buffers to BIGNUMs to store in osslDh. */
    WOLFENGINE_MSG(WE_LOG_KE, "Converting paramters to BIGNUMs");
    if (ret == 1) {
        /* Allocate a big number and set value to be: Prime. */
        pBn = BN_bin2bn(p, pLen, NULL);
        if (pBn == NULL) {
            WOLFENGINE_ERROR_FUNC_NULL(WE_LOG_KE, "BN_bin2bn(pBn)", pBn);
            ret = 0;
        }
    }
    if (ret == 1) {
        /* Allocate a big number and set value to be: Group prime. */
        qBn = BN_bin2bn(q, qLen, NULL);
        if (qBn == NULL) {
            WOLFENGINE_ERROR_FUNC_NULL(WE_LOG_KE, "BN_bin2bn(qBn)", qBn);
            ret = 0;
        }
    }
    if (ret == 1) {
        /* Allocate a big number and set value to be: Generator. */
        gBn = BN_bin2bn(g, gLen, NULL);
        if (gBn == NULL) {
            WOLFENGINE_ERROR_FUNC_NULL(WE_LOG_KE, "BN_bin2bn(gBn)", gBn);
            ret = 0;
        }
    }
    if (ret == 1) {
        /* Assign prime, group prime and generator big numbers to DH. */
        rc = DH_set0_pqg(osslDh, pBn, qBn, gBn);
        if (rc != 1) {
            WOLFENGINE_ERROR_FUNC(WE_LOG_KE, "DH_set0_pqg", rc);
            ret = 0;
        }
        else {
            /* Big numbers assigned - don't free. */
            pBn = NULL;
            qBn = NULL;
            gBn = NULL;
        }
    }

    /* Dispose of allocated memory. */
    if (gBn != NULL) {
        BN_free(gBn);
    }
    if (qBn != NULL) {
        BN_free(qBn);
    }
    if (pBn != NULL) {
        BN_free(pBn);
    }
    if (g != NULL) {
        OPENSSL_free(g);
    }
    if (q != NULL) {
        OPENSSL_free(q);
    }
    if (p != NULL) {
        OPENSSL_free(p);
    }

    WOLFENGINE_LEAVE(WE_LOG_KE, "we_dh_convert_params", ret);

    return ret;
}

/**
 * Generate parameters for DH key pair generation.
 *
 * @param  dh        [out]   OpenSSL DH object.
 * @param  engineDh  [in]    Internal DH object.
 * @returns  1 on success and 0 on failure.
 */
static int we_dh_paramgen_int(DH *dh, we_Dh *engineDh)
{
    int ret = 1;
    int rc;
#ifndef WE_SINGLE_THREADED
    WC_RNG *pRng = &engineDh->rng;
#else
    WC_RNG *pRng = we_rng;
#endif

    WOLFENGINE_ENTER(WE_LOG_KE, "we_dh_paramgen_int");

    /* Generate the parameters. */
    rc = wc_DhGenerateParams(pRng, engineDh->primeLen, &engineDh->key);
    if (rc != 0) {
        WOLFENGINE_ERROR_FUNC(WE_LOG_KE, "we_dh_pkey_paramgen", rc);
        ret = 0;
    }

    if (ret == 1) {
        WOLFENGINE_MSG(WE_LOG_KE, "Converting DH params to OpenSSL DH");
        /* Convert the parameters from wolfSSL to OpenSSL data structure. */
        ret = we_dh_convert_params(&engineDh->key, dh);
    }

    WOLFENGINE_LEAVE(WE_LOG_KE, "we_dh_paramgen_int", ret);

    return ret;
}

/**
 * Generate parameters for DH key pair generation.
 *
 * @param  dh        [in,out]  OpenSSL DH object.
 * @param  primeLen  [in]      Length of prime.
 * @param  g         [in]      Generator to use. (ignored)
 * @param  cb        [in]      Callback to show generation progress. (ignored)
 * @returns  1 on success and 0 on failure.
 */
static int we_dh_generate_params(DH *dh, int primeLen, int g, BN_GENCB *cb)
{
    int ret = 1;
    we_Dh *engineDh;

    WOLFENGINE_ENTER(WE_LOG_KE, "we_dh_generate_parameters");
    WOLFENGINE_MSG_VERBOSE(WE_LOG_KE, "ARGS [dh = %p, primeLen = %d, g = %d, "
                           "cb = %p]", dh, primeLen, g, cb);

    /* Cannot set g or callback to wolfSSL parameter generation. */
    (void)g;
    (void)cb;

    /* Retrieve internal DH object. */
    engineDh = (we_Dh *)DH_get_ex_data(dh, WE_DH_EX_DATA_IDX);
    if (engineDh == NULL) {
        WOLFENGINE_ERROR_FUNC_NULL(WE_LOG_KE, "DH_get_ex_data", engineDh);
        ret = 0;
    }

    if (ret == 1) {
        engineDh->primeLen = primeLen;
        /* Generate the parameters with wolfSSL and copy into OpenSSL object. */
        ret = we_dh_paramgen_int(dh, engineDh);
    }

    WOLFENGINE_LEAVE(WE_LOG_KE, "we_dh_generate_parameters", ret);

    return ret;
}

/**
 * Initialize the DH method.
 *
 * @return  1 on success and 0 on failure.
 */
int we_init_dh_meth(void)
{
    int ret = 1;

    WOLFENGINE_ENTER(WE_LOG_KE, "we_init_dh_meth");

    /* Create a new DH method. */
    we_dh_method = DH_meth_new("wolfengine_dh", 0);
    if (we_dh_method == NULL) {
        WOLFENGINE_ERROR_FUNC_NULL(WE_LOG_KE, "DH_meth_new", we_dh_method);
        ret = 0;
    }

    if (ret == 1) {
        /* Set all the methods we want to support. */
        DH_meth_set_init(we_dh_method, we_dh_init);
        DH_meth_set_finish(we_dh_method, we_dh_finish);
        DH_meth_set_generate_key(we_dh_method, we_dh_generate_key);
        DH_meth_set_compute_key(we_dh_method, we_dh_compute_key);
        DH_meth_set_generate_params(we_dh_method, we_dh_generate_params);
    }

    /* No errors after allocation - no need to free method on error. */

    WOLFENGINE_LEAVE(WE_LOG_KE, "we_init_dh_meth", ret);

    return ret;
}

#ifdef WE_HAVE_EVP_PKEY

/** DH public key method - DH using wolfSSL for the implementation. */
EVP_PKEY_METHOD *we_dh_pkey_method = NULL;

/**
 * Initialize and set the data required to complete a DH operation.
 *
 * @param  ctx  [in]  Public key context of operation.
 * @returns  1 on success and 0 on failure.
 */
static int we_dh_pkey_init(EVP_PKEY_CTX *ctx)
{
    int ret = 1;
    we_Dh *dh;

    WOLFENGINE_ENTER(WE_LOG_KE, "we_dh_pkey_init");
    WOLFENGINE_MSG_VERBOSE(WE_LOG_KE, "ARGS [ctx = %p]", ctx);

    /* Allocate and initialize the internal DH object. */
    ret = we_dh_init_int(&dh);
    if (ret == 1) {
        /* Store internal DH object against context. */
        EVP_PKEY_CTX_set_data(ctx, dh);
    }

    if ((ret == 0) && (dh != NULL)) {
        /* Dispose of internal DH object. */
        we_dh_free_int(dh);
    }

    WOLFENGINE_LEAVE(WE_LOG_KE, "we_dh_pkey_init", ret);

    return ret;
}

/**
 * Clean up the DH operation data.
 *
 * @param  ctx  [in]  Public key context of operation.
 */
static void we_dh_pkey_cleanup(EVP_PKEY_CTX *ctx)
{
    /* Retrieve internal DH object. */
    we_Dh *dh = (we_Dh *)EVP_PKEY_CTX_get_data(ctx);

    WOLFENGINE_ENTER(WE_LOG_KE, "we_dh_pkey_cleanup");
    WOLFENGINE_MSG_VERBOSE(WE_LOG_KE, "ARGS [ctx = %p]", ctx);

    if (dh != NULL) {
        /* Free the wolfSSL key, RNG and internal DH object. */
        we_dh_free_int(dh);
    }

    WOLFENGINE_LEAVE(WE_LOG_KE, "we_dh_pkey_cleanup", 1);
}

/**
 * Extra operations for working with DH.
 * Supported operations include:
 *  - EVP_PKEY_CTRL_DH_PARAMGEN_PRIME_LEN: set the length of the prime, "p."
 *  - EVP_PKEY_CTRL_DH_PARAMGEN_GENERATOR: intended to set the generator, "g",
 *    but doesn't actually do this, as wolfCrypt doesn't allow you to specify
 *    the generator used in DH key creation.
 *  - EVP_PKEY_CTRL_PEER_KEY: intended to set the peer key, but doesn't actually
 *    do this, as we can get the peer key directly from the ctx when needed.
 *
 * @param  ctx   [in]  Public key context of operation.
 * @param  type  [in]  Type of operation to perform.
 * @param  num   [in]  Integer parameter.
 * @param  ptr   [in]  Pointer parameter.
 * @returns  1 on success and 0 on failure.
 */
static int we_dh_pkey_ctrl(EVP_PKEY_CTX *ctx, int type, int num, void *ptr)
{
    int ret = 1;
    we_Dh *dh = NULL;
    char errBuff[WOLFENGINE_MAX_LOG_WIDTH];

    (void)ptr;

    WOLFENGINE_ENTER(WE_LOG_KE, "we_dh_pkey_ctrl");
    WOLFENGINE_MSG_VERBOSE(WE_LOG_KE, "ARGS [ctx = %p, type = %d, num = %d, "
                           "ptr = %p", ctx, type, num, ptr);

    /* Retrieve internal DH object. */
    dh = (we_Dh *)EVP_PKEY_CTX_get_data(ctx);
    if (dh == NULL) {
        WOLFENGINE_ERROR_FUNC_NULL(WE_LOG_KE, "EVP_PKEY_CTX_get_data", dh);
        ret = 0;
    }

    if (ret == 1) {
        switch (type) {
            case EVP_PKEY_CTRL_DH_PARAMGEN_PRIME_LEN:
                /* num  [in]  Prime length. */
                WOLFENGINE_MSG(WE_LOG_KE,
                               "EVP_PKEY_CTRL_DH_PARAMGEN_PRIME_LEN");
                /* These are the sizes allowed by wolfCrypt. */
                if (num != 1024 && num != 2048 && num != 3072) {
                    WOLFENGINE_ERROR_MSG(WE_LOG_KE,
                                         "Invalid DH prime bit length.");
                    ret = 0;
                }
                else {
                    /* Cache prime length for parameter generation operation. */
                    dh->primeLen = num;
                    WOLFENGINE_MSG(WE_LOG_KE, "Setting DH prime len: %d", num);
                }
                break;
            case EVP_PKEY_CTRL_DH_PARAMGEN_GENERATOR:
                WOLFENGINE_MSG(WE_LOG_KE,
                               "EVP_PKEY_CTRL_DH_PARAMGEN_GENERATOR");
                WOLFENGINE_ERROR_MSG(WE_LOG_KE, "wolfCrypt does not allow "
                    "setting the generator when generating DH params");
                /* wolfCrypt doesn't allow setting the generator when generating
                 * DH params. */
                break;
            case EVP_PKEY_CTRL_PEER_KEY:
                WOLFENGINE_MSG(WE_LOG_KE, "EVP_PKEY_CTRL_PEER_KEY");
                /* No need to store peer key. We can get it from ctx in
                 * we_dh_pkey_derive. Must return 1, though, so peer key does
                 * get stored in the ctx. See EVP_PKEY_derive_set_peer. */
                break;
            default:
                /* Unsupported control type. */
                XSNPRINTF(errBuff, sizeof(errBuff), "Unsupported ctrl type %d",
                          type);
                WOLFENGINE_ERROR_MSG(WE_LOG_KE, errBuff);
                ret = 0;
                break;
        }
    }

    WOLFENGINE_LEAVE(WE_LOG_KE, "we_dh_pkey_ctrl", ret);

    return ret;
}

/**
 * Generate parameters for DH key pair generation.
 *
 * @param  ctx   [in]   Public key context of operation.
 * @param  pkey  [out]  EVP public key to hold result.
 * @returns  1 on success and 0 on failure.
 */
static int we_dh_pkey_paramgen(EVP_PKEY_CTX *ctx, EVP_PKEY *pkey)
{
    int ret = 1;
    we_Dh *engineDh = NULL;
    DH *dh = NULL;

    WOLFENGINE_ENTER(WE_LOG_KE, "we_dh_pkey_paramgen");
    WOLFENGINE_MSG_VERBOSE(WE_LOG_KE, "ARGS [ctx = %p, pkey = %p]",
                           ctx, pkey);

    /* Retrieve internal DH object. */
    engineDh = (we_Dh *)EVP_PKEY_CTX_get_data(ctx);
    if (engineDh == NULL) {
        WOLFENGINE_ERROR_FUNC_NULL(WE_LOG_KE,
                                   "EVP_PKEY_CTX_get_data", engineDh);
        ret = 0;
    }

    if (ret == 1) {
        /* Allocate new OpenSSL DH object to hold parameters. */
        dh = DH_new();
        if (dh == NULL) {
            WOLFENGINE_ERROR_FUNC_NULL(WE_LOG_KE, "DH_new", dh);
            ret = 0;
        }
    }

    if (ret == 1) {
        /* Assign OpenSSL DH object to PKEY. */
        EVP_PKEY_assign_DH(pkey, dh);
    }

    if (ret == 1) {
        /* Generate the parameters with wolfSSL and copy into OpenSSL object. */
        ret = we_dh_paramgen_int(dh, engineDh);
    }

    WOLFENGINE_LEAVE(WE_LOG_KE, "we_dh_pkey_paramgen", ret);

    return ret;
}

/**
 * Generate a DH key pair using the parameters in ctx. Store the resulting key
 * pair in pkey.
 *
 * @param  ctx   [in]  Public key context of operation.
 * @param  pkey  [in]  EVP public key to hold result.
 * @returns  1 on success and 0 on failure.
 */
static int we_dh_pkey_keygen(EVP_PKEY_CTX *ctx, EVP_PKEY *pkey)
{
    int ret = 1;
    int rc;
    we_Dh *engineDh = NULL;
    EVP_PKEY *paramsKey;
    DH *dh;

    WOLFENGINE_ENTER(WE_LOG_KE, "we_dh_pkey_keygen");
    WOLFENGINE_MSG_VERBOSE(WE_LOG_KE, "ARGS [ctx = %p, pkey = %p]",
                           ctx, pkey);

    /* Retrieve internal DH object. */
    engineDh = (we_Dh *)EVP_PKEY_CTX_get_data(ctx);
    if (engineDh == NULL) {
        WOLFENGINE_ERROR_FUNC_NULL(WE_LOG_KE,
                                   "EVP_PKEY_CTX_get_data", engineDh);
        ret = 0;
    }

    /* Create a new DH object to hold the generated DH key pair. */
    if (ret == 1) {
        dh = DH_new();
        if (dh == NULL) {
            WOLFENGINE_ERROR_FUNC_NULL(WE_LOG_KE, "DH_new", dh);
            ret = 0;
        }
    }

    /* Assign the DH object to pkey. */
    if (ret == 1) {
        ret = EVP_PKEY_assign_DH(pkey, dh);
        if (ret != 1) {
            WOLFENGINE_ERROR_FUNC(WE_LOG_KE, "EVP_PKEY_assign_DH", ret);
        }
    }

    /* The ctx holds the EVP_PKEY which holds the DH params. */
    if (ret == 1) {
        paramsKey = EVP_PKEY_CTX_get0_pkey(ctx);
        if (paramsKey == NULL) {
            WOLFENGINE_ERROR_FUNC_NULL(WE_LOG_KE,
                                       "EVP_PKEY_CTX_get0_pkey", paramsKey);
            ret = 0;
        }
    }

    /* Copy the parameters from the ctx EVP_PKEY to pkey. */
    if (ret == 1) {
        rc = EVP_PKEY_copy_parameters(pkey, paramsKey);
        if (rc != 1) {
            WOLFENGINE_ERROR_FUNC(WE_LOG_KE, "EVP_PKEY_copy_parameters", rc);
            ret = 0;
        }
    }

    /* Generate the key pair. */
    if (ret == 1) {
        WOLFENGINE_MSG(WE_LOG_KE, "Generating DH key pair");
        rc = we_dh_generate_key_int(dh, engineDh);
        if (rc != 1) {
            WOLFENGINE_ERROR_FUNC(WE_LOG_KE, "we_dh_generate_key_int", rc);
            ret = 0;
        }
    }

    WOLFENGINE_LEAVE(WE_LOG_KE, "we_dh_generate_key", ret);

    return ret;
}

/**
 * Derive a DH shared secret.
 *
 * @param  ctx        [in]      Public key context of operation.
 * @param  secret     [out]     Buffer holding the shared secret. If NULL,
 *                              return max length of secret buffer in secretLen.
 * @param  secretLen  [in/out]  Length of shared secret buffer.
 * @returns  1 on success and 0 on failure.
 */
static int we_dh_pkey_derive(EVP_PKEY_CTX *ctx, unsigned char *secret,
                             size_t *secretLen)
{
    int ret = 1;
    we_Dh *engineDh = NULL;
    EVP_PKEY *ourKey = NULL;
    DH *ourDh = NULL;
    EVP_PKEY *peerKey = NULL;
    DH *peerDh = NULL;
    const BIGNUM *peerPub = NULL;

    WOLFENGINE_ENTER(WE_LOG_KE, "we_dh_pkey_derive");
    WOLFENGINE_MSG_VERBOSE(WE_LOG_KE, "ARGS [ctx = %p, secret = %p, "
                           "secretLen = %p]", ctx, secret, secretLen);

    /* Retrieve internal DH object. */
    engineDh = (we_Dh *)EVP_PKEY_CTX_get_data(ctx);
    if (engineDh == NULL) {
        WOLFENGINE_ERROR_FUNC_NULL(WE_LOG_KE,
                                   "EVP_PKEY_CTX_get_data", engineDh);
        ret = 0;
    }

    if (ret == 1) {
        /* Get our private key. */
        ourKey = EVP_PKEY_CTX_get0_pkey(ctx);
        if (ourKey == NULL) {
            WOLFENGINE_ERROR_FUNC_NULL(WE_LOG_KE,
                                       "EVP_PKEY_CTX_get0_pkey", ourKey);
            ret = 0;
        }
    }

    if (ret == 1) {
        /* Get Dh object from our private key. */
        ourDh = (DH *)EVP_PKEY_get0_DH(ourKey);
        if (ourDh == NULL) {
            WOLFENGINE_ERROR_FUNC_NULL(WE_LOG_KE, "EVP_PKEY_get0_DH", ourDh);
            ret = 0;
        }
    }

    if ((ret == 1) && (secret == NULL)) {
        /* Return the length of the secret only. */
        *secretLen = DH_size(ourDh);
    }
    else if (ret == 1) {
        /* Get the peer's key. */
        peerKey = EVP_PKEY_CTX_get0_peerkey(ctx);
        if (peerKey == NULL) {
            WOLFENGINE_ERROR_FUNC_NULL(WE_LOG_KE,
                                       "EVP_PKEY_CTX_get0_peerkey", peerKey);
            ret = 0;
        }

        if (ret == 1) {
            /* Get the DH object from peer's key. */
            peerDh = (DH *)EVP_PKEY_get0_DH(peerKey);
            if (peerDh == NULL) {
                WOLFENGINE_ERROR_FUNC_NULL(WE_LOG_KE, "EVP_PKEY_get0_DH",
                                           peerDh);
                ret = 0;
            }
        }

        if (ret == 1) {
            /* Get public key as a big number. */
            peerPub = DH_get0_pub_key(peerDh);
            if (peerPub == NULL) {
                WOLFENGINE_ERROR_FUNC_NULL(WE_LOG_KE, "DH_get0_pub_key", NULL);
                ret = 0;
            }
        }

        if (ret == 1) {
            WOLFENGINE_MSG(WE_LOG_KE, "Generating DH secret, len = %d",
                           secretLen);
            /* Compute the secret from the peer's public key and our key. */
            ret = we_dh_compute_key_int(engineDh, secret, secretLen, peerPub,
                                        ourDh);
            if (ret != 1) {
                WOLFENGINE_ERROR_FUNC(WE_LOG_KE, "we_dh_compute_key_int", ret);
            }
            else {
                WOLFENGINE_MSG(WE_LOG_KE, "Generated DH shared secret");
            }
        }
    }

    WOLFENGINE_LEAVE(WE_LOG_KE, "we_dh_pkey_derive", ret);

    return ret;
}

/**
 * Initialize the DH method for use with the EVP_PKEY API.
 *
 * @return  1 on success and 0 on failure.
 */
int we_init_dh_pkey_meth(void)
{
    int ret = 1;

    WOLFENGINE_ENTER(WE_LOG_KE, "we_init_dh_pkey_meth");

    /* Create a new PKEY method for DH. */
    we_dh_pkey_method = EVP_PKEY_meth_new(EVP_PKEY_DH, 0);
    if (we_dh_pkey_method == NULL) {
        WOLFENGINE_ERROR_FUNC_NULL(WE_LOG_KE,
                                   "EVP_PKEY_meth_new", we_dh_pkey_method);
        ret = 0;
    }

    if (ret == 1) {
        /* Set all the methods we want to support. */
        EVP_PKEY_meth_set_init(we_dh_pkey_method, we_dh_pkey_init);
        EVP_PKEY_meth_set_cleanup(we_dh_pkey_method, we_dh_pkey_cleanup);
        EVP_PKEY_meth_set_ctrl(we_dh_pkey_method, we_dh_pkey_ctrl, NULL);
        EVP_PKEY_meth_set_paramgen(we_dh_pkey_method, NULL,
                                   we_dh_pkey_paramgen);
        EVP_PKEY_meth_set_keygen(we_dh_pkey_method, NULL, we_dh_pkey_keygen);
        EVP_PKEY_meth_set_derive(we_dh_pkey_method, NULL, we_dh_pkey_derive);
    }

    /* No errors after allocation - no need to free method on error. */

    WOLFENGINE_LEAVE(WE_LOG_KE, "we_init_dh_pkey_meth", ret);

    return ret;
}

#endif /* WE_HAVE_EVP_PKEY */

#endif /* WE_HAVE_DH */
