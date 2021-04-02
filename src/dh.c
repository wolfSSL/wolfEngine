/* dh.c
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

#ifdef WE_HAVE_DH

#define DEFAULT_PRIME_LEN 1024

/**
 * Data required to complete DH operations.
 */
typedef struct we_Dh
{
    /* wolfSSL structure for holding DH key data. */
    DhKey key;
    /* Length of prime ("p") in bits. */
    int primeLen;
} we_Dh;

DH_METHOD *we_dh_method = NULL;

/**
 * Initialize and set the data required to complete DH operations.
 *
 * @param  dh  [in/out]  DH data structure.
 * @returns  1 on success and 0 on failure.
 */
static int we_dh_init(DH *dh)
{
    int ret = 1;
    int rc = 0;
    we_Dh *engineDh = NULL;

    WOLFENGINE_ENTER(WE_LOG_KE, "we_dh_init");

    engineDh = (we_Dh *)OPENSSL_zalloc(sizeof(we_Dh));
    if (engineDh == NULL) {
        WOLFENGINE_ERROR_FUNC_NULL(WE_LOG_KE, "OPENSSL_zalloc", engineDh);
        ret = 0;
    }

    if (ret == 1) {
        rc = wc_InitDhKey(&engineDh->key);
        if (rc != 0) {
            WOLFENGINE_ERROR_FUNC(WE_LOG_KE, "wc_InitDhKey", rc);
            ret = 0;
        }
        engineDh->primeLen = DEFAULT_PRIME_LEN;
    }

    if (ret == 1) {
        rc = DH_set_ex_data(dh, 0, engineDh);
        if (rc != 1) {
            WOLFENGINE_ERROR_FUNC(WE_LOG_KE, "DH_set_ex_data", rc);
            ret = 0;
        }
    }

    if (ret == 0 && engineDh != NULL) {
        wc_FreeDhKey(&engineDh->key);
        OPENSSL_free(engineDh);
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

    engineDh = (we_Dh *)DH_get_ex_data(dh, 0);
    if (engineDh == NULL) {
        WOLFENGINE_ERROR_FUNC_NULL(WE_LOG_KE, "DH_get_ex_data", engineDh);
        ret = 0;
    }

    if (ret == 1) {
        wc_FreeDhKey(&engineDh->key);
        OPENSSL_free(engineDh);
        DH_set_ex_data(dh, 0, NULL);
    }

    WOLFENGINE_LEAVE(WE_LOG_KE, "we_dh_finish", ret);

    return ret;
}

/**
 * Take the p and g parameters from dh and convert and store them in the DhKey
 * owned by engineDh.
 *
 * @param  dh        [in]   OpenSSL DH data structure.
 * @param  engineDh  [out]  wolfEngine DH object holding wolfSSL DhKey.
 * @returns  1 on success and 0 on failure.
 */
static int we_set_dh_parameters(const DH *dh, we_Dh *engineDh)
{
    int ret = 1;
    int rc = 0;
    unsigned char *pBuf = NULL;
    int pBufLen = 0;
    unsigned char *gBuf = NULL;
    int gBufLen = 0;

    WOLFENGINE_ENTER(WE_LOG_KE, "we_set_dh_parameters");

    pBuf = (unsigned char *)OPENSSL_malloc(BN_num_bytes(DH_get0_p(dh)));
    if (pBuf == NULL) {
        WOLFENGINE_ERROR_FUNC_NULL(WE_LOG_KE, "OPENSSL_malloc", pBuf);
        ret = 0;
    }

    if (ret == 1) {
        gBuf = (unsigned char *)OPENSSL_malloc(BN_num_bytes(DH_get0_g(dh)));
        if (gBuf == NULL) {
            WOLFENGINE_ERROR_FUNC_NULL(WE_LOG_KE, "OPENSSL_malloc", gBuf);
            ret = 0;
        }
    }

    if (ret == 1) {
        pBufLen = BN_bn2bin(DH_get0_p(dh), pBuf);
        if (pBufLen == 0) {
            WOLFENGINE_ERROR_FUNC(WE_LOG_KE, "BN_bn2bin", pBufLen);
            ret = 0;
        }
    }

    if (ret == 1) {
        gBufLen = BN_bn2bin(DH_get0_g(dh), gBuf);
        if (gBufLen == 0) {
            WOLFENGINE_ERROR_FUNC(WE_LOG_KE, "BN_bn2bin", gBufLen);
            ret = 0;
        }
    }

    if (ret == 1) {
        rc = wc_DhSetKey(&engineDh->key, pBuf, pBufLen, gBuf, gBufLen);
        if (rc != 0) {
            WOLFENGINE_ERROR_FUNC(WE_LOG_KE, "wc_DhSetKey", rc);
            ret = 0;
        }
    }

    if (pBuf != NULL)
        OPENSSL_free(pBuf);
    if (gBuf != NULL)
        OPENSSL_free(gBuf);

    WOLFENGINE_LEAVE(WE_LOG_KE, "we_set_dh_parameters", ret);

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
    int rc = 0;
    unsigned char *priv = NULL;
    unsigned int privLen = 0;
    unsigned int actualPrivLen = 0;
    unsigned char *pub = NULL;
    unsigned int pubLen = 0;
    unsigned int actualPubLen = 0;
    BIGNUM *privBn = NULL;
    BIGNUM *pubBn = NULL;

    WOLFENGINE_ENTER(WE_LOG_KE, "we_dh_generate_key_int");

    pubLen = BN_num_bytes(DH_get0_p(dh));
    pub = (unsigned char*)OPENSSL_malloc(pubLen);
    if (pub == NULL) {
        WOLFENGINE_ERROR_FUNC_NULL(WE_LOG_KE, "OPENSSL_malloc", pub);
        ret = 0;
    }

    if (ret == 1) {
        if (DH_get_length(dh) != 0) {
            /* Convert bits to bytes. */
            privLen = (unsigned int)(DH_get_length(dh) / 8);
        }
        else {
            privLen = pubLen;
        }

        priv = (unsigned char*)OPENSSL_malloc(privLen);
        if (priv == NULL) {
            WOLFENGINE_ERROR_FUNC_NULL(WE_LOG_KE, "OPENSSL_malloc", priv);
            ret = 0;
        }
    }

    /* Set parameters in engineDH. */
    if (ret == 1) {
        rc = we_set_dh_parameters(dh, engineDh);
        if (rc != 1) {
            WOLFENGINE_ERROR_FUNC(WE_LOG_KE, "we_set_dh_parameters", rc);
            ret = 0;
        }
    }

    if (ret == 1) {
        actualPrivLen = privLen;
        actualPubLen = pubLen;
        rc = wc_DhGenerateKeyPair(&engineDh->key, we_rng, priv, &actualPrivLen,
                                  pub, &actualPubLen);
        if (rc != 0) {
            WOLFENGINE_ERROR_FUNC(WE_LOG_KE, "wc_DhGenerateKeyPair", rc);
            ret = 0;
        }
    }

    if (ret == 1) {
        privBn = BN_bin2bn(priv, actualPrivLen, NULL);
        if (privBn == NULL) {
            WOLFENGINE_ERROR_FUNC_NULL(WE_LOG_KE, "BN_bin2bn", privBn);
            ret = 0;
        }
    }

    if (ret == 1) {
        pubBn = BN_bin2bn(pub, actualPubLen, NULL);
        if (pubBn == NULL) {
            WOLFENGINE_ERROR_FUNC_NULL(WE_LOG_KE, "BN_bin2bn", pubBn);
            ret = 0;
        }
    }

    if (ret == 1) {
        rc = DH_set0_key(dh, pubBn, privBn);
        if (rc != 1) {
            WOLFENGINE_ERROR_FUNC(WE_LOG_KE, "DH_set0_key", rc);
            BN_free(privBn);
            ret = 0;
        }
    }

    if (pub != NULL)
        OPENSSL_free(pub);
    if (priv != NULL)
        OPENSSL_clear_free(priv, privLen);

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
    int rc = 0;
    we_Dh *engineDh = NULL;

    WOLFENGINE_ENTER(WE_LOG_KE, "we_dh_generate_key");

    engineDh = (we_Dh *)DH_get_ex_data(dh, 0);
    if (engineDh == NULL) {
        WOLFENGINE_ERROR_FUNC_NULL(WE_LOG_KE, "DH_get_ex_data", engineDh);
        ret = 0;
    }

    if (ret == 1) {
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
    int rc = 0;
    unsigned char *pubBuf = NULL;
    int pubLen = 0;
    unsigned char *privBuf = NULL;
    int privLen = 0;
    unsigned int secLen = 0;

    WOLFENGINE_ENTER(WE_LOG_KE, "we_dh_compute_key_int");

    if (ret == 1) {
        pubBuf = (unsigned char *)OPENSSL_malloc(BN_num_bytes(pubKey));
        if (pubBuf == NULL) {
            WOLFENGINE_ERROR_FUNC_NULL(WE_LOG_KE, "OPENSSL_malloc", pubBuf);
            ret = 0;
        }
    }

    if (ret == 1) {
        privBuf = (unsigned char *)OPENSSL_malloc(BN_num_bytes(
                                                  DH_get0_priv_key(dh)));
        if (privBuf == NULL) {
            WOLFENGINE_ERROR_FUNC_NULL(WE_LOG_KE, "OPENSSL_malloc", privBuf);
            ret = 0;
        }
    }

    if (ret == 1) {
        pubLen = BN_bn2bin(pubKey, pubBuf);
        if (pubLen == 0) {
            WOLFENGINE_ERROR_FUNC(WE_LOG_KE, "BN_bn2bin", pubLen);
            ret = 0;
        }
    }

    if (ret == 1) {
        privLen = BN_bn2bin(DH_get0_priv_key(dh), privBuf);
        if (privLen == 0) {
            WOLFENGINE_ERROR_FUNC(WE_LOG_KE, "BN_bn2bin", privLen);
            ret = 0;
        }
    }

    /* Set parameters in engineDH. */
    if (ret == 1) {
        rc = we_set_dh_parameters(dh, engineDh);
        if (rc != 1) {
            WOLFENGINE_ERROR_FUNC(WE_LOG_KE, "we_set_dh_parameters", rc);
            ret = 0;
        }
    }

    if (ret == 1) {
        secLen = (unsigned int)*secretLen;
        rc = wc_DhAgree(&engineDh->key, secret, &secLen, privBuf, privLen,
                         pubBuf, pubLen);
        if (rc != 0) {
            WOLFENGINE_ERROR_FUNC(WE_LOG_KE, "wc_DhAgree", rc);
            ret = 0;
        }
        else {
            *secretLen = secLen;
        }
    }

    if (pubBuf != NULL)
        OPENSSL_free(pubBuf);
    if (privBuf != NULL)
        OPENSSL_free(privBuf);

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

    engineDh = (we_Dh *)DH_get_ex_data(dh, 0);
    if (engineDh == NULL) {
        WOLFENGINE_ERROR_FUNC_NULL(WE_LOG_KE, "DH_get_ex_data", engineDh);
        ret = -1;
    }

    if (ret == 1) {
        secretLen = DH_size(dh);
        ret = we_dh_compute_key_int(engineDh, secret, &secretLen, pubKey, dh);
        if (ret == 0) {
            WOLFENGINE_ERROR_FUNC(WE_LOG_KE, "we_dh_compute_key_int", ret);
            ret = -1;
        }
        else {
            ret = secretLen;
        }
    }

    WOLFENGINE_LEAVE(WE_LOG_KE, "we_compute_key", ret);
    (void)ret;

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

    we_dh_method = DH_meth_new("wolfengine_dh", 0);
    if (we_dh_method == NULL) {
        WOLFENGINE_ERROR_FUNC_NULL(WE_LOG_KE, "DH_meth_new", we_dh_method);
        ret = 0;
    }

    if (ret == 1) {
        DH_meth_set_init(we_dh_method, we_dh_init);
        DH_meth_set_finish(we_dh_method, we_dh_finish);
        DH_meth_set_generate_key(we_dh_method, we_dh_generate_key);
        DH_meth_set_compute_key(we_dh_method, we_dh_compute_key);
    }

    if (ret == 0 && we_dh_method != NULL) {
        DH_meth_free(we_dh_method);
        we_dh_method = NULL;
    }

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
    int rc = 0;
    we_Dh *dh;

    WOLFENGINE_ENTER(WE_LOG_KE, "we_dh_pkey_init");

    dh = (we_Dh *)OPENSSL_zalloc(sizeof(we_Dh));
    if (dh == NULL) {
        WOLFENGINE_ERROR_FUNC_NULL(WE_LOG_KE, "OPENSSL_zalloc", dh);
        ret = 0;
    }

    if (ret == 1) {
        rc = wc_InitDhKey(&dh->key);
        if (rc != 0) {
            WOLFENGINE_ERROR_FUNC(WE_LOG_KE, "wc_InitDhKey", rc);
            ret = 0;
        }
        dh->primeLen = DEFAULT_PRIME_LEN;
    }

    if (ret == 1) {
        EVP_PKEY_CTX_set_data(ctx, dh);
    }

    if (ret == 0 && dh != NULL) {
        wc_FreeDhKey(&dh->key);
        OPENSSL_free(dh);
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
    we_Dh *dh = (we_Dh *)EVP_PKEY_CTX_get_data(ctx);

    WOLFENGINE_ENTER(WE_LOG_KE, "we_dh_pkey_cleanup");

    if (dh != NULL) {
        wc_FreeDhKey(&dh->key);
        OPENSSL_free(dh);
        EVP_PKEY_CTX_set_data(ctx, NULL);
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
    char errBuff[WOLFENGINE_MAX_ERROR_SZ];

    (void)ptr;

    WOLFENGINE_ENTER(WE_LOG_KE, "we_dh_pkey_ctrl");

    dh = (we_Dh *)EVP_PKEY_CTX_get_data(ctx);
    if (dh == NULL) {
        WOLFENGINE_ERROR_FUNC_NULL(WE_LOG_KE, "EVP_PKEY_CTX_get_data", dh);
        ret = 0;
    }

    if (ret == 1) {
        switch (type) {
            case EVP_PKEY_CTRL_DH_PARAMGEN_PRIME_LEN:
                /* These are the sizes allowed by wolfCrypt. */
                if (num != 1024 && num != 2048 && num != 3072) {
                    WOLFENGINE_ERROR_MSG(WE_LOG_KE,
                                         "Invalid DH prime bit length.");
                    ret = 0;
                }
                else {
                    dh->primeLen = num;
                }
                break;
            case EVP_PKEY_CTRL_DH_PARAMGEN_GENERATOR:
                /* wolfCrypt doesn't allow setting the generator when generating
                   DH params. */
                break;
            case EVP_PKEY_CTRL_PEER_KEY:
                /* No need to store peer key. We can get it from ctx in
                   we_dh_pkey_derive. Must return 1, though, so peer key does
                   get stored in the ctx. See EVP_PKEY_derive_set_peer. */
                break;
            default:
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
 * Take DH parameters from a wolfSSL DhKey and store them in an OpenSSL DH.
 *
 * @param  wolfDh   [in]   The wolfSSL DhKey to take the parameters from.
 * @param  osslDh   [out]  The OpenSSL DH to store the parameters in.
 * @returns  1 on success and 0 on failure.
 */
static int we_convert_dh_params(DhKey *wolfDh, DH *osslDh)
{
    int ret = 1;
    int rc = 0;
    BIGNUM *pBn = NULL;
    BIGNUM *qBn = NULL;
    BIGNUM *gBn = NULL;
    unsigned char *p = NULL;
    unsigned int pLen = 0;
    unsigned char *g = NULL;
    unsigned int gLen = 0;
    unsigned char *q = NULL;
    unsigned int qLen = 0;

    WOLFENGINE_ENTER(WE_LOG_KE, "we_convert_dh_params");

    /* Call with NULL for the buffers to get required lengths. */
    rc = wc_DhExportParamsRaw(wolfDh, NULL, &pLen, NULL, &qLen, NULL, &gLen);
    if (rc != LENGTH_ONLY_E) {
        WOLFENGINE_ERROR_FUNC(WE_LOG_KE, "wc_DhExportParamsRaw", rc);
        ret = 0;
    }

    if (ret == 1) {
        p = (unsigned char*)OPENSSL_malloc(pLen);
        if (p == NULL) {
            WOLFENGINE_ERROR_FUNC_NULL(WE_LOG_KE, "OPENSSL_malloc", p);
            ret = 0;
        }
    }
    if (ret == 1) {
        q = (unsigned char*)OPENSSL_malloc(qLen);
        if (q == NULL) {
            WOLFENGINE_ERROR_FUNC_NULL(WE_LOG_KE, "OPENSSL_malloc", q);
            ret = 0;
        }
    }
    if (ret == 1) {
        g = (unsigned char*)OPENSSL_malloc(pLen);
        if (g == NULL) {
            WOLFENGINE_ERROR_FUNC_NULL(WE_LOG_KE, "OPENSSL_malloc", g);
            ret = 0;
        }
    }
    if (ret == 1) {
        /* With buffers allocated, write the parameters. */
        rc = wc_DhExportParamsRaw(wolfDh, p, &pLen, q, &qLen, g, &gLen);
        if (rc != 0) {
            WOLFENGINE_ERROR_FUNC(WE_LOG_KE, "wc_DhExportParamsRaw", rc);
            ret = 0;
        }
    }

    /* Convert the parameter byte buffers to BIGNUMs to store in osslDh. */
    if (ret == 1) {
        pBn = BN_bin2bn(p, pLen, NULL);
        if (pBn == NULL) {
            WOLFENGINE_ERROR_FUNC_NULL(WE_LOG_KE, "BN_bin2bn", pBn);
            ret = 0;
        }
    }
    if (ret == 1) {
        qBn = BN_bin2bn(q, qLen, NULL);
        if (qBn == NULL) {
            WOLFENGINE_ERROR_FUNC_NULL(WE_LOG_KE, "BN_bin2bn", qBn);
            ret = 0;
        }
    }
    if (ret == 1) {
        gBn = BN_bin2bn(g, gLen, NULL);
        if (gBn == NULL) {
            WOLFENGINE_ERROR_FUNC_NULL(WE_LOG_KE, "BN_bin2bn", gBn);
            ret = 0;
        }
    }
    if (ret == 1) {
        rc = DH_set0_pqg(osslDh, pBn, qBn, gBn);
        if (rc != 1) {
            WOLFENGINE_ERROR_FUNC(WE_LOG_KE, "DH_set0_pqg", rc);
            ret = 0;
        }
    }

    if (p != NULL) {
        OPENSSL_free(p);
    }
    if (q != NULL) {
        OPENSSL_free(q);
    }
    if (g != NULL) {
        OPENSSL_free(g);
    }

    WOLFENGINE_LEAVE(WE_LOG_KE, "we_convert_dh_params", ret);

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
    int rc = 0;
    we_Dh *engineDh = NULL;
    DH *dh = NULL;

    WOLFENGINE_ENTER(WE_LOG_KE, "we_dh_pkey_paramgen");
    
    engineDh = (we_Dh *)EVP_PKEY_CTX_get_data(ctx);
    if (engineDh == NULL) {
        WOLFENGINE_ERROR_FUNC_NULL(WE_LOG_KE,
                                   "EVP_PKEY_CTX_get_data", engineDh);
        ret = 0;
    }

    if (ret == 1) {
        dh = DH_new();
        if (dh == NULL) {
            WOLFENGINE_ERROR_FUNC_NULL(WE_LOG_KE, "DH_new", dh);
            ret = 0;
        }
    }

    /* Generate the parameters. */
    if (ret == 1) {
        rc = wc_DhGenerateParams(we_rng, engineDh->primeLen, &engineDh->key);
        if (rc != 0) {
            WOLFENGINE_ERROR_FUNC(WE_LOG_KE, "we_dh_pkey_paramgen", rc);
            ret = 0;
        }
    }

    /* Convert the parameters from wolfSSL to OpenSSL data structure. */
    if (ret == 1) {
        rc = we_convert_dh_params(&engineDh->key, dh);
        if (rc != 1) {
            WOLFENGINE_ERROR_FUNC(WE_LOG_KE, "we_convert_dh_params", rc);
            ret = 0;
        }
    }

    if (ret == 1) {
        EVP_PKEY_assign_DH(pkey, dh);
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
    int rc = 0;
    we_Dh *engineDh = NULL;
    EVP_PKEY *paramsKey;
    DH *dh;

    WOLFENGINE_ENTER(WE_LOG_KE, "we_dh_pkey_keygen");
    
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

    /* Assign the DH to pkey. */
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
    
    engineDh = (we_Dh *)EVP_PKEY_CTX_get_data(ctx);
    if (engineDh == NULL) {
        WOLFENGINE_ERROR_FUNC_NULL(WE_LOG_KE,
                                   "EVP_PKEY_CTX_get_data", engineDh);
        ret = 0;
    }

    if (ret == 1) {
        ourKey = EVP_PKEY_CTX_get0_pkey(ctx);
        if (ourKey == NULL) {
            WOLFENGINE_ERROR_FUNC_NULL(WE_LOG_KE,
                                       "EVP_PKEY_CTX_get0_pkey", ourKey);
            ret = 0;
        }
    }

    if (ret == 1) {
        ourDh = EVP_PKEY_get0_DH(ourKey);
        if (ourDh == NULL) {
            WOLFENGINE_ERROR_FUNC_NULL(WE_LOG_KE, "EVP_PKEY_get0_DH", ourDh);
            ret = 0;
        }
    }

    if (ret == 1 && secret == NULL) {
        *secretLen = DH_size(ourDh);
        return ret;
    }

    if (ret == 1) {
        peerKey = EVP_PKEY_CTX_get0_peerkey(ctx);
        if (peerKey == NULL) {
            WOLFENGINE_ERROR_FUNC_NULL(WE_LOG_KE,
                                       "EVP_PKEY_CTX_get0_peerkey", peerKey);
            ret = 0;
        }
    }

    if (ret == 1) {
        peerDh = EVP_PKEY_get0_DH(peerKey);
        if (peerDh == NULL) {
            WOLFENGINE_ERROR_FUNC_NULL(WE_LOG_KE, "EVP_PKEY_get0_DH", peerDh);
            ret = 0;
        }
    }

    if (ret == 1) {
        peerPub = DH_get0_pub_key(peerDh);
        if (peerPub == NULL) {
            WOLFENGINE_ERROR_FUNC_NULL(WE_LOG_KE, "DH_get0_pub_key", NULL);
            ret = 0;
        }
    }

    if (ret == 1) {
        ret = we_dh_compute_key_int(engineDh, secret, secretLen, peerPub,
                                    ourDh);
        if (ret != 1) {
            WOLFENGINE_ERROR_FUNC(WE_LOG_KE, "we_dh_compute_key_int", ret);
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

    we_dh_pkey_method = EVP_PKEY_meth_new(EVP_PKEY_DH, 0);
    if (we_dh_pkey_method == NULL) {
        WOLFENGINE_ERROR_FUNC_NULL(WE_LOG_KE,
                                   "EVP_PKEY_meth_new", we_dh_pkey_method);
        ret = 0;
    }

    if (ret == 1) {
        EVP_PKEY_meth_set_init(we_dh_pkey_method, we_dh_pkey_init);
        EVP_PKEY_meth_set_cleanup(we_dh_pkey_method, we_dh_pkey_cleanup);
        EVP_PKEY_meth_set_ctrl(we_dh_pkey_method, we_dh_pkey_ctrl, NULL);
        EVP_PKEY_meth_set_paramgen(we_dh_pkey_method, NULL,
                                   we_dh_pkey_paramgen);
        EVP_PKEY_meth_set_keygen(we_dh_pkey_method, NULL, we_dh_pkey_keygen);
        EVP_PKEY_meth_set_derive(we_dh_pkey_method, NULL, we_dh_pkey_derive);
    }

    if (ret == 0 && we_dh_pkey_method != NULL) {
        EVP_PKEY_meth_free(we_dh_pkey_method);
        we_dh_pkey_method = NULL;
    }

    WOLFENGINE_LEAVE(WE_LOG_KE, "we_init_dh_pkey_meth", ret);

    return ret;
}

#endif /* WE_HAVE_EVP_PKEY */

#endif /* WE_HAVE_DH */
