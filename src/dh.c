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

/**
 * Data required to complete DH operations.
 */
typedef struct we_Dh
{
    /* wolfSSL structure for holding DH key data. */
    DhKey key;
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

    WOLFENGINE_ENTER("we_dh_init");

    engineDh = (we_Dh *)OPENSSL_zalloc(sizeof(we_Dh));
    if (engineDh == NULL) {
        WOLFENGINE_ERROR_FUNC_NULL("OPENSSL_zalloc", engineDh);
        ret = 0;
    }

    if (ret == 1) {
        rc = wc_InitDhKey(&engineDh->key);
        if (rc != 0) {
            WOLFENGINE_ERROR_FUNC("wc_InitDhKey", rc);
            ret = 0;
        }
    }

    if (ret == 1) {
        rc = DH_set_ex_data(dh, 0, engineDh);
        if (rc != 1) {
            WOLFENGINE_ERROR_FUNC("DH_set_ex_data", rc);
            ret = 0;
        }
    }

    if (ret == 0 && engineDh != NULL) {
        wc_FreeDhKey(&engineDh->key);
        OPENSSL_free(engineDh);
    }

    WOLFENGINE_LEAVE("we_dh_init", ret);

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

    WOLFENGINE_ENTER("we_dh_finish");

    engineDh = (we_Dh *)DH_get_ex_data(dh, 0);
    if (engineDh == NULL) {
        WOLFENGINE_ERROR_FUNC_NULL("DH_get_ex_data", engineDh);
        ret = 0;
    }

    if (ret == 1) {
        wc_FreeDhKey(&engineDh->key);
        OPENSSL_free(engineDh);
        DH_set_ex_data(dh, 0, NULL);
    }

    WOLFENGINE_LEAVE("we_dh_finish", ret);

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

    WOLFENGINE_ENTER("we_set_dh_parameters");

    pBuf = (unsigned char *)OPENSSL_malloc(BN_num_bytes(dh->p));
    if (pBuf == NULL) {
        WOLFENGINE_ERROR_FUNC_NULL("OPENSSL_malloc", pBuf);
        ret = 0;
    }

    if (ret == 1) {
        gBuf = (unsigned char *)OPENSSL_malloc(BN_num_bytes(dh->g));
        if (gBuf == NULL) {
            WOLFENGINE_ERROR_FUNC_NULL("OPENSSL_malloc", gBuf);
            ret = 0;
        }
    }

    if (ret == 1) {
        pBufLen = BN_bn2bin(dh->p, pBuf);
        if (pBufLen == 0) {
            WOLFENGINE_ERROR_FUNC("BN_bn2bin", pBufLen);
            ret = 0;
        }
    }

    if (ret == 1) {
        gBufLen = BN_bn2bin(dh->g, gBuf);
        if (gBufLen == 0) {
            WOLFENGINE_ERROR_FUNC("BN_bn2bin", gBufLen);
            ret = 0;
        }
    }

    if (ret == 1) {
        rc = wc_DhSetKey(&engineDh->key, pBuf, pBufLen, gBuf, gBufLen);
        if (rc != 0) {
            WOLFENGINE_ERROR_FUNC("wc_DhSetKey", rc);
            ret = 0;
        }
    }

    if (pBuf != NULL)
        OPENSSL_free(pBuf);
    if (gBuf != NULL)
        OPENSSL_free(gBuf);

    WOLFENGINE_LEAVE("we_set_dh_parameters", ret);

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
    unsigned char *priv = NULL;
    unsigned int privLen = 0;
    unsigned int actualPrivLen = 0;
    unsigned char *pub = NULL;
    unsigned int pubLen = 0;
    unsigned int actualPubLen = 0;
    BIGNUM *privBn = NULL;
    BIGNUM *pubBn = NULL;

    WOLFENGINE_ENTER("we_dh_generate_key");

    engineDh = (we_Dh *)DH_get_ex_data(dh, 0);
    if (engineDh == NULL) {
        WOLFENGINE_ERROR_FUNC_NULL("DH_get_ex_data", engineDh);
        ret = 0;
    }

    if (ret == 1) {
        rc = we_set_dh_parameters(dh, engineDh);
        if (rc != 1) {
            WOLFENGINE_ERROR_FUNC("we_set_dh_parameters", rc);
            ret = 0;
        }
    }

    if (ret == 1) {
        pubLen = BN_num_bytes(dh->p);
        pub = (unsigned char*)OPENSSL_malloc(pubLen);
        if (pub == NULL) {
            WOLFENGINE_ERROR_FUNC_NULL("OPENSSL_malloc", pub);
            ret = 0;
        }
    }
    if (ret == 1) {
        if (dh->length != 0) {
            privLen = dh->length / 8; /* Convert bits to bytes. */
        }
        else {
            privLen = pubLen;
        }

        priv = (unsigned char*)OPENSSL_malloc(privLen);
        if (priv == NULL) {
            WOLFENGINE_ERROR_FUNC_NULL("OPENSSL_malloc", priv);
            ret = 0;
        }
    }

    if (ret == 1) {
        rc = wc_DhGenerateKeyPair(&engineDh->key, we_rng, priv, &actualPrivLen,
                                  pub, &actualPubLen);
        if (rc != 0) {
            WOLFENGINE_ERROR_FUNC("wc_DhGenerateKeyPair", rc);
            ret = 0;
        }
    }

    if (ret == 1) {
        privBn = BN_bin2bn(priv, actualPrivLen, NULL);
        if (privBn == NULL) {
            WOLFENGINE_ERROR_FUNC_NULL("BN_bin2bn", privBn);
            ret = 0;
        }
        else {
            dh->priv_key = privBn;
        }
    }

    if (ret == 1) {
        pubBn = BN_bin2bn(pub, actualPubLen, NULL);
        if (pubBn == NULL) {
            WOLFENGINE_ERROR_FUNC_NULL("BN_bin2bn", pubBn);
            ret = 0;
        }
        else {
            dh->pub_key = pubBn;
        }
    }
    
    if (pub != NULL)
        OPENSSL_free(pub);
    if (priv != NULL)
        OPENSSL_clear_free(priv, privLen);

    WOLFENGINE_LEAVE("we_dh_generate_key", ret);

    return ret;
}

/**
 * Compute a DH shared secret using the private key in dh and the peer's public
 * key in pubKey. Store the result in key.
 *
 * @param  key     [out]  Buffer holding the shared secret.
 * @param  pubKey  [in]   Peer's public key.
 * @param  dh      [in]   DH data structure.
 * @returns  Length of shared secret on success and -1 on failure.
 */
static int we_dh_compute_key(unsigned char *key, const BIGNUM *pubKey, DH *dh)
{
    int ret = 1;
    int rc = 0;
    we_Dh *engineDh = NULL;
    unsigned char *pubBuf = NULL;
    int pubLen = 0;
    unsigned char *privBuf = NULL;
    int privLen = 0;
    unsigned int keyLen = 0;

    WOLFENGINE_ENTER("we_compute_key");

    engineDh = (we_Dh *)DH_get_ex_data(dh, 0);
    if (engineDh == NULL) {
        WOLFENGINE_ERROR_FUNC_NULL("DH_get_ex_data", engineDh);
        ret = -1;
    }

    if (ret == 1) {
        pubBuf = (unsigned char *)OPENSSL_malloc(BN_num_bytes(pubKey));
        if (pubBuf == NULL) {
            WOLFENGINE_ERROR_FUNC_NULL("OPENSSL_malloc", pubBuf);
            ret = -1;
        }
    }

    if (ret == 1) {
        privBuf = (unsigned char *)OPENSSL_malloc(BN_num_bytes(dh->priv_key));
        if (privBuf == NULL) {
            WOLFENGINE_ERROR_FUNC_NULL("OPENSSL_malloc", privBuf);
            ret = -1;
        }
    }

    if (ret == 1) {
        pubLen = BN_bn2bin(pubKey, pubBuf);
        if (pubLen == 0) {
            WOLFENGINE_ERROR_FUNC("BN_bn2bin", pubLen);
            ret = -1;
        }
    }

    if (ret == 1) {
        privLen = BN_bn2bin(dh->priv_key, privBuf);
        if (privLen == 0) {
            WOLFENGINE_ERROR_FUNC("BN_bn2bin", privLen);
            ret = -1;
        }
    }

    if (ret == 1) {
        keyLen = DH_size(dh);
        rc = wc_DhAgree(&engineDh->key, key, &keyLen, privBuf, privLen,
                        pubBuf, pubLen);
        if (rc != 0) {
            WOLFENGINE_ERROR_FUNC("wc_DhAgree", rc);
            ret = -1;
        }
    }

    if (pubBuf != NULL)
        OPENSSL_free(pubBuf);
    if (privBuf != NULL)
        OPENSSL_free(privBuf);

    WOLFENGINE_LEAVE("we_compute_key", ret);

    return keyLen;
}

/**
 * Initialize the DH method.
 *
 * @return  1 on success and 0 on failure.
 */
int we_init_dh_meth(void)
{
    int ret = 1;

    WOLFENGINE_ENTER("we_init_dh_meth");

    we_dh_method = DH_meth_new("wolfengine_dh", 0);
    if (we_dh_method == NULL) {
        WOLFENGINE_ERROR_FUNC_NULL("DH_meth_new", we_dh_method);
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

    WOLFENGINE_LEAVE("we_init_dh_meth", ret);

    return ret;
}

#endif /* WE_HAVE_DH */
