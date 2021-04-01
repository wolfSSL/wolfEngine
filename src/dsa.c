/* dsa.c
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

#ifdef WE_HAVE_DSA

#define WE_APP_DATA_IDX 0

/**
 * Data required to complete a DSA operation.
 */
typedef struct we_Dsa
{
    /* wolfSSL structure for holding DSA key data. */
    DsaKey key;
    /* Stored by control command EVP_PKEY_CTRL_MD. */
    EVP_MD *md;
    /* The modulus size in bits. */
    int pbits;
    /* The q size in bits. */
    int qbits;
    /* Indicates private key has been set into wolfSSL structure. */
    int privKeySet:1;
    /* Indicates public key has been set into wolfSSL structure. */
    int pubKeySet:1;
} we_Dsa;

#define DEFAULT_PBITS           2048
#define DEFAULT_QBITS           256

/** DSA direct method - DSA using wolfSSL for the implementation. */
DSA_METHOD *we_dsa_method = NULL;

/**
 * Initialize and set the data required to complete an DSA operation.
 *
 * @param  dsa  [in]  DSA context of operation.
 * @returns  1 on success and 0 on failure.
 */
static int we_dsa_init(DSA *dsa)
{
    int ret = 1;
    int rc = 0;
    we_Dsa *engineDsa;

    WOLFENGINE_ENTER("we_dsa_init");

    engineDsa = (we_Dsa *)OPENSSL_zalloc(sizeof(we_Dsa));
    if (engineDsa == NULL) {
        WOLFENGINE_ERROR_FUNC_NULL("OPENSSL_zalloc", engineDsa);
        ret = 0;
    }

    if (ret == 1) {
        rc = wc_InitDsaKey(&engineDsa->key);
        if (rc != 0) {
            WOLFENGINE_ERROR_FUNC("wc_InitDsaKey", rc);
            ret = 0;
        }
    }

    if (ret == 1) {
        rc = DSA_set_ex_data(dsa, WE_APP_DATA_IDX, engineDsa);
        if (rc != 1) {
            WOLFENGINE_ERROR_FUNC("RSA_set_app_data", rc);
            ret = 0;
        }
    }

    if (ret == 0 && engineDsa != NULL) {
        OPENSSL_free(engineDsa);
    }

    WOLFENGINE_LEAVE("we_dsa_init", ret);

    return ret;
}

/**
 * Clean up the DSA operation data.
 *
 * @param  dsa  [in]  DSA context of operation.
 * @returns  1 on success and 0 on failure.
 */
static int we_dsa_finish(DSA *dsa)
{
    we_Dsa *engineDsa;

    WOLFENGINE_ENTER("we_dsa_finish");

    engineDsa = DSA_get_ex_data(dsa, WE_APP_DATA_IDX);
    if (engineDsa != NULL) {
        wc_FreeDsaKey(&engineDsa->key);
        OPENSSL_free(engineDsa);
        DSA_set_ex_data(dsa, WE_APP_DATA_IDX, NULL);
    }

    WOLFENGINE_LEAVE("we_dsa_finish", 1);

    return 1;
}

static int DsaParamgen(we_Dsa *engineDsa, int pbits)
{
    int ret = 1;
    int rc = 0;

    if (engineDsa == NULL) {
        WOLFENGINE_ERROR_FUNC_NULL("DSA_get_ex_data/EVP_PKEY_CTX_get_data",
                engineDsa);
        ret = 0;
    }
    if (ret == 1 && pbits == 0) {
        pbits = engineDsa->pbits;
    }
    if (ret == 1) {
#ifndef WE_HAVE_FIPS
        rc = wc_MakeDsaParameters(we_rng, pbits, &engineDsa->key);
        if (rc != MP_OKAY) {
            WOLFENGINE_ERROR_FUNC("wc_MakeDsaParameters", rc);
            ret = 0;
        }
#else
        /* For cert #3389 we have wc_DhGenerateParams included but not
         * the DSA equivalent. Its the same algorithm. */
        DhKey dh;
        char initDone = 1;
        rc = wc_InitDhKey(&dh); /* Init DH struct */
        if (rc != 0) {
            WOLFENGINE_ERROR_FUNC("wc_InitDhKey", rc);
            ret = 0;
            initDone = 0;
        }
        if (ret == 1) { /* Generate parameters */
            rc = wc_DhGenerateParams(we_rng, pbits, &dh);
            if (rc != 0) {
                WOLFENGINE_ERROR_FUNC("wc_DhGenerateParams", rc);
                ret = 0;
            }
        }
        if (ret == 1) { /* Copy parameters into DsaKey struct */
            rc = mp_copy(&dh.p, &engineDsa->key.p);
            if (rc == MP_OKAY)
                rc = mp_copy(&dh.q, &engineDsa->key.q);
            if (rc == MP_OKAY)
                rc = mp_copy(&dh.g, &engineDsa->key.g);
            if (rc != MP_OKAY) {
                WOLFENGINE_ERROR_FUNC("mp_copy", rc);
                ret = 0;
            }
        }
        if (initDone) {
            rc = wc_FreeDhKey(&dh);
            if (rc != 0) {
                WOLFENGINE_ERROR_FUNC("wc_FreeDhKey", rc);
                ret = 0;
            }
        }
#endif
    }

    return ret;
}

static int we_dsa_paramgen(DSA *dsa, int pbits, const unsigned char *seed_in,
        int seed_len, int *counter_ret, unsigned long *h_ret, BN_GENCB *cb)
{
    int ret = 1;

    WOLFENGINE_ENTER("we_dsa_paramgen");

    /* wolfSSL does not support the following parameters */
    (void)seed_in;
    (void)seed_len;
    (void)counter_ret;
    (void)h_ret;
    (void)cb;

    ret = DsaParamgen((we_Dsa*)DSA_get_ex_data(dsa, WE_APP_DATA_IDX), pbits);

    WOLFENGINE_LEAVE("we_dsa_finish", ret);
    return ret;
}

static int DsaKeygen(we_Dsa *engineDsa)
{
    int ret = 1;
    int rc = 0;

    if (engineDsa == NULL) {
        WOLFENGINE_ERROR_FUNC_NULL("DSA_get_ex_data/EVP_PKEY_CTX_get_data",
                engineDsa);
        ret = 0;
    }
    if (ret == 1) {
#ifndef WE_HAVE_FIPS
        rc = wc_MakeDsaKey(we_rng, &engineDsa->key);
        if (rc != MP_OKAY) {
            WOLFENGINE_ERROR_FUNC("wc_MakeDsaKey", rc);
            ret = 0;
        }
#else
        /* For cert #3389 we have wc_DhGenerateKeyPair included but not
         * the DSA equivalent. Its the same algorithm. */
        DhKey dh;
        byte priv[MAX_DSA_INT_SZ];
        word32 privSz = sizeof(priv);
        byte pub[MAX_DSA_INT_SZ];
        word32 pubSz = sizeof(pub);
        char initDone = 1;
        rc = wc_InitDhKey(&dh); /* Init DH struct */
        if (rc != 0) {
            WOLFENGINE_ERROR_FUNC("wc_InitDhKey", rc);
            ret = 0;
            initDone = 0;
        }
        if (ret == 1) { /* Copy parameters into dh */
            rc = mp_copy(&engineDsa->key.p, &dh.p);
            if (rc == MP_OKAY)
                rc = mp_copy(&engineDsa->key.q, &dh.q);
            if (rc == MP_OKAY)
                rc = mp_copy(&engineDsa->key.g, &dh.g);
            if (rc != MP_OKAY) {
                WOLFENGINE_ERROR_FUNC("mp_copy", rc);
                ret = 0;
            }
        }
        if (ret == 1) { /* Generate key */
            rc = wc_DhGenerateKeyPair(&dh, we_rng, priv, &privSz, pub, &pubSz);
            if (rc != 0) {
                WOLFENGINE_ERROR_FUNC("wc_DhGenerateKeyPair", rc);
                ret = 0;
            }
        }
        if (ret == 1) { /* Decode parameters */
            rc = mp_read_unsigned_bin(&engineDsa->key.x, priv, (int)privSz);
            if (rc == MP_OKAY)
                rc = mp_read_unsigned_bin(&engineDsa->key.y, pub, (int)pubSz);
            if (rc != MP_OKAY) {
                WOLFENGINE_ERROR_FUNC("mp_read_unsigned_bin", rc);
                ret = 0;
            }
        }
        if (initDone) {
            rc = wc_FreeDhKey(&dh);
            if (rc != 0) {
                WOLFENGINE_ERROR_FUNC("wc_FreeDhKey", rc);
                ret = 0;
            }
        }
        if (ret == 1) {
            engineDsa->key.type = DSA_PRIVATE;
        }
#endif
    }
    if (ret == 1) {
        engineDsa->privKeySet = 1;
        engineDsa->pubKeySet = 1;
    }

    return ret;
}

static int we_dsa_keygen(DSA *dsa)
{
    int ret = 1;

    WOLFENGINE_ENTER("we_dsa_keygen");

    ret = DsaKeygen((we_Dsa*)DSA_get_ex_data(dsa, WE_APP_DATA_IDX));

    WOLFENGINE_LEAVE("we_dsa_keygen", ret);
    return ret;
}

int we_init_dsa_meth(void)
{
    int ret = 1;

    WOLFENGINE_ENTER("we_init_dsa_meth");

    we_dsa_method = DSA_meth_new("wolfengine_dsa", 0);
    if (we_dsa_method == NULL) {
        WOLFENGINE_ERROR_FUNC_NULL("DSA_meth_new", we_dsa_method);
        ret = 0;
    }

    if (ret == 1) {
        DSA_meth_set_init(we_dsa_method, we_dsa_init);
        DSA_meth_set_paramgen(we_dsa_method, we_dsa_paramgen);
        DSA_meth_set_keygen(we_dsa_method, we_dsa_keygen);
        DSA_meth_set_finish(we_dsa_method, we_dsa_finish);
    }

    if (ret == 0 && we_dsa_method != NULL) {
        DSA_meth_free(we_dsa_method);
        we_dsa_method = NULL;
    }

    WOLFENGINE_LEAVE("we_init_dsa_meth", ret);

    return ret;
}

#ifdef WE_HAVE_EVP_PKEY

/**
 * Initialize and set the data required to complete an DSA operation.
 *
 * @param  ctx  [in]  Public key context of operation.
 * @returns  1 on success and 0 on failure.
 */
static int we_dsa_pkey_init(EVP_PKEY_CTX *ctx)
{
    int ret = 1;
    int rc = 0;
    we_Dsa *dsa;

    WOLFENGINE_ENTER("we_dsa_pkey_init");

    dsa = (we_Dsa *)OPENSSL_zalloc(sizeof(we_Dsa));
    if (dsa == NULL) {
        WOLFENGINE_ERROR_FUNC_NULL("OPENSSL_zalloc", dsa);
        ret = 0;
    }

    if (ret == 1) {
        rc = wc_InitDsaKey(&dsa->key);
        if (rc != 0) {
            WOLFENGINE_ERROR_FUNC("wc_InitDsaKey", rc);
            ret = 0;
        }
    }

    /* Try to set parameters from ctx */
    if (ret == 1 && EVP_PKEY_CTX_get0_pkey(ctx) != NULL) {
        DSA *osslDsa = EVP_PKEY_get0(EVP_PKEY_CTX_get0_pkey(ctx));
        byte *buf = NULL;
        word32 idx = 0;

        if (osslDsa != NULL) {
            /* Determine what is available for importing */
            const BIGNUM* p = DSA_get0_p(osslDsa);
            const BIGNUM* q = DSA_get0_q(osslDsa);
            const BIGNUM* g = DSA_get0_g(osslDsa);
            const BIGNUM* pub = DSA_get0_pub_key(osslDsa);
            const BIGNUM* priv = DSA_get0_priv_key(osslDsa);

            /* Import one of the following:
             * - private key
             * - public key
             * - only DSA parameters */
            if (p != NULL && q != NULL && g != NULL) {
                if (pub != NULL && priv != NULL) {
                    rc = i2d_DSAPrivateKey(osslDsa, &buf);
                    if (rc <= 0) {
                        WOLFENGINE_ERROR_FUNC("i2d_DSAPrivateKey", rc);
                        ret = 0;
                    }
                    else {
                        rc = wc_DsaPrivateKeyDecode(buf, &idx, &dsa->key, rc);
                        if (rc != 0) {
                            WOLFENGINE_ERROR_FUNC("wc_DsaPrivateKeyDecode", rc);
                            ret = 0;
                        }
                    }
                }
                else if (pub != NULL) {
                    rc = i2d_DSAPublicKey(osslDsa, &buf);
                    if (rc <= 0) {
                        WOLFENGINE_ERROR_FUNC("i2d_DSAPublicKey", rc);
                        ret = 0;
                    }
                    else {
                        rc = wc_DsaPublicKeyDecode(buf, &idx, &dsa->key, rc);
                        if (rc != 0) {
                            WOLFENGINE_ERROR_FUNC("wc_DsaPublicKeyDecode", rc);
                            ret = 0;
                        }
                    }
                }
                else {
                    rc = i2d_DSAparams(osslDsa, &buf);
                    if (rc <= 0) {
                        WOLFENGINE_ERROR_FUNC("i2d_DSAparams", rc);
                        ret = 0;
                    }
                    else {
                        rc = wc_DsaParamsDecode(buf, &idx, &dsa->key, rc);
                        if (rc != 0) {
                            WOLFENGINE_ERROR_FUNC("wc_DsaParamsDecode", rc);
                            ret = 0;
                        }
                    }
                }
            }
            if (buf != NULL)
                OPENSSL_free(buf);
        }
    }

    if (ret == 1) {
        EVP_PKEY_CTX_set_data(ctx, dsa);
        dsa->pbits = DEFAULT_PBITS;
        dsa->qbits = DEFAULT_QBITS;
    }

    if (ret == 0 && dsa != NULL) {
        OPENSSL_free(dsa);
    }

    WOLFENGINE_LEAVE("we_dsa_pkey_init", ret);

    return ret;

}

/**
 * Clean up the DSA operation data.
 *
 * @param  ctx  [in]  Public key context of operation.
 */
static void we_dsa_pkey_cleanup(EVP_PKEY_CTX *ctx)
{
    we_Dsa *dsa = (we_Dsa *)EVP_PKEY_CTX_get_data(ctx);

    WOLFENGINE_ENTER("we_dsa_pkey_cleanup");

    if (dsa != NULL) {
        wc_FreeDsaKey(&dsa->key);
        OPENSSL_free(dsa);
        EVP_PKEY_CTX_set_data(ctx, NULL);
    }
}

/**
 *
 * @param key  [in]  Key material to export
 * @param pkey  [out]  Target for key material export
 * @return  1 on success and 0 on failure.
 */
static int DsaKey2EvpPkey(DsaKey* key, EVP_PKEY *pkey, int paramsOnly)
{
    int ret = 1;
    int derLen = 0;
    DSA *dsa = NULL;
    byte derBuf[MAX_SEQ_SZ + MAX_VERSION_SZ + (DSA_INTS * MAX_DSA_INT_SZ)];
    const unsigned char *pp = derBuf;

    if (paramsOnly)
        derLen = wc_DsaKeyToParamsDer(key, derBuf, sizeof(derBuf));
    else
        derLen = wc_DsaKeyToDer(key, derBuf, sizeof(derBuf));
    if (derLen <= 0) {
        WOLFENGINE_ERROR_FUNC("wc_DsaKeyToDer", derLen);
        ret = 0;
    }
    if (ret == 1) {
        if (paramsOnly)
            d2i_DSAparams(&dsa, &pp, derLen);
        else
            d2i_DSAPrivateKey(&dsa, &pp, derLen);
        if (dsa == NULL) {
            WOLFENGINE_ERROR_FUNC_NULL("d2i_DSAparams", NULL);
            ret = 0;
        }
    }
    if (ret == 1 ) {
        ret = EVP_PKEY_assign_DSA(pkey, dsa);
        if (ret == 0) {
            WOLFENGINE_ERROR_FUNC("EVP_PKEY_assign_DSA", ret);
        }
    }
    if (ret == 0 && dsa != NULL) {
        DSA_free(dsa);
    }
    return ret;
}

/**
 * Generate DSA parameters.
 *
 * @param  ctx   [in]  Public key context of operation.
 * @param  pkey  [in]  EVP public key to hold result.
 * @returns  1 on success and 0 on failure.
 */
static int we_dsa_pkey_paramgen(EVP_PKEY_CTX *ctx, EVP_PKEY *pkey)
{
    int ret = 1;
    we_Dsa *engineDsa = (we_Dsa*)EVP_PKEY_CTX_get_data(ctx);

    WOLFENGINE_ENTER("we_dsa_pkey_paramgen");

    /* DsaParamgen takes care of NULL check */
    ret = DsaParamgen(engineDsa, 0);
    if (ret == 1)
        ret = DsaKey2EvpPkey(&engineDsa->key, pkey, 1);

    WOLFENGINE_LEAVE("we_dsa_pkey_paramgen", ret);

    return ret;
}

/**
 * Generate a DSA key.
 *
 * @param  ctx   [in]  Public key context of operation.
 * @param  pkey  [in]  EVP public key to hold result.
 * @returns  1 on success and 0 on failure.
 */
static int we_dsa_pkey_keygen(EVP_PKEY_CTX *ctx, EVP_PKEY *pkey)
{
    int ret = 1;
    we_Dsa *engineDsa = (we_Dsa*)EVP_PKEY_CTX_get_data(ctx);

    WOLFENGINE_ENTER("we_dsa_pkey_paramgen");

    /* DsaKeygen takes care of NULL check */
    ret = DsaKeygen(engineDsa);
    if (ret == 1)
        ret = DsaKey2EvpPkey(&engineDsa->key, pkey, 0);

    WOLFENGINE_LEAVE("we_dsa_pkey_paramgen", ret);

    return ret;

}


/**
 * Extra operations for working with DSA.
 * Supported operations include:
 *  - EVP_PKEY_CTRL_DSA_PARAMGEN_BITS: set the key size for generation
 *  - EVP_PKEY_CTRL_DSA_PARAMGEN_Q_BITS: set the q size for generation
 *
 * @param  ctx   [in]  Public key context of operation.
 * @param  type  [in]  Type of operation to perform.
 * @param  num   [in]  Integer parameter.
 * @param  ptr   [in]  Pointer parameter.
 * @returns  1 on success and 0 on failure and -2 on not supported
 */
static int we_dsa_pkey_ctrl(EVP_PKEY_CTX *ctx, int type, int num, void *ptr)
{
    int ret = 1;
    we_Dsa *engineDsa = (we_Dsa*)EVP_PKEY_CTX_get_data(ctx);

    WOLFENGINE_ENTER("we_dsa_pkey_ctrl");

    (void)ptr;

    if (engineDsa == NULL) {
        WOLFENGINE_ERROR_FUNC_NULL("EVP_PKEY_CTX_get_data", engineDsa);
        ret = 0;
    }
    if (ret == 1) {
        switch (type) {
            case EVP_PKEY_CTRL_DSA_PARAMGEN_BITS:
                switch (num) {
                    case 1024:
                        if (engineDsa->qbits && engineDsa->qbits != 160)
                            ret = -2;
                        else
                            engineDsa->qbits = 160;
                        break;
                    case 2048:
                    case 3072:
                        if (engineDsa->qbits && engineDsa->qbits != 256)
                            ret = -2;
                        else
                            engineDsa->qbits = 256;
                        break;
                    default:
                        ret = -2;
                }
                if (ret == 1)
                    engineDsa->pbits = num;
                break;
            case EVP_PKEY_CTRL_DSA_PARAMGEN_Q_BITS:
                switch (num) {
                    case 160:
                        if (engineDsa->pbits && engineDsa->pbits != 1024)
                            ret = -2;
                        else
                            engineDsa->pbits = 1024;
                        break;
                    case 256:
                        if (engineDsa->pbits) {
                            if (engineDsa->pbits != 2048 &&
                                engineDsa->pbits != 3072)
                                ret = -2;
                        }
                        else
                            engineDsa->pbits = 2048;
                        break;
                    default:
                        ret = -2;
                }
                if (ret == 1)
                    engineDsa->qbits = num;
                break;
            case EVP_PKEY_CTRL_MD:
                if (EVP_MD_type((const EVP_MD *)ptr) != NID_sha1 &&
                    EVP_MD_type((const EVP_MD *)ptr) != NID_dsa &&
                    EVP_MD_type((const EVP_MD *)ptr) != NID_dsaWithSHA &&
                    EVP_MD_type((const EVP_MD *)ptr) != NID_sha224 &&
                    EVP_MD_type((const EVP_MD *)ptr) != NID_sha256 &&
                    EVP_MD_type((const EVP_MD *)ptr) != NID_sha384 &&
                    EVP_MD_type((const EVP_MD *)ptr) != NID_sha512 &&
                    EVP_MD_type((const EVP_MD *)ptr) != NID_sha3_224 &&
                    EVP_MD_type((const EVP_MD *)ptr) != NID_sha3_256 &&
                    EVP_MD_type((const EVP_MD *)ptr) != NID_sha3_384 &&
                    EVP_MD_type((const EVP_MD *)ptr) != NID_sha3_512) {
                    DSAerr(DSA_F_PKEY_DSA_CTRL, DSA_R_INVALID_DIGEST_TYPE);
                    ret = 0;
                }
                else
                    engineDsa->md = ptr;
                break;
            case EVP_PKEY_CTRL_PEER_KEY:
                DSAerr(DSA_F_PKEY_DSA_CTRL,
                       EVP_R_OPERATION_NOT_SUPPORTED_FOR_THIS_KEYTYPE);
                ret = -2;
                break;
            default:
                ret = -2;
                break;
        }
    }


    WOLFENGINE_LEAVE("we_dsa_pkey_ctrl", ret);

    return ret;
}

/** EVP public key method - DSA using wolfSSL for the implementation. */
EVP_PKEY_METHOD *we_dsa_pkey_method = NULL;

int we_init_dsa_pkey_meth(void)
{
    int ret = 1;

    we_dsa_pkey_method = EVP_PKEY_meth_new(EVP_PKEY_DSA, 0);
    if (we_dsa_pkey_method == NULL) {
        WOLFENGINE_ERROR_FUNC_NULL("EVP_PKEY_meth_new", we_dsa_pkey_method);
        ret = 0;
    }

    if (ret == 1) {
        EVP_PKEY_meth_set_init(we_dsa_pkey_method, we_dsa_pkey_init);
        EVP_PKEY_meth_set_cleanup(we_dsa_pkey_method, we_dsa_pkey_cleanup);
        EVP_PKEY_meth_set_paramgen(we_dsa_pkey_method, NULL, we_dsa_pkey_paramgen);
        EVP_PKEY_meth_set_keygen(we_dsa_pkey_method, NULL, we_dsa_pkey_keygen);
        EVP_PKEY_meth_set_ctrl(we_dsa_pkey_method, we_dsa_pkey_ctrl, NULL);
    }

    if (ret == 0 && we_dsa_pkey_method != NULL) {
        EVP_PKEY_meth_free(we_dsa_pkey_method);
        we_dsa_pkey_method = NULL;
    }

    return ret;
}

#endif /* WE_HAVE_EVP_PKEY */

#endif /* WE_HAVE_DSA */
