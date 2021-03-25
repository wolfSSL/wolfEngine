/* rsa.c
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

#ifdef WE_HAVE_RSA

/* Maximum DER digest size, taken from wolfSSL. Sum of the maximum size of the
   encoded digest, algorithm tag, and sequence tag. */
#define MAX_DER_DIGEST_SZ 98
/* The default RSA key/modulus size in bits. */
#define DEFAULT_KEY_BITS 2048
/* The default RSA public exponent, e. */
#define DEFAULT_PUB_EXP WC_RSA_EXPONENT

/**
 * Data required to complete an RSA operation.
 */
typedef struct we_Rsa
{
    /* wolfSSL structure for holding RSA key data. */
    RsaKey key;
    /* Stored by control command EVP_PKEY_CTRL_MD. */
    EVP_MD *md;
    /* Padding mode */
    int padMode;
    /* The public exponent ("e"). */
    int pubExp;
    /* The key/modulus size in bits. */
    int bits;
    /* Indicates private key has been set into wolfSSL structure. */
    int privKeySet:1;
    /* Indicates public key has been set into wolfSSL structure. */
    int pubKeySet:1;
} we_Rsa;

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
    int ret;
    we_Rsa *rsa;

    WOLFENGINE_MSG("RSA PKEY - Init");

    ret = (rsa = OPENSSL_zalloc(sizeof(we_Rsa))) != NULL;
    if (ret == 1) {
        ret = wc_InitRsaKey(&rsa->key, NULL) == 0;
    }
    if (ret == 1) {
        EVP_PKEY_CTX_set_data(ctx, rsa);
    }
    if (ret == 1) {
        rsa->pubExp = DEFAULT_PUB_EXP;
        rsa->bits = DEFAULT_KEY_BITS;
    }

    if (ret == 0 && rsa != NULL) {
        OPENSSL_free(rsa);
    }

    return ret;
}

/**
 * Clean up the RSA operation data.
 *
 * @param  ctx  [in]  Public key context of operation.
 */
static void we_rsa_pkey_cleanup(EVP_PKEY_CTX *ctx)
{
    we_Rsa *rsa = (we_Rsa *)EVP_PKEY_CTX_get_data(ctx);

    WOLFENGINE_MSG("RSA PKEY - Cleanup");

    if (rsa != NULL) {
        wc_FreeRsaKey(&rsa->key);
        OPENSSL_free(rsa);
        EVP_PKEY_CTX_set_data(ctx, NULL);
    }
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

    (void)dst;
    (void)src;

    WOLFENGINE_MSG("RSA PKEY - Copy");

    return ret;
}

/**
 * Generate an RSA key.
 *
 * @param  ctx   [in]  Public key context of operation.
 * @param  pkey  [in]  EVP public key to hold result.
 * @returns  1 on success and 0 on failure.
 */
static int we_rsa_pkey_keygen(EVP_PKEY_CTX *ctx, EVP_PKEY *pkey)
{
    int ret = 0;
    we_Rsa *engineRsa = NULL;
    RSA *rsa = NULL;
    unsigned char *der = NULL;
    const unsigned char *p = NULL;
    int derLen = 0;

    WOLFENGINE_MSG("RSA PKEY - Key Gen");

    ret = (engineRsa = (we_Rsa *)EVP_PKEY_CTX_get_data(ctx)) != NULL;
    if (ret == 1) {
        ret = wc_MakeRsaKey(&engineRsa->key, engineRsa->bits, engineRsa->pubExp,
                            we_rng) == 0;
    }
    if (ret == 1) {
        ret = (derLen = wc_RsaKeyToDer(&engineRsa->key, NULL, 0)) > 0;
    }
    if (ret == 1) {
        ret = (der = OPENSSL_malloc(derLen)) != NULL;
    }
    if (ret == 1) {
        ret = (derLen = wc_RsaKeyToDer(&engineRsa->key, der, derLen)) > 0;
    }
    if (ret == 1) {
        /*
         * The pointer passed to d2i_RSAPrivateKey will get advanced to the
         * end of the buffer, so we save the original pointer in order to free
         * the buffer later.
         */
        p = (const unsigned char *)der;
        rsa = d2i_RSAPrivateKey(NULL, &p, derLen);
        ret = rsa != NULL;
    }
    if (ret == 1) {
        ret = EVP_PKEY_assign_RSA(pkey, rsa);
    }

    if (der != NULL) {
        OPENSSL_free(der);
    }
    if (ret == 0 && rsa != NULL) {
        RSA_free(rsa);
    }

    return ret;
}

/**
 * Extra operations for working with RSA.
 * Supported operations include:
 *  - EVP_PKEY_CTRL_MD: set the method used when digesting.
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
    char *bnDec = NULL;
    long e;

    WOLFENGINE_MSG("RSA PKEY - Ctrl");

    rsa = (we_Rsa *)EVP_PKEY_CTX_get_data(ctx);
    if (rsa == NULL)
        ret = 0;

    if (ret == 1) {
        switch (type) {
            case EVP_PKEY_CTRL_RSA_PADDING:
                /* TODO: Make sign/verify use padding mode. */
                rsa->padMode = num;
                break;
            case EVP_PKEY_CTRL_GET_RSA_PADDING:
                *(int *)ptr = rsa->padMode;
                break;
            case EVP_PKEY_CTRL_MD:
                rsa->md = (EVP_MD*)ptr;
                break;
            case EVP_PKEY_CTRL_GET_MD:
                *(EVP_MD **)ptr = rsa->md;
                break;
            case EVP_PKEY_CTRL_DIGESTINIT:
                break;
#if OPENSSL_VERSION_NUMBER >= 0x1010100fL
            case EVP_PKEY_CTRL_RSA_KEYGEN_PRIMES:
                /* wolfCrypt can only do key generation with 2 primes. */
                break;
#endif
            case EVP_PKEY_CTRL_RSA_KEYGEN_BITS:
                if (num < RSA_MIN_SIZE || num > RSA_MAX_SIZE) {
                    WOLFENGINE_ERROR_MSG("RSA key size not in range.");
                    ret = 0;
                }
                else {
                    rsa->bits = num;
                    ret = 1;
                }
                break;
            case EVP_PKEY_CTRL_RSA_KEYGEN_PUBEXP:
                bn = (BIGNUM*)ptr;
                e = (long)BN_get_word(bn);
                if (e == (long)BN_MASK2) {
                    WOLFENGINE_ERROR_MSG("RSA public exponent too large.");
                    ret = 0;
                }
                if (ret == 1 && e == 0) {
                    WOLFENGINE_ERROR_MSG("RSA public exponent is 0.");
                    ret = 0;
                }
                if (ret == 1) {
                    rsa->pubExp = e;
                }
                break;
            default:
                ret = 0;
                break;
        }
    }
    
    if (bnDec != NULL) {
        OPENSSL_free(bnDec);
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
    int ret = 0;
    int hashOID = 0;

    if (*encodedDigest == NULL) {
        *encodedDigest = OPENSSL_malloc(MAX_DER_DIGEST_SZ);
    }
    ret = *encodedDigest != NULL;
    if (ret == 1) {
        hashOID = we_nid_to_wc_hash_oid(EVP_MD_type(md));
        ret = hashOID > 0;
    }
    if (ret == 1) {
        ret = wc_EncodeSignature(*encodedDigest, digest, (word32)digestLen,
                                 hashOID);
    }

    return ret;
}

/**
 * Set the private key in a we_Rsa structure.
 *
 * @param  ctx     [in]  Public key context of operation.
 * @param  rsa     [in]  RSA structure to hold private key.
 * @returns  1 on success and 0 on failure.
 */
static int we_set_private_key(RSA *rsaKey, we_Rsa *engineRsa)
{
    int ret = 0;
    unsigned char *privDer = NULL;
    int privDerLen = 0;
    word32 idx = 0;

    privDerLen = i2d_RSAPrivateKey(rsaKey, &privDer);
    ret = privDerLen >= 0;
    if (ret == 1) {
        ret = wc_RsaPrivateKeyDecode(privDer, &idx, &engineRsa->key,
                                     privDerLen) == 0;
    }
    if (ret == 1) {
        engineRsa->privKeySet = 1;
    }

    if (privDer != NULL) {
        OPENSSL_clear_free(privDer, privDerLen);
    }

    return ret;
}

/**
 * Sign data with a private RSA key.
 *
 * @param  ctx     [in]      Public key context of operation.
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
    int ret = 0;
    we_Rsa *rsa = NULL;
    EVP_PKEY *pkey = NULL;
    RSA *rsaKey = NULL;
    unsigned char *encodedDigest = NULL;
    int encodedDigestLen = 0;
    int actualSigLen = 0;

    WOLFENGINE_MSG("RSA PKEY - Sign");

    ret = (rsa = (we_Rsa *)EVP_PKEY_CTX_get_data(ctx)) != NULL;

    /* Set up private key */
    if (ret == 1 && !rsa->privKeySet) {
        ret = (pkey = EVP_PKEY_CTX_get0_pkey(ctx)) != NULL;
        if (ret == 1) {
            ret = (rsaKey = (RSA*)EVP_PKEY_get0_RSA(pkey)) != NULL;
        }
        if (ret == 1) {
            ret = we_set_private_key(rsaKey, rsa);
        }
    }
    if (ret == 1 && sig == NULL) {
        /* Return signature size in bytes. */
        *sigLen = wc_SignatureGetSize(WC_SIGNATURE_TYPE_RSA, &rsa->key,
                                      sizeof(rsa->key));
    }
    if (ret == 1 && sig != NULL) {
        if (rsa->md != NULL) {
            /* In this case, OpenSSL expects a proper PKCS #1 v1.5 signature. */
            encodedDigestLen = we_der_encode_digest(rsa->md, tbs, tbsLen,
                                                    &encodedDigest);
            ret = encodedDigestLen > 0;
            if (ret == 1) {
                tbs = encodedDigest;
                tbsLen = encodedDigestLen;
            }
        }

        if (ret == 1) {
            actualSigLen = wc_RsaSSL_Sign(tbs, (word32)tbsLen, sig,
                                          (word32)*sigLen, &rsa->key, we_rng);
            ret = actualSigLen > 0;
            if (ret == 1) {
                *sigLen = actualSigLen;
            }
        }
    }

    if (encodedDigest != NULL) {
        OPENSSL_free(encodedDigest);
    }

    return ret;
}

/**
 * Set the public key in a we_Rsa structure.
 *
 * @param  ctx     [in]  Public key context of operation.
 * @param  rsa     [in]  RSA structure to hold public key.
 * @returns  1 on success and 0 on failure.
 */
static int we_set_public_key(RSA *rsaKey, we_Rsa *engineRsa)
{
    int ret = 0;
    unsigned char *pubDer = NULL;
    int pubDerLen = 0;
    word32 idx = 0;

    pubDerLen = i2d_RSAPublicKey(rsaKey, &pubDer);
    ret = pubDerLen >= 0;
    if (ret == 1) {
        ret = wc_RsaPublicKeyDecode(pubDer, &idx, &engineRsa->key,
                                    pubDerLen) == 0;
    }
    if (ret == 1) {
        engineRsa->pubKeySet = 1;
    }

    if (pubDer != NULL) {
        OPENSSL_free(pubDer);
    }

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
    int ret = 0;
    we_Rsa *rsa = NULL;
    EVP_PKEY *pkey = NULL;
    RSA *rsaKey = NULL;
    unsigned char *decryptedSig = NULL;
    unsigned char *encodedDigest = NULL;
    size_t encodedDigestLen = 0;

    WOLFENGINE_MSG("RSA PKEY - Verify");

    ret = (rsa = (we_Rsa *)EVP_PKEY_CTX_get_data(ctx)) != NULL;

    if (ret == 1 && !rsa->pubKeySet) {
        ret = (pkey = EVP_PKEY_CTX_get0_pkey(ctx)) != NULL;
        if (ret == 1) {
            ret = (rsaKey = (RSA*)EVP_PKEY_get0_RSA(pkey)) != NULL;
        }
        if (ret == 1) {
            ret = we_set_public_key(rsaKey, rsa);
        }
    }
    if (ret == 1) {
        decryptedSig = OPENSSL_malloc(MAX_DER_DIGEST_SZ);
        ret = decryptedSig != NULL;
    }
    if (ret == 1) {
        ret = wc_RsaSSL_Verify(sig, (word32)sigLen, decryptedSig,
                               (word32)sigLen, &rsa->key) > 0;
        if (ret == 1) {
            if (rsa->md != NULL) {
                /* In this case, we have a proper DER-encoded signature, not
                   just arbitrary signed data, so we must compare with the
                   encoded digest. */
                encodedDigestLen = we_der_encode_digest(rsa->md, tbs, tbsLen,
                                                        &encodedDigest);
                ret = encodedDigestLen > 0;
                if (ret == 1) {
                    tbs = encodedDigest;
                    tbsLen = encodedDigestLen;
                }
            }
            ret = XMEMCMP(tbs, decryptedSig, tbsLen) == 0;
        }
    }

    if (decryptedSig != NULL) {
        OPENSSL_free(decryptedSig);
    }

    if (encodedDigest != NULL) {
        OPENSSL_free(encodedDigest);
    }

    return ret;
}

/**
 * Initialize the RSA method for use with the EVP_PKEY API.
 *
 * @return  1 on success and 0 on failure.
 */
int we_init_rsa_pkey_meth(void)
{
    int ret;

    ret = (we_rsa_pkey_method = EVP_PKEY_meth_new(EVP_PKEY_RSA, 0)) != NULL;
    if (ret == 1) {
        EVP_PKEY_meth_set_init(we_rsa_pkey_method, we_rsa_pkey_init);
        EVP_PKEY_meth_set_sign(we_rsa_pkey_method, NULL, we_rsa_pkey_sign);
        EVP_PKEY_meth_set_verify(we_rsa_pkey_method, NULL, we_rsa_pkey_verify);
        EVP_PKEY_meth_set_cleanup(we_rsa_pkey_method, we_rsa_pkey_cleanup);
        EVP_PKEY_meth_set_ctrl(we_rsa_pkey_method, we_rsa_pkey_ctrl, NULL);
        EVP_PKEY_meth_set_copy(we_rsa_pkey_method, we_rsa_pkey_copy);
        EVP_PKEY_meth_set_keygen(we_rsa_pkey_method, NULL, we_rsa_pkey_keygen);
    }

    if (ret == 0 && we_rsa_pkey_method != NULL) {
        EVP_PKEY_meth_free(we_rsa_pkey_method);
        we_rsa_pkey_method = NULL;
    }

    return ret;
}

#endif /* WE_HAVE_EVP_PKEY */

#endif /* WE_HAVE_RSA */
