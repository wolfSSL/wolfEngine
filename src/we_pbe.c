/* we_pbe_keygen.c
 *
 * Copyright (C) 2019-2021 wolfSSL Inc.
 *
 * This file is part of wolfEngine.
 *
 * wolfEngine is free software; you can redistribute it and/or modify
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

#ifdef WE_HAVE_PBE

#ifndef NO_PWDBASED
/**
 * Convert the OpenSSL HMAC NID to a wolfCrypt hash type.
 *
 * @param  nid  [in]  OpenSSL HMAC NID.
 * @returns  wolfCrypt hash type on success and 0 on failure.
 */
static int we_hmac_to_wc_hash(int nid)
{
    int hashType;

    switch (nid) {
    #ifndef NO_MD5
        case NID_hmacWithMD5:
        case NID_hmac_md5:
            hashType = WC_MD5;
            break;
    #endif
    #ifndef NO_SHA
        case NID_hmacWithSHA1:
        case NID_hmac_sha1:
            hashType = WC_SHA;
            break;
    #endif
    #ifdef WOLFSSL_SHA224
        case NID_hmacWithSHA224:
            hashType = WC_SHA224;
            break;
    #endif
    #ifndef NO_SHA256
        case NID_hmacWithSHA256:
            hashType = WC_SHA256;
            break;
    #endif
    #ifdef WOLFSSL_SHA384
        case NID_hmacWithSHA384:
            hashType = WC_SHA384;
            break;
    #endif
    #ifdef WOLFSSL_SHA512
        case NID_hmacWithSHA512:
            hashType = WC_SHA512;
            break;
    #endif
        /* TODO: OpenSSL also has -
         *     NID_hmacWithSHA512_224
         *     NID_hmacWithSHA512_256
         */
        default:
            /* Unsupported hash algorithm in wolfCrypt. */
            WOLFENGINE_ERROR_MSG(WE_LOG_PBE, "Hash not supported");
            hashType = 0;
            break;
    }

    return hashType;
}

/**
 * Derive the key with PBKDF2 and BER encoded parameters using the password.
 *
 * @param  ctx        [in]  Cipher context to set up with a key.
 * @param  passwd     [in]  Password to derive key from.
 * @param  passwdLen  [in]  Length of password.
 * @param  param      [in]  BER encoded PBKDF2 parameters
 * @param  cipher     [in]  Cipher to use for encryption. (ignored)
 * @param  md         [in]  Hash algorithm to use in derivation. (ignored)
 * @param  en_de      [in]  Setup cipher for encryption or decryption.
 * @returns  1 on success and 0 on failure.
 */
static int we_pbkdf2_keygen(EVP_CIPHER_CTX *ctx, const char *passwd,
    int passwdLen, ASN1_TYPE *param, const EVP_CIPHER *cipher, const EVP_MD *md,
    int en_de)
{
    int ret = 1;
    int rc;
    unsigned char key[EVP_MAX_KEY_LENGTH];
    int kLen;
    int kdfKeyLen;
    PBKDF2PARAM *kdf = NULL;
    int prfNid = NID_hmacWithSHA1;
    int iterations;
    unsigned char *salt;
    int sLen;
    int hashType;

    /* Cipher already set.  */
    (void)cipher;
    /* Digest comes from BER encoded parameters.  */
    (void)md;

    WOLFENGINE_ENTER(WE_LOG_PBE, "we_pbkdf2_keygen");
    WOLFENGINE_MSG_VERBOSE(WE_LOG_PBE, "ARGS [ctx = %p, passwd = %p, "
        "passwdLen = %d, param = %p, cipher = %p, md = %p, en_de = %d]", ctx,
        passwd, passwdLen, param, cipher, md, en_de);

    /* Get the key length to derive. */
    kLen = (int)EVP_CIPHER_CTX_key_length(ctx);
    if (kLen > EVP_MAX_KEY_LENGTH) {
        WOLFENGINE_ERROR_FUNC(WE_LOG_PBE, "EVP_CIPHER_CTX_key_length", kLen);
        ret = 0;
    }

    if (ret == 1) {
        /* Decode the PBKDF2 parameters. */
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
        kdf = ASN1_TYPE_unpack_sequence(ASN1_ITEM_rptr(PBKDF2PARAM), param);
#else
        const unsigned char *pBuf = param->value.sequence->data;
        int pLen = param->value.sequence->length;
        kdf = d2i_PBKDF2PARAM(NULL, &pBuf, pLen);
#endif /* OPENSSL_VERSION_NUMBER >= 0x10100000L */
        if (kdf == NULL) {
            WOLFENGINE_ERROR_FUNC_NULL(WE_LOG_PBE, "ASN1_TYPE_unpack_sequence",
                                       kdf);
            ret = 0;
        }
    }
    /* Validate salt type. */
    if ((ret == 1) && (kdf->salt->type != V_ASN1_OCTET_STRING)) {
        WOLFENGINE_ERROR_MSG(WE_LOG_PBE, "Salt type not OCTET_STRING");
        ret = 0;
    }
    /* Get key length if present and check against cipher's. */
    if ((ret == 1) && (kdf->keylength != NULL)) {
        kdfKeyLen = (int)ASN1_INTEGER_get(kdf->keylength);
        if (kdfKeyLen != kLen) {
            WOLFENGINE_ERROR_FUNC(WE_LOG_PBE, "ASN1_INTEGER_get", kdfKeyLen);
            ret = 0;
        }
    }
    /* Get the PRF if present - default is HMAC-SHA1. */
    if ((ret == 1) && (kdf->prf != NULL)) {
        prfNid = OBJ_obj2nid(kdf->prf->algorithm);
    }
    if (ret == 1) {
        /* Get the wolfCrypt hash type. */
        hashType = we_hmac_to_wc_hash(prfNid);
        if (hashType == 0) {
            WOLFENGINE_ERROR_FUNC(WE_LOG_PBE, "we_hmac_to_wc_hash", hashType);
            ret = 0;
        }
    }
    if (ret == 1) {
        /* Get salt and iterations. */
        salt = kdf->salt->value.octet_string->data;
        sLen = kdf->salt->value.octet_string->length;
        iterations = (int)ASN1_INTEGER_get(kdf->iter);

        WOLFENGINE_MSG(WE_LOG_PBE, "Deriving key with PBKDF2");
        /* Derive the key. */
        rc = wc_PBKDF2_ex(key, (const byte*)passwd, passwdLen, salt, sLen,
            iterations, kLen, hashType, NULL, INVALID_DEVID);
        if (rc != 0) {
            WOLFENGINE_ERROR_FUNC(WE_LOG_PBE, "wc_PBKDF2_ex", rc);
            ret = 0;
        }
    }
    if (ret == 1) {
        /* Set up cipher with key and encrypt or decrypt. */
        ret = EVP_CipherInit_ex(ctx, NULL, NULL, key, NULL, en_de);
    }

    /* Free allocated data. */
    PBKDF2PARAM_free(kdf);

    WOLFENGINE_LEAVE(WE_LOG_PBE, "we_pbkdf2_keygen", ret);

    return ret;
}

/**
 * Convert the OpenSSL digest NID into a wolfCrypt hash type.
 *
 * OpenSSL supportes PBE with: MD2, MD5 and SHA-1.
 * Only supporting SHA-1.
 * (NID_pbe_WithSHA1And3_Key_TripleDES_CBC)
 *
 * @param  nid  [in]  OpenSSL digest NID.
 * @returns  wolfCrypt hash type on success and 0 on failure.
 */
static int we_digest_to_wc_hash(int nid)
{
    int hashType;

    switch (nid) {
    #ifndef NO_SHA
        case NID_sha1:
            hashType = WC_SHA;
            break;
    #endif
        default:
            /* Unsupported hash algorithm in wolfCrypt. */
            WOLFENGINE_ERROR_MSG(WE_LOG_PBE, "Hash not supported");
            hashType = 0;
            break;
    }

    return hashType;
}

/**
 * Determine key and IV length for the OpenSSL cipher NID.
 *
 * OpenSSL supportes with PBE:
 *    RC2-CBC (40-bits and 128-bits)
 *    RC4
 *    DES-CBC
 *    DES-EDE-CBC (2 keys)
 *    DES-EDE3-CBC (3 keys)
 * Only supporting DES-EDE3-CBC.
 * (NID_pbe_WithSHA1And3_Key_TripleDES_CBC)
 *
 * @param  nid     [in]   OpenSSL digest NID.
 * @param  keyLen  [out]  Length of key for cipher.
 * @param  ivLen   [out]  Length of IV for cipher.
 * @returns  1 on success and 0 on failure.
 */
static int we_cipher_to_lengths(int nid, int *keyLen, int *ivLen)
{
    int ret = 1;

    switch (nid) {
    #ifndef NO_DES3
        /* 3-key DES CBC. */
        case NID_des_ede3_cbc:
            *keyLen = 24;
            *ivLen = 8;
            break;
    #endif
        default:
            /* Unsupported cipher algorithm in wolfCrypt. */
            WOLFENGINE_ERROR_MSG(WE_LOG_PBE, "Cipher not supported");
            ret = 0;
            break;
    }

    return ret;
}

/**
 * Derive the key with PBE and BER encoded parameters using the password.
 *
 * OpenSSL 1.1.0+ convert password from UTF8 to Unicode.
 * OpenSSL 1.0.2 converts password from ASCII to Unicode.
 *
 * @param  ctx        [in]  Cipher context to set up with a key.
 * @param  passwd     [in]  Password to derive key from.
 * @param  passwdLen  [in]  Length of password.
 * @param  param      [in]  BER encoded PBKDF2 parameters
 * @param  cipher     [in]  Cipher to use for encryption.
 * @param  md         [in]  Hash algorithm to use in derivation.
 * @param  en_de      [in]  Setup cipher for encryption or decryption.
 * @returns  1 on success and 0 on failure.
 */
static int we_pbe_keyivgen(EVP_CIPHER_CTX *ctx, const char *passwd,
    int passwdLen, ASN1_TYPE *param, const EVP_CIPHER *cipher, const EVP_MD *md,
    int en_de)
{
    int ret = 1;
    int rc;
    PBEPARAM *params = NULL;
    int iterations = 1;
    int kLen;
    int ivLen;
    unsigned char *salt;
    int sLen;
    int hashType;
    unsigned char key[EVP_MAX_KEY_LENGTH];
    unsigned char iv[EVP_MAX_IV_LENGTH];
    unsigned char *uniPass = NULL;
    int uniLen;

    WOLFENGINE_ENTER(WE_LOG_PBE, "we_pbe_keyivgen");
    WOLFENGINE_MSG_VERBOSE(WE_LOG_PBE, "ARGS [ctx = %p, passwd = %p, "
        "passwdLen = %d, param = %p, cipher = %p, md = %p, en_de = %d]", ctx,
        passwd, passwdLen, param, cipher, md, en_de);

    /* Validate parameters. */
    if (cipher == NULL) {
        WOLFENGINE_ERROR_FUNC_NULL(WE_LOG_PBE, "we_pbe_keygen", cipher);
        ret = 0;
    }

    if (ret == 1) {
        /* Decode the PBE parameters. */
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
        params = ASN1_TYPE_unpack_sequence(ASN1_ITEM_rptr(PBEPARAM), param);
#else
        const unsigned char *pBuf = param->value.sequence->data;
        int pLen = param->value.sequence->length;
        params = d2i_PBEPARAM(NULL, &pBuf, pLen);
#endif /* OPENSSL_VERSION_NUMBER >= 0x10100000L */
        if (params == NULL) {
            WOLFENGINE_ERROR_FUNC_NULL(WE_LOG_PBE, "ASN1_TYPE_unpack_sequence",
                                       params);
            ret = 0;
        }
    }
    if ((ret == 1) && (params->iter != NULL)) {
        /* Get the iteration count from parameters. */
        iterations = (int)ASN1_INTEGER_get(params->iter);
    }

    if (ret == 1) {
        /* Determine hash to use from parameter. */
        hashType = we_digest_to_wc_hash(EVP_MD_nid(md));
        if (hashType == 0) {
            WOLFENGINE_ERROR_FUNC(WE_LOG_PBE, "we_digest_to_wc_hash", hashType);
            ret = 0;
        }
    }
    if (ret == 1) {
        /* Determine key and IV length to derive from parameter. */
        ret = we_cipher_to_lengths(EVP_CIPHER_nid(cipher), &kLen, &ivLen);
        if (ret != 1) {
            WOLFENGINE_ERROR_FUNC(WE_LOG_PBE, "we_cipher_to_lengths", ret);
        }
    }
    if (ret == 1) {
        /* Convert password to unicode. Behaviour matches version of OpenSSL. */
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
        if (OPENSSL_utf82uni(passwd, passwdLen, &uniPass, &uniLen) == NULL) {
            WOLFENGINE_ERROR_FUNC_NULL(WE_LOG_PBE, "OPENSSL_utf82uni", NULL);
            ret = 0;
        }
#else
        if (OPENSSL_asc2uni(passwd, passwdLen, &uniPass, &uniLen) == NULL) {
            WOLFENGINE_ERROR_FUNC_NULL(WE_LOG_PBE, "OPENSSL_utf82uni", NULL);
            ret = 0;
        }
#endif
    }
    if (ret == 1) {
        /* Get the salt from the parameters. */
        salt = params->salt->data;
        sLen = params->salt->length;

        WOLFENGINE_MSG(WE_LOG_PBE, "Deriving key with PKCS#12 PBKDF");
        /* Derive the key using the unicode password and id for a key. */
        rc = wc_PKCS12_PBKDF_ex(key, uniPass, uniLen, salt, sLen, iterations,
            kLen, hashType, PKCS12_KEY_ID, NULL);
        if (rc != 0) {
            WOLFENGINE_ERROR_FUNC(WE_LOG_PBE, "wc_PBKDF1_ex", rc);
            ret = 0;
        }
    }
    if (ret == 1) {
        /* Derive the IV using the unicode password and id for an IV. */
        rc = wc_PKCS12_PBKDF_ex(iv, uniPass, uniLen, salt, sLen, iterations,
            ivLen, hashType, PKCS12_IV_ID, NULL);
        if (rc != 0) {
            WOLFENGINE_ERROR_FUNC(WE_LOG_PBE, "wc_PBKDF1_ex", rc);
            ret = 0;
        }
    }
    if (ret == 1) {
        /* Setup the cipher context with the cipher, key, iv and enc/dec. */
        ret = EVP_CipherInit_ex(ctx, cipher, NULL, key, iv, en_de);
    }

    /* Dispose of allocated data. */
    if (uniPass != NULL) {
        OPENSSL_clear_free(uniPass, uniLen);
    }
    PBEPARAM_free(params);

    WOLFENGINE_LEAVE(WE_LOG_PBE, "we_pbe_keyivgen", ret);

    return ret;
}

#if OPENSSL_VERSION_NUMBER < 0x10100000L
/**
 * Derive the key with PBES2 and BER encoded parameters using the password.
 *
 * @param  ctx        [in]  Cipher context to set up with a key.
 * @param  passwd     [in]  Password to derive key from.
 * @param  passwdLen  [in]  Length of password.
 * @param  param      [in]  BER encoded PBKDF2 parameters
 * @param  cipher     [in]  Cipher to use for encryption. (ignored)
 * @param  md         [in]  Hash algorithm to use in derivation. (ignored)
 * @param  en_de      [in]  Setup cipher for encryption or decryption.
 * @returns  1 on success and 0 on failure.
 */
static int we_pbes2_keyivgen(EVP_CIPHER_CTX *ctx, const char *passwd,
    int passwdLen, ASN1_TYPE *param, const EVP_CIPHER *c, const EVP_MD *md,
    int en_de)
{
    int ret = 1;
    int rc;
    PBE2PARAM *pbe2 = NULL;
    const EVP_CIPHER *cipher;

    /* Cipher ingored in favour of PBES2 parameters. */
    (void)c;

    WOLFENGINE_ENTER(WE_LOG_PBE, "we_pbes2_keyivgen");
    WOLFENGINE_MSG_VERBOSE(WE_LOG_PBE, "ARGS [ctx = %p, passwd = %p, "
        "passwdLen = %d, param = %p, c = %p, md = %p, en_de = %d]", ctx, passwd,
        passwdLen, param, c, md, en_de);

    /* Check param is not NULL. */
    if (param == NULL) {
        WOLFENGINE_ERROR_FUNC_NULL(WE_LOG_PBE, "we_pbes2_keyivgen", param);
        ret = 0;
    }
    /* Ensure param is a SEQUENCE. */
    if ((ret == 1) && (param->type != V_ASN1_SEQUENCE)) {
        WOLFENGINE_ERROR_MSG(WE_LOG_PBE, "Parameters not SEQUENCE");
        ret = 0;
    }
    /* Ensure param has data. */
    if ((ret == 1) && (param->value.sequence == NULL)) {
        WOLFENGINE_ERROR_MSG(WE_LOG_PBE, "param->value.sequence == NULL");
        ret = 0;
    }
    if (ret == 1) {
        const unsigned char *pBuf = param->value.sequence->data;
        int pLen = param->value.sequence->length;

        /* Decode the PBES2 parameters. */
        pbe2 = d2i_PBE2PARAM(NULL, &pBuf, pLen);
        if (pbe2 == NULL) {
            WOLFENGINE_ERROR_FUNC_NULL(WE_LOG_PBE, "d2i_PBE2PARAM", pbe2);
            ret = 0;
        }
    }

    /* KDF algorithm must be PBKDF2. */
    if ((ret == 1) &&
        (OBJ_obj2nid(pbe2->keyfunc->algorithm) != NID_id_pbkdf2)) {
        WOLFENGINE_ERROR_MSG(WE_LOG_PBE, "KDF algorithm not PBKDF2");
        ret = 0;
    }

    if (ret == 1) {
        /* Convert encryption algorithm into a cipher object. */
        cipher = EVP_get_cipherbyobj(pbe2->encryption->algorithm);
        if (cipher == NULL) {
            WOLFENGINE_ERROR_FUNC_NULL(WE_LOG_PBE, "EVP_get_cipherbyobj", NULL);
            ret = 0;
        }
    }

    if (ret == 1) {
       WOLFENGINE_MSG(WE_LOG_PBE, "Setting up PBES2 key");
        /* Create cipher context with cipher and enc/dec. */
        ret = EVP_CipherInit_ex(ctx, cipher, NULL, NULL, NULL, en_de);
        if (ret != 1) {
            WOLFENGINE_ERROR_FUNC(WE_LOG_PBE, "EVP_CipherInit_ex", ret);
        }
    }
    if (ret == 1) {
        /* Set the BER encoded encryption parameters. */
        rc = EVP_CIPHER_asn1_to_param(ctx, pbe2->encryption->parameter);
        if (rc < 0) {
            WOLFENGINE_ERROR_FUNC(WE_LOG_PBE, "EVP_CIPHER_asn1_to_param", rc);
        }
    }
    if (ret == 1) {
        /* Derive the key using PBKDF2. */
        ret = we_pbkdf2_keygen(ctx, passwd, passwdLen, pbe2->keyfunc->parameter,
                               cipher, md, en_de);
    }

    /* Dispose of allocated data. */
    PBE2PARAM_free(pbe2);

    WOLFENGINE_LEAVE(WE_LOG_PBE, "we_pbes2_keyivgen", ret);

    return ret;
}
#endif /* OPENSSL_VERSION_NUMBER < 0x10100000L */
#endif /* !NO_PWDBASED */

/**
 * Set the PBE functions to lookup for PBE, PBES2 and PKBDF2.
 *
 * @returns  1 on success and 0 on failure.
 */
int we_init_pbe_keygen()
{
#ifndef NO_PWDBASED
    int ret;

    ret = EVP_PBE_alg_add_type(EVP_PBE_TYPE_OUTER, NID_id_pbkdf2, -1, -1,
        we_pbkdf2_keygen);
    if (ret != 1) {
        WOLFENGINE_ERROR_FUNC(WE_LOG_PBE, "EVP_PBE_alg_add_type", ret);
    }
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
    if (ret == 1) {
        /* Let PKCS5_v2_PBE_keyivgen look up the KDF function. */
        ret = EVP_PBE_alg_add_type(EVP_PBE_TYPE_KDF, NID_id_pbkdf2, -1, -1,
            we_pbkdf2_keygen);
        if (ret != 1) {
            WOLFENGINE_ERROR_FUNC(WE_LOG_PBE, "EVP_PBE_alg_add_type", ret);
        }
    }
#else
    if (ret == 1) {
        /* PKCS5_v2_PBE_keyivgen doesn't look up the KDF function. */
        ret = EVP_PBE_alg_add_type(EVP_PBE_TYPE_OUTER, NID_pbes2, -1, -1,
            we_pbes2_keyivgen);
        if (ret != 1) {
            WOLFENGINE_ERROR_FUNC(WE_LOG_PBE, "EVP_PBE_alg_add_type", ret);
        }
    }
#endif /* OPENSSL_VERSION_NUMBER >= 0x10100000L */
    if (ret == 1) {
        ret = EVP_PBE_alg_add_type(EVP_PBE_TYPE_OUTER,
            NID_pbe_WithSHA1And3_Key_TripleDES_CBC, NID_des_ede3_cbc, NID_sha1,
            we_pbe_keyivgen);
        if (ret != 1) {
            WOLFENGINE_ERROR_FUNC(WE_LOG_PBE, "EVP_PBE_alg_add_type", ret);
        }
    }

    return ret;
#else
    WOLFENGINE_MSG(WE_LOG_PBE, "wolfCrypt does not support PBKDF");
    return 1;
#endif /* !NO_PWDBASED */
}

#endif /* WE_HAVE_PBE */
