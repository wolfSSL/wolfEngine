/* we_aes_ctr.c
 *
 * Copyright (C) 2006-2023 wolfSSL Inc.
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

#ifdef WE_HAVE_AESCTR

/*
 * AES-CTR
 */

/**
 * Data required to complete an AES-CTR block encrypt/decrypt operation.
 */
typedef struct we_AesCtr
{
    /* The wolfSSL AES data object. */
    Aes aes;
    word32 keyed;
} we_AesCtr;


/**
 * Initialize the AES-CTR encrypt/decrypt operation using wolfSSL.
 *
 * @param  ctx  [in,out]  EVP cipher context of operation.
 * @param  key  [in]      AES key - 16/24/32 bytes.
 * @param  iv   [in]      Initialization Vector - 12 bytes.
 * @param  enc  [in]      1 when initializing for encrypt and 0 when decrypt.
 * @return  1 on success and 0 on failure.
 */
static int we_aes_ctr_init(EVP_CIPHER_CTX *ctx, const unsigned char *key,
                           const unsigned char *iv, int enc)
{
    int ret = 1;
    int rc;
    we_AesCtr *aes;
    const unsigned char* tmpIv = iv;

    WOLFENGINE_ENTER(WE_LOG_CIPHER, "we_aes_ctr_init");
    WOLFENGINE_MSG_VERBOSE(WE_LOG_CIPHER, "ARGS [ctx = %p, key = %p, iv = %p, "
                           "enc = %d]", ctx, key, iv, enc);

    (void)enc;

    aes = (we_AesCtr *)EVP_CIPHER_CTX_get_cipher_data(ctx);
    if (aes == NULL) {
        WOLFENGINE_ERROR_FUNC_NULL(WE_LOG_CIPHER,
                                   "EVP_CIPHER_CTX_get_cipher_data", aes);
        ret = 0;
    }

    /* Do not reinitialize if already keyed, unless setting a new key */
    if ((ret == 1) && ((aes->keyed == 0) || (key != NULL))) {
        rc = wc_AesInit(&aes->aes, NULL, INVALID_DEVID);
        if (rc != 0) {
            WOLFENGINE_ERROR_FUNC(WE_LOG_CIPHER, "wc_AesInit", rc);
            ret = 0;
        }
    }
    if ((ret == 1) && (key != NULL)) {
        if (tmpIv == NULL) {
            /* If no IV given, attempt to use previously set ctx IV. */
            tmpIv = EVP_CIPHER_CTX_iv_noconst(ctx);
        }
        /* No decryption for CTR (hence AES_ENCRYPTION). */
        rc = wc_AesSetKey(&aes->aes, key, EVP_CIPHER_CTX_key_length(ctx), tmpIv,
                          AES_ENCRYPTION);
        if (rc != 0) {
            WOLFENGINE_ERROR_FUNC(WE_LOG_CIPHER, "wc_AesSetKey", rc);
            ret = 0;
        }
        aes->keyed = 1;
    }
    if ((ret == 1) && (iv != NULL)) {
        rc = wc_AesSetIV(&aes->aes, iv);
        if (rc != 0) {
            WOLFENGINE_ERROR_FUNC(WE_LOG_CIPHER, "wc_AesSetIV", rc);
            ret = -1;
        }
        else {
            /*
             * wc_AesSetIV should clear this field, but it doesn't in some
             * wolfSSL versions.
             */
            aes->aes.left = 0;
        }
    }

    WOLFENGINE_LEAVE(WE_LOG_CIPHER, "we_aes_ctr_init", ret);

    return ret;
}

/**
 * Encrypt/decrypt the data using wolfSSL.
 *
 * Supports pad/no pad and streaming.
 *
 * @param  ctx  [in/out]  EVP cipher context of operation.
 * @param  out  [out]     Buffer to store enciphered result.
 * @param  in   [in]      Data to encrypt/decrypt.
 * @param  len  [in]      Length of data to encrypt/decrypt.
 * @return  -1 on failure.
 * @return  Length of output data on success.
 */
static int we_aes_ctr_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out,
                             const unsigned char *in, size_t len)
{
    int ret = 1;
    we_AesCtr* aes;
    int rc;

    WOLFENGINE_ENTER(WE_LOG_CIPHER, "we_aes_ctr_cipher");
    WOLFENGINE_MSG_VERBOSE(WE_LOG_CIPHER, "ARGS [ctx = %p, out = %p, in = %p, "
                           "len = %d]", ctx, out, in, len);

    /* Get the AES-CTR object to work with. */
    aes = (we_AesCtr *)EVP_CIPHER_CTX_get_cipher_data(ctx);
    if (aes == NULL) {
        WOLFENGINE_ERROR_FUNC_NULL(WE_LOG_CIPHER,
                                   "EVP_CIPHER_CTX_get_cipher_data", aes);
        ret = -1;
    }

    if (ret == 1) {
        if (in != NULL && len > 0) {
            rc = wc_AesCtrEncrypt(&aes->aes, out, in, (word32)len);
            if (rc != 0) {
                WOLFENGINE_ERROR_FUNC(WE_LOG_CIPHER, "wc_AesCtrEncrypt", rc);
                ret = -1;
            }
            else {
                unsigned int num = EVP_CIPHER_CTX_num(ctx);
                num = (num + len) % AES_128_KEY_SIZE;
                EVP_CIPHER_CTX_set_num(ctx, num);

                XMEMCPY(EVP_CIPHER_CTX_iv_noconst(ctx), aes->aes.reg,
                        AES_BLOCK_SIZE);

                ret = (int)len;
            }
        }
        else if (in == NULL)  {
            ret = 0;
        }
    }

    WOLFENGINE_LEAVE(WE_LOG_CIPHER, "we_aes_ctr_cipher", ret);

    return ret;
}

/**
 * Extra operations for AES-CTR.
 *
 * No supported operations yet.
 *
 * @param  ctx   [in]  EVP cipher context of operation.
 * @param  type  [in]  Type of operation to perform.
 * @param  arg   [in]  Integer argument.
 * @param  ptr   [in]  Pointer argument.
 * @return  1 on success and 0 on failure.
 */
static int we_aes_ctr_ctrl(EVP_CIPHER_CTX *ctx, int type, int arg, void *ptr)
{
    int ret = 1;
    we_AesCtr *aes;
    char errBuff[WOLFENGINE_MAX_LOG_WIDTH];

    WOLFENGINE_ENTER(WE_LOG_CIPHER, "we_aes_ctr_ctrl");
    WOLFENGINE_MSG_VERBOSE(WE_LOG_CIPHER, "ARGS [ctx = %p, type = %d, "
                           "arg = %d, ptr = %p]", ctx, type, arg, ptr);

    (void)arg;
    (void)ptr;

    /* Get the AES-CTR data to work with. */
    aes = (we_AesCtr *)EVP_CIPHER_CTX_get_cipher_data(ctx);
    if (aes != NULL) {
        WOLFENGINE_ERROR_FUNC_NULL(WE_LOG_CIPHER,
                                   "EVP_CIPHER_CTX_get_cipher_data", aes);
        ret = 0;
    }
    if (ret == 1) {
        switch (type) {
            default:
                XSNPRINTF(errBuff, sizeof(errBuff), "Unsupported ctrl type %d",
                          type);
                WOLFENGINE_ERROR_MSG(WE_LOG_CIPHER, errBuff);
                ret = 0;
                break;
        }
    }

    WOLFENGINE_LEAVE(WE_LOG_CIPHER, "we_aes_ctr_ctrl", ret);

    return ret;
}

/** Flags for AES-CTR method. */
#define AES_CTR_FLAGS              \
    (EVP_CIPH_ALWAYS_CALL_INIT   | \
     EVP_CIPH_FLAG_CUSTOM_CIPHER | \
     EVP_CIPH_FLAG_DEFAULT_ASN1  | \
     EVP_CIPH_CTR_MODE)

/** AES128-CTR EVP cipher method. */
EVP_CIPHER* we_aes128_ctr_ciph = NULL;
/** AES192-CTR EVP cipher method. */
EVP_CIPHER* we_aes192_ctr_ciph = NULL;
/** AES256-CTR EVP cipher method. */
EVP_CIPHER* we_aes256_ctr_ciph = NULL;

/**
 * Initialize an AES-CTR method.
 *
 * @return  1 on success and 0 on failure.
 */
static int we_init_aesctr_meth(EVP_CIPHER *cipher)
{
    int ret;

    WOLFENGINE_ENTER(WE_LOG_CIPHER, "we_init_aesctr_meth");

    ret = EVP_CIPHER_meth_set_iv_length(cipher, AES_IV_SIZE);
    if (ret == 1) {
        ret = EVP_CIPHER_meth_set_flags(cipher, AES_CTR_FLAGS);
    }
    if (ret == 1) {
        ret = EVP_CIPHER_meth_set_init(cipher, we_aes_ctr_init);
    }
    if (ret == 1) {
        ret = EVP_CIPHER_meth_set_do_cipher(cipher, we_aes_ctr_cipher);
    }
    if (ret == 1) {
        ret = EVP_CIPHER_meth_set_ctrl(cipher, we_aes_ctr_ctrl);
    }
    if (ret == 1) {
        ret = EVP_CIPHER_meth_set_impl_ctx_size(cipher, sizeof(we_AesCtr));
    }

    WOLFENGINE_LEAVE(WE_LOG_CIPHER, "we_init_aesctr_meth", ret);

    return ret;
}

/**
 * Initialize the AES-CTR methods.
 *
 * @return  1 on success and 0 on failure.
 */
int we_init_aesctr_meths()
{
    int ret = 1;

    WOLFENGINE_ENTER(WE_LOG_CIPHER, "we_init_aesctr_meths");

    /* AES128-CTR */
    we_aes128_ctr_ciph = EVP_CIPHER_meth_new(NID_aes_128_ctr, 1,
                                             AES_128_KEY_SIZE);
    if (we_aes128_ctr_ciph == NULL) {
        WOLFENGINE_ERROR_FUNC_NULL(WE_LOG_CIPHER,
                                   "EVP_CIPHER_meth_new - AES-128-CTR",
                                   we_aes128_ctr_ciph);
        ret = 0;
    }
    if (ret == 1) {
        ret = we_init_aesctr_meth(we_aes128_ctr_ciph);
    }

    /* AES192-CTR */
    if (ret == 1) {
        we_aes192_ctr_ciph = EVP_CIPHER_meth_new(NID_aes_192_ctr, 1,
                                                 AES_192_KEY_SIZE);
        if (we_aes192_ctr_ciph == NULL) {
            WOLFENGINE_ERROR_FUNC_NULL(WE_LOG_CIPHER,
                                       "EVP_CIPHER_meth_new - AES-192-CTR",
                                       we_aes192_ctr_ciph);
            ret = 0;
        }
    }
    if (ret == 1) {
        ret = we_init_aesctr_meth(we_aes192_ctr_ciph);
    }

    /* AES256-CTR */
    if (ret == 1) {
        we_aes256_ctr_ciph = EVP_CIPHER_meth_new(NID_aes_256_ctr, 1,
                                                 AES_256_KEY_SIZE);
        if (we_aes256_ctr_ciph == NULL) {
            WOLFENGINE_ERROR_FUNC_NULL(WE_LOG_CIPHER,
                                       "EVP_CIPHER_meth_new - AES-256-CTR",
                                       we_aes256_ctr_ciph);
            ret = 0;
        }
    }
    if (ret == 1) {
        ret = we_init_aesctr_meth(we_aes256_ctr_ciph);
    }

    /* Cleanup */
    if ((ret == 0) && (we_aes128_ctr_ciph != NULL)) {
        EVP_CIPHER_meth_free(we_aes128_ctr_ciph);
        we_aes128_ctr_ciph = NULL;
    }
    if ((ret == 0) && (we_aes192_ctr_ciph != NULL)) {
        EVP_CIPHER_meth_free(we_aes192_ctr_ciph);
        we_aes192_ctr_ciph = NULL;
    }
    if ((ret == 0) && (we_aes256_ctr_ciph != NULL)) {
        EVP_CIPHER_meth_free(we_aes256_ctr_ciph);
        we_aes256_ctr_ciph = NULL;
    }

    WOLFENGINE_LEAVE(WE_LOG_CIPHER, "we_init_aesctr_meths", ret);

    return ret;
}

#endif /* WE_HAVE_AESCTR */
