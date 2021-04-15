/* we_des3_cbc.c
 *
 * Copyright (C) 2006-2019 wolfSSL Inc.
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


#ifdef WE_HAVE_DES3CBC

/*
 * DES3-CBC
 */

/**
 * Data required to complete an DES3-CBC encrypt/decrypt operation.
 */
typedef struct we_Des3Cbc
{
    /** The wolfSSL DES3 data object. */
    Des3           des3;
    /** Flag to indicate whether wolfSSL DES3 object initialized. */
    unsigned int   init:1;
    /** Flag to indicate whether we are doing encrypt (1) or decrpyt (0). */
    unsigned int   enc:1;
} we_Des3Cbc;

/**
 * Initialize the DES3-CBC encrypt/decrypt operation using wolfSSL.
 *
 * @param  ctx  [in,out]  EVP cipher context of operation.
 * @param  key  [in]      DES3 key - 24 bytes.
 * @param  iv   [in]      Initialization Vector - 8 bytes.
 * @param  enc  [in]      1 when initializing for encrypt and 0 when decrypt.
 * @return  1 on success and 0 on failure.
 */
static int we_des3_cbc_init(EVP_CIPHER_CTX *ctx, const unsigned char *key,
                            const unsigned char *iv, int enc)
{
    int ret = 1;
    int rc;
    we_Des3Cbc *des3;

    WOLFENGINE_ENTER(WE_LOG_CIPHER, "we_des3_cbc_init");
    WOLFENGINE_MSG_VERBOSE(WE_LOG_CIPHER, "ARGS [ctx = %p, key = %p, "
                           "iv = %p, enc = %d]", ctx, key, iv, enc);

    if ((iv == NULL) && (key == NULL)) {
        WOLFENGINE_ERROR_MSG(WE_LOG_CIPHER, "iv == NULL && key == NULL");
        ret = 0;
    }

    if (ret == 1) {
        des3 = (we_Des3Cbc *)EVP_CIPHER_CTX_get_cipher_data(ctx);
        if (des3 == NULL) {
            WOLFENGINE_ERROR_FUNC_NULL(WE_LOG_CIPHER,
                                       "EVP_CIPHER_CTX_get_cipher_data", des3);
            ret = 0;
        }
    }

    if ((ret == 1) && (!des3->init)) {
        WOLFENGINE_MSG(WE_LOG_CIPHER, "Initializing wolfCrypt Des3 "
                       "structure: %p", &des3->des3);
        rc = wc_Des3Init(&des3->des3, NULL, INVALID_DEVID);
        if (rc != 0) {
            WOLFENGINE_ERROR_FUNC(WE_LOG_CIPHER, "wc_Des3Init", rc);
            ret = 0;
        }
    }

    if (ret == 1) {
        des3->init = 1;
        des3->enc = enc;

        if (key != NULL) {
            WOLFENGINE_MSG(WE_LOG_CIPHER, "Setting 3DES key");
            rc = wc_Des3_SetKey(&des3->des3, key, iv,
                                enc ? DES_ENCRYPTION : DES_DECRYPTION);
            if (rc != 0) {
                WOLFENGINE_ERROR_FUNC(WE_LOG_CIPHER, "wc_Des3_SetKey", rc);
                ret = 0;
            }
        }
        else {
            WOLFENGINE_MSG(WE_LOG_CIPHER, "Setting 3DES IV");
            rc = wc_Des3_SetIV(&des3->des3, iv);
            if (rc != 0) {
                WOLFENGINE_ERROR_FUNC(WE_LOG_CIPHER, "wc_Des3_SetIV", rc);
                ret = 0;
            }
        }
    }

    WOLFENGINE_LEAVE(WE_LOG_CIPHER, "we_des3_cbc_init", ret);

    return ret;
}

/**
 * Encrypt the data using wolfSSL.
 *
 * Supports pad/no pad and streaming.
 *
 * @param  ctx   [in/out]  EVP cipher context of operation.
 * @param  des3  [in]      Internal DES3-CBC object.
 * @param  out   [out]     Buffer to store enciphered result.
 * @param  in    [in]      Data to encrypt.
 * @param  len   [in]      Length of data to encrypt.
 * @return  0 on failure, 1 on success.
 */
static int we_des3_cbc_encrypt(EVP_CIPHER_CTX *ctx, we_Des3Cbc* des3,
    unsigned char *out, const unsigned char *in, size_t len)
{
    int ret = 1;
    int rc;

    (void)ctx;

    WOLFENGINE_ENTER(WE_LOG_CIPHER, "we_des3_cbc_encrypt");

    if (len % DES_BLOCK_SIZE) {
        WOLFENGINE_ERROR_MSG(WE_LOG_CIPHER, "we_des3_cbc_encrypt: len must be "
                                            "a multiple of DES_BLOCK_SIZE");
        ret = 0;
    }

    if (ret == 1) {
        rc = wc_Des3_CbcEncrypt(&des3->des3, out, in, (word32)len);
        if (rc != 0) {
            WOLFENGINE_ERROR_FUNC(WE_LOG_CIPHER,
                                  "wc_Des3_CbcEncrypt", rc);
            ret = 0;
        } else {
            WOLFENGINE_MSG_VERBOSE(WE_LOG_CIPHER, "Encrypted %zu bytes "
                                   "(3DES-CBC):", len);
            WOLFENGINE_BUFFER(WE_LOG_CIPHER, out, len);
        }
    }

    WOLFENGINE_LEAVE(WE_LOG_CIPHER, "we_des3_cbc_encrypt", ret);

    return ret;
}

/**
 * Decrypt the data using wolfSSL.
 *
 * Supports pad/no pad and streaming.
 *
 * @param  ctx   [in/out]  EVP cipher context of operation.
 * @param  des3  [in]      Internal DES3-CBC object.
 * @param  out   [out]     Buffer to store enciphered result.
 * @param  in    [in]      Data to decrypt.
 * @param  len   [in]      Length of data to decrypt.
 * @return  0 on failure, 1 on success.
 */
static int we_des3_cbc_decrypt(EVP_CIPHER_CTX *ctx, we_Des3Cbc* des3,
    unsigned char *out, const unsigned char *in, size_t len)
{
    int ret = 1;
    int rc;

    (void)ctx;

    WOLFENGINE_ENTER(WE_LOG_CIPHER, "we_des3_cbc_decrypt");

    if (len % DES_BLOCK_SIZE) {
        WOLFENGINE_ERROR_MSG(WE_LOG_CIPHER, "we_des3_cbc_decrypt: len must be "
                                            "a multiple of DES_BLOCK_SIZE");
        ret = 0;
    }

    if (ret == 1) {
        rc = wc_Des3_CbcDecrypt(&des3->des3, out, in, (word32)len);
        if (rc != 0) {
            WOLFENGINE_ERROR_FUNC(WE_LOG_CIPHER,
                                  "wc_Des3_CbcEncrypt 1", rc);
            ret = 0;
        } else {
            WOLFENGINE_MSG_VERBOSE(WE_LOG_CIPHER, "Decrypted %zu bytes "
                                   "(3DES-CBC):", len);
            WOLFENGINE_BUFFER(WE_LOG_CIPHER, out, len);
        }
    }

    WOLFENGINE_LEAVE(WE_LOG_CIPHER, "we_des3_cbc_decrypt", ret);

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
 * @return  0 on failure, 1 on success.
 */
static int we_des3_cbc_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out,
                             const unsigned char *in, size_t len)
{
    int ret = 1;
    we_Des3Cbc* des3;

    WOLFENGINE_ENTER(WE_LOG_CIPHER, "we_des3_cbc_cipher");
    WOLFENGINE_MSG_VERBOSE(WE_LOG_CIPHER, "ARGS [ctx = %p, out = %p, in = %p, "
                           "len = %zu]", ctx, out, in, len);

    /* Get the DES3-CBC object to work with. */
    des3 = (we_Des3Cbc *)EVP_CIPHER_CTX_get_cipher_data(ctx);
    if (des3 == NULL) {
        WOLFENGINE_ERROR_FUNC_NULL(WE_LOG_CIPHER,
                                   "EVP_CIPHER_CTX_get_cipher_data", des3);
        ret = 0;
    }
    if (ret == 1) {
        if (des3->enc) {
            ret = we_des3_cbc_encrypt(ctx, des3, out, in, len);
        }
        else {
            ret = we_des3_cbc_decrypt(ctx, des3, out, in, len);
        }
    }

    WOLFENGINE_LEAVE(WE_LOG_CIPHER, "we_des3_cbc_cipher", ret);

    return ret;
}

/**
 * Extra operations for DES3-CBC.
 *
 * No supported operations yet.
 *
 * @param  ctx   [in]  EVP cipher context of operation.
 * @param  type  [in]  Type of operation to perform.
 * @param  arg   [in]  Integer argument.
 * @param  ptr   [in]  Pointer argument.
 * @return  1 on success and 0 on failure.
 */
static int we_des3_cbc_ctrl(EVP_CIPHER_CTX *ctx, int type, int arg, void *ptr)
{
    int ret = 1;
    we_Des3Cbc *des3;
    char errBuff[WOLFENGINE_MAX_LOG_WIDTH];

    WOLFENGINE_ENTER(WE_LOG_CIPHER, "we_des3_cbc_ctrl");
    WOLFENGINE_MSG_VERBOSE(WE_LOG_CIPHER, "ARGS [ctx = %p, type = %d, "
                           "arg = %p, ptr = %p]", ctx, type, arg, ptr);

    (void)arg;
    (void)ptr;

    /* Get the DES3-CBC data to work with. */
    des3 = (we_Des3Cbc *)EVP_CIPHER_CTX_get_cipher_data(ctx);
    if (des3 != NULL) {
        WOLFENGINE_ERROR_FUNC_NULL(WE_LOG_CIPHER,
                                   "EVP_CIPHER_CTX_get_cipher_data", des3);
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

    WOLFENGINE_LEAVE(WE_LOG_CIPHER, "we_des3_cbc_ctrl", ret);

    return ret;
}

/* Flags for DES3-CBC method.
 *
 * NOTE: EVP_CIPH_FLAG_CUSTOM_CIPHER is deliberately not added so that OpenSSL
 *       handles the last block of encryption/decryption and padding itself.
 *       Further, adding the flag will break wolfEngine compatibility with
 *       certain TLS 1.0/1.1 ciphers.
 * NOTE: EVP_CIPH_ALWAYS_CALL_INIT is deliberately not added. This flag
 *       causes the AES init method to be called even if key is NULL. Currently
 *       wolfEngine does not need to initialize until a key is available.
 */
#define DES3_CBC_FLAGS             \
     (EVP_CIPH_FLAG_DEFAULT_ASN1 | \
     EVP_CIPH_CBC_MODE)

/** DES3-CBC EVP cipher method. */
EVP_CIPHER* we_des3_cbc_ciph = NULL;


/**
 * Initialize an DES3-CBC method.
 *
 * @return  1 on success and 0 on failure.
 */
static int we_init_des3cbc_meth(EVP_CIPHER *cipher)
{
    int ret;

    WOLFENGINE_ENTER(WE_LOG_CIPHER, "we_init_des3cbc_meth");

    /* NOTE: We intentionally set the IV length to DES_BLOCK_SIZE (8) here
     *       rather than use DES_IV_SIZE, which is 16 in some wolfCrypt
     *       versions. 8 is the correct value. */
    ret = EVP_CIPHER_meth_set_iv_length(cipher, DES_BLOCK_SIZE);
    if (ret == 1) {
        ret = EVP_CIPHER_meth_set_flags(cipher, DES3_CBC_FLAGS);
    }
    if (ret == 1) {
        ret = EVP_CIPHER_meth_set_init(cipher, we_des3_cbc_init);
    }
    if (ret == 1) {
        ret = EVP_CIPHER_meth_set_do_cipher(cipher, we_des3_cbc_cipher);
    }
    if (ret == 1) {
        ret = EVP_CIPHER_meth_set_ctrl(cipher, we_des3_cbc_ctrl);
    }
    if (ret == 1) {
        ret = EVP_CIPHER_meth_set_impl_ctx_size(cipher, sizeof(we_Des3Cbc));
    }

    WOLFENGINE_LEAVE(WE_LOG_CIPHER, "we_init_des3cbc_meth", ret);

    return ret;
}

/**
 * Initialize the DES3-CBC methods.
 *
 * @return  1 on success and 0 on failure.
 */
int we_init_des3cbc_meths()
{
    int ret = 1;

    WOLFENGINE_ENTER(WE_LOG_CIPHER, "we_init_des3cbc_meths");

    /* DES3-CBC */
    we_des3_cbc_ciph = EVP_CIPHER_meth_new(NID_des_ede3_cbc, DES_BLOCK_SIZE,
                                           DES3_KEY_SIZE);
    if (we_des3_cbc_ciph == NULL) {
        WOLFENGINE_ERROR_MSG(WE_LOG_CIPHER, "EVP_CIPHER_meth_new - DES3-CBC");
        ret = 0;
    }
    if (ret == 1) {
        ret = we_init_des3cbc_meth(we_des3_cbc_ciph);
    }

    /* Cleanup */
    if ((ret == 0) && (we_des3_cbc_ciph != NULL)) {
        EVP_CIPHER_meth_free(we_des3_cbc_ciph);
        we_des3_cbc_ciph = NULL;
    }

    WOLFENGINE_LEAVE(WE_LOG_CIPHER, "we_init_des3cbc_meths", ret);

    return ret;
}

#endif /* WE_HAVE_DES3CBC */

