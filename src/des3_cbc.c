/* des3_cbc.c
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

#include "internal.h"


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
    /** Buffer for streaming. */
    unsigned char  lastBlock[DES_BLOCK_SIZE];
    /** Number of buffered bytes.  */
    unsigned int   over;
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

    if ((iv == NULL) && (key == NULL)) {
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
        rc = wc_Des3Init(&des3->des3, NULL, INVALID_DEVID);
        if (rc != 0) {
            WOLFENGINE_ERROR_FUNC(WE_LOG_CIPHER, "wc_Des3Init", rc);
            ret = 0;
        }
    }

    if (ret == 1) {
        /* Must have initialized wolfSSL DES3 object when here. */
        des3->init = 1;
        des3->over = 0;
        /* Store whether encrypting. */
        des3->enc = enc;

        if (key != NULL) {
            rc = wc_Des3_SetKey(&des3->des3, key, iv,
                                enc ? DES_ENCRYPTION : DES_DECRYPTION);
            if (rc != 0) {
                WOLFENGINE_ERROR_FUNC(WE_LOG_CIPHER, "wc_Des3_SetKey", rc);
                ret = 0;
            }
        }
        else {
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
 * @param  in    [in]      Data to encrypt/decrypt.
 * @param  len   [in]      Length of data to encrypt/decrypt.
 * @return  -1 on failure.
 * @return  Number of bytes put in out on success.
 */
static int we_des3_cbc_encrypt(EVP_CIPHER_CTX *ctx, we_Des3Cbc* des3,
    unsigned char *out, const unsigned char *in, size_t len)
{
    int ret = 1;
    int rc;
    int outl = 0;
    int noPad = EVP_CIPHER_CTX_test_flags(ctx, EVP_CIPH_NO_PADDING);

    WOLFENGINE_ENTER(WE_LOG_CIPHER, "we_des3_cbc_encrypt");

    /* Length of 0 means Final called. */
    if (len == 0) {
        if (noPad) {
            if (des3->over != 0) {
                WOLFENGINE_ERROR_MSG(WE_LOG_CIPHER,
                                     "No Pad - last encrypt block not full");
                ret = 0;
            }
        }
        else {
            byte pad = DES_BLOCK_SIZE - des3->over;

            /* Padding - fill rest of block with number of padding blocks. */
            XMEMSET(des3->lastBlock + des3->over, pad, pad);
            des3->over = DES_BLOCK_SIZE;
            /* Encrypt lastBlock and return in out. */
        }
    }
    
    if (ret == 1) {
        unsigned int l;

        /* Check for cached data. */
        if (des3->over > 0) {
            /* Partial block not yet encrypted. */
            l = DES_BLOCK_SIZE - des3->over;
            if (l > len) {
                l = (int)len;
            }

            /* Copy as much of input as possible to fill in block. */
            if (l > 0) {
                XMEMCPY(des3->lastBlock + des3->over, in, l);
                des3->over += l;
                in += l;
                len -= l;
            }
            /* Check if we have a complete block to encrypt. */
            if (des3->over == DES_BLOCK_SIZE) {
                /* Encrypt and return block. */
                rc = wc_Des3_CbcEncrypt(&des3->des3, out, des3->lastBlock,
                                        DES_BLOCK_SIZE);
                if (rc != 0) {
                    WOLFENGINE_ERROR_FUNC(WE_LOG_CIPHER,
                                          "wc_Des3_CbcEncrypt", rc);
                    ret = 0;
                }
                /* Data put to output. */
                out += DES_BLOCK_SIZE;
                outl += DES_BLOCK_SIZE;
                /* No more cached data. */
                des3->over = 0;
            }
        }
        /* Encrypt full blocks from remaining input. */
        if ((ret == 1) && (len >= DES_BLOCK_SIZE)) {
            /* Calculate full blocks. */
            l = (int)len & (~(DES_BLOCK_SIZE - 1));

            rc = wc_Des3_CbcEncrypt(&des3->des3, out, in, l);
            if (rc != 0) {
                WOLFENGINE_ERROR_FUNC(WE_LOG_CIPHER,
                                      "wc_Des3_CbcEncrypt", rc);
                ret = 0;
            }

            outl += l;
            in += l;
            len -= l;
        }
        if ((ret == 1) && (len > 0)) {
            /* Copy remaining input as incomplete block. */
            XMEMCPY(des3->lastBlock, in, len);
            des3->over = (int)len;
        }
    }
    if (ret == 1) {
        /* Return length of encrypted data. */
        ret = outl;
    }
    else {
        /* Return -ve for error. */
        ret = -1;
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
 * @param  in    [in]      Data to encrypt/decrypt.
 * @param  len   [in]      Length of data to encrypt/decrypt.
 * @return  -1 on failure.
 * @return  Number of bytes put in out on success.
 */
static int we_des3_cbc_decrypt(EVP_CIPHER_CTX *ctx, we_Des3Cbc* des3,
    unsigned char *out, const unsigned char *in, size_t len)
{
    int ret = 1;
    int rc;
    int outl = 0;
    int noPad = EVP_CIPHER_CTX_test_flags(ctx, EVP_CIPH_NO_PADDING);

    WOLFENGINE_ENTER(WE_LOG_CIPHER, "we_des3_cbc_decrypt");

    /* Length of 0 means Final called. */
    if (len == 0) {
        if (noPad) {
            if (des3->over != 0) {
                WOLFENGINE_ERROR_MSG(WE_LOG_CIPHER,
                                     "No Pad - last decrypt block not full");
                ret = 0;
            }
        }
        else {
            byte pad;
            int i;

            /* Must have a full block over to decrypt. */
            if (des3->over != DES_BLOCK_SIZE) {
                WOLFENGINE_ERROR_MSG(WE_LOG_CIPHER,
                                     "Padding - last cached decrypt block not "
                                     "full");
                ret = 0;
            }
            if (ret == 1) {
                /* Decrypt last block - may be all padding. */
                rc = wc_Des3_CbcDecrypt(&des3->des3, des3->lastBlock,
                                        des3->lastBlock, DES_BLOCK_SIZE);
                if (rc != 0) {
                    WOLFENGINE_ERROR_FUNC(WE_LOG_CIPHER,
                                          "wc_Des3_CbcDecrypt", rc);
                    ret = 0;
                }
                des3->over = 0;
            }
            if (ret == 1) {
                /* Last byte is length of padding. */
                pad = des3->lastBlock[DES_BLOCK_SIZE - 1];
                if ((pad == 0) || (pad > DES_BLOCK_SIZE)) {
                    WOLFENGINE_ERROR_MSG(WE_LOG_CIPHER, "Padding byte invalid");
                    ret = 0;
                }
            }
            if (ret == 1) {
                /* Copy out non-padding bytes. */
                outl = DES_BLOCK_SIZE - pad;
                XMEMCPY(out, des3->lastBlock, outl);
                /* Check padding bytes are all the same. */
                for (i = outl; (ret == 1) && (i < DES_BLOCK_SIZE - 1); i++) {
                   if (des3->lastBlock[i] != pad) {
                       WOLFENGINE_ERROR_MSG(WE_LOG_CIPHER,
                                            "Padding byte doesn't different");
                       ret = 0;
                   }
                }
            }
        }
    }
    if (ret == 1) {
        unsigned int l;

        /* Check for cached data. */
        if (des3->over > 0) {
            /* Calculate amount of input that can be used. */
            l = DES_BLOCK_SIZE - des3->over;
            if (l > len) {
                l = (int)len;
            }

            if (l > 0) {
                /* Copy as much of input as possible to fill in block. */
                XMEMCPY(des3->lastBlock + des3->over, in, l);
                des3->over += l;
                in += l;
                len -= l;
            }
            /* Padding and not last full block or not padding and full block. */
            if ((noPad && des3->over == DES_BLOCK_SIZE) || len > 0) {
                /* Decrypt block cached block. */
                rc = wc_Des3_CbcDecrypt(&des3->des3, out, des3->lastBlock,
                                        DES_BLOCK_SIZE);
                if (rc != 0) {
                    WOLFENGINE_ERROR_FUNC(WE_LOG_CIPHER,
                                          "wc_Des3_CbcDecrypt", rc);
                    ret = 0;
                }
                /* Data put to output. */
                out += DES_BLOCK_SIZE;
                outl += DES_BLOCK_SIZE;
                /* No more cached data. */
                des3->over = 0;
            }
        }
        /* Decrypt full blocks from remaining input. */
        if ((ret == 1) && (len >= DES_BLOCK_SIZE)) {
            /* Calculate full blocks. */
            l = (int)len & (~(DES_BLOCK_SIZE - 1));

            /* Not last full block when padding. */
            if ((!noPad) && (len - l == 0)) {
                l -= DES_BLOCK_SIZE;
            }
            if (l > 0) {
                rc = wc_Des3_CbcDecrypt(&des3->des3, out, in, l);
                if (rc != 0) {
                    WOLFENGINE_ERROR_FUNC(WE_LOG_CIPHER,
                                          "wc_Des3_CbcDecrypt", rc);
                    ret = 0;
                }
            }

            outl += l;
            in += l;
            len -= l;
        }
        if ((ret == 1) && (len > 0)) {
            /* Copy remaining input as incomplete block. */
            XMEMCPY(des3->lastBlock, in, len);
            des3->over = (int)len;
        }
    }
    if (ret == 1) {
        /* Return length of encrypted data. */
        ret = outl;
    }
    else {
        /* Return -ve for error. */
        ret = -1;
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
 * @return  -1 on failure.
 * @return  Number of bytes put in out on success.
 */
static int we_des3_cbc_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out,
                             const unsigned char *in, size_t len)
{
    int ret;
    we_Des3Cbc* des3;

    WOLFENGINE_ENTER(WE_LOG_CIPHER, "we_des3_cbc_cipher");

    /* Get the DES3-CBC object to work with. */
    des3 = (we_Des3Cbc *)EVP_CIPHER_CTX_get_cipher_data(ctx);
    if (des3 == NULL) {
        WOLFENGINE_ERROR_FUNC_NULL(WE_LOG_CIPHER,
                                   "EVP_CIPHER_CTX_get_cipher_data", des3);
        ret = -1;
    }
    else if (des3->enc) {
        ret = we_des3_cbc_encrypt(ctx, des3, out, in, len);
    }
    else {
        ret = we_des3_cbc_decrypt(ctx, des3, out, in, len);
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
    char errBuff[WOLFENGINE_MAX_ERROR_SZ];

    WOLFENGINE_ENTER(WE_LOG_CIPHER, "we_des3_cbc_ctrl");

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

/** Flags for DES3-CBC method. */
#define DES3_CBC_FLAGS             \
    (EVP_CIPH_FLAG_CUSTOM_CIPHER | \
     EVP_CIPH_ALWAYS_CALL_INIT   | \
     EVP_CIPH_FLAG_DEFAULT_ASN1  | \
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

    ret = EVP_CIPHER_meth_set_iv_length(cipher, DES_IV_SIZE);
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
    we_des3_cbc_ciph = EVP_CIPHER_meth_new(NID_des_ede3_cbc, 1, DES3_KEY_SIZE);
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

