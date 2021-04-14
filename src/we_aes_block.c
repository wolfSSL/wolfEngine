/* we_aes_block.c
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

#if defined(WE_HAVE_AESCBC) || defined(WE_HAVE_AESECB)

/**
 * Data required to complete an AES block encrypt/decrypt operation.
 */
typedef struct we_AesBlock
{
    /** The wolfSSL AES data object. */
    Aes            aes;
    /** Buffer for streaming. */
    unsigned char  lastBlock[AES_BLOCK_SIZE];
    /** Number of buffered bytes.  */
    unsigned int   over;
    /** Flag to indicate whether wolfSSL AES object initialized. */
    unsigned int   init:1;
    /** Flag to indicate whether we are doing encrypt (1) or decrpyt (0). */
    unsigned int   enc:1;
} we_AesBlock;

#endif


#ifdef WE_HAVE_AESCBC

/*
 * AES-CBC
 */

/**
 * Initialize the AES-CBC encrypt/decrypt operation using wolfSSL.
 *
 * @param  ctx  [in,out]  EVP cipher context of operation.
 * @param  key  [in]      AES key - 16/24/32 bytes.
 * @param  iv   [in]      Initialization Vector - 12 bytes.
 * @param  enc  [in]      1 when initializing for encrypt and 0 when decrypt.
 * @return  1 on success and 0 on failure.
 */
static int we_aes_cbc_init(EVP_CIPHER_CTX *ctx, const unsigned char *key,
                           const unsigned char *iv, int enc)
{
    int ret = 1;
    int rc;
    we_AesBlock *aes;

    WOLFENGINE_ENTER(WE_LOG_CIPHER, "we_aes_cbc_init");

    if ((iv == NULL) && (key == NULL)) {
        WOLFENGINE_ERROR_MSG(WE_LOG_CIPHER, "iv == NULL && key == NULL");
        ret = 0;
    }

    if (ret == 1) {
        aes = (we_AesBlock *)EVP_CIPHER_CTX_get_cipher_data(ctx);
        if (aes == NULL) {
            WOLFENGINE_ERROR_FUNC_NULL(WE_LOG_CIPHER,
                                       "EVP_CIPHER_CTX_get_cipher_data", aes);
            ret = 0;
        }
    }

    if ((ret == 1) && (!aes->init)) {
        rc = wc_AesInit(&aes->aes, NULL, INVALID_DEVID);
        if (rc != 0) {
            WOLFENGINE_ERROR_FUNC(WE_LOG_CIPHER, "wc_AesInit", rc);
            ret = 0;
        }
    }

    if (ret == 1) {
        /* Must have initialized wolfSSL AES object when here. */
        aes->init = 1;
        aes->over = 0;
        /* Store whether encrypting. */
        aes->enc = enc;

        if (key != NULL) {
            rc = wc_AesSetKey(&aes->aes, key, EVP_CIPHER_CTX_key_length(ctx),
                              iv, enc ? AES_ENCRYPTION : AES_DECRYPTION);
            if (rc != 0) {
                WOLFENGINE_ERROR_FUNC(WE_LOG_CIPHER, "wc_AesSetKey", rc);
                ret = 0;
            }
        }
        if (ret == 1 && iv != NULL) {
            rc = wc_AesSetIV(&aes->aes, iv);
            if (rc != 0) {
                WOLFENGINE_ERROR_FUNC(WE_LOG_CIPHER, "wc_AesSetIV", rc);
                ret = 0;
            }
        }
    }

    WOLFENGINE_LEAVE(WE_LOG_CIPHER, "we_aes_cbc_init", ret);

    return ret;
}

/**
 * Encrypt the data using wolfSSL.
 *
 * Supports pad/no pad and streaming.
 *
 * @param  ctx  [in/out]  EVP cipher context of operation.
 * @param  aes  [in]      Internal AES object.
 * @param  out  [out]     Buffer to store enciphered result.
 * @param  in   [in]      Data to encrypt/decrypt.
 * @param  len  [in]      Length of data to encrypt/decrypt.
 * @return  -1 on failure.
 * @return  Number of bytes put in out on success.
 */
static int we_aes_cbc_encrypt(EVP_CIPHER_CTX *ctx, we_AesBlock* aes,
    unsigned char *out, const unsigned char *in, size_t len)
{
    int ret = 1;
    int rc;
    int outl = 0;
    int noPad = EVP_CIPHER_CTX_test_flags(ctx, EVP_CIPH_NO_PADDING);

    WOLFENGINE_ENTER(WE_LOG_CIPHER, "we_aes_cbc_encrypt");

    /* Length of 0 means Final called. */
    if (len == 0) {
        if (noPad) {
            if (aes->over != 0) {
                WOLFENGINE_ERROR_MSG(WE_LOG_CIPHER,
                                     "No Pad - last encrypt block not full");
                ret = 0;
            }
        }
        else {
            byte pad = AES_BLOCK_SIZE - aes->over;

            /* Padding - fill rest of block with number of padding blocks. */
            XMEMSET(aes->lastBlock + aes->over, pad, pad);
            aes->over = AES_BLOCK_SIZE;
            /* Encrypt lastBlock and return in out. */
        }
    }
    
    if (ret == 1) {
        unsigned int l;

        /* Check for cached data. */
        if (aes->over > 0) {
            /* Partial block not yet encrypted. */
            l = AES_BLOCK_SIZE - aes->over;
            if (l > len) {
                l = (int)len;
            }

            /* Copy as much of input as possible to fill in block. */
            if (l > 0) {
                XMEMCPY(aes->lastBlock + aes->over, in, l);
                aes->over += l;
                in += l;
                len -= l;
            }
            /* Check if we have a complete block to encrypt. */
            if (aes->over == AES_BLOCK_SIZE) {
                /* Encrypt and return block. */
                rc = wc_AesCbcEncrypt(&aes->aes, out, aes->lastBlock,
                                      AES_BLOCK_SIZE);
                if (rc != 0) {
                    WOLFENGINE_ERROR_FUNC(WE_LOG_CIPHER,
                                          "wc_AesCbcEncrypt", rc);
                    ret = 0;
                }
                /* Data put to output. */
                out += AES_BLOCK_SIZE;
                outl += AES_BLOCK_SIZE;
                /* No more cached data. */
                aes->over = 0;
            }
        }
        /* Encrypt full blocks from remaining input. */
        if ((ret == 1) && (len >= AES_BLOCK_SIZE)) {
            /* Calculate full blocks. */
            l = (int)len & (~(AES_BLOCK_SIZE - 1));

            rc = wc_AesCbcEncrypt(&aes->aes, out, in, l);
            if (rc != 0) {
                WOLFENGINE_ERROR_FUNC(WE_LOG_CIPHER, "wc_AesCbcEncrypt", rc);
                ret = 0;
            }

            outl += l;
            in += l;
            len -= l;
        }
        if ((ret == 1) && (len > 0)) {
            /* Copy remaining input as incomplete block. */
            XMEMCPY(aes->lastBlock, in, len);
            aes->over = (int)len;
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

    WOLFENGINE_LEAVE(WE_LOG_CIPHER, "we_aes_cbc_encrypt", ret);

    return ret;
}

/**
 * Decrypt the data using wolfSSL.
 *
 * Supports pad/no pad and streaming.
 *
 * @param  ctx  [in/out]  EVP cipher context of operation.
 * @param  aes  [in]      Internal AES object.
 * @param  out  [out]     Buffer to store enciphered result.
 * @param  in   [in]      Data to encrypt/decrypt.
 * @param  len  [in]      Length of data to encrypt/decrypt.
 * @return  -1 on failure.
 * @return  Number of bytes put in out on success.
 */
static int we_aes_cbc_decrypt(EVP_CIPHER_CTX *ctx, we_AesBlock* aes,
    unsigned char *out, const unsigned char *in, size_t len)
{
    int ret = 1;
    int rc;
    int outl = 0;
    int noPad = EVP_CIPHER_CTX_test_flags(ctx, EVP_CIPH_NO_PADDING);

    WOLFENGINE_ENTER(WE_LOG_CIPHER, "we_aes_cbc_decrypt");

    /* Length of 0 means Final called. */
    if (len == 0) {
        if (noPad) {
            if (aes->over != 0) {
                WOLFENGINE_ERROR_MSG(WE_LOG_CIPHER,
                                     "No Pad - last decrypt block not full");
                ret = 0;
            }
        }
        else {
            byte pad;
            int i;

            /* Must have a full block over to decrypt. */
            if (aes->over != AES_BLOCK_SIZE) {
                WOLFENGINE_ERROR_MSG(WE_LOG_CIPHER,
                                     "Padding - last cached decrypt block not "
                                     "full");
                ret = 0;
            }
            if (ret == 1) {
                /* Decrypt last block - may be all padding. */
                rc = wc_AesCbcDecrypt(&aes->aes, aes->lastBlock, aes->lastBlock,
                                      AES_BLOCK_SIZE);
                if (rc != 0) {
                    WOLFENGINE_ERROR_FUNC(WE_LOG_CIPHER,
                                          "wc_AesCbcDecrypt", rc);
                    ret = 0;
                }
                aes->over = 0;
            }
            if (ret == 1) {
                /* Last byte is length of padding. */
                pad = aes->lastBlock[AES_BLOCK_SIZE - 1];
                if ((pad == 0) || (pad > AES_BLOCK_SIZE)) {
                    WOLFENGINE_ERROR_MSG(WE_LOG_CIPHER, "Padding byte invalid");
                    ret = 0;
                }
            }
            if (ret == 1) {
                /* Copy out non-padding bytes. */
                outl = AES_BLOCK_SIZE - pad;
                XMEMCPY(out, aes->lastBlock, outl);
                /* Check padding bytes are all the same. */
                for (i = outl; (ret == 1) && (i < AES_BLOCK_SIZE - 1); i++) {
                   if (aes->lastBlock[i] != pad) {
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
        if (aes->over > 0) {
            /* Calculate amount of input that can be used. */
            l = AES_BLOCK_SIZE - aes->over;
            if (l > len) {
                l = (int)len;
            }

            if (l > 0) {
                /* Copy as much of input as possible to fill in block. */
                XMEMCPY(aes->lastBlock + aes->over, in, l);
                aes->over += l;
                in += l;
                len -= l;
            }
            /* Padding and not last full block or not padding and full block. */
            if ((noPad && aes->over == AES_BLOCK_SIZE) || len > 0) {
                /* Decrypt block cached block. */
                rc = wc_AesCbcDecrypt(&aes->aes, out, aes->lastBlock,
                                      AES_BLOCK_SIZE);
                if (rc != 0) {
                    WOLFENGINE_ERROR_FUNC(WE_LOG_CIPHER,
                                          "wc_AesCbcDecrypt", rc);
                    ret = 0;
                }
                /* Data put to output. */
                out += AES_BLOCK_SIZE;
                outl += AES_BLOCK_SIZE;
                /* No more cached data. */
                aes->over = 0;
            }
        }
        /* Decrypt full blocks from remaining input. */
        if ((ret == 1) && (len >= AES_BLOCK_SIZE)) {
            /* Calculate full blocks. */
            l = (int)len & (~(AES_BLOCK_SIZE - 1));

            /* Not last full block when padding. */
            if ((!noPad) && (len - l == 0)) {
                l -= AES_BLOCK_SIZE;
            }
            if (l > 0) {
                rc = wc_AesCbcDecrypt(&aes->aes, out, in, l);
                if (rc != 0) {
                    WOLFENGINE_ERROR_FUNC(WE_LOG_CIPHER,
                                          "wc_AesCbcDecrypt", rc);
                    ret = 0;
                }
            }

            outl += l;
            in += l;
            len -= l;
        }
        if ((ret == 1) && (len > 0)) {
            /* Copy remaining input as incomplete block. */
            XMEMCPY(aes->lastBlock, in, len);
            aes->over = (int)len;
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

    WOLFENGINE_LEAVE(WE_LOG_CIPHER, "we_aes_cbc_decrypt", ret);

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
static int we_aes_cbc_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out,
                             const unsigned char *in, size_t len)
{
    int ret;
    we_AesBlock* aes;

    WOLFENGINE_ENTER(WE_LOG_CIPHER, "we_aes_cbc_cipher");

    /* Get the AES-CBC object to work with. */
    aes = (we_AesBlock *)EVP_CIPHER_CTX_get_cipher_data(ctx);
    if (aes == NULL) {
        WOLFENGINE_ERROR_FUNC_NULL(WE_LOG_CIPHER,
                                   "EVP_CIPHER_CTX_get_cipher_data", aes);
        ret = -1;
    }
    else if (aes->enc) {
        ret = we_aes_cbc_encrypt(ctx, aes, out, in, len);
    }
    else {
        ret = we_aes_cbc_decrypt(ctx, aes, out, in, len);
    }

    WOLFENGINE_LEAVE(WE_LOG_CIPHER, "we_aes_cbc_cipher", ret);

    return ret;
}

/**
 * Extra operations for AES-CBC.
 *
 * No supported operations yet.
 *
 * @param  ctx   [in]  EVP cipher context of operation.
 * @param  type  [in]  Type of operation to perform.
 * @param  arg   [in]  Integer argument.
 * @param  ptr   [in]  Pointer argument.
 * @return  1 on success and 0 on failure.
 */
static int we_aes_cbc_ctrl(EVP_CIPHER_CTX *ctx, int type, int arg, void *ptr)
{
    int ret = 1;
    we_AesBlock *aes;
    char errBuff[WOLFENGINE_MAX_ERROR_SZ];

    WOLFENGINE_ENTER(WE_LOG_CIPHER, "we_aes_cbc_ctrl");

    (void)arg;
    (void)ptr;

    /* Get the AES-CBC data to work with. */
    aes = (we_AesBlock *)EVP_CIPHER_CTX_get_cipher_data(ctx);
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

    WOLFENGINE_LEAVE(WE_LOG_CIPHER, "we_aes_cbc_ctrl", ret);

    return ret;
}

/** Flags for AES-CBC method.
 *
 * NOTE: EVP_CIPH_ALWAYS_CALL_INIT is deliberately not added. This flag
 *       causes the AES init method to be called even if key is NULL. Currently
 *       wolfEngine does not need to initialize until a key is available.
 */
#define AES_CBC_FLAGS              \
    (EVP_CIPH_FLAG_CUSTOM_CIPHER | \
     EVP_CIPH_FLAG_DEFAULT_ASN1  | \
     EVP_CIPH_CBC_MODE)

/** AES128-CBC EVP cipher method. */
EVP_CIPHER* we_aes128_cbc_ciph = NULL;
/** AES192-CBC EVP cipher method. */
EVP_CIPHER* we_aes192_cbc_ciph = NULL;
/** AES256-CBC EVP cipher method. */
EVP_CIPHER* we_aes256_cbc_ciph = NULL;


/**
 * Initialize an AES-CBC method.
 *
 * @return  1 on success and 0 on failure.
 */
static int we_init_aescbc_meth(EVP_CIPHER *cipher)
{
    int ret;

    WOLFENGINE_ENTER(WE_LOG_CIPHER, "we_init_aescbc_meth");

    ret = EVP_CIPHER_meth_set_iv_length(cipher, AES_IV_SIZE);
    if (ret == 1) {
        ret = EVP_CIPHER_meth_set_flags(cipher, AES_CBC_FLAGS);
    }
    if (ret == 1) {
        ret = EVP_CIPHER_meth_set_init(cipher, we_aes_cbc_init);
    }
    if (ret == 1) {
        ret = EVP_CIPHER_meth_set_do_cipher(cipher, we_aes_cbc_cipher);
    }
    if (ret == 1) {
        ret = EVP_CIPHER_meth_set_ctrl(cipher, we_aes_cbc_ctrl);
    }
    if (ret == 1) {
        ret = EVP_CIPHER_meth_set_impl_ctx_size(cipher, sizeof(we_AesBlock));
    }

    WOLFENGINE_LEAVE(WE_LOG_CIPHER, "we_init_aescbc_meth", ret);

    return ret;
}

/**
 * Initialize the AES-CBC methods.
 *
 * @return  1 on success and 0 on failure.
 */
int we_init_aescbc_meths()
{
    int ret = 1;

    WOLFENGINE_ENTER(WE_LOG_CIPHER, "we_init_aescbc_meths");

    /* AES128-CBC */
    we_aes128_cbc_ciph = EVP_CIPHER_meth_new(NID_aes_128_cbc, AES_BLOCK_SIZE,
                                             AES_128_KEY_SIZE);
    if (we_aes128_cbc_ciph == NULL) {
        WOLFENGINE_ERROR_FUNC_NULL(WE_LOG_CIPHER,
                                   "EVP_CIPHER_meth_new - AES-128-CBC",
                                   we_aes128_cbc_ciph);
        ret = 0;
    }
    if (ret == 1) {
        ret = we_init_aescbc_meth(we_aes128_cbc_ciph);
    }

    /* AES192-CBC */
    if (ret == 1) {
        we_aes192_cbc_ciph = EVP_CIPHER_meth_new(NID_aes_192_cbc,
                                                 AES_BLOCK_SIZE,
                                                 AES_192_KEY_SIZE);
        if (we_aes192_cbc_ciph == NULL) {
            WOLFENGINE_ERROR_FUNC_NULL(WE_LOG_CIPHER,
                                       "EVP_CIPHER_meth_new - AES-192-CBC",
                                       we_aes192_cbc_ciph);
            ret = 0;
        }
    }
    if (ret == 1) {
        ret = we_init_aescbc_meth(we_aes192_cbc_ciph);
    }

    /* AES256-CBC */
    if (ret == 1) {
        we_aes256_cbc_ciph = EVP_CIPHER_meth_new(NID_aes_256_cbc,
                                                 AES_BLOCK_SIZE,
                                                 AES_256_KEY_SIZE);
        if (we_aes256_cbc_ciph == NULL) {
            WOLFENGINE_ERROR_FUNC_NULL(WE_LOG_CIPHER,
                                       "EVP_CIPHER_meth_new - AES-256-CBC",
                                       we_aes256_cbc_ciph);
            ret = 0;
        }
    }
    if (ret == 1) {
        ret = we_init_aescbc_meth(we_aes256_cbc_ciph);
    }

    /* Cleanup */
    if ((ret == 0) && (we_aes128_cbc_ciph != NULL)) {
        EVP_CIPHER_meth_free(we_aes128_cbc_ciph);
        we_aes128_cbc_ciph = NULL;
    }
    if ((ret == 0) && (we_aes192_cbc_ciph != NULL)) {
        EVP_CIPHER_meth_free(we_aes192_cbc_ciph);
        we_aes192_cbc_ciph = NULL;
    }
    if ((ret == 0) && (we_aes256_cbc_ciph != NULL)) {
        EVP_CIPHER_meth_free(we_aes256_cbc_ciph);
        we_aes256_cbc_ciph = NULL;
    }

    WOLFENGINE_LEAVE(WE_LOG_CIPHER, "we_init_aescbc_meths", ret);

    return ret;
}

#endif /* WE_HAVE_AESCBC */

#ifdef WE_HAVE_AESECB

/*
 * AES-ECB
 */

/**
 * Initialize the AES-ECB encrypt/decrypt operation using wolfSSL.
 *
 * @param  ctx  [in,out]  EVP cipher context of operation.
 * @param  key  [in]      AES key - 16/24/32 bytes.
 * @param  iv   [in]      Initialization Vector - not used.
 * @param  enc  [in]      1 when initializing for encrypt and 0 when decrypt.
 * @return  1 on success and 0 on failure.
 */
static int we_aes_ecb_init(EVP_CIPHER_CTX *ctx, const unsigned char *key,
                           const unsigned char *iv, int enc)
{
    int ret = 1;
    int rc;
    we_AesBlock *aes;

    WOLFENGINE_ENTER(WE_LOG_CIPHER, "we_aes_ecb_init");

    (void)iv;

    aes = (we_AesBlock *)EVP_CIPHER_CTX_get_cipher_data(ctx);
    if (aes == NULL) {
        WOLFENGINE_ERROR_FUNC_NULL(WE_LOG_CIPHER,
                                   "EVP_CIPHER_CTX_get_cipher_data", aes);
        ret = 0;
    }

    if ((ret == 1) && ((key == NULL) || (!aes->init))) {
        rc = wc_AesInit(&aes->aes, NULL, INVALID_DEVID);
        if (rc != 0) {
            WOLFENGINE_ERROR_FUNC(WE_LOG_CIPHER, "wc_AesInit", rc);
            ret = 0;
        }
    }

    if (ret == 1) {
        /* Must have initialized wolfSSL AES object when here. */
        aes->init = 1;
        aes->over = 0;
        /* Store whether encrypting. */
        aes->enc = enc;
    }

    if ((ret == 1) && (key != NULL)) {
        rc = wc_AesSetKey(&aes->aes, key, EVP_CIPHER_CTX_key_length(ctx),
                          NULL, enc ? AES_ENCRYPTION : AES_DECRYPTION);
        if (rc != 0) {
            WOLFENGINE_ERROR_FUNC(WE_LOG_CIPHER, "wc_AesSetKey", rc);
            ret = 0;
        }
    }

    WOLFENGINE_LEAVE(WE_LOG_CIPHER, "we_aes_ecb_init", ret);

    return ret;
}

/**
 * Encrypt the data using wolfSSL.
 *
 * Supports pad/no pad and streaming.
 *
 * @param  ctx  [in/out]  EVP cipher context of operation.
 * @param  aes  [in]      Internal AES object.
 * @param  out  [out]     Buffer to store enciphered result.
 * @param  in   [in]      Data to encrypt/decrypt.
 * @param  len  [in]      Length of data to encrypt/decrypt.
 * @return  -1 on failure.
 * @return  Number of bytes put in out on success.
 */
static int we_aes_ecb_encrypt(EVP_CIPHER_CTX *ctx, we_AesBlock* aes,
    unsigned char *out, const unsigned char *in, size_t len)
{
    int ret = 1;
    int rc;
    int outl = 0;
    int noPad = EVP_CIPHER_CTX_test_flags(ctx, EVP_CIPH_NO_PADDING);

    WOLFENGINE_ENTER(WE_LOG_CIPHER, "we_aes_ecb_encrypt");

    /* Length of 0 means Final called. */
    if (len == 0) {
        if (noPad) {
            if (aes->over != 0) {
                WOLFENGINE_ERROR_MSG(WE_LOG_CIPHER,
                                     "No Pad - last encrypt block not full");
                ret = 0;
            }
        }
        else {
            byte pad = AES_BLOCK_SIZE - aes->over;

            /* Padding - fill rest of block with number of padding blocks. */
            XMEMSET(aes->lastBlock + aes->over, pad, pad);
            aes->over = AES_BLOCK_SIZE;
            /* Encrypt lastBlock and return in out. */
        }
    }
    
    if (ret == 1) {
        unsigned int l;

        /* Check for cached data. */
        if (aes->over > 0) {
            /* Partial block not yet encrypted. */
            l = AES_BLOCK_SIZE - aes->over;
            if (l > len) {
                l = (int)len;
            }

            /* Copy as much of input as possible to fill in block. */
            if (l > 0) {
                XMEMCPY(aes->lastBlock + aes->over, in, l);
                aes->over += l;
                in += l;
                len -= l;
            }
            /* Check if we have a complete block to encrypt. */
            if (aes->over == AES_BLOCK_SIZE) {
                /* Encrypt and return block. */
                rc = wc_AesEcbEncrypt(&aes->aes, out, aes->lastBlock,
                                      AES_BLOCK_SIZE);
                if (rc != 0) {
                    WOLFENGINE_ERROR_FUNC(WE_LOG_CIPHER,
                                          "wc_AesEcbEncrypt", rc);
                    ret = 0;
                }
                /* Data put to output. */
                out += AES_BLOCK_SIZE;
                outl += AES_BLOCK_SIZE;
                /* No more cached data. */
                aes->over = 0;
            }
        }
        /* Encrypt full blocks from remaining input. */
        if ((ret == 1) && (len >= AES_BLOCK_SIZE)) {
            /* Calculate full blocks. */
            l = (int)len & (~(AES_BLOCK_SIZE - 1));

            rc = wc_AesEcbEncrypt(&aes->aes, out, in, l);
            if (rc != 0) {
                WOLFENGINE_ERROR_FUNC(WE_LOG_CIPHER, "wc_AesEcbEncrypt", rc);
                ret = 0;
            }

            outl += l;
            in += l;
            len -= l;
        }
        if ((ret == 1) && (len > 0)) {
            /* Copy remaining input as incomplete block. */
            XMEMCPY(aes->lastBlock, in, len);
            aes->over = (int)len;
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

    WOLFENGINE_LEAVE(WE_LOG_CIPHER, "we_aes_ecb_encrypt", ret);

    return ret;
}

/**
 * Decrypt the data using wolfSSL.
 *
 * Supports pad/no pad and streaming.
 *
 * @param  ctx  [in/out]  EVP cipher context of operation.
 * @param  aes  [in]      Internal AES object.
 * @param  out  [out]     Buffer to store enciphered result.
 * @param  in   [in]      Data to encrypt/decrypt.
 * @param  len  [in]      Length of data to encrypt/decrypt.
 * @return  -1 on failure.
 * @return  Number of bytes put in out on success.
 */
static int we_aes_ecb_decrypt(EVP_CIPHER_CTX *ctx, we_AesBlock* aes,
    unsigned char *out, const unsigned char *in, size_t len)
{
    int ret = 1;
    int rc;
    int outl = 0;
    int noPad = EVP_CIPHER_CTX_test_flags(ctx, EVP_CIPH_NO_PADDING);

    WOLFENGINE_ENTER(WE_LOG_CIPHER, "we_aes_ecb_decrypt");

    /* Length of 0 means Final called. */
    if (len == 0) {
        if (noPad) {
            if (aes->over != 0) {
                WOLFENGINE_ERROR_MSG(WE_LOG_CIPHER,
                                     "No Pad - last decrypt block not full");
                ret = 0;
            }
        }
        else {
            byte pad;
            int i;

            /* Must have a full block over to decrypt. */
            if (aes->over != AES_BLOCK_SIZE) {
                WOLFENGINE_ERROR_MSG(WE_LOG_CIPHER,
                                     "Padding - last cached decrypt block not "
                                     "full");
                ret = 0;
            }
            if (ret == 1) {
                /* Decrypt last block - may be all padding. */
                rc = wc_AesEcbDecrypt(&aes->aes, aes->lastBlock, aes->lastBlock,
                                      AES_BLOCK_SIZE);
                if (rc != 0) {
                    WOLFENGINE_ERROR_FUNC(WE_LOG_CIPHER,
                                          "wc_AesEcbDecrypt", rc);
                    ret = 0;
                }
                aes->over = 0;
            }
            if (ret == 1) {
                /* Last byte is length of padding. */
                pad = aes->lastBlock[AES_BLOCK_SIZE - 1];
                if ((pad == 0) || (pad > AES_BLOCK_SIZE)) {
                    WOLFENGINE_ERROR_MSG(WE_LOG_CIPHER, "Padding byte invalid");
                    ret = 0;
                }
            }
            if (ret == 1) {
                /* Copy out non-padding bytes. */
                outl = AES_BLOCK_SIZE - pad;
                XMEMCPY(out, aes->lastBlock, outl);
                /* Check padding bytes are all the same. */
                for (i = outl; (ret == 1) && (i < AES_BLOCK_SIZE - 1); i++) {
                   if (aes->lastBlock[i] != pad) {
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
        if (aes->over > 0) {
            /* Calculate amount of input that can be used. */
            l = AES_BLOCK_SIZE - aes->over;
            if (l > len) {
                l = (int)len;
            }

            if (l > 0) {
                /* Copy as much of input as possible to fill in block. */
                XMEMCPY(aes->lastBlock + aes->over, in, l);
                aes->over += l;
                in += l;
                len -= l;
            }
            /* Padding and not last full block or not padding and full block. */
            if ((noPad && aes->over == AES_BLOCK_SIZE) || len > 0) {
                /* Decrypt block cached block. */
                rc = wc_AesEcbDecrypt(&aes->aes, out, aes->lastBlock,
                                      AES_BLOCK_SIZE);
                if (rc != 0) {
                    WOLFENGINE_ERROR_FUNC(WE_LOG_CIPHER,
                                          "wc_AesEcbDecrypt", rc);
                    ret = 0;
                }
                /* Data put to output. */
                out += AES_BLOCK_SIZE;
                outl += AES_BLOCK_SIZE;
                /* No more cached data. */
                aes->over = 0;
            }
        }
        /* Decrypt full blocks from remaining input. */
        if ((ret == 1) && (len >= AES_BLOCK_SIZE)) {
            /* Calculate full blocks. */
            l = (int)len & (~(AES_BLOCK_SIZE - 1));

            /* Not last full block when padding. */
            if ((!noPad) && (len - l == 0)) {
                l -= AES_BLOCK_SIZE;
            }
            if (l > 0) {
                rc = wc_AesEcbDecrypt(&aes->aes, out, in, l);
                if (rc != 0) {
                    WOLFENGINE_ERROR_FUNC(WE_LOG_CIPHER,
                                          "wc_AesEcbDecrypt", rc);
                    ret = 0;
                }
            }

            outl += l;
            in += l;
            len -= l;
        }
        if ((ret == 1) && (len > 0)) {
            /* Copy remaining input as incomplete block. */
            XMEMCPY(aes->lastBlock, in, len);
            aes->over = (int)len;
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

    WOLFENGINE_LEAVE(WE_LOG_CIPHER, "we_aes_ecb_decrypt", ret);

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
static int we_aes_ecb_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out,
                             const unsigned char *in, size_t len)
{
    int ret;
    we_AesBlock* aes;

    WOLFENGINE_ENTER(WE_LOG_CIPHER, "we_aes_ecb_cipher");

    /* Get the AES object to work with. */
    aes = (we_AesBlock *)EVP_CIPHER_CTX_get_cipher_data(ctx);
    if (aes == NULL) {
        WOLFENGINE_ERROR_FUNC_NULL(WE_LOG_CIPHER,
                                   "EVP_CIPHER_CTX_get_cipher_data", aes);
        ret = -1;
    }
    else if (aes->enc) {
        ret = we_aes_ecb_encrypt(ctx, aes, out, in, len);
    }
    else {
        ret = we_aes_ecb_decrypt(ctx, aes, out, in, len);
    }

    WOLFENGINE_LEAVE(WE_LOG_CIPHER, "we_aes_ecb_cipher", ret);

    return ret;
}

/**
 * Extra operations for AES-ECB.
 *
 * No supported operations yet.
 *
 * @param  ctx   [in]  EVP cipher context of operation.
 * @param  type  [in]  Type of operation to perform.
 * @param  arg   [in]  Integer argument.
 * @param  ptr   [in]  Pointer argument.
 * @return  1 on success and 0 on failure.
 */
static int we_aes_ecb_ctrl(EVP_CIPHER_CTX *ctx, int type, int arg, void *ptr)
{
    int ret = 1;
    we_AesBlock *aes;
    char errBuff[WOLFENGINE_MAX_ERROR_SZ];

    WOLFENGINE_ENTER(WE_LOG_CIPHER, "we_aes_ecb_ctrl");

    (void)arg;
    (void)ptr;

    /* Get the AES-ECB data to work with. */
    aes = (we_AesBlock *)EVP_CIPHER_CTX_get_cipher_data(ctx);
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

    WOLFENGINE_LEAVE(WE_LOG_CIPHER, "we_aes_ecb_ctrl", ret);

    return ret;
}

/** Flags for AES-ECB method. */
#define AES_ECB_FLAGS              \
    (EVP_CIPH_FLAG_CUSTOM_CIPHER | \
     EVP_CIPH_ALWAYS_CALL_INIT   | \
     EVP_CIPH_FLAG_DEFAULT_ASN1  | \
     EVP_CIPH_ECB_MODE)

/** AES128-ECB EVP cipher method. */
EVP_CIPHER* we_aes128_ecb_ciph = NULL;
/** AES192-ECB EVP cipher method. */
EVP_CIPHER* we_aes192_ecb_ciph = NULL;
/** AES256-ECB EVP cipher method. */
EVP_CIPHER* we_aes256_ecb_ciph = NULL;


/**
 * Initialize an AES-ECB method.
 *
 * @return  1 on success and 0 on failure.
 */
static int we_init_aesecb_meth(EVP_CIPHER *cipher)
{
    int ret;

    WOLFENGINE_ENTER(WE_LOG_CIPHER, "we_init_aesecb_meth");

    ret = EVP_CIPHER_meth_set_iv_length(cipher, 0);
    if (ret == 1) {
        ret = EVP_CIPHER_meth_set_flags(cipher, AES_ECB_FLAGS);
    }
    if (ret == 1) {
        ret = EVP_CIPHER_meth_set_init(cipher, we_aes_ecb_init);
    }
    if (ret == 1) {
        ret = EVP_CIPHER_meth_set_do_cipher(cipher, we_aes_ecb_cipher);
    }
    if (ret == 1) {
        ret = EVP_CIPHER_meth_set_ctrl(cipher, we_aes_ecb_ctrl);
    }
    if (ret == 1) {
        ret = EVP_CIPHER_meth_set_impl_ctx_size(cipher, sizeof(we_AesBlock));
    }

    WOLFENGINE_LEAVE(WE_LOG_CIPHER, "we_init_aesecb_meth", ret);

    return ret;
}

/**
 * Initialize the AES-ECB methods.
 *
 * @return  1 on success and 0 on failure.
 */
int we_init_aesecb_meths()
{
    int ret = 1;

    WOLFENGINE_ENTER(WE_LOG_CIPHER, "we_init_aesecb_meths");

    /* AES128-ECB */
    we_aes128_ecb_ciph = EVP_CIPHER_meth_new(NID_aes_128_ecb, AES_BLOCK_SIZE,
                                             AES_128_KEY_SIZE);
    if (we_aes128_ecb_ciph == NULL) {
        WOLFENGINE_ERROR_FUNC_NULL(WE_LOG_CIPHER,
                                   "EVP_CIPHER_meth_new - AES-128-ECB",
                                   we_aes128_ecb_ciph);
        ret = 0;
    }
    if (ret == 1) {
        ret = we_init_aesecb_meth(we_aes128_ecb_ciph);
    }

    /* AES192-ECB */
    if (ret == 1) {
        we_aes192_ecb_ciph = EVP_CIPHER_meth_new(NID_aes_192_ecb,
            AES_BLOCK_SIZE, AES_192_KEY_SIZE);
        if (we_aes192_ecb_ciph == NULL) {
            WOLFENGINE_ERROR_FUNC_NULL(WE_LOG_CIPHER,
                                       "EVP_CIPHER_meth_new - AES-192-ECB",
                                       we_aes192_ecb_ciph);
            ret = 0;
        }
    }
    if (ret == 1) {
        ret = we_init_aesecb_meth(we_aes192_ecb_ciph);
    }

    /* AES256-ECB */
    if (ret == 1) {
        we_aes256_ecb_ciph = EVP_CIPHER_meth_new(NID_aes_256_ecb,
            AES_BLOCK_SIZE, AES_256_KEY_SIZE);
        if (we_aes256_ecb_ciph == NULL) {
            WOLFENGINE_ERROR_FUNC_NULL(WE_LOG_CIPHER,
                                       "EVP_CIPHER_meth_new - AES-256-ECB",
                                       we_aes256_ecb_ciph);
            ret = 0;
        }
    }
    if (ret == 1) {
        ret = we_init_aesecb_meth(we_aes256_ecb_ciph);
    }

    /* Cleanup */
    if ((ret == 0) && (we_aes128_ecb_ciph != NULL)) {
        EVP_CIPHER_meth_free(we_aes128_ecb_ciph);
        we_aes128_ecb_ciph = NULL;
    }
    if ((ret == 0) && (we_aes192_ecb_ciph != NULL)) {
        EVP_CIPHER_meth_free(we_aes192_ecb_ciph);
        we_aes192_ecb_ciph = NULL;
    }
    if ((ret == 0) && (we_aes256_ecb_ciph != NULL)) {
        EVP_CIPHER_meth_free(we_aes256_ecb_ciph);
        we_aes256_ecb_ciph = NULL;
    }

    WOLFENGINE_LEAVE(WE_LOG_CIPHER, "we_init_aesecb_meths", ret);

    return ret;
}

#endif /* WE_HAVE_AESECB */

