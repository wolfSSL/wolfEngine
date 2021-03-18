/* cipher.c
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

#include "wolfengine.h"

/* May not be available in FIPS builds of wolfSSL */
#ifndef GCM_NONCE_MAX_SZ
#define GCM_NONCE_MAX_SZ        16
#endif
#ifndef GCM_NONCE_MID_SZ
#define GCM_NONCE_MID_SZ        12
#endif


#ifdef WE_HAVE_AESGCM

/*
 * AES-GCM
 */

/**
 * Data required to complete an AES-GCM encrypt/decrypt operation.
 */
typedef struct we_AesGcm
{
    /** The wolfSSL AES data object. */
    Aes            aes;
    /** IV to use with encrypt/decrypt. */
    unsigned char  iv[GCM_NONCE_MAX_SZ];
    /** Length of IV data. */
    int            ivLen;
    /** IV set. */
    int            ivSet;
    /** Tag created when encrypting or tag set for decryption. */
    unsigned char  tag[AES_BLOCK_SIZE];
    /** Length of tag data stored.  */
    int            tagLen;
    /** Additional Authentication Data (AAD) - cumulative. */
    unsigned char *aad;
    /** Length of AAD stored. */
    int            aadLen;
    /** Flag to indicate whether we are doing encrypt (1) or decrpyt (0). */
    unsigned int   enc:1;
    /** Flag to indicate whether dping this for TLS */
    unsigned int   tls:1;
} we_AesGcm;

/**
 * Initialize the AES-GCM encrypt/decrypt operation using wolfSSL.
 *
 * @param  ctx  [in]  EVP cipher context of operation.
 * @param  key  [in]  AES key - 16 bytes.
 * @param  iv   [in]  Initialization Vector/nonce - 12 bytes.
 * @param  enc  [in]  1 when initializing for encrypt and 0 when decrypt.
 * @return  1 on success and 0 on failure.
 */
static int we_aes_gcm_init(EVP_CIPHER_CTX *ctx, const unsigned char *key,
                           const unsigned char *iv, int enc)
{
    int ret = 1;
    we_AesGcm *aes;

    WOLFENGINE_MSG("AES-GCM: Init");

    if (iv == NULL && key == NULL)
        ret = 0;

    if (ret == 1) {
        ret = (aes = (we_AesGcm *)EVP_CIPHER_CTX_get_cipher_data(ctx)) != NULL;
    }

    if (ret == 1) {
        /* No IV yet. */
        aes->ivLen = 0;
        aes->ivSet = 0;
        /* No tag set. */
        aes->tagLen = 0;
        /* Start with no AAD. */
        aes->aad = NULL;
        aes->aadLen = 0;
        aes->enc = enc;

        if (key != NULL) {
            ret = wc_AesGcmSetKey(&aes->aes, key,
                                  EVP_CIPHER_CTX_key_length(ctx)) == 0;
        }
    }
    if (ret == 1 && (key == NULL || iv != NULL)) {
        aes->ivLen = GCM_NONCE_MID_SZ;
        XMEMCPY(aes->iv, iv, GCM_NONCE_MID_SZ);
    }

    return ret;
}

/**
 * Encrypt/decrypt the data.
 * One-shot encrypt/decrypt - not streaming.
 *
 * @param  ctx  [in]  EVP cipher context of operation.
 * @param  out  [in]  Buffer to store enciphered result.<br>
 *                    NULL indicates AAD in.
 * @param  in   [in]  AAD or data to encrypt/decrypt.
 * @param  len  [in]  Length of AAD or data to encrypt/decrypt.
 * @return  When out is NULL, length of input data on success and 0 on failure.
 *          <br>
 *          When out is not NULL, length of output data on success and 0 on
 *          failure.
 */
static int we_aes_gcm_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out,
                             const unsigned char *in, size_t len)
{
    int ret = len;
    we_AesGcm *aes;
    unsigned char *p;

    WOLFENGINE_MSG("AES-GCM: Cipher");

    /* Get the AES-GCM data to work with. */
    aes = (we_AesGcm *)EVP_CIPHER_CTX_get_cipher_data(ctx);
    if (aes == NULL) {
        ret = 0;
    }

    if (ret != 0 && aes->tls) {
        if (aes->enc) {
            word32 encLen = (word32)len - EVP_GCM_TLS_EXPLICIT_IV_LEN - 16;
            if (ret != 0) {
                XMEMCPY(out, aes->iv + EVP_GCM_TLS_FIXED_IV_LEN,
                        EVP_GCM_TLS_EXPLICIT_IV_LEN);

                ret = wc_AesGcmEncrypt_ex(&aes->aes,
                                          out + EVP_GCM_TLS_EXPLICIT_IV_LEN,
                                          in + EVP_GCM_TLS_EXPLICIT_IV_LEN,
                                          encLen, aes->iv, aes->ivLen,
                                          out + len - 16, 16, aes->aad,
                                          aes->aadLen) == 0;
            }
            if (ret != 0) {
#if OPENSSL_VERSION_NUMBER < 0x30000000L
                ret = len;
#endif
                XMEMCPY(aes->iv, aes->aes.reg, aes->ivLen);
            }
        }
        else {
            word32 decLen = (word32)len - EVP_GCM_TLS_EXPLICIT_IV_LEN - 16;
            if (ret != 0) {
                XMEMCPY(aes->iv + EVP_GCM_TLS_FIXED_IV_LEN, in,
                        EVP_GCM_TLS_EXPLICIT_IV_LEN);

                ret = wc_AesGcmDecrypt(&aes->aes,
                                       out + EVP_GCM_TLS_EXPLICIT_IV_LEN,
                                       in + EVP_GCM_TLS_EXPLICIT_IV_LEN,
                                       decLen, aes->iv, aes->ivLen,
                                       out + len - 16, 16, aes->aad,
                                       aes->aadLen) == 0;
            }
            if (ret != 0) {
#if OPENSSL_VERSION_NUMBER < 0x30000000L
                ret = decLen;
#endif
                XMEMCPY(aes->iv, aes->aes.reg, aes->ivLen);
            }
        }

        /* Dispose of any AAD - all used now. */
        OPENSSL_free(aes->aad);
        aes->aad = NULL;
        aes->aadLen = 0;
    }
    else if (ret != 0 && out == NULL) {
        /* Resize stored AAD and append new data. */
        p = OPENSSL_realloc(aes->aad, aes->aadLen + len);
        if (p == NULL) {
            ret = 0;
        }
        else {
            aes->aad = p;
            XMEMCPY(aes->aad + aes->aadLen, in, len);
            aes->aadLen += len;
        }
    }
    else if (ret != 0) {
        if (aes->enc) {
            if (!aes->ivSet) {
                ret = wc_AesGcmSetExtIV(&aes->aes, aes->iv, aes->ivLen) == 0;
            }
            if (ret != 0) {
                aes->tagLen = AES_BLOCK_SIZE;
                ret = wc_AesGcmEncrypt_ex(&aes->aes, out, in, (word32)len,
                                          aes->iv, aes->ivLen, aes->tag,
                                          aes->tagLen, aes->aad,
                                          aes->aadLen) == 0;
            }
            if (ret != 0) {
                XMEMCPY(aes->iv, aes->aes.reg, aes->ivLen);
            }
        }
        else {
            ret = wc_AesGcmDecrypt(&aes->aes, out, in, (word32)len, aes->iv,
                                   aes->ivLen, aes->tag, aes->tagLen,
                                   aes->aad, aes->aadLen) == 0;
            if (ret != 0) {
                XMEMCPY(aes->iv, aes->aes.reg, aes->ivLen);
            }
        }

        /* Dispose of any AAD - all used now. */
        OPENSSL_free(aes->aad);
        aes->aad = NULL;
        aes->aadLen = 0;
    }

    return ret;
}

/**
 * Extra operations for AES-GCM.
 * Supported operations include:
 *  - EVP_CTRL_GET_IV (version 3.0+): get IV from wolfengine object
 *  - EVP_CTRL_AEAD_SET_IVLEN: set the length of an IV/nonce
 *  - EVP_CTRL_GCM_SET_IV_FIXED: set the fixed part of an IV/nonce
 *  - EVP_CTRL_GCM_IV_GEN: set the generated IV/nonce
 *  - EVP_CTRL_AEAD_GET_TAG: get the tag value after encrypt
 *  - EVP_CTRL_AEAD_SET_TAG: set the tag value before decrypt
 *  - EVP_CTRL_AEAD_TLS1_AAD: set AAD for TLS
 *
 * @param  ctx   [in]  EVP cipher context of operation.
 * @param  type  [in]  Type of operation to perform.
 * @param  arg   [in]  Integer argument.
 * @param  ptr   [in]  Pointer argument.
 * @return  1 on success and 0 on failure.
 */
static int we_aes_gcm_ctrl(EVP_CIPHER_CTX *ctx, int type, int arg, void *ptr)
{
    int ret = 1;
    we_AesGcm *aes;

    WOLFENGINE_MSG("AES-GCM - CTRL");

    /* Get the AES-GCM data to work with. */
    ret = (aes = (we_AesGcm *)EVP_CIPHER_CTX_get_cipher_data(ctx)) != NULL;
    if (ret == 1) {
        switch (type) {
            case EVP_CTRL_AEAD_SET_IVLEN:
                /* Set the IV/nonce length to use
                 *   arg [in] length of IV/nonce to use
                 *   ptr [in] Unused
                 */
                if (arg <= 0 || arg > GCM_NONCE_MAX_SZ) {
                    ret = 0;
                }
                else {
                    aes->ivLen = arg;
                }
                break;

            case EVP_CTRL_GCM_SET_IV_FIXED:
                 /* Set the fixed part of an IV
                 *   arg [in] size of fixed part of IV/nonce
                 *   ptr [in] fixed part of IV/nonce data
                 */
                if (arg == -1) {
                    /* arg of -1 means copy all data. */
                    if (aes->ivLen == 0)
                        aes->ivLen = GCM_NONCE_MID_SZ;
                    XMEMCPY(aes->iv, ptr, aes->ivLen);
                    XMEMCPY(EVP_CIPHER_CTX_iv_noconst(ctx), ptr, aes->ivLen);
                }
                else {
                    /* Set ta fixed IV and have the rest generated. */
                    if (aes->ivLen == 0)
                        aes->ivLen = GCM_NONCE_MID_SZ;
                    ret = wc_AesGcmSetIV(&aes->aes, aes->ivLen, ptr, arg,
                                         we_rng) == 0;
                    if (ret == 1) {
                       aes->ivSet = 1;
                       XMEMCPY(aes->iv, aes->aes.reg, aes->ivLen);
                       XMEMCPY(EVP_CIPHER_CTX_iv_noconst(ctx), aes->iv,
                               aes->ivLen);
                    }
                }
                break;

            case EVP_CTRL_GCM_IV_GEN:
                 /* Set the generated IV
                 *   arg [in] size of generated IV/nonce
                 *   ptr [in] generated IV/nonce data
                 */
                if (arg <= 0 || arg > GCM_NONCE_MAX_SZ) {
                    ret = 0;
                }
                else {
                    int i;
                    XMEMCPY(aes->iv, ptr, arg);
                    for (i = aes->ivLen - 1; i >= aes->ivLen - 8; i--) {
                        if ((++aes->iv[i]) != 0) {
                            break;
                        }
                    }
                }
                break;

            case EVP_CTRL_AEAD_GET_TAG:
                /* Get the tag from encryption.
                 *   arg [in] size of buffer
                 *   ptr [in] buffer to copy into
                 */
                if (!aes->enc || arg <= 0 || arg > aes->tagLen) {
                    ret = 0;
                }
                else {
                    XMEMCPY(ptr, aes->tag, arg);
                }
                break;

            case EVP_CTRL_AEAD_SET_TAG:
                /* Set the tag for decryption.
                 *   arg [in] size of tag
                 *   ptr [in] tag data to copy
                 */
                if (aes->enc || arg <= 0 || arg > AES_BLOCK_SIZE) {
                    ret = 0;
                }
                else {
                    XMEMCPY(aes->tag, ptr, arg);
                    aes->tagLen = arg;
                }
                break;

            case EVP_CTRL_AEAD_TLS1_AAD:
                /* Set additional authentication data for TLS
                 *   arg [in] size of AAD
                 *   ptr [in] AAD to use
                 */
                if (arg != EVP_AEAD_TLS1_AAD_LEN) {
                    ret = 0;
                }
                if (ret == 1) {
                    unsigned int len;

                    /* Set modified AAD based on record header */
                    if (aes->aad != NULL) {
                        OPENSSL_free(aes->aad);
                    }
                    ret = (aes->aad = OPENSSL_malloc(arg)) != NULL;
                    if (ret == 1) {
                        XMEMCPY(aes->aad, ptr, arg);
                        aes->aadLen = arg;
                        len = (aes->aad[arg - 2] << 8) | aes->aad[arg - 1];
                        if (len < EVP_GCM_TLS_EXPLICIT_IV_LEN) {
                            ret = 0;
                        }
                    }
                    if (ret == 1) {
                        len -= EVP_GCM_TLS_EXPLICIT_IV_LEN;
                        if (!aes->enc) {
                            if (len < EVP_GCM_TLS_TAG_LEN) {
                                ret = 0;
                            }
                            else {
                                len -= EVP_GCM_TLS_TAG_LEN;
                            }
                        }
                    }
                    if (ret == 1) {
                        aes->aad[arg - 2] = len >> 8;
                        aes->aad[arg - 1] = len;
                        aes->tls = 1;
                        ret = EVP_GCM_TLS_TAG_LEN;
                    }
                }
                break;

            default:
                ret = 0;
                break;
        }
    }

    return ret;
}

/** Flags for AES-GCM method. */
#define AES_GCM_FLAGS              \
    (EVP_CIPH_FLAG_CUSTOM_CIPHER | \
     EVP_CIPH_ALWAYS_CALL_INIT   | \
     EVP_CIPH_FLAG_AEAD_CIPHER   | \
     EVP_CIPH_GCM_MODE)

/** AES128-GCM EVP cipher method. */
EVP_CIPHER* we_aes128_gcm_ciph = NULL;
/** AES256-GCM EVP cipher method. */
EVP_CIPHER* we_aes256_gcm_ciph = NULL;


/**
 * Initialize an AES-GCM method.
 *
 * @return  1 on success and 0 on failure.
 */
static int we_init_aesgcm_meth(EVP_CIPHER *cipher)
{
    int ret;

    ret = EVP_CIPHER_meth_set_iv_length(cipher, GCM_NONCE_MID_SZ);
    if (ret == 1) {
        ret = EVP_CIPHER_meth_set_flags(cipher, AES_GCM_FLAGS);
    }
    if (ret == 1) {
        ret = EVP_CIPHER_meth_set_init(cipher, we_aes_gcm_init);
    }
    if (ret == 1) {
        ret = EVP_CIPHER_meth_set_do_cipher(cipher, we_aes_gcm_cipher);
    }
    if (ret == 1) {
        ret = EVP_CIPHER_meth_set_ctrl(cipher, we_aes_gcm_ctrl);
    }
    if (ret == 1) {
        ret = EVP_CIPHER_meth_set_impl_ctx_size(cipher, sizeof(we_AesGcm));
    }

    return ret;
}

/**
 * Initialize the AES-GCM methods.
 *
 * @return  1 on success and 0 on failure.
 */
int we_init_aesgcm_meths()
{
    int ret = 1;

    /* AES128-GCM */
    we_aes128_gcm_ciph = EVP_CIPHER_meth_new(NID_aes_128_gcm, 1,
                                             AES_128_KEY_SIZE);
    if (we_aes128_gcm_ciph == NULL) {
        ret = 0;
    }
    if (ret == 1) {
        ret = we_init_aesgcm_meth(we_aes128_gcm_ciph);
    }

    /* AES256-GCM */
    if (ret == 1) {
        we_aes256_gcm_ciph = EVP_CIPHER_meth_new(NID_aes_256_gcm, 1,
                                                 AES_256_KEY_SIZE);
        if (we_aes256_gcm_ciph == NULL) {
            ret = 0;
        }
    }
    if (we_aes256_gcm_ciph == NULL) {
        ret = 0;
    }
    if (ret == 1) {
        ret = we_init_aesgcm_meth(we_aes256_gcm_ciph);
    }

    /* Cleanup */
    if (ret == 0 && we_aes128_gcm_ciph != NULL) {
        EVP_CIPHER_meth_free(we_aes128_gcm_ciph);
        we_aes128_gcm_ciph = NULL;
    }
    if (ret == 0 && we_aes256_gcm_ciph != NULL) {
        EVP_CIPHER_meth_free(we_aes256_gcm_ciph);
        we_aes256_gcm_ciph = NULL;
    }
    return ret;
}

#endif /* WE_HAVE_AESGM */

