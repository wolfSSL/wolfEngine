/* we_aes_ccm.c
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

/* May not be available in FIPS builds of wolfSSL */
#ifndef CCM_NONCE_MAX_SZ
/* Maximum size of a nonce. */
#define CCM_NONCE_MAX_SZ        13
#endif
#ifndef CCM_NONCE_MIN_SZ
/* Minimum size of a nonce. */
#define CCM_NONCE_MIN_SZ        7
#endif

/* Older versions of OpenSSL don't define these. */
#ifndef EVP_CCM_TLS_EXPLICIT_IV_LEN
#define EVP_CCM_TLS_EXPLICIT_IV_LEN     EVP_GCM_TLS_EXPLICIT_IV_LEN
#endif
#ifndef EVP_CCM_TLS_TAG_LEN
#define EVP_CCM_TLS_TAG_LEN             EVP_GCM_TLS_TAG_LEN
#endif
#ifndef EVP_CCM_TLS_FIXED_IV_LEN
#define EVP_CCM_TLS_FIXED_IV_LEN        EVP_GCM_TLS_FIXED_IV_LEN
#endif
#ifndef EVP_CTRL_CCM_SET_IV_FIXED
#define EVP_CTRL_CCM_SET_IV_FIXED       EVP_CTRL_GCM_SET_IV_FIXED
#endif

/* MIN/MAX values for CCM length field (RFC3610) */
#define CCM_LEN_FIELD_MIN_SZ  2
#define CCM_LEN_FIELD_MAX_SZ  8

#ifdef WE_HAVE_AESCCM

/*
 * AES-CCM
 */

/**
 * Data required to complete an AES-CCM encrypt/decrypt operation.
 */
typedef struct we_AesCcm
{
    /** The wolfSSL AES data object. */
    Aes            aes;
    /** IV to use with encrypt/decrypt. */
    unsigned char  iv[CCM_NONCE_MAX_SZ];
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
    /** Size of CCM length field, default is 8 for OpenSSL AES unless set
     *  with ctrl function. wolfSSL calculates L based on nonce, but OpenSSL
     *  allows ctrl command to set L. */
    int            L;
    /** Flag to indicate whether object initialized. */
    unsigned int   init:1;
    /** Flag to indicate whether we are doing encrypt (1) or decrpyt (0). */
    unsigned int   enc:1;
    /** Flag to indicate whether doing this for TLS */
    unsigned int   tls:1;
} we_AesCcm;

/**
 * Initialize the AES-CCM encrypt/decrypt operation using wolfSSL.
 *
 * @param  ctx  [in,out]  EVP cipher context of operation.
 * @param  key  [in]      AES key - 16/24/32 bytes.
 * @param  iv   [in]      Initialization Vector/nonce - 12 bytes.
 * @param  enc  [in]      1 when initializing for encrypt and 0 when decrypt.
 * @return  1 on success and 0 on failure.
 */
static int we_aes_ccm_init(EVP_CIPHER_CTX *ctx, const unsigned char *key,
                           const unsigned char *iv, int enc)
{
    int ret = 1;
    int rc;
    we_AesCcm *aes;

    WOLFENGINE_ENTER(WE_LOG_CIPHER, "we_aes_ccm_init");

    /* Get the internal AES-CCM object. */
    aes = (we_AesCcm *)EVP_CIPHER_CTX_get_cipher_data(ctx);
    if (aes == NULL) {
        WOLFENGINE_ERROR_FUNC_NULL(WE_LOG_CIPHER,
                                   "EVP_CIPHER_CTX_get_cipher_data", aes);
        ret = 0;
    }

    if ((ret == 1) && (((key == NULL) && (iv == NULL)) || (!aes->init))) {
        /* Default L size for OpenSSL is 8, used to calc nonce/iv size */
        aes->L = CCM_LEN_FIELD_MAX_SZ;
        /* No IV yet, set to default length (15-L). */
        aes->ivLen = 15 - aes->L;
        aes->ivSet = 0;
        /* No tag set. */
        aes->tagLen = 0;
        /* Start with no AAD. */
        aes->aad = NULL;
        aes->aadLen = 0;
        aes->enc = enc;
        /* Internal AES-CCM object initialized. */
        aes->init = 1;
        /* Not doing CCM for TLS unless ctrl function called. */
        aes->tls = 0;
    }
    if ((ret == 1) && (key != NULL)) {
        /* Set the AES-CCM key. */
        rc = wc_AesCcmSetKey(&aes->aes, key, EVP_CIPHER_CTX_key_length(ctx));
        if (rc != 0) {
            WOLFENGINE_ERROR_FUNC(WE_LOG_CIPHER, "wc_AesCcmSetKey", rc);
            ret = 0;
        }
    }
    if ((ret == 1) && (iv != NULL)) {
        /* Cache IV - see ctrl func for other ways to set IV. IV length
         * default set above, unless reset by application through ctrl cmd. */
        XMEMCPY(aes->iv, iv, aes->ivLen);
    }

    WOLFENGINE_LEAVE(WE_LOG_CIPHER, "we_aes_ccm_init", ret);

    return ret;
}

/**
 * Encrypt/decrypt the data for TLS.
 * One-shot encrypt/decrypt - not streaming.
 *
 * @param  aes  [in,out]  Internal AES-CCM object.
 * @param  out  [out]     Buffer to store enciphered result.<br>
 *                        NULL indicates AAD in.
 * @param  in   [in]      AAD or data to encrypt/decrypt.
 * @param  len  [in]      Length of AAD or data to encrypt/decrypt.
 * @return  When out is NULL, length of input data on success and 0 on failure.
 *          <br>
 *          When out is not NULL, length of output data on success and 0 on
 *          failure.
 */
static int we_aes_ccm_tls_cipher(we_AesCcm *aes, unsigned char *out,
                                 const unsigned char *in, size_t len)
{
    int ret = 1;
    int rc;

    XMEMCPY(aes->iv + EVP_CCM_TLS_FIXED_IV_LEN, in,
            EVP_CCM_TLS_EXPLICIT_IV_LEN);
    /* Doing the TLS variation. */
    if (aes->enc) {
        /* Plaintext is input buffer without IV and tag. */
        word32 encLen = (word32)len - EVP_CCM_TLS_EXPLICIT_IV_LEN
                                    - EVP_CCM_TLS_TAG_LEN;
        if (!aes->ivSet) {
            /* Set Nonce/IV. */
            rc = wc_AesCcmSetNonce(&aes->aes, aes->iv, aes->ivLen);
            if (rc != 0) {
                WOLFENGINE_ERROR_FUNC(WE_LOG_CIPHER, "wc_AesCcmSetExtIV", rc);
                ret = 0;
            }
            aes->ivSet = 1;
        }
        if ((ret == 1) && (len != 0)) {
            /* Copy the explicit part of the IV into out. */
            XMEMCPY(out, aes->iv + EVP_CCM_TLS_FIXED_IV_LEN,
                    EVP_CCM_TLS_EXPLICIT_IV_LEN);

            /* Encrypt the data except explicit IV.
             * Tag goes at end of output buffer.
             */
            rc = wc_AesCcmEncrypt_ex(&aes->aes,
                                     out + EVP_CCM_TLS_EXPLICIT_IV_LEN,
                                     in + EVP_CCM_TLS_EXPLICIT_IV_LEN,
                                     encLen, aes->iv, aes->ivLen,
                                     out + len - EVP_CCM_TLS_TAG_LEN,
                                     EVP_CCM_TLS_TAG_LEN, aes->aad,
                                     aes->aadLen);
            if (rc != 0) {
                WOLFENGINE_ERROR_FUNC(WE_LOG_CIPHER, "wc_AesCcmEncrypt_ex", rc);
                ret = 0;
            }
        }
        if (ret == 1) {
            ret = (int)len;
        }
    }
    else {
        /* Cipher text is input buffer without IV and tag. */
        word32 decLen = (word32)len - EVP_CCM_TLS_EXPLICIT_IV_LEN
                                    - EVP_CCM_TLS_TAG_LEN;
        if (len != 0) {
            /* Copy the explicit part of the IV from input. */
            XMEMCPY(aes->iv + EVP_CCM_TLS_FIXED_IV_LEN, in,
                    EVP_CCM_TLS_EXPLICIT_IV_LEN);

            /* Decrypt the data except explicit IV.
             * Tag is at end of input buffer.
             */
            rc = wc_AesCcmDecrypt(&aes->aes,
                                  out + EVP_CCM_TLS_EXPLICIT_IV_LEN,
                                  in + EVP_CCM_TLS_EXPLICIT_IV_LEN,
                                  decLen, aes->iv, aes->ivLen,
                                  in + len - EVP_CCM_TLS_TAG_LEN,
                                  EVP_CCM_TLS_TAG_LEN, aes->aad, aes->aadLen);
            if (rc != 0) {
                WOLFENGINE_ERROR_FUNC(WE_LOG_CIPHER, "wc_AesCcmDecrypt", rc);
                ret = 0;
            }
        }
        if (ret == 1) {
#if OPENSSL_VERSION_NUMBER < 0x30000000L
            ret = (int)decLen;
#else
            ret = (int)len;
#endif
        }
    }

    /* Dispose of any AAD - all used now. */
    OPENSSL_free(aes->aad);
    aes->aad = NULL;
    aes->aadLen = 0;

    return ret;
}

/**
 * Encrypt/decrypt the data.
 * One-shot encrypt/decrypt - not streaming.
 *
 * @param  ctx  [in,out]  EVP cipher context of operation.
 * @param  out  [out]     Buffer to store enciphered result.<br>
 *                        NULL indicates AAD in.
 * @param  in   [in]      AAD or data to encrypt/decrypt.
 * @param  len  [in]      Length of AAD or data to encrypt/decrypt.
 * @return  When out is NULL, length of input data on success and 0 on failure.
 *          <br>
 *          When out is not NULL, and either in is not NULL or length is not 0,
 *          length of output data on success and 0 on
 *          failure.
 *          When out is not NULL, in is NULL, and len is 0, return 0 (no data).
 */
static int we_aes_ccm_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out,
                             const unsigned char *in, size_t len)
{
    int ret = 1;
    int rc;
    we_AesCcm *aes;
    unsigned char *p;

    WOLFENGINE_ENTER(WE_LOG_CIPHER, "we_aes_ccm_cipher");

    /* Get the AES-CCM data to work with. */
    aes = (we_AesCcm *)EVP_CIPHER_CTX_get_cipher_data(ctx);
    if (aes == NULL) {
        WOLFENGINE_ERROR_FUNC_NULL(WE_LOG_CIPHER,
                                   "EVP_CIPHER_CTX_get_cipher_data", aes);
        ret = 0;
    }

    if ((ret == 1) && aes->tls) {
        ret = we_aes_ccm_tls_cipher(aes, out, in, len);
    }
    else if ((ret == 1) && (out == NULL) && (in == NULL)) {
        /* Don't need to cache length of plain text. Just return size. */
        ret = len;
    }
    else if ((ret == 1) && (out == NULL)) {
        /* Resize stored AAD and append new data. */
        p = OPENSSL_realloc(aes->aad, aes->aadLen + (int)len);
        if (p == NULL) {
            WOLFENGINE_ERROR_FUNC_NULL(WE_LOG_CIPHER, "OPENSSL_realloc", p);
            ret = 0;
        }
        else {
            /* Copy in new data after existing data. */
            aes->aad = p;
            XMEMCPY(aes->aad + aes->aadLen, in, len);
            aes->aadLen += len;
            /* Return size of AAD data added */
            ret = len;
        }
    }
    else if ((ret == 1) && (len > 0)) {
        if (aes->enc) {
            if (!aes->ivSet) {
                /* Set extern IV. */
                rc = wc_AesCcmSetNonce(&aes->aes, aes->iv, aes->ivLen);
                if (rc != 0) {
                    WOLFENGINE_ERROR_FUNC(WE_LOG_CIPHER,
                                          "wc_AesCcmSetExtIV", rc);
                    ret = 0;
                }
            }
            if (ret == 1) {
                /* Tag always full size on calculation. */
                aes->tagLen = EVP_CCM_TLS_TAG_LEN;
                /* Encrypt the data. */
                rc = wc_AesCcmEncrypt_ex(&aes->aes, out, in, (word32)len,
                                         aes->iv, aes->ivLen, aes->tag,
                                         aes->tagLen, aes->aad, aes->aadLen);
                if (rc != 0) {
                    WOLFENGINE_ERROR_FUNC(WE_LOG_CIPHER,
                                          "wc_AesCcmEncrypt_ex", rc);
                    ret = 0;
                }
            }
            if (ret == 1) {
                /* Cache nonce/IV. */
                XMEMCPY(aes->iv, aes->aes.reg, aes->ivLen);
                /* Return encrypted data length */
                ret = len;
            }
        }
        else {
            /* Decrypt the data. */
            rc = wc_AesCcmDecrypt(&aes->aes, out, in, (word32)len, aes->iv,
                                  aes->ivLen, aes->tag, aes->tagLen,
                                  aes->aad, aes->aadLen);
            if (rc != 0) {
                WOLFENGINE_ERROR_FUNC(WE_LOG_CIPHER, "wc_AesCcmDecrypt_ex", rc);
                ret = 0;
            }
            if (ret == 1) {
                /* Cache nonce/IV. */
                XMEMCPY(aes->iv, aes->aes.reg, aes->ivLen);
                /* Return decrypted data length */
                ret = len;
            }
        }

        /* Dispose of any AAD - all used now. */
        OPENSSL_free(aes->aad);
        aes->aad = NULL;
        aes->aadLen = 0;
    } else if ((ret == 1) && (in == NULL)) {
        /* no error, but no input data or AAD to process, return 0 length */
        ret = 0;
    }

    WOLFENGINE_LEAVE(WE_LOG_CIPHER, "we_aes_ccm_cipher", ret);

    return ret;
}

/**
 * Extra operations for AES-CCM.
 * Supported operations include:
 *  - EVP_CTRL_SET_IV (version 3.0+): get IV from wolfengine object
 *  - EVP_CTRL_AEAD_SET_IVLEN: set the length of an IV/nonce
 *  - EVP_CTRL_GET_IVLEN: get the total IV/nonce length
 *  - EVP_CTRL_CCM_SET_IV_FIXED: set the fixed part of an IV/nonce
 *  - EVP_CTRL_CCM_IV_GEN: set the generated IV/nonce
 *  - EVP_CTRL_AEAD_GET_TAG: get the tag value after encrypt
 *  - EVP_CTRL_AEAD_SET_TAG: set the tag value before decrypt
 *  - EVP_CTRL_AEAD_TLS1_AAD: set AAD for TLS
 *
 * @param  ctx   [in.out]  EVP cipher context of operation.
 * @param  type  [in]      Type of operation to perform.
 * @param  arg   [in]      Integer argument.
 * @param  ptr   [in]      Pointer argument.
 * @return  1 on success and 0 on failure.
 */
static int we_aes_ccm_ctrl(EVP_CIPHER_CTX *ctx, int type, int arg, void *ptr)
{
    int ret = 1;
    we_AesCcm *aes;
    char errBuff[WOLFENGINE_MAX_ERROR_SZ];

    WOLFENGINE_ENTER(WE_LOG_CIPHER, "we_aes_ccm_ctrl");

    /* Get the AES-CCM data to work with. */
    aes = (we_AesCcm *)EVP_CIPHER_CTX_get_cipher_data(ctx);
    if (aes == NULL) {
        WOLFENGINE_ERROR_FUNC_NULL(WE_LOG_CIPHER,
                                   "EVP_CIPHER_CTX_get_cipher_data", aes);
        ret = 0;
    }
    if (ret == 1) {
        switch (type) {
            case EVP_CTRL_CCM_SET_L:
                WOLFENGINE_MSG(WE_LOG_CIPHER, "EVP_CTRL_CCM_SET_L");
                /* Set the length field, L
                 *   arg [in] value to use for length field (L)
                 *   ptr [in] Unused
                 */
                if ((arg <= 0) ||
                    arg < CCM_LEN_FIELD_MIN_SZ || arg > CCM_LEN_FIELD_MAX_SZ) {
                    WOLFENGINE_ERROR_MSG(WE_LOG_CIPHER,
                                         "Invalid CCM length field");
                    ret = 0;
                } else {
                    aes->L = arg;
                }
                break;
            case EVP_CTRL_AEAD_SET_IVLEN:
                WOLFENGINE_MSG(WE_LOG_CIPHER, "EVP_CTRL_AEAD_SET_IVLEN");
                /* Set the IV/nonce length to use
                 *   arg [in] length of IV/nonce to use
                 *   ptr [in] Unused
                 */
                if ((arg <= 0) || (arg > CCM_NONCE_MAX_SZ)) {
                    WOLFENGINE_ERROR_MSG(WE_LOG_CIPHER, "Invalid nonce length");
                    ret = 0;
                }
                else {
                    aes->ivLen = arg;
                }
                break;

            case EVP_CTRL_GET_IVLEN:
                WOLFENGINE_MSG(WE_LOG_CIPHER, "EVP_CTRL_GET_IVLEN");
                /* Set the generated IV
                 *   ptr [out] length of iv
                 */
                *(int *)ptr = aes->ivLen;
                break;

            case EVP_CTRL_CCM_SET_IV_FIXED:
                WOLFENGINE_MSG(WE_LOG_CIPHER, "EVP_CTRL_CCM_SET_IV_FIXED");
                /* Set the fixed part of an IV
                 *   arg [in] size of fixed part of IV/nonce
                 *   ptr [in] fixed part of IV/nonce data
                 */
                if (arg == EVP_CCM_TLS_FIXED_IV_LEN) {
                    XMEMCPY(aes->iv, ptr, arg);
                    XMEMCPY(EVP_CIPHER_CTX_iv_noconst(ctx), aes->iv, arg);
                }
                else {
                    ret = 0;
                }
                break;

            case EVP_CTRL_AEAD_GET_TAG:
                WOLFENGINE_MSG(WE_LOG_CIPHER, "EVP_CTRL_AEAD_GET_TAG");
                /* Get the tag from encryption.
                 *   arg [in] size of buffer
                 *   ptr [in] buffer to copy into
                 */
                if ((!aes->enc) || (arg <= 0) || (arg > aes->tagLen)) {
                    ret = 0;
                }
                else {
                    XMEMCPY(ptr, aes->tag, arg);
                }
                break;

            case EVP_CTRL_AEAD_SET_TAG:
                WOLFENGINE_MSG(WE_LOG_CIPHER, "EVP_CTRL_AEAD_SET_TAG");
                /* Set the tag for decryption.
                 *   arg [in] size of tag
                 *   ptr [in] tag data to copy
                 */
                if ((arg <= 0) || (arg > AES_BLOCK_SIZE)) {
                    WOLFENGINE_ERROR_MSG(WE_LOG_CIPHER, "Invalid tag size");
                    ret = 0;
                }
                else {
                    if (!aes->enc && (ptr != NULL)) {
                        XMEMCPY(aes->tag, ptr, arg);
                    }
                    aes->tagLen = arg;
                }
                break;

            case EVP_CTRL_AEAD_TLS1_AAD:
                WOLFENGINE_MSG(WE_LOG_CIPHER, "EVP_CTRL_AEAD_TLS1_AAD");
                /* Set additional authentication data for TLS
                 *   arg [in] size of AAD
                 *   ptr [in] AAD to use
                 */
                if (arg != EVP_AEAD_TLS1_AAD_LEN) {
                    WOLFENGINE_ERROR_MSG(WE_LOG_CIPHER, "Invalid TLS AAD size");
                    ret = 0;
                }
                if (ret == 1) {
                    unsigned int len;

                    /* Set modified AAD based on record header */
                    if (aes->aad != NULL) {
                        OPENSSL_free(aes->aad);
                    }
                    aes->aad = OPENSSL_malloc(arg);
                    if (aes->aad == NULL) {
                        WOLFENGINE_ERROR_FUNC_NULL(WE_LOG_CIPHER,
                                                   "OPENSSL_malloc", aes->aad);
                        ret = 0;
                    }
                    if (ret == 1) {
                        XMEMCPY(aes->aad, ptr, arg);
                        aes->aadLen = arg;
                        /* Get last two bytes of AAD. */
                        len = (aes->aad[arg - 2] << 8) | aes->aad[arg - 1];
                        if (len < EVP_CCM_TLS_EXPLICIT_IV_LEN) {
                            WOLFENGINE_ERROR_MSG(WE_LOG_CIPHER,
                                                 "Length in AAD invalid");
                            ret = 0;
                        }
                    }
                    if (ret == 1) {
                        len -= EVP_CCM_TLS_EXPLICIT_IV_LEN;
                        if (!aes->enc) {
                            if (len < EVP_CCM_TLS_TAG_LEN) {
                                WOLFENGINE_ERROR_MSG(WE_LOG_CIPHER,
                                                     "Length in AAD invalid");
                                ret = 0;
                            }
                            else {
                                len -= EVP_CCM_TLS_TAG_LEN;
                            }
                        }
                    }
                    if (ret == 1) {
                        /* Set last two bytes of AAD to exclude explicit len. */
                        aes->aad[arg - 2] = len >> 8;
                        aes->aad[arg - 1] = len;
                        /* Encryption to do TLS path. */
                        aes->tls = 1;
                        ret = EVP_CCM_TLS_TAG_LEN;
                    }
                }
                break;

            default:
                XSNPRINTF(errBuff, sizeof(errBuff), "Unsupported ctrl type %d",
                          type);
                WOLFENGINE_ERROR_MSG(WE_LOG_CIPHER, errBuff);
                ret = 0;
                break;
        }
    }

    WOLFENGINE_LEAVE(WE_LOG_CIPHER, "we_aes_ccm_ctrl", ret);

    return ret;
}

/** Flags for AES-CCM method. */
#define AES_CCM_FLAGS              \
    (EVP_CIPH_FLAG_CUSTOM_CIPHER | \
     EVP_CIPH_CUSTOM_IV_LENGTH   | \
     EVP_CIPH_CUSTOM_IV          | \
     EVP_CIPH_ALWAYS_CALL_INIT   | \
     EVP_CIPH_FLAG_AEAD_CIPHER   | \
     EVP_CIPH_FLAG_DEFAULT_ASN1  | \
     EVP_CIPH_CCM_MODE)

/** AES128-CCM EVP cipher method. */
EVP_CIPHER* we_aes128_ccm_ciph = NULL;
/** AES192-CCM EVP cipher method. */
EVP_CIPHER* we_aes192_ccm_ciph = NULL;
/** AES256-CCM EVP cipher method. */
EVP_CIPHER* we_aes256_ccm_ciph = NULL;


/**
 * Initialize an AES-CCM method.
 *
 * @return  1 on success and 0 on failure.
 */
static int we_init_aesccm_meth(EVP_CIPHER *cipher)
{
    int ret;

    WOLFENGINE_ENTER(WE_LOG_CIPHER, "we_init_aesccm_meth");

    ret = EVP_CIPHER_meth_set_iv_length(cipher, CCM_NONCE_MAX_SZ);
    if (ret == 1) {
        ret = EVP_CIPHER_meth_set_flags(cipher, AES_CCM_FLAGS);
    }
    if (ret == 1) {
        ret = EVP_CIPHER_meth_set_init(cipher, we_aes_ccm_init);
    }
    if (ret == 1) {
        ret = EVP_CIPHER_meth_set_do_cipher(cipher, we_aes_ccm_cipher);
    }
    if (ret == 1) {
        ret = EVP_CIPHER_meth_set_ctrl(cipher, we_aes_ccm_ctrl);
    }
    if (ret == 1) {
        ret = EVP_CIPHER_meth_set_impl_ctx_size(cipher, sizeof(we_AesCcm));
    }

    WOLFENGINE_LEAVE(WE_LOG_CIPHER, "we_init_aesccm_meth", ret);

    return ret;
}

/**
 * Initialize the AES-CCM methods.
 *
 * @return  1 on success and 0 on failure.
 */
int we_init_aesccm_meths()
{
    int ret = 1;

    WOLFENGINE_ENTER(WE_LOG_CIPHER, "we_init_aesccm_meths");

    /* AES128-CCM */
    we_aes128_ccm_ciph = EVP_CIPHER_meth_new(NID_aes_128_ccm, 1,
                                             AES_128_KEY_SIZE);
    if (we_aes128_ccm_ciph == NULL) {
        WOLFENGINE_ERROR_FUNC_NULL(WE_LOG_CIPHER,
                                   "EVP_CIPHER_meth_new - AES-128-CCM",
                                   we_aes128_ccm_ciph);
        ret = 0;
    }
    if (ret == 1) {
        ret = we_init_aesccm_meth(we_aes128_ccm_ciph);
    }

    /* AES192-CCM */
    if (ret == 1) {
        we_aes192_ccm_ciph = EVP_CIPHER_meth_new(NID_aes_192_ccm, 1,
                                                 AES_192_KEY_SIZE);
        if (we_aes192_ccm_ciph == NULL) {
            WOLFENGINE_ERROR_FUNC_NULL(WE_LOG_CIPHER,
                                       "EVP_CIPHER_meth_new - AES-192-CCM",
                                       we_aes192_ccm_ciph);
            ret = 0;
        }
    }
    if (ret == 1) {
        ret = we_init_aesccm_meth(we_aes192_ccm_ciph);
    }

    /* AES256-CCM */
    if (ret == 1) {
        we_aes256_ccm_ciph = EVP_CIPHER_meth_new(NID_aes_256_ccm, 1,
                                                 AES_256_KEY_SIZE);
        if (we_aes256_ccm_ciph == NULL) {
            WOLFENGINE_ERROR_FUNC_NULL(WE_LOG_CIPHER,
                                       "EVP_CIPHER_meth_new - AES-256-CCM",
                                       we_aes256_ccm_ciph);
            ret = 0;
        }
    }
    if (ret == 1) {
        ret = we_init_aesccm_meth(we_aes256_ccm_ciph);
    }

    /* Cleanup */
    if ((ret == 0) && (we_aes128_ccm_ciph != NULL)) {
        EVP_CIPHER_meth_free(we_aes128_ccm_ciph);
        we_aes128_ccm_ciph = NULL;
    }
    if ((ret == 0) && (we_aes192_ccm_ciph != NULL)) {
        EVP_CIPHER_meth_free(we_aes192_ccm_ciph);
        we_aes192_ccm_ciph = NULL;
    }
    if ((ret == 0) && (we_aes256_ccm_ciph != NULL)) {
        EVP_CIPHER_meth_free(we_aes256_ccm_ciph);
        we_aes256_ccm_ciph = NULL;
    }

    WOLFENGINE_LEAVE(WE_LOG_CIPHER, "we_init_aesccm_meths", ret);

    return ret;
}

#endif /* WE_HAVE_AESCCM */

