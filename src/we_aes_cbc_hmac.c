/* we_aes_cbc_hmac.c
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

#ifdef WE_HAVE_AESCBC

/**
 * Data required to complete an AES CBC HMAC encrypt/decrypt operation.
 */
typedef struct we_AesCbcHmac
{
    /** The wolfSSL AES data object. */
    Aes            aes;
    /** HMAC object. */
    Hmac           hmac;
    /** TLS AAD */
    unsigned char  tlsAAD[16];
    /** Payload len */
    int            pLen;
    /** Flag to indicate whether wolfSSL AES object initialized. */
    unsigned int   init:1;
    /** Flag to indicate whether we are doing encrypt (1) or decrpyt (0). */
    unsigned int   enc:1;
    /** Flag to indicate whether we are doing TLS 1.1 or above. */
    unsigned int   tls11:1;
} we_AesCbcHmac;

/*
 * AES-CBC HMAC
 */

/**
 * Initialize the AES-CBC HMAC encrypt/decrypt operation using wolfSSL.
 *
 * @param  ctx  [in,out]  EVP cipher context of operation.
 * @param  key  [in]      AES key - 16/24/32 bytes.
 * @param  iv   [in]      Initialization Vector - 12 bytes.
 * @param  enc  [in]      1 when initializing for encrypt and 0 when decrypt.
 * @return  1 on success and 0 on failure.
 */
static int we_aes_cbc_hmac_init(EVP_CIPHER_CTX *ctx, const unsigned char *key,
                                const unsigned char *iv, int enc)
{
    int ret = 1;
    int rc;
    we_AesCbcHmac *aes;

    WOLFENGINE_ENTER(WE_LOG_CIPHER, "we_aes_cbc_hmac_init");
    WOLFENGINE_MSG_VERBOSE(WE_LOG_CIPHER, "ARGS [ctx = %p, key = %p, iv = %p, "
                           "enc = %d]", ctx, key, iv, enc);

    if ((iv == NULL) && (key == NULL)) {
        WOLFENGINE_ERROR_MSG(WE_LOG_CIPHER, "iv == NULL && key == NULL");
        ret = 0;
    }

    if (ret == 1) {
        aes = (we_AesCbcHmac *)EVP_CIPHER_CTX_get_cipher_data(ctx);
        if (aes == NULL) {
            WOLFENGINE_ERROR_FUNC_NULL(WE_LOG_CIPHER,
                                       "EVP_CIPHER_CTX_get_cipher_data", aes);
            ret = 0;
        }
    }

    /* Initialize the wolfSSL AES object. */
    if ((ret == 1) && (!aes->init)) {
        WOLFENGINE_MSG(WE_LOG_CIPHER,
                       "Initializing wolfCrypt Aes structure: %p", &aes->aes);
        rc = wc_AesInit(&aes->aes, NULL, INVALID_DEVID);
        if (rc != 0) {
            WOLFENGINE_ERROR_FUNC(WE_LOG_CIPHER, "wc_AesInit", rc);
            ret = 0;
        }
    }
    /* Initialize the wolfSSL HMAC. */
    if ((ret == 1) && (!aes->init)) {
        WOLFENGINE_MSG(WE_LOG_CIPHER,
                       "Initializing wolfCrypt Hmac structure: %p", &aes->hmac);
        rc = wc_HmacInit(&aes->hmac, NULL, INVALID_DEVID);
        if (rc != 0) {
            WOLFENGINE_ERROR_FUNC(WE_LOG_CIPHER, "wc_HmacInit", rc);
            ret = 0;
        }
    }

    if (ret == 1) {
        /* Must have initialized wolfSSL AES object when here. */
        aes->init = 1;
        /* Store whether encrypting. */
        aes->enc = enc;
        /* No payload yet. */
        aes->pLen = 0;

        if (key != NULL) {
            /* Set the key into wolfSSL AES object. */
            WOLFENGINE_MSG(WE_LOG_CIPHER, "Setting AES key (%d bytes)",
                           EVP_CIPHER_CTX_key_length(ctx));
            rc = wc_AesSetKey(&aes->aes, key, EVP_CIPHER_CTX_key_length(ctx),
                              iv, enc ? AES_ENCRYPTION : AES_DECRYPTION);
            if (rc != 0) {
                WOLFENGINE_ERROR_FUNC(WE_LOG_CIPHER, "wc_AesSetKey", rc);
                ret = 0;
            }
        }
        else {
            /* Set the IV into wolfSSL AES object. */
            WOLFENGINE_MSG(WE_LOG_CIPHER, "Setting AES IV");
            rc = wc_AesSetIV(&aes->aes, iv);
            if (rc != 0) {
                WOLFENGINE_ERROR_FUNC(WE_LOG_CIPHER, "wc_AesSetIV", rc);
                ret = 0;
            }
        }
    }

    WOLFENGINE_LEAVE(WE_LOG_CIPHER, "we_aes_cbc_hmac_init", ret);

    return ret;
}

/**
 * Encrypt and MAC using wolfSSL.
 *
 * @param  aes  [in]      Internal AES object.
 * @param  out  [out]     Buffer to store enciphered result.
 * @param  in   [in]      Data to encrypt/decrypt.
 * @param  len  [in]      Length of data to encrypt/decrypt.
 * @return  -1 on failure.
 * @return  Number of bytes put in out on success.
 */
static int we_aes_cbc_hmac_enc(we_AesCbcHmac* aes, unsigned char *out,
                               const unsigned char *in, size_t len)
{
    int ret = 0;
    int rc;
    int off = 0;
    unsigned char pb;
    int pLen;
    int tls;

    WOLFENGINE_ENTER(WE_LOG_CIPHER, "we_aes_cbc_hmac_enc");

    /* Get payload length to get TLS. */
    pLen = aes->pLen;
    tls = (pLen != 0);
    if (!tls) {
        WOLFENGINE_MSG(WE_LOG_CIPHER, "Not being called from TLS");
        pLen = (int)len;
    }
    else if (aes->tls11) {
        /* When TLS v1.1 and v1.2 the IV is at the front. */
        WOLFENGINE_MSG(WE_LOG_CIPHER, "Setting AES IV, aes->tls11 = %d",
                       aes->tls11);
        off = AES_BLOCK_SIZE;
        rc = wc_AesSetIV(&aes->aes, in);
        if (rc != 0) {
            WOLFENGINE_ERROR_FUNC(WE_LOG_CIPHER, "wc_AesSetIV", rc);
            ret = -1;
        }
    }
    if (ret != -1) {
        /* Record layer MACed in ctrl function. */
        /* MAC the handshake message/data. */
        WOLFENGINE_MSG(WE_LOG_CIPHER, "MAC handshake message/data: len = %d",
                       pLen - off);
        rc = we_hmac_update(&aes->hmac, in + off, pLen - off);
        if (rc != 1) {
            WOLFENGINE_ERROR_FUNC(WE_LOG_CIPHER, "we_hmac_update", rc);
            ret = -1;
        }
    }
    if ((ret != -1) && tls) {
        /* Copy input to output buffer to encrypt contiguous memory. */
        XMEMCPY(out, in, pLen);

        /* Put the MAC after data. */
        WOLFENGINE_MSG(WE_LOG_CIPHER,
                       "Doing HMAC Final, putting MAC after data");
        rc = wc_HmacFinal(&aes->hmac, out + pLen);
        if (rc != 0) {
             WOLFENGINE_ERROR_FUNC(WE_LOG_CIPHER, "wc_HmacFinal", rc);
             ret = -1;
        }
    }
    if ((ret != -1) && tls) {
        in = out;
        /* Put padding after MAC. */
        WOLFENGINE_MSG(WE_LOG_CIPHER, "Adding padding after MAC");
        pLen += SHA256_DIGEST_LENGTH;
        pb = (unsigned char)(len - pLen - 1);
        for (; pLen < (int)len; pLen++) {
            out[pLen] = pb;
        }
    }
    if (ret != -1) {
        /* Encrypt the msg and MAC but not IV. */
        WOLFENGINE_MSG(WE_LOG_CIPHER, "Encrypting message and MAC");
        rc = wc_AesCbcEncrypt(&aes->aes, out + off, in + off, (int)len - off);
        if (rc != 0) {
            WOLFENGINE_ERROR_FUNC(WE_LOG_CIPHER, "wc_AesCbcEncrypt", rc);
            ret = 0;
        }
        else {
            ret = (int)len;
            WOLFENGINE_BUFFER(WE_LOG_CIPHER, out + off, (int)(len - off));
        }
    }

    WOLFENGINE_LEAVE(WE_LOG_CIPHER, "we_aes_cbc_hmac_enc", ret);

    return ret;
}

/**
 * Decrypt and verify MAC using wolfSSL.
 *
 * @param  aes  [in]      Internal AES object.
 * @param  out  [out]     Buffer to store enciphered result.
 * @param  in   [in]      Data to encrypt/decrypt.
 * @param  len  [in]      Length of data to encrypt/decrypt.
 * @return  -1 on failure.
 * @return  Number of bytes put in out on success.
 */
static int we_aes_cbc_hmac_dec(we_AesCbcHmac* aes, unsigned char *out,
                               const unsigned char *in, size_t len)
{
    int ret = 0;
    int rc;
    int off = 0;
    unsigned char pb;
    int pLen;
    int tls;
    unsigned char mac[SHA256_DIGEST_LENGTH];
    int i;

    WOLFENGINE_ENTER(WE_LOG_CIPHER, "we_aes_cbc_hmac_dec");

    /* Get payload length. */
    pLen = aes->pLen;
    tls = (pLen != 0);
    if (aes->tls11) {
        /* TLS v1.1 and v1.2 have IV before message. */
        WOLFENGINE_MSG(WE_LOG_CIPHER, "Setting AES IV, aes->tls11 = %d",
                       aes->tls11);
        off = AES_BLOCK_SIZE;
        rc = wc_AesSetIV(&aes->aes, in);
        if (rc != 0) {
            WOLFENGINE_ERROR_FUNC(WE_LOG_CIPHER, "wc_AesSetIV", rc);
            ret = -1;
       }
    }
    if (ret != -1) {
        /* Decrypt all but IV. */
        rc = wc_AesCbcDecrypt(&aes->aes, out + off, in + off, (int)len - off);
        if (rc != 0) {
            WOLFENGINE_ERROR_FUNC(WE_LOG_CIPHER, "wc_AesCbcDecrypt", rc);
            ret = -1;
        }
        else {
            /* Calculate decrypted data length. */
            ret = (int)len - off;

            WOLFENGINE_MSG_VERBOSE(WE_LOG_CIPHER, "Decrypted %d bytes "
                                   "(AES-CBC-HMAC)", (int)len - off);
            WOLFENGINE_BUFFER(WE_LOG_CIPHER, out + off, (int)len - off);
        }
    }
    if ((ret != -1) && tls) {
        /* TODO: not constant time. */
        /* Remove padding. */
        pb = out[off + ret - 1];
        if (pb >= AES_BLOCK_SIZE) {
            ret = -1;
        }
        for (i = 1; (ret != -1) && (i <= pb); i++) {
            if (out[off + ret - 1 - i] != pb)
                ret = -1;
        }
        if (ret != -1) {
            /* Remove padding and MAC length. */
            ret -= pb + 1 + SHA256_DIGEST_LENGTH;
        }

        /* Update record header to have correct message length. */
        aes->tlsAAD[aes->pLen - 2] = ret >> 8;
        aes->tlsAAD[aes->pLen - 1] = ret;

        /* MAC the record header. */
        WOLFENGINE_MSG(WE_LOG_CIPHER, "Generate MAC over record header: "
                       "len = %d", aes->pLen);
        rc = we_hmac_update(&aes->hmac, aes->tlsAAD, aes->pLen);
        if (rc != 1) {
            WOLFENGINE_ERROR_FUNC(WE_LOG_CIPHER, "we_hmac_update", rc);
            ret = -1;
        }
    }
    /* TODO: not constant time. */
    if (ret != -1) {
        /* MAC the message/input. */
        WOLFENGINE_MSG(WE_LOG_CIPHER, "Generate MAC over message/input, "
                       "len = %d", ret);
        rc = we_hmac_update(&aes->hmac, out + off, ret);
        if (rc != 1) {
            WOLFENGINE_ERROR_FUNC(WE_LOG_CIPHER, "we_hmac_update", rc);
            ret = -1;
        }
    }
    if (ret != -1) {
        /* Calculate MAC. */
        rc = wc_HmacFinal(&aes->hmac, mac);
        if (rc != 0) {
            WOLFENGINE_ERROR_FUNC(WE_LOG_CIPHER, "wc_HmacFinal", rc);
            ret = -1;
        }
    }
    if (ret != -1) {
        WOLFENGINE_MSG_VERBOSE(WE_LOG_CIPHER, "Generated MAC:");
        WOLFENGINE_BUFFER(WE_LOG_CIPHER, mac, SHA256_DIGEST_LENGTH);

        /* Check MAC. */
        pb = 0;
        for (i = 0; i < SHA256_DIGEST_LENGTH; i++) {
            pb |= mac[i] ^ out[off + ret + i];
        }
        if (pb != 0) {
            WOLFENGINE_ERROR_MSG(WE_LOG_CIPHER, "MAC check failed");
            ret = -1;
        }
    }

    WOLFENGINE_LEAVE(WE_LOG_CIPHER, "we_aes_cbc_hmac_dec", ret);

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
static int we_aes_cbc_hmac_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out,
                                  const unsigned char *in, size_t len)
{
    int ret = 1;
    we_AesCbcHmac* aes;


    WOLFENGINE_ENTER(WE_LOG_CIPHER, "we_aes_cbc_hmac_cipher");
    WOLFENGINE_MSG_VERBOSE(WE_LOG_CIPHER, "ARGS [ctx = %p, out = %p, in = %p, "
                           "len = %zu]", ctx, out, in, len);

    /* Get the AES-CBC object to work with. */
    aes = (we_AesCbcHmac *)EVP_CIPHER_CTX_get_cipher_data(ctx);
    if (aes == NULL) {
        WOLFENGINE_ERROR_FUNC_NULL(WE_LOG_CIPHER,
                                   "EVP_CIPHER_CTX_get_cipher_data", aes);
        ret = -1;
    }
    else if (aes->enc) {
        ret = we_aes_cbc_hmac_enc(aes, out, in, len);
    }
    else {
        ret = we_aes_cbc_hmac_dec(aes, out, in, len);
    }

    WOLFENGINE_LEAVE(WE_LOG_CIPHER, "we_aes_cbc_hmac_cipher", ret);

    return ret;
}

/**
 * Extra operations for AES-CBC HMAC.
 *
 * @param  ctx   [in]  EVP cipher context of operation.
 * @param  type  [in]  Type of operation to perform.
 * @param  arg   [in]  Integer argument.
 * @param  ptr   [in]  Pointer argument.
 * @return  1 on success and 0 on failure.
 */
static int we_aes_cbc_hmac_ctrl(EVP_CIPHER_CTX *ctx, int type, int arg,
                                void *ptr)
{
    int ret = 1;
    we_AesCbcHmac *aes;
    int rc;
    unsigned char *tls;
    int tlsVer;
    int len;
    char errBuff[WOLFENGINE_MAX_LOG_WIDTH];

    WOLFENGINE_ENTER(WE_LOG_CIPHER, "we_aes_cbc_hmac_ctrl");
    WOLFENGINE_MSG_VERBOSE(WE_LOG_CIPHER, "ARGS [ctx = %p, type = %d, "
                           "arg = %d, ptr = %p]", ctx, type, arg, ptr);

    (void)arg;
    (void)ptr;

    /* Get the AES-CBC data to work with. */
    aes = (we_AesCbcHmac *)EVP_CIPHER_CTX_get_cipher_data(ctx);
    if (aes == NULL) {
        WOLFENGINE_ERROR_FUNC_NULL(WE_LOG_CIPHER,
                                   "EVP_CIPHER_CTX_get_cipher_data", aes);
        ret = 0;
    }
    if (ret == 1) {
        switch (type) {
            case EVP_CTRL_AEAD_SET_MAC_KEY:
                WOLFENGINE_MSG(WE_LOG_CIPHER, "EVP_CTRL_AEAD_SET_MAC_KEY");
                /* Set the HMAC key. */
                rc = wc_HmacSetKey(&aes->hmac, WC_SHA256, (const byte*)ptr,
                        arg);
                if (rc != 0) {
                    WOLFENGINE_ERROR_FUNC(WE_LOG_CIPHER, "wc_HmacSetKey", rc);
                    ret = 0;
                }
                break;
            case EVP_CTRL_AEAD_TLS1_AAD:
                WOLFENGINE_MSG(WE_LOG_CIPHER, "EVP_CTRL_AEAD_TLS1_AAD");
                tls = (unsigned char *)ptr;
                if (arg != EVP_AEAD_TLS1_AAD_LEN) {
                    WOLFENGINE_ERROR_MSG(WE_LOG_CIPHER,
                                         "AAD len != EVP_AEAD_TLS1_AAD_LEN");
                    ret = -1;
                }
                if (ret == 1) {
                    /* Get the verion from the record layer. */
                    tlsVer = (tls[arg - 4] << 8) | tls[arg - 3];
                    /* Record whether it is TLS v1.1 or above. */
                    aes->tls11 = (tlsVer >= TLS1_1_VERSION);
                    WOLFENGINE_MSG(WE_LOG_CIPHER, "tlsVer = %d, aes->enc = %d",
                                   tlsVer, aes->enc);

                    if (aes->enc) {
                        /* Get length from record layer. */
                        len = (tls[arg - 2] << 8) | tls[arg - 1];
                        /* Store payload length. */
                        aes->pLen = len;
                        if (aes->tls11) {
                            /* Must be space for IV. */
                            if (len < AES_BLOCK_SIZE) {
                                ret = -1;
                            }
                            else {
                                /* Remove IV and update record header. */
                                len -= AES_BLOCK_SIZE;
                                tls[arg - 2] = len >> 8;
                                tls[arg - 1] = len;
                            }
                        }
                        if (ret == 1) {
                            /* MAC the record header. */
                            WOLFENGINE_MSG(WE_LOG_CIPHER,
                                           "Updating MAC with record header");
                            rc = we_hmac_update(&aes->hmac, tls, arg);
                            if (rc != 1) {
                                WOLFENGINE_ERROR_FUNC(WE_LOG_CIPHER,
                                                      "we_hmac_update", rc);
                                ret = -1;
                            }
                        }
                        if (ret == 1) {
                            /* Calculate length with padding. */
                            ret = ((len + SHA256_DIGEST_LENGTH +
                                    AES_BLOCK_SIZE) & -AES_BLOCK_SIZE) - len;
                        }
                    }
                    else {
                        /* Store record header for later. */
                        WOLFENGINE_MSG(WE_LOG_CIPHER, "Storing record header "
                                       "for later");
                        aes->pLen = arg;
                        XMEMCPY(aes->tlsAAD, ptr, arg);
                        /* MAC size. */
                        ret = SHA256_DIGEST_LENGTH;
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

    WOLFENGINE_LEAVE(WE_LOG_CIPHER, "we_aes_cbc_hmac_ctrl", ret);

    return ret;
}

/** Flags for AES-CBC HMAC-SHA256 method. */
#define AES_CBC_HMAC_FLAGS                \
    (EVP_CIPH_FLAG_CUSTOM_CIPHER        | \
     EVP_CIPH_ALWAYS_CALL_INIT          | \
     EVP_CIPH_CBC_MODE                  | \
     EVP_CIPH_FLAG_DEFAULT_ASN1         | \
     EVP_CIPH_FLAG_AEAD_CIPHER)

/** AES128-CBC HMAC SHA256 EVP cipher method. */
EVP_CIPHER* we_aes128_cbc_hmac_ciph = NULL;
/** AES256-CBC HMAC SHA256 EVP cipher method. */
EVP_CIPHER* we_aes256_cbc_hmac_ciph = NULL;


/**
 * Initialize an AES-CBC HMAC method.
 *
 * @return  1 on success and 0 on failure.
 */
static int we_init_aescbc_hmac_meth(EVP_CIPHER *cipher)
{
    int ret;

    WOLFENGINE_ENTER(WE_LOG_CIPHER, "we_init_aescbc_meth");

    ret = EVP_CIPHER_meth_set_iv_length(cipher, AES_IV_SIZE);
    if (ret == 1) {
        ret = EVP_CIPHER_meth_set_flags(cipher, AES_CBC_HMAC_FLAGS);
    }
    if (ret == 1) {
        ret = EVP_CIPHER_meth_set_init(cipher, we_aes_cbc_hmac_init);
    }
    if (ret == 1) {
        ret = EVP_CIPHER_meth_set_do_cipher(cipher, we_aes_cbc_hmac_cipher);
    }
    if (ret == 1) {
        ret = EVP_CIPHER_meth_set_ctrl(cipher, we_aes_cbc_hmac_ctrl);
    }
    if (ret == 1) {
        ret = EVP_CIPHER_meth_set_impl_ctx_size(cipher, sizeof(we_AesCbcHmac));
    }

    WOLFENGINE_LEAVE(WE_LOG_CIPHER, "we_init_aescbc_meth", ret);

    return ret;
}

/**
 * Initialize the AES-CBC methods.
 *
 * @return  1 on success and 0 on failure.
 */
int we_init_aescbc_hmac_meths()
{
    int ret = 1;

    WOLFENGINE_ENTER(WE_LOG_CIPHER, "we_init_aescbc_meths");

    /* AES128-CBC HMAC-SHA256 */
    we_aes128_cbc_hmac_ciph = EVP_CIPHER_meth_new(NID_aes_128_cbc_hmac_sha256,
        AES_BLOCK_SIZE, AES_128_KEY_SIZE);
    if (we_aes128_cbc_ciph == NULL) {
        WOLFENGINE_ERROR_FUNC_NULL(WE_LOG_CIPHER,
                                   "EVP_CIPHER_meth_new - AES-128-CBC "
                                   "HMAC SHA256", we_aes128_cbc_ciph);
        ret = 0;
    }
    if (ret == 1) {
        ret = we_init_aescbc_hmac_meth(we_aes128_cbc_hmac_ciph);
    }

    /* AES256-CBC HMAC-SHA256 */
    if (ret == 1) {
        we_aes256_cbc_hmac_ciph = EVP_CIPHER_meth_new(
            NID_aes_256_cbc_hmac_sha256, AES_BLOCK_SIZE, AES_256_KEY_SIZE);
        if (we_aes256_cbc_ciph == NULL) {
            WOLFENGINE_ERROR_FUNC_NULL(WE_LOG_CIPHER,
                                       "EVP_CIPHER_meth_new - AES-256-CBC "
                                       "HMAC SHA256", we_aes256_cbc_ciph);
            ret = 0;
        }
    }
    if (ret == 1) {
        ret = we_init_aescbc_hmac_meth(we_aes256_cbc_hmac_ciph);
    }

    /* Cleanup */
    if ((ret == 0) && (we_aes128_cbc_hmac_ciph != NULL)) {
        EVP_CIPHER_meth_free(we_aes128_cbc_hmac_ciph);
        we_aes128_cbc_hmac_ciph = NULL;
    }
    if ((ret == 0) && (we_aes256_cbc_hmac_ciph != NULL)) {
        EVP_CIPHER_meth_free(we_aes256_cbc_hmac_ciph);
        we_aes256_cbc_hmac_ciph = NULL;
    }

    WOLFENGINE_LEAVE(WE_LOG_CIPHER, "we_init_aescbc_meths", ret);

    return ret;
}

#endif /* WE_HAVE_AESCBC */

