/* test_aestag.c
 *
 * Copyright (C) 2019-2021 wolfSSL Inc.
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

#include "unit.h"

#ifndef EVP_CCM_TLS_FIXED_IV_LEN
#define EVP_CCM_TLS_FIXED_IV_LEN        EVP_GCM_TLS_FIXED_IV_LEN
#endif
#ifndef EVP_CCM_TLS_TAG_LEN
#define EVP_CCM_TLS_TAG_LEN             EVP_GCM_TLS_TAG_LEN
#endif

#if defined(WE_HAVE_AESGCM) || defined(WE_HAVE_AESCCM)

static int test_aes_tag_enc(ENGINE *e, const EVP_CIPHER *cipher,
                            unsigned char *key, unsigned char *iv, int ivLen,
                            unsigned char *aad, unsigned char *msg, int len,
                            unsigned char *enc, unsigned char *tag, int ccm,
                            int ccmL)
{
    int err;
    EVP_CIPHER_CTX *ctx;
    int encLen;
    unsigned int tagLen = 16;

    err = (ctx = EVP_CIPHER_CTX_new()) == NULL;
    if (err == 0) {
        err = EVP_EncryptInit_ex(ctx, cipher, e, NULL, NULL) != 1;
    }
    if (err == 0 && ccm && ccmL != 0) {
        /* Applications can set CCM length field (L), default is 8 if unset. */
        err = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_SET_L, ccmL, NULL) != 1;
    }
    if (err == 0) {
        if (ccm && ccmL != 0) {
            /* adjust IV based on L, should be 15-L */
            ivLen = 15-ccmL;
        }
        err = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, ivLen,
                                  NULL) != 1;
    }
    if (err == 0 && ccm) {
        /* Only CCM needs tag length set before encryption. */
        err = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, tagLen,
                                  NULL) != 1;
    }
    if (err == 0) {
        err = EVP_EncryptInit_ex(ctx, NULL, e, key, iv) != 1;
    }
    if ((err == 0) && ccm) {
        /* OpenSSL's CCM needs the length of plaintext set. */
        err = EVP_EncryptUpdate(ctx, NULL, &encLen, NULL, len) != 1;
        if (encLen != len) {
            /* Should return length */
            err = 1;
        }
    }
    if ((err == 0) && ccm) {
        /* No AAD streaming available in OpenSSL CCM mode. */
        err = EVP_EncryptUpdate(ctx, NULL, &encLen, aad,
                                (int)strlen((char *)aad)) != 1;
        if (encLen != (int)strlen((char *)aad)) {
            /* Should return length of AAD data added */
            err = 1;
        }
    }
    if ((err == 0) && !ccm) {
        /* AAD streaming available in OpenSSL GCM mode - part 1. */
        err = EVP_EncryptUpdate(ctx, NULL, &encLen, aad, 1) != 1;
    }
    if ((err == 0) && !ccm) {
        /* AAD streaming available in OpenSSL GCM mode - part 2. */
        err = EVP_EncryptUpdate(ctx, NULL, &encLen, aad + 1,
                                (int)strlen((char *)aad) - 1) != 1;
    }
    if (err == 0 && len > 0) {
        /* Update with msg, if len > 0 (not GMAC) */
        err = EVP_EncryptUpdate(ctx, enc, &encLen, msg, len) != 1;
        if (encLen != len) {
            err = 1;
        }
    }
    if (err == 0) {
        err = EVP_EncryptFinal_ex(ctx, enc + encLen, &encLen) != 1;
        if (encLen != 0) {
            /* should be no more data left */
            err = 1;
        }
    }
    if (err == 0) {
        err = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, tagLen, tag) != 1;
    }

    if (err == 0) {
        PRINT_BUFFER("Encrypted", enc, len);
        PRINT_BUFFER("Tag", tag, 16);
    }

    EVP_CIPHER_CTX_free(ctx);

    return err;
}

static int test_aes_tag_dec(ENGINE *e, const EVP_CIPHER *cipher,
                            unsigned char *key, unsigned char *iv, int ivLen,
                            unsigned char *aad, unsigned char *msg, int len,
                            unsigned char *enc, unsigned char *tag,
                            unsigned char *dec, int ccm, int ccmL)
{
    int err;
    EVP_CIPHER_CTX *ctx;
    int decLen;
    unsigned int tagLen = 16;

    err = (ctx = EVP_CIPHER_CTX_new()) == NULL;
    if (err == 0) {
        err = EVP_DecryptInit_ex(ctx, cipher, e, NULL, NULL) != 1;
    }
    if (err == 0 && ccm && ccmL != 0) {
        /* Applications can set CCM length field (L), default is 8 if unset. */
        err = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_SET_L, ccmL, NULL) != 1;
    }
    if (err == 0) {
        if (ccm && ccmL != 0) {
            /* adjust IV based on L, should be 15-L */
            ivLen = 15-ccmL;
        }
        err = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, ivLen,
                                  NULL) != 1;
    }
    if (err == 0) {
        err = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, tagLen,
                                  (void *)tag) != 1;
    }
    if (err == 0) {
        err = EVP_DecryptInit_ex(ctx, NULL, e, key, iv) != 1;
    }
    if ((err == 0) && ccm) {
        /* OpenSSL's CCM needs the length of plaintext set. */
        err = EVP_DecryptUpdate(ctx, NULL, &decLen, NULL, len) != 1;
    }
    if (err == 0) {
        err = EVP_DecryptUpdate(ctx, NULL, &decLen, aad,
                                (int)strlen((char *)aad)) != 1;
        if (err == 0 && (decLen != (int)strlen((char *)aad))) {
            PRINT_MSG("EVP_DecryptUpdate did not return correct size of AAD");
            err = 1;
        }
    }
    if (err == 0 && len > 0) {
        /* Not used in GMAC test (len == 0) */
        err = EVP_DecryptUpdate(ctx, dec, &decLen, enc, len) != 1;
    } else {
        /* Reset decLen, represented AAD length above */
        decLen = 0;
    }
#if OPENSSL_VERSION_NUMBER >= 0x10101000L
    /* Bug in older versions has tag_set cleared and causes failure. */
    if (err == 0) {
#else
    if (err == 0 && (!ccm || len == 0)) {
#endif
        err = EVP_DecryptFinal_ex(ctx, dec + decLen, &decLen) != 1;
    }

    if (err == 0 && dec != NULL && msg != NULL) {
        PRINT_BUFFER("Decrypted", dec, len);

        if (memcmp(dec, msg, len) != 0) {
            err = 1;
        }
    }

    EVP_CIPHER_CTX_free(ctx);

    return err;
}

static int test_aes_tag(ENGINE *e, void *data, const EVP_CIPHER *cipher,
                        int keyLen, int ivLen, int ccm, int ccmL)
{
    int err = 0;
    unsigned char msg[] = "Test pattern";
    unsigned char key[32];
    unsigned char iv[AES_BLOCK_SIZE];
    unsigned char aad[] = "AAD";
    unsigned char enc[sizeof(msg)];
    unsigned char tag[AES_BLOCK_SIZE];
    unsigned char dec[sizeof(msg)];

    (void)data;

    memset(key, 0, keyLen);
    memset(iv, 0, ivLen);

    if (err == 0) {
        PRINT_BUFFER("Key", key, keyLen);
        PRINT_BUFFER("IV", iv, ivLen);
        PRINT_BUFFER("Message", msg, sizeof(msg));
    }

    if (err == 0) {
        PRINT_MSG("Encrypt with OpenSSL");
        err = test_aes_tag_enc(NULL, cipher, key, iv, ivLen, aad, msg,
                               sizeof(msg), enc, tag, ccm, ccmL);
    }
    if (err == 0) {
        PRINT_MSG("Decrypt with wolfengine");
        err = test_aes_tag_dec(e, cipher, key, iv, ivLen, aad, msg, sizeof(msg),
                               enc, tag, dec, ccm, ccmL);
    }

    if (err == 0) {
        PRINT_MSG("Encrypt with wolfengine");
        err = test_aes_tag_enc(e, cipher, key, iv, ivLen, aad, msg, sizeof(msg),
                               enc, tag, ccm, ccmL);
    }
    if (err == 0) {
        PRINT_MSG("Decrypt with OpenSSL");
        err = test_aes_tag_dec(NULL, cipher, key, iv, ivLen, aad, msg,
                               sizeof(msg), enc, tag, dec, ccm, ccmL);
    }

    return err;
}

/* AES-GCM GMAC test, empty plaintext, operation only outputs tag value */
static int test_aes_gcm_gmac(ENGINE* e, void* data, const EVP_CIPHER* cipher,
                             int keyLen, int ivLen)
{
    int err = 0;
    unsigned char key[32];
    unsigned char iv[AES_BLOCK_SIZE];
    unsigned char aad[] = "AAD";
    unsigned char tag[AES_BLOCK_SIZE];

    (void)data;

    memset(key, 0, keyLen);
    memset(iv, 0, ivLen);

    PRINT_BUFFER("Key", key, keyLen);
    PRINT_BUFFER("IV", iv, ivLen);

    if (err == 0) {
        PRINT_MSG("Encrypt with OpenSSL");
        err = test_aes_tag_enc(NULL, cipher, key, iv, ivLen, aad, NULL,
                               0, NULL, tag, 0, 0);
    }
    if (err == 0) {
        PRINT_MSG("Decrypt with wolfengine");
        err = test_aes_tag_dec(e, cipher, key, iv, ivLen, aad, NULL, 0,
                               NULL, tag, NULL, 0, 0);
    }

    if (err == 0) {
        PRINT_MSG("Encrypt with wolfengine");
        err = test_aes_tag_enc(e, cipher, key, iv, ivLen, aad, NULL, 0,
                               NULL, tag, 0, 0);
    }
    if (err == 0) {
        PRINT_MSG("Decrypt with OpenSSL");
        err = test_aes_tag_dec(NULL, cipher, key, iv, ivLen, aad, NULL,
                               0, NULL, tag, NULL, 0, 0);
    }

    return err;
}

/******************************************************************************/

static int test_aes_tag_fixed_enc(ENGINE *e, const EVP_CIPHER *cipher,
    unsigned char *key, unsigned char *iv, int ivFixedLen, int ivLen,
    unsigned char *aad, unsigned char *msg, int len, unsigned char *enc,
    unsigned char *tag)
{
    int err;
    EVP_CIPHER_CTX *ctx;
    int encLen = len;
    unsigned int tagLen = 16;

    err = (ctx = EVP_CIPHER_CTX_new()) == NULL;
    if (err == 0) {
       err = EVP_EncryptInit_ex(ctx, cipher, e, key, NULL) != 1;
    }
    if (err == 0) {
       err = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IV_FIXED, ivFixedLen,
                                 iv) != 1;
    }
    if (err == 0) {
       memcpy(iv, EVP_CIPHER_CTX_iv(ctx), ivLen);
       err = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_IV_GEN, ivLen, iv) != 1;
    }
    if (err == 0) {
        err = EVP_EncryptUpdate(ctx, NULL, &encLen, aad,
                                (int)strlen((char *)aad)) != 1;
    }
    if (err == 0) {
        err = EVP_EncryptUpdate(ctx, enc, &encLen, msg, len) != 1;
    }
    if (err == 0) {
        err = EVP_EncryptFinal_ex(ctx, enc + encLen, &encLen) != 1;
    }
    if (err == 0) {
        err = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, tagLen, tag) != 1;
    }
    if (err == 0) {
    }

    if (err == 0) {
        PRINT_BUFFER("Encrypted", enc, len);
        PRINT_BUFFER("Tag", tag, 16);
    }

    EVP_CIPHER_CTX_free(ctx);

    return err;
}

static int test_aes_tag_fixed(ENGINE *e, void *data, const EVP_CIPHER *cipher,
                              int keyLen, int ivFixedLen, int ivLen)
{
    int err = 0;
    unsigned char msg[] = "Test pattern";
    unsigned char key[32];
    unsigned char iv[12];
    unsigned char aad[] = "AAD";
    unsigned char enc[sizeof(msg)];
    unsigned char tag[AES_BLOCK_SIZE];
    unsigned char dec[sizeof(msg)];

    (void)data;

    if (RAND_bytes(key, keyLen) == 0) {
        err = 1;
    }
    if (err == 0) {
        if (RAND_bytes(iv, sizeof(iv)) == 0) {
            err = 1;
        }
    }

    if (err == 0) {
        PRINT_BUFFER("Key", key, keyLen);
        PRINT_BUFFER("IV", iv, ivLen);
        PRINT_BUFFER("Message", msg, sizeof(msg));
    }

    if (err == 0) {
        PRINT_MSG("Encrypt with OpenSSL");
        err = test_aes_tag_fixed_enc(NULL, cipher, key, iv, ivFixedLen, ivLen,
                                     aad, msg, sizeof(msg), enc, tag);
    }
    if (err == 0) {
        PRINT_MSG("Decrypt with wolfengine");
        err = test_aes_tag_dec(e, cipher, key, iv, ivLen, aad, msg, sizeof(msg),
                               enc, tag, dec, 0, 0);
    }

    if (err == 0) {
        PRINT_MSG("Encrypt with wolfengine");
        err = test_aes_tag_fixed_enc(e, cipher, key, iv, ivFixedLen, ivLen, aad,
                                     msg, sizeof(msg), enc, tag);
    }
    if (err == 0) {
        PRINT_MSG("Decrypt with OpenSSL");
        err = test_aes_tag_dec(NULL, cipher, key, iv, ivLen, aad, msg,
                               sizeof(msg), enc, tag, dec, 0, 0);
    }

    return err;
}

/******************************************************************************/

static int test_aes_tag_tls_enc(ENGINE *e, const EVP_CIPHER *cipher,
                                unsigned char *key, unsigned char *iv,
                                int ivLen, unsigned char *aad,
                                unsigned char *msg, int len, int ccm)
{
    int err;
    EVP_CIPHER_CTX *ctx;
    int tagLen;

    err = (ctx = EVP_CIPHER_CTX_new()) == NULL;
    if (err == 0) {
       err = EVP_EncryptInit_ex(ctx, cipher, e, ccm ? NULL : key, NULL) != 1;
    }
    if ((err == 0) && ccm) {
        err = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, 12, NULL) != 1;
    }
    if ((err == 0) && ccm) {
        err = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, 16, NULL) != 1;
    }
    if (err == 0) {
       err = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IV_FIXED, ivLen,
                                 iv) != 1;
    }
    if ((err == 0) && ccm) {
        err = EVP_EncryptInit_ex(ctx, NULL, e, key, NULL) != 1;
    }
    if (err == 0) {
       tagLen = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_TLS1_AAD,
                                    EVP_AEAD_TLS1_AAD_LEN, aad);
       if (ccm) {
           err = (tagLen != EVP_CCM_TLS_TAG_LEN);
       }
       else {
           err = (tagLen != EVP_GCM_TLS_TAG_LEN);
       }
    }
    if (err == 0) {
        err = EVP_Cipher(ctx, msg, msg, len) != len;
    }

    if (err == 0) {
        int eLen = len - EVP_GCM_TLS_EXPLICIT_IV_LEN - EVP_GCM_TLS_TAG_LEN;
        PRINT_BUFFER("Message Buffer", msg, len);
        PRINT_BUFFER("Explicit IV", msg, EVP_GCM_TLS_EXPLICIT_IV_LEN);
        PRINT_BUFFER("Encrypted", msg + EVP_GCM_TLS_EXPLICIT_IV_LEN, eLen);
        PRINT_BUFFER("Tag", msg + (len - 16), 16);
        (void)eLen;
    }

    EVP_CIPHER_CTX_free(ctx);

    return err;
}

static int test_aes_tag_tls_dec(ENGINE *e, const EVP_CIPHER *cipher,
                                unsigned char *key, unsigned char *iv,
                                int ivLen, unsigned char *aad,
                                unsigned char *msg, int len, int ccm)
{
    int err;
    EVP_CIPHER_CTX *ctx;
    int dLen = len - EVP_GCM_TLS_EXPLICIT_IV_LEN - EVP_GCM_TLS_TAG_LEN;

    err = (ctx = EVP_CIPHER_CTX_new()) == NULL;
    if (err == 0) {
       err = EVP_DecryptInit_ex(ctx, cipher, e, NULL, NULL) != 1;
    }
    if ((err == 0) && ccm) {
        err = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, 12, NULL) != 1;
    }
    if ((err == 0) && ccm) {
        err = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, 16, NULL) != 1;
    }
    if (err == 0) {
       err = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IV_FIXED, ivLen,
                                 iv) != 1;
    }
    if (err == 0) {
        err = EVP_DecryptInit_ex(ctx, NULL, e, key, NULL) != 1;
    }
    if (err == 0) {
       err = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_TLS1_AAD,
                                 EVP_AEAD_TLS1_AAD_LEN,
                                 aad) != EVP_GCM_TLS_TAG_LEN;
    }
    if (err == 0) {
        int decLen;
        decLen = EVP_Cipher(ctx, msg, msg, len);
#if OPENSSL_VERSION_NUMBER < 0x30000000L
        err = decLen != dLen;
#else
        err = decLen != len;
#endif
    }

    if (err == 0) {
        PRINT_BUFFER("Decrypted", msg + EVP_GCM_TLS_EXPLICIT_IV_LEN, dLen);
        (void)dLen;
    }

    EVP_CIPHER_CTX_free(ctx);

    return err;
}

static int test_aes_tag_tls(ENGINE *e, void *data, const EVP_CIPHER *cipher,
                            int keyLen, int ivLen, int ccm)
{
    int err = 0;
    unsigned char aad[EVP_AEAD_TLS1_AAD_LEN] = {0,};
    unsigned char msg[24];
    unsigned char buf[48] = {0,};
    unsigned char key[32];
    unsigned char iv[EVP_GCM_TLS_FIXED_IV_LEN];
    int dataLen = sizeof(msg);

    (void)data;

    aad[8]  = 23; /* Content type */
    aad[9]  = 3;  /* Protocol major version */
    aad[10] = 2;  /* Protocol minor version */

    if (RAND_bytes(key, keyLen) == 0) {
        err = 1;
    }
    if (err == 0) {
        if (RAND_bytes(iv, ivLen) == 0) {
            err = 1;
        }
    }
    if (err == 0) {
        if (RAND_bytes(msg, dataLen) == 0) {
            err = 1;
        }
    }

    if (err == 0) {
        memcpy(buf + EVP_GCM_TLS_EXPLICIT_IV_LEN, msg, dataLen);

        PRINT_BUFFER("Key", key, keyLen);
        PRINT_BUFFER("Implicit IV", iv, sizeof(iv));
        PRINT_BUFFER("Message Buffer", buf, sizeof(buf));
        PRINT_BUFFER("Message", msg, dataLen);

        PRINT_MSG("Encrypt with OpenSSL - TLS");
        aad[12] = sizeof(buf) - EVP_GCM_TLS_TAG_LEN;
        err = test_aes_tag_tls_enc(NULL, cipher, key, iv, ivLen, aad, buf,
                                   sizeof(buf), ccm);
    }
    if (err == 0) {
        PRINT_MSG("Decrypt with wolfengine - TLS");
        aad[12] = sizeof(buf);
        err = test_aes_tag_tls_dec(e, cipher, key, iv, ivLen, aad, buf,
                                   sizeof(buf), ccm);
    }

    if (err == 0) {
        memset(buf, 0, sizeof(buf));
        memcpy(buf + EVP_GCM_TLS_EXPLICIT_IV_LEN, msg, dataLen);

        PRINT_BUFFER("Message Buffer", buf, sizeof(buf));

        aad[12] = sizeof(buf) - EVP_GCM_TLS_TAG_LEN;
        PRINT_MSG("Encrypt with wolfengine - TLS");
        err = test_aes_tag_tls_enc(e, cipher, key, iv, ivLen, aad, buf,
                                   sizeof(buf), ccm);
    }
    if (err == 0) {
        PRINT_MSG("Decrypt with OpenSSL - TLS");
        aad[12] = sizeof(buf);
        err = test_aes_tag_tls_dec(NULL, cipher, key, iv, ivLen, aad, buf,
                                   sizeof(buf), ccm);
    }

    return err;
}

#endif /* WE_HAVE_AESGCM || WE_HAVE_AESCCM */

#ifdef WE_HAVE_AESGCM

int test_aes128_gcm(ENGINE *e, void *data)
{
    int err = 0;

    err = test_aes_tag(e, data, EVP_aes_128_gcm(), 16, 12, 0, 0);

    if (err == 0) {
        err = test_aes_gcm_gmac(e, data, EVP_aes_128_gcm(), 16, 12);
    }

    return err;
}

/******************************************************************************/

int test_aes192_gcm(ENGINE *e, void *data)
{
    int err = 0;

    err = test_aes_tag(e, data, EVP_aes_192_gcm(), 24, 12, 0, 0);

    if (err == 0) {
        err = test_aes_gcm_gmac(e, data, EVP_aes_192_gcm(), 24, 12);
    }

    return err;
}

/******************************************************************************/

int test_aes256_gcm(ENGINE *e, void *data)
{
    int err = 0;

    err = test_aes_tag(e, data, EVP_aes_256_gcm(), 32, 12, 0, 0);

    if (err == 0) {
        err = test_aes_gcm_gmac(e, data, EVP_aes_256_gcm(), 32, 12);
    }

    return err;
}

/******************************************************************************/

int test_aes128_gcm_fixed(ENGINE *e, void *data)
{
    return test_aes_tag_fixed(e, data, EVP_aes_128_gcm(), 16,
                              EVP_GCM_TLS_FIXED_IV_LEN, 12);
}

/******************************************************************************/

int test_aes128_gcm_tls(ENGINE *e, void *data)
{
    return test_aes_tag_tls(e, data, EVP_aes_128_gcm(), 16,
                            EVP_GCM_TLS_FIXED_IV_LEN, 0);
}

/* 
 * OpenSSL doesn't recommend using EVP_Cipher(), but there are applications
 * using it, so we need to support it. With wolfCrypt, AES-GCM decryption cannot
 * be decoupled from checking the authentication tag, so we only expect the
 * decryption to succeed when the caller has set the tag properly. It is not
 * possible to decrypt ciphertext without checking the tag.
 */
int test_aes_gcm_evp_cipher(ENGINE *e, void *data)
{
    int err = 0;
    EVP_CIPHER_CTX* ctx = NULL;
    unsigned char key[AES_128_KEY_SIZE] = {0};
    unsigned char iv[AES_BLOCK_SIZE] = {0};
    unsigned char aad[3] = {0x01, 0x02, 0x03};
    unsigned char plainText[5] = {0x04, 0x05, 0x06, 0x07, 0x08};
    unsigned char cipherText[sizeof(plainText)];
    unsigned char decryptedText[sizeof(plainText)];
    unsigned char tag[EVP_GCM_TLS_TAG_LEN];

    (void)data;

    /* Encrypt with OpenSSL. */
    err = (ctx = EVP_CIPHER_CTX_new()) == NULL;
    if (err == 0) {
        err = EVP_CipherInit_ex(ctx, EVP_aes_128_gcm(), NULL, key, iv, 1) != 1;
    }
    if (err == 0) {
        /* AAD */
        err = EVP_Cipher(ctx, NULL, aad, sizeof(aad)) <= 0;
    }
    if (err == 0) {
        err = EVP_Cipher(ctx, cipherText, plainText, sizeof(plainText)) <= 0;
    }
    if (err == 0) {
        /* Compute tag. */
        err = EVP_Cipher(ctx, NULL, NULL, 0) < 0;
    }
    if (err == 0) {
        err = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG,
                                  EVP_GCM_TLS_TAG_LEN, tag) != 1;
    }
    if (ctx != NULL) {
        EVP_CIPHER_CTX_free(ctx);
    }

    /* Decrypt with wolfEngine. */
    if (err == 0) {
        err = (ctx = EVP_CIPHER_CTX_new()) == NULL;
    }
    if (err == 0) {
        err = EVP_CipherInit_ex(ctx, EVP_aes_128_gcm(), e, key, iv, 0) != 1;
    }
    if (err == 0) {
        /* AAD */
        err = EVP_Cipher(ctx, NULL, aad, sizeof(aad)) <= 0;
    }
    if (err == 0) {
        err = EVP_Cipher(ctx, decryptedText, cipherText,
                         sizeof(cipherText)) <= 0;
    }
    if (err == 0) {
        /* Decrypt without tag set, should fail. */
        err = EVP_Cipher(ctx, NULL, NULL, 0) >= 0;
    }

    /* Try the same sequence again, but set the tag before the final
     * EVP_Cipher() call. */
    if (err == 0) {
        err = EVP_Cipher(ctx, NULL, aad, sizeof(aad)) <= 0;
    }
    if (err == 0) {
        err = EVP_Cipher(ctx, decryptedText, cipherText,
                         sizeof(cipherText)) <= 0;
    }
    if (err == 0) {
        err = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG,
                                  EVP_GCM_TLS_TAG_LEN, tag) != 1;
    }
    if (err == 0) {
        /* Decrypt with tag set, should succeed. */
        err = EVP_Cipher(ctx, NULL, NULL, 0) < 0;
    }
    if (ctx != NULL) {
        EVP_CIPHER_CTX_free(ctx);
    }

    return err;
}

#endif /* WE_HAVE_AESGCM */

/******************************************************************************/

#ifdef WE_HAVE_AESCCM

int test_aes128_ccm(ENGINE *e, void *data)
{
    int err = 0;

    /* test with default length field (L) */
    err = test_aes_tag(e, data, EVP_aes_128_ccm(), 16, 13, 1, 0);

#if OPENSSL_VERSION_NUMBER < 0x30000000L
    /* test with modified length field (L) of 7 */
    if (err == 0) {
        err = test_aes_tag(e, data, EVP_aes_128_ccm(), 16, 13, 1, 7);
    }
#endif

    return err;
}

/******************************************************************************/

int test_aes192_ccm(ENGINE *e, void *data)
{
    int err = 0;

    /* test with default length field (L) */
    err = test_aes_tag(e, data, EVP_aes_192_ccm(), 24, 13, 1, 0);

#if OPENSSL_VERSION_NUMBER < 0x30000000L
    /* test with modified length field (L) of 7 */
    if (err == 0) {
        err = test_aes_tag(e, data, EVP_aes_192_ccm(), 24, 13, 1, 7);
    }
#endif

    return err;
}

/******************************************************************************/

int test_aes256_ccm(ENGINE *e, void *data)
{
    int err = 0;

    /* test with default length field (L) */
    err = test_aes_tag(e, data, EVP_aes_256_ccm(), 32, 13, 1, 0);

#if OPENSSL_VERSION_NUMBER < 0x30000000L
    /* test with modified length field (L) of 7 */
    if (err == 0) {
        err = test_aes_tag(e, data, EVP_aes_256_ccm(), 32, 13, 1, 7);
    }
#endif

    return err;
}

/******************************************************************************/

#if OPENSSL_VERSION_NUMBER >= 0x10100000L
/* Older versions don't support TLS ops with CCM. */
int test_aes128_ccm_tls(ENGINE *e, void *data)
{
    return test_aes_tag_tls(e, data, EVP_aes_128_ccm(), 16,
                            EVP_CCM_TLS_FIXED_IV_LEN, 1);
}
#endif

#endif /* WE_HAVE_AESCCM */

