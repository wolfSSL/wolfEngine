/* test_cipher.c
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

#include "unit.h"

#ifdef WE_HAVE_AESGCM

int test_aes_gcm_enc(ENGINE *e, const EVP_CIPHER *cipher,
                     unsigned char *key, unsigned char *iv,
                     unsigned char *aad, unsigned char *msg, size_t len,
                     unsigned char *enc, unsigned char *tag)
{
    int err;
    EVP_CIPHER_CTX *ctx;
    int encLen = len;
    unsigned int tagLen = 16;

    err = (ctx = EVP_CIPHER_CTX_new()) == NULL;
    if (err == 0) {
       err = EVP_EncryptInit_ex(ctx, cipher, e, key, iv) != 1;
    }
    if (err == 0) {
        err = EVP_EncryptUpdate(ctx, NULL, &encLen, aad, 1) != 1;
    }
    if (err == 0) {
        err = EVP_EncryptUpdate(ctx, NULL, &encLen, aad + 1,
                                strlen((char *)aad) - 1) != 1;
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
        PRINT_BUFFER("Encrypted", enc, len);
        PRINT_BUFFER("Tag", tag, 16);
    }

    EVP_CIPHER_CTX_free(ctx);

    return err;
}

int test_aes_gcm_dec(ENGINE *e, const EVP_CIPHER *cipher,
                     unsigned char *key, unsigned char *iv,
                     unsigned char *aad, unsigned char *msg, size_t len,
                     unsigned char *enc, unsigned char *tag,
                     unsigned char *dec)
{
    int err;
    EVP_CIPHER_CTX *ctx;
    int decLen = len;
    unsigned int tagLen = 16;

    err = (ctx = EVP_CIPHER_CTX_new()) == NULL;
    if (err == 0) {
        err = EVP_DecryptInit_ex(ctx, cipher, e, key, iv) != 1;
    }
    if (err == 0) {
        err = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, tagLen, tag) != 1;
    }
    if (err == 0) {
        err = EVP_DecryptUpdate(ctx, NULL, &decLen, aad,
                                strlen((char *)aad)) != 1;
    }
    if (err == 0) {
        err = EVP_DecryptUpdate(ctx, dec, &decLen, enc, len) != 1;
    }
    if (err == 0) {
        err = EVP_DecryptFinal_ex(ctx, dec + decLen, &decLen) != 1;
    }

    if (err == 0) {
        PRINT_BUFFER("Decrypted", dec, len);

        if (memcmp(dec, msg, len) != 0) {
            err = 1;
        }
    }

    EVP_CIPHER_CTX_free(ctx);

    return err;
}

int test_aes128_gcm(ENGINE *e, void *data)
{
    int err = 0;
    const EVP_CIPHER *cipher = EVP_aes_128_gcm();
    unsigned char msg[] = "Test pattern";
    unsigned char key[16];
    unsigned char iv[12];
    unsigned char aad[] = "AAD";
    unsigned char enc[sizeof(msg)];
    unsigned char tag[AES_BLOCK_SIZE];
    unsigned char dec[sizeof(msg)];

    (void)data;

    if (RAND_bytes(key, sizeof(key)) == 0) {
        err = 1;
    }
    if (err == 0) {
        if (RAND_bytes(iv, sizeof(iv)) == 0) {
            err = 0;
        }
    }

    if (err == 0) {
        PRINT_BUFFER("Key", key, sizeof(key));
        PRINT_BUFFER("IV", iv, sizeof(iv));
        PRINT_BUFFER("Message", msg, sizeof(msg));
    }

    if (err == 0) {
        PRINT_MSG("Encrypt with OpenSSL");
        err = test_aes_gcm_enc(NULL, cipher, key, iv, aad, msg, sizeof(msg),
                               enc, tag);
    }
    if (err == 0) {
        PRINT_MSG("Decrypt with wolfengine");
        err = test_aes_gcm_dec(e, cipher, key, iv, aad, msg, sizeof(msg), enc,
                               tag, dec);
    }

    if (err == 0) {
        PRINT_MSG("Encrypt with wolfengine");
        err = test_aes_gcm_enc(e, cipher, key, iv, aad, msg, sizeof(msg), enc,
                               tag);
    }
    if (err == 0) {
        PRINT_MSG("Decrypt with OpenSSL");
        err = test_aes_gcm_dec(NULL, cipher, key, iv, aad, msg, sizeof(msg),
                               enc, tag, dec);
    }

    return err;
}

/******************************************************************************/

int test_aes256_gcm(ENGINE *e, void *data)
{
    int err = 0;
    const EVP_CIPHER *cipher = EVP_aes_256_gcm();
    unsigned char msg[] = "Test pattern";
    unsigned char key[32];
    unsigned char iv[12];
    unsigned char aad[] = "AAD";
    unsigned char enc[sizeof(msg)];
    unsigned char tag[AES_BLOCK_SIZE];
    unsigned char dec[sizeof(msg)];

    (void)data;

    if (RAND_bytes(key, sizeof(key)) == 0) {
        err = 1;
    }
    if (err == 0) {
        if (RAND_bytes(iv, sizeof(iv)) == 0) {
            err = 0;
        }
    }

    if (err == 0) {
        PRINT_BUFFER("Key", key, sizeof(key));
        PRINT_BUFFER("IV", iv, sizeof(iv));
        PRINT_BUFFER("Message", msg, sizeof(msg));
    }

    if (err == 0) {
        PRINT_MSG("Encrypt with OpenSSL");
        err = test_aes_gcm_enc(NULL, cipher, key, iv, aad, msg, sizeof(msg),
                               enc, tag);
    }
    if (err == 0) {
        PRINT_MSG("Decrypt with wolfengine");
        err = test_aes_gcm_dec(e, cipher, key, iv, aad, msg, sizeof(msg), enc,
                               tag, dec);
    }

    if (err == 0) {
        PRINT_MSG("Encrypt with wolfengine");
        err = test_aes_gcm_enc(e, cipher, key, iv, aad, msg, sizeof(msg), enc,
                               tag);
    }
    if (err == 0) {
        PRINT_MSG("Decrypt with OpenSSL");
        err = test_aes_gcm_dec(NULL, cipher, key, iv, aad, msg, sizeof(msg),
                               enc, tag, dec);
    }

    return err;
}

/******************************************************************************/

int test_aes128_gcm_fixed_enc(ENGINE *e, const EVP_CIPHER *cipher,
                              unsigned char *key, unsigned char *iv,
                              unsigned char *aad, unsigned char *msg,
                              size_t len, unsigned char *enc,
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
       err = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IV_FIXED,
                                 EVP_GCM_TLS_FIXED_IV_LEN, iv) != 1;
    }
    if (err == 0) {
       memcpy(iv, EVP_CIPHER_CTX_iv(ctx), 12);
       err = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_IV_GEN, 12, iv) != 1;
    }
    if (err == 0) {
        err = EVP_EncryptUpdate(ctx, NULL, &encLen, aad, 1) != 1;
    }
    if (err == 0) {
        err = EVP_EncryptUpdate(ctx, NULL, &encLen, aad + 1,
                                strlen((char *)aad) - 1) != 1;
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

int test_aes128_gcm_fixed_dec(ENGINE *e, const EVP_CIPHER *cipher,
                              unsigned char *key, unsigned char *iv,
                              unsigned char *aad, unsigned char *msg,
                              size_t len, unsigned char *enc,
                              unsigned char *tag, unsigned char *dec)
{
    int err;
    EVP_CIPHER_CTX *ctx;
    int decLen = len;
    unsigned int tagLen = 16;

    err = (ctx = EVP_CIPHER_CTX_new()) == NULL;
    if (err == 0) {
        err = EVP_DecryptInit_ex(ctx, cipher, e, key, iv) != 1;
    }
    if (err == 0) {
        err = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, tagLen, tag) != 1;
    }
    if (err == 0) {
        err = EVP_DecryptUpdate(ctx, NULL, &decLen, aad,
                                strlen((char *)aad)) != 1;
    }
    if (err == 0) {
        err = EVP_DecryptUpdate(ctx, dec, &decLen, enc, len) != 1;
    }
    if (err == 0) {
        err = EVP_DecryptFinal_ex(ctx, dec + decLen, &decLen) != 1;
    }

    if (err == 0) {
        PRINT_BUFFER("Decrypted", dec, len);

        if (memcmp(dec, msg, len) != 0) {
            err = 1;
        }
    }

    EVP_CIPHER_CTX_free(ctx);

    return err;
}

int test_aes128_gcm_fixed(ENGINE *e, void *data)
{
    int err = 0;
    const EVP_CIPHER *cipher = EVP_aes_128_gcm();
    unsigned char msg[] = "Test pattern";
    unsigned char key[16];
    unsigned char iv[12];
    unsigned char aad[] = "AAD";
    unsigned char enc[sizeof(msg)];
    unsigned char tag[AES_BLOCK_SIZE];
    unsigned char dec[sizeof(msg)];

    (void)data;

    if (RAND_bytes(key, sizeof(key)) == 0) {
        err = 1;
    }
    if (err == 0) {
        if (RAND_bytes(iv, sizeof(iv)) == 0) {
            err = 0;
        }
    }

    if (err == 0) {
        PRINT_BUFFER("Key", key, sizeof(key));
        PRINT_BUFFER("IV", iv, sizeof(iv));
        PRINT_BUFFER("Message", msg, sizeof(msg));
    }

    if (err == 0) {
        PRINT_MSG("Encrypt with OpenSSL");
        err = test_aes128_gcm_fixed_enc(NULL, cipher, key, iv, aad, msg,
                                        sizeof(msg), enc, tag);
    }
    if (err == 0) {
        PRINT_MSG("Decrypt with wolfengine");
        err = test_aes128_gcm_fixed_dec(e, cipher, key, iv, aad, msg,
                                        sizeof(msg), enc, tag, dec);
    }

    if (err == 0) {
        PRINT_MSG("Encrypt with wolfengine");
        err = test_aes128_gcm_fixed_enc(e, cipher, key, iv, aad, msg,
                                        sizeof(msg), enc, tag);
    }
    if (err == 0) {
        PRINT_MSG("Decrypt with OpenSSL");
        err = test_aes128_gcm_fixed_dec(NULL, cipher, key, iv, aad, msg,
                                        sizeof(msg), enc, tag, dec);
    }

    return err;
}

/******************************************************************************/

int test_aes128_gcm_tls_enc(ENGINE *e, const EVP_CIPHER *cipher,
                            unsigned char *key, unsigned char *iv,
                            unsigned char *aad, unsigned char *msg,
                            size_t len)
{
    int err;
    EVP_CIPHER_CTX *ctx;

    err = (ctx = EVP_CIPHER_CTX_new()) == NULL;
    if (err == 0) {
       err = EVP_EncryptInit_ex(ctx, cipher, e, key, NULL) != 1;
    }
    if (err == 0) {
       err = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IV_FIXED,
                                 EVP_GCM_TLS_FIXED_IV_LEN, iv) != 1;
    }
    if (err == 0) {
       err = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_TLS1_AAD,
                                 EVP_AEAD_TLS1_AAD_LEN,
                                 aad) != EVP_GCM_TLS_TAG_LEN;
    }
    if (err == 0) {
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
        err = EVP_Cipher(ctx, msg, msg, len) != 1;
#else
        err = EVP_Cipher(ctx, msg, msg, len) != (int)len;
#endif
    }

    if (err == 0) {
        size_t encLen = len - EVP_GCM_TLS_EXPLICIT_IV_LEN - EVP_GCM_TLS_TAG_LEN;
        PRINT_BUFFER("Message Buffer", msg, len);
        PRINT_BUFFER("Explicit IV", msg, EVP_GCM_TLS_EXPLICIT_IV_LEN);
        PRINT_BUFFER("Encrypted", msg + EVP_GCM_TLS_EXPLICIT_IV_LEN, encLen);
        PRINT_BUFFER("Tag", msg + (len - 16), 16);
        (void)encLen;
    }

    EVP_CIPHER_CTX_free(ctx);

    return err;
}

int test_aes128_gcm_tls_dec(ENGINE *e, const EVP_CIPHER *cipher,
                            unsigned char *key, unsigned char *iv,
                            unsigned char *aad, unsigned char *msg,
                            size_t len)
{
    int err;
    EVP_CIPHER_CTX *ctx;
#if OPENSSL_VERSION_NUMBER < 0x30000000L
    size_t decLen = len - EVP_GCM_TLS_EXPLICIT_IV_LEN - EVP_GCM_TLS_TAG_LEN;
#endif

    err = (ctx = EVP_CIPHER_CTX_new()) == NULL;
    if (err == 0) {
       err = EVP_DecryptInit_ex(ctx, cipher, e, key, NULL) != 1;
    }
    if (err == 0) {
       err = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IV_FIXED,
                                 EVP_GCM_TLS_FIXED_IV_LEN, iv) != 1;
    }
    if (err == 0) {
       err = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_TLS1_AAD,
                                 EVP_AEAD_TLS1_AAD_LEN,
                                 aad) != EVP_GCM_TLS_TAG_LEN;
    }
    if (err == 0) {
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
        err = EVP_Cipher(ctx, msg, msg, len) != 1;
#else
        err = EVP_Cipher(ctx, msg, msg, len) != (int)decLen;
#endif
    }

    if (err == 0) {
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
        PRINT_BUFFER("Decrypted", msg + EVP_GCM_TLS_EXPLICIT_IV_LEN, len);
#else
        PRINT_BUFFER("Decrypted", msg + EVP_GCM_TLS_EXPLICIT_IV_LEN, decLen);
#endif
    }

    EVP_CIPHER_CTX_free(ctx);

    return err;
}

int test_aes128_gcm_tls(ENGINE *e, void *data)
{
    int err = 0;
    const EVP_CIPHER *cipher = EVP_aes_128_gcm();
    unsigned char aad[EVP_AEAD_TLS1_AAD_LEN] = {0,};
    unsigned char msg[24];
    unsigned char buf[48] = {0,};
    unsigned char key[16];
    unsigned char iv[EVP_GCM_TLS_FIXED_IV_LEN];
    size_t dataLen = sizeof(msg);

    (void)data;

    aad[8]  = 23; /* Content type */
    aad[9]  = 3;  /* Protocol major version */
    aad[10] = 2;  /* Protocol minor version */

    if (RAND_bytes(key, sizeof(key)) == 0) {
        err = 1;
    }
    if (err == 0) {
        if (RAND_bytes(iv, sizeof(iv)) == 0) {
            err = 0;
        }
    }
    if (err == 0) {
        if (RAND_bytes(msg, dataLen) == 0) {
            err = 0;
        }
    }

    if (err == 0) {
        memcpy(buf + EVP_GCM_TLS_EXPLICIT_IV_LEN, msg, dataLen);

        PRINT_BUFFER("Key", key, sizeof(key));
        PRINT_BUFFER("Implicit IV", iv, sizeof(iv));
        PRINT_BUFFER("Message Buffer", buf, sizeof(buf));
        PRINT_BUFFER("Message", msg, dataLen);
    }

    if (err == 0) {
        PRINT_MSG("Encrypt with OpenSSL - TLS");
        aad[12] = sizeof(buf) - EVP_GCM_TLS_TAG_LEN;
        err = test_aes128_gcm_tls_enc(NULL, cipher, key, iv, aad, buf,
                                      sizeof(buf));
    }
    if (err == 0) {
        PRINT_MSG("Decrypt with wolfengine - TLS");
        aad[12] = sizeof(buf);
        err = test_aes128_gcm_tls_dec(e, cipher, key, iv, aad, buf,
                                      sizeof(buf));
    }

    if (err == 0) {
        memset(buf, 0, sizeof(buf));
        memcpy(buf + EVP_GCM_TLS_EXPLICIT_IV_LEN, msg, dataLen);
    }
    if (err == 0) {
        PRINT_BUFFER("Message Buffer", buf, sizeof(buf));

        aad[12] = sizeof(buf) - EVP_GCM_TLS_TAG_LEN;
        PRINT_MSG("Encrypt with wolfengine - TLS");
        err = test_aes128_gcm_tls_enc(e, cipher, key, iv, aad, buf,
                                      sizeof(buf));
    }
    if (err == 0) {
        PRINT_MSG("Decrypt with OpenSSL - TLS");
        aad[12] = sizeof(buf);
        err = test_aes128_gcm_tls_dec(NULL, cipher, key, iv, aad, buf,
                                      sizeof(buf));
    }

    return err;
}

#endif /* WE_HAVE_AESGCM */
