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

#if defined(WE_HAVE_DES3CBC) || defined(WE_HAVE_AESCBC)

static int test_cipher_enc(ENGINE *e, const EVP_CIPHER *cipher,
                           unsigned char *key, unsigned char *iv,
                           unsigned char *msg, int len, unsigned char *enc,
                           int pad)
{
    int err;
    EVP_CIPHER_CTX *ctx;
    int encLen;
    int fLen = 0;

    err = (ctx = EVP_CIPHER_CTX_new()) == NULL;
    if (err == 0) {
       err = EVP_EncryptInit_ex(ctx, cipher, e, key, iv) != 1;
    }
    if (err == 0) {
        err = EVP_CIPHER_CTX_set_padding(ctx, pad) != 1;
    }
    if (err == 0) {
        err = EVP_EncryptUpdate(ctx, enc, &encLen, msg, len) != 1;
    }
    if (err == 0) {
        err = EVP_EncryptFinal_ex(ctx, enc + encLen, &fLen) != 1;
    }

    if (err == 0) {
        PRINT_BUFFER("Encrypted", enc, encLen + fLen);
    }

    EVP_CIPHER_CTX_free(ctx);

    return err;
}

static int test_cipher_dec(ENGINE *e, const EVP_CIPHER *cipher,
                           unsigned char *key, unsigned char *iv,
                           unsigned char *msg, int len, unsigned char *enc,
                           int encLen, unsigned char *dec, int pad)
{
    int err;
    EVP_CIPHER_CTX *ctx;
    int decLen;
    int fLen;

    err = (ctx = EVP_CIPHER_CTX_new()) == NULL;
    if (err == 0) {
        err = EVP_DecryptInit_ex(ctx, cipher, e, key, iv) != 1;
    }
    if (err == 0) {
        err = EVP_CIPHER_CTX_set_padding(ctx, pad) != 1;
    }
    if (err == 0) {
        err = EVP_DecryptUpdate(ctx, dec, &decLen, enc, encLen) != 1;
    }
    if (err == 0) {
        err = EVP_DecryptFinal_ex(ctx, dec + decLen, &fLen) != 1;
    }

    if (err == 0) {
        PRINT_BUFFER("Decrypted", dec, decLen + fLen);

        if (decLen + fLen != (int)len || memcmp(dec, msg, len) != 0) {
            err = 1;
        }
    }

    EVP_CIPHER_CTX_free(ctx);

    return err;
}

static int test_cipher_enc_dec(ENGINE *e, void *data, const EVP_CIPHER *cipher,
                               int keyLen, int ivLen)
{
    int err = 0;
    unsigned char msg[16] = "Test pattern";
    unsigned char key[32];
    unsigned char iv[16];
    unsigned char enc[sizeof(msg) + 16];
    unsigned char dec[sizeof(msg) + 16];

    (void)data;

    if (RAND_bytes(key, keyLen) != 1) {
        err = 1;
    }
    if (err == 0) {
        if (RAND_bytes(iv, ivLen) != 1) {
            err = 1;
        }
    }

    if (err == 0) {
        PRINT_BUFFER("Key", key, keyLen);
        PRINT_BUFFER("IV", iv, ivLen);
        PRINT_BUFFER("Message", msg, sizeof(msg));
    }

    if (err == 0) {
        PRINT_MSG("Encrypt with OpenSSL - padding");
        err = test_cipher_enc(NULL, cipher, key, iv, msg, sizeof(msg), enc, 1);
    }
    if (err == 0) {
        PRINT_MSG("Decrypt with wolfengine - padding");
        err = test_cipher_dec(e, cipher, key, iv, msg, sizeof(msg), enc,
                              sizeof(msg) + ivLen, dec, 1);
    }

    if (err == 0) {
        PRINT_MSG("Encrypt with wolfengine - padding");
        err = test_cipher_enc(e, cipher, key, iv, msg, sizeof(msg), enc, 1);
    }
    if (err == 0) {
        PRINT_MSG("Decrypt with OpenSSL - padding");
        err = test_cipher_dec(NULL, cipher, key, iv, msg, sizeof(msg), enc,
                              sizeof(msg) + ivLen, dec, 1);
    }

    if (err == 0) {
        PRINT_MSG("Encrypt with OpenSSL - no pad");
        err = test_cipher_enc(NULL, cipher, key, iv, msg, sizeof(msg), enc, 0);
    }
    if (err == 0) {
        PRINT_MSG("Decrypt with wolfengine - no pad");
        err = test_cipher_dec(e, cipher, key, iv, msg, sizeof(msg), enc,
                              sizeof(msg), dec, 0);
    }

    if (err == 0) {
        PRINT_MSG("Encrypt with wolfengine - no pad");
        err = test_cipher_enc(e, cipher, key, iv, msg, sizeof(msg), enc, 0);
    }
    if (err == 0) {
        PRINT_MSG("Decrypt with OpenSSL - no pad");
        err = test_cipher_dec(NULL, cipher, key, iv, msg, sizeof(msg), enc,
                              sizeof(msg), dec, 0);
    }

    return err;
}


/******************************************************************************/

static int test_stream_enc(ENGINE *e, const EVP_CIPHER *cipher,
                           unsigned char *key, unsigned char *iv,
                           unsigned char *msg, int len, unsigned char *enc,
                           unsigned char *encExp, int expLen)
{
    int err;
    EVP_CIPHER_CTX *ctx;
    int eLen = 0;
    int encLen;
    int i;
    int j;

    err = (ctx = EVP_CIPHER_CTX_new()) == NULL;
    for (i = 1; (err == 0) && (i <= (int)len); i++) {
        eLen = 0;
        err = EVP_EncryptInit_ex(ctx, cipher, e, key, iv) != 1;

        for (j = 0; (err == 0) && (j < (int)len); j += i) {
            int l = len - j;
            if (i < l)
                l = i;
            err = EVP_EncryptUpdate(ctx, enc + eLen, &encLen, msg + j, l) != 1;
            if (err == 0) {
                eLen += encLen;
            }
        }

        if (err == 0) {
            err = EVP_EncryptFinal_ex(ctx, enc + eLen, &encLen) != 1;
            if (err == 0) {
                eLen += encLen;
            }
        }
        if (err == 0 && (eLen != expLen || memcmp(enc, encExp, expLen) != 0)) {
            err = 1;
        }
    }
    if (err == 0) {
        PRINT_BUFFER("Encrypted", enc, eLen);
    }

    EVP_CIPHER_CTX_free(ctx);

    return err;
}

static int test_stream_dec(ENGINE *e, const EVP_CIPHER *cipher,
                           unsigned char *key, unsigned char *iv,
                           unsigned char *msg, int len, unsigned char *enc,
                           int encLen, unsigned char *dec)
{
    int err;
    EVP_CIPHER_CTX *ctx;
    int dLen;
    int decLen;
    int i;
    int j;

    err = (ctx = EVP_CIPHER_CTX_new()) == NULL;
    for (i = 1; (err == 0) && (i < (int)encLen - 1); i++) {
        dLen = 0;
        err = EVP_DecryptInit_ex(ctx, cipher, e, key, iv) != 1;

        for (j = 0; (err == 0) && (j < (int)encLen); j += i) {
            int l = encLen - j;
            if (i < l)
                l = i;
            err = EVP_DecryptUpdate(ctx, dec + dLen, &decLen, enc + j, l) != 1;
            if (err == 0) {
                dLen += decLen;
            }
        }

        if (err == 0) {
            err = EVP_DecryptFinal_ex(ctx, dec + dLen, &decLen) != 1;
            if (err == 0) {
                dLen += decLen;
            }
        }
        if ((err == 0) && ((dLen != len) || (memcmp(dec, msg, len) != 0))) {
            PRINT_BUFFER("Decrypted", dec, dLen);
            err = 1;
        }
    }
    if (err == 0) {
        PRINT_BUFFER("Decrypted", dec, len);
    }

    EVP_CIPHER_CTX_free(ctx);

    return err;
}

static int test_stream_enc_dec(ENGINE *e, void *data, const EVP_CIPHER *cipher,
                               int keyLen, int ivLen, int msgLen, int pad)
{
    int err = 0;
    unsigned char msg[16] = "Test pattern";
    unsigned char key[32];
    unsigned char iv[16];
    unsigned char enc[sizeof(msg) + 16];
    unsigned char encExp[sizeof(msg) + 16];
    unsigned char dec[sizeof(msg) + 16];
    int encLen;

    if (pad) {
        encLen = (msgLen + ivLen) & (~(ivLen-1));
    }
    else {
        encLen = msgLen;
    }

    (void)data;

    if (RAND_bytes(key, keyLen) != 1) {
        printf("generate key failed\n");
        err = 1;
    }
    if (err == 0) {
        if (RAND_bytes(iv, ivLen) != 1) {
            printf("generate iv failed\n");
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
        err = test_cipher_enc(NULL, cipher, key, iv, msg, msgLen, encExp, 1);
    }

    if (err == 0) {
        PRINT_MSG("Encrypt Stream with wolfengine");
        err = test_stream_enc(e, cipher, key, iv, msg, msgLen, enc, encExp,
                              encLen);
    }
    if (err == 0) {
        PRINT_MSG("Decrypt Stream with wolfengine");
        err = test_stream_dec(e, cipher, key, iv, msg, msgLen, enc, encLen,
                              dec);
    }

    return err;
}

#endif /* WE_HAVE_DES3CBC || WE_HAVE_AESCBC */

/******************************************************************************/

#ifdef WE_HAVE_DES3CBC


int test_des3_cbc(ENGINE *e, void *data)
{
    return test_cipher_enc_dec(e, data, EVP_des_ede3_cbc(), 24, 8);
}

/******************************************************************************/

int test_des3_cbc_stream(ENGINE *e, void *data)
{
    int err;

    err = test_stream_enc_dec(e, data, EVP_des_ede3_cbc(), 24, 8, 16, 1);
    if (err == 0)
        err = test_stream_enc_dec(e, data, EVP_des_ede3_cbc(), 24, 8, 1, 1);
    if (err == 0)
        err = test_stream_enc_dec(e, data, EVP_des_ede3_cbc(), 24, 8, 7, 1);

    return err;
}

#endif /* WE_HAVE_DES3CBC */

/******************************************************************************/

#ifdef WE_HAVE_AESECB

int test_aes128_ecb(ENGINE *e, void *data)
{
    return test_cipher_enc_dec(e, data, EVP_aes_128_ecb(), 16, 16);
}

/******************************************************************************/

int test_aes192_ecb(ENGINE *e, void *data)
{
    return test_cipher_enc_dec(e, data, EVP_aes_192_ecb(), 24, 16);
}

/******************************************************************************/

int test_aes256_ecb(ENGINE *e, void *data)
{
    return test_cipher_enc_dec(e, data, EVP_aes_256_ecb(), 32, 16);
}

/******************************************************************************/

int test_aes128_ecb_stream(ENGINE *e, void *data)
{
    int err;

    err = test_stream_enc_dec(e, data, EVP_aes_128_ecb(), 16, 16, 16, 1);
    if (err == 0)
        err = test_stream_enc_dec(e, data, EVP_aes_128_ecb(), 16, 16, 1, 1);

    return err;
}

/******************************************************************************/

int test_aes192_ecb_stream(ENGINE *e, void *data)
{
    int err;

    err = test_stream_enc_dec(e, data, EVP_aes_192_ecb(), 24, 16, 15, 1);
    if (err == 0)
        err = test_stream_enc_dec(e, data, EVP_aes_128_ecb(), 16, 16, 2, 1);

    return err;
}

/******************************************************************************/

int test_aes256_ecb_stream(ENGINE *e, void *data)
{
    int err;

    err = test_stream_enc_dec(e, data, EVP_aes_256_ecb(), 32, 16, 14, 1);
    if (err == 0)
        err = test_stream_enc_dec(e, data, EVP_aes_256_ecb(), 32, 16, 3, 1);

    return err;
}

#endif /* WE_HAVE_AESECB */

/******************************************************************************/

#ifdef WE_HAVE_AESCBC

int test_aes128_cbc(ENGINE *e, void *data)
{
    return test_cipher_enc_dec(e, data, EVP_aes_128_cbc(), 16, 16);
}

/******************************************************************************/

int test_aes192_cbc(ENGINE *e, void *data)
{
    return test_cipher_enc_dec(e, data, EVP_aes_192_cbc(), 24, 16);
}

/******************************************************************************/

int test_aes256_cbc(ENGINE *e, void *data)
{
    return test_cipher_enc_dec(e, data, EVP_aes_256_cbc(), 32, 16);
}

/******************************************************************************/

int test_aes128_cbc_stream(ENGINE *e, void *data)
{
    int err;

    err = test_stream_enc_dec(e, data, EVP_aes_128_cbc(), 16, 16, 16, 1);
    if (err == 0)
        err = test_stream_enc_dec(e, data, EVP_aes_128_cbc(), 16, 16, 1, 1);

    return err;
}

/******************************************************************************/

int test_aes192_cbc_stream(ENGINE *e, void *data)
{
    int err;

    err = test_stream_enc_dec(e, data, EVP_aes_192_cbc(), 24, 16, 15, 1);
    if (err == 0)
        err = test_stream_enc_dec(e, data, EVP_aes_128_cbc(), 16, 16, 2, 1);

    return err;
}

/******************************************************************************/

int test_aes256_cbc_stream(ENGINE *e, void *data)
{
    int err;

    err = test_stream_enc_dec(e, data, EVP_aes_256_cbc(), 32, 16, 14, 1);
    if (err == 0)
        err = test_stream_enc_dec(e, data, EVP_aes_256_cbc(), 32, 16, 3, 1);

    return err;
}

#endif /* WE_HAVE_AESCBC */

/******************************************************************************/

#ifdef WE_HAVE_AESCTR

int test_aes128_ctr_stream(ENGINE *e, void *data)
{
    int err;

    err = test_stream_enc_dec(e, data, EVP_aes_128_ctr(), 16, 16, 16, 0);
    if (err == 0)
        err = test_stream_enc_dec(e, data, EVP_aes_128_ctr(), 16, 16, 1, 0);

    return err;
}

/******************************************************************************/

int test_aes192_ctr_stream(ENGINE *e, void *data)
{
    int err;

    err = test_stream_enc_dec(e, data, EVP_aes_192_ctr(), 24, 16, 15, 0);
    if (err == 0)
        err = test_stream_enc_dec(e, data, EVP_aes_128_ctr(), 16, 16, 2, 0);

    return err;
}

/******************************************************************************/

int test_aes256_ctr_stream(ENGINE *e, void *data)
{
    int err;

    err = test_stream_enc_dec(e, data, EVP_aes_256_ctr(), 32, 16, 14, 0);
    if (err == 0)
        err = test_stream_enc_dec(e, data, EVP_aes_256_ctr(), 32, 16, 3, 0);

    return err;
}

#endif /* WE_HAVE_AESCTR */

