/* test_cipher.c
 *
 * Copyright (C) 2019-2023 wolfSSL Inc.
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

/*
 * This test exercises a bug in some versions of wolfSSL where partial block
 * data (i.e. data that didn't align to the AES block size of 16 bytes) from a
 * previous AES-CTR operation would be mixed in with the next operation's input
 * data, even when the IV was changed in between. When the key or IV changes,
 * any partial block data should not be used.
 */
int test_aes_ctr_leftover_data_regression(ENGINE *e, void *data)
{
    enum {
        NUM_PACKETS = 2,
        PACKET_SIZE = AES_BLOCK_SIZE + 1
    };
    int err = 0;
    const unsigned char key[AES_128_KEY_SIZE] = {
        0x37, 0xe8, 0x46, 0x48, 0xf4, 0xd6, 0xa7, 0x28, 0xc6, 0xd5, 0x2e, 0x3b,
        0xf4, 0xc4, 0x46, 0x66
    };
    const unsigned char ivs[NUM_PACKETS][AES_BLOCK_SIZE] = {
        {
            0x88, 0x93, 0x6f, 0xfd, 0x7d, 0x94, 0x21, 0xcc, 0x40, 0x64, 0xde,
            0x8a, 0xb9, 0xaf, 0xdd, 0xe4
        },
        {
            0x0f, 0x10, 0x9c, 0xc9, 0x25, 0x9a, 0x53, 0xf0, 0xd3, 0x92, 0xdf,
            0x35, 0xb2, 0x35, 0xa6, 0xd8
        }
    };
    const unsigned char packets[NUM_PACKETS][PACKET_SIZE] = {
        {
            0x3c, 0x89, 0x18, 0x76, 0xfc, 0xae, 0xdc, 0xee, 0xab, 0xf2, 0xf7,
            0x56, 0x47, 0x1f, 0xe9, 0x20, 0x67
        },
        {
            0xb5, 0x3b, 0x8d, 0xa1, 0xe7, 0x0a, 0x46, 0x56, 0xf6, 0xfd, 0xeb,
            0x85, 0x61, 0xd8, 0xaf, 0xac, 0xfb
        }
    };
    EVP_CIPHER_CTX* encCtx = NULL;
    EVP_CIPHER_CTX* decCtx = NULL;
    unsigned char encText[PACKET_SIZE];
    unsigned char decText[PACKET_SIZE];
    int i;

    (void)data;

    if (err == 0) {
        err = (encCtx = EVP_CIPHER_CTX_new()) == NULL;
    }
    if (err == 0) {
        err = (decCtx = EVP_CIPHER_CTX_new()) == NULL;
    }

    /* Set key. */
    if (err == 0) {
        err = EVP_CipherInit_ex(encCtx, EVP_aes_128_ctr(), NULL, key,
                                NULL, -1) != 1;
    }
    if (err == 0) {
        err = EVP_CipherInit_ex(decCtx, EVP_aes_128_ctr(), e, key,
                                NULL, -1) != 1;
    }

    for (i = 0; err == 0 && i < NUM_PACKETS; ++ i) {
        /* Set IV. */
        if (err == 0) {
            err = EVP_CipherInit_ex(encCtx, NULL, NULL, NULL, ivs[i], 1) != 1;
        }
        if (err == 0) {
            err = EVP_CipherInit_ex(decCtx, NULL, e, NULL, ivs[i], 0) != 1;
        }
        /* Encrypt. */
        if (err == 0) {
            err = EVP_Cipher(encCtx, encText, packets[i], PACKET_SIZE) < 0;
        }
        /* Decrypt. */
        if (err == 0) {
            err = EVP_Cipher(decCtx, decText, encText, PACKET_SIZE) < 0;
        }
        /* Ensure decrypted and plaintext match. */
        if (err == 0) {
            err = memcmp(decText, packets[i], PACKET_SIZE) != 0;
        }
    }

    /* Try the other way, now. Encrypt with wolfEngine, decrypt with openSSL.
     * The EVP_CIPHER_CTX remembers any engine it was loaded with, meaning we
     * need to reset the ctxs before reuse or the decCtx will still pick up
     * wolfEngine */
    if (encCtx != NULL)
        EVP_CIPHER_CTX_free(encCtx);
    if (decCtx != NULL)
        EVP_CIPHER_CTX_free(decCtx);

    if (err == 0) {
        err = (encCtx = EVP_CIPHER_CTX_new()) == NULL;
    }
    if (err == 0) {
        err = (decCtx = EVP_CIPHER_CTX_new()) == NULL;
    }

    if (err == 0) {
        err = EVP_CipherInit_ex(encCtx, EVP_aes_128_ctr(), e, key,
                                NULL, -1) != 1;
    }
    if (err == 0) {
        err = EVP_CipherInit_ex(decCtx, EVP_aes_128_ctr(), NULL, key,
                                NULL, -1) != 1;
    }

    for (i = 0; err == 0 && i < NUM_PACKETS; ++ i) {
        if (err == 0) {
            err = EVP_CipherInit_ex(encCtx, NULL, e, NULL, ivs[i], 1) != 1;
        }
        if (err == 0) {
            err = EVP_CipherInit_ex(decCtx, NULL, NULL, NULL, ivs[i], 0) != 1;
        }
        if (err == 0) {
            err = EVP_Cipher(encCtx, encText, packets[i], PACKET_SIZE) < 0;
        }
        if (err == 0) {
            err = EVP_Cipher(decCtx, decText, encText, PACKET_SIZE) < 0;
        }
        if (err == 0) {
            err = memcmp(decText, packets[i], PACKET_SIZE) != 0;
        }
    }

    if (encCtx != NULL)
        EVP_CIPHER_CTX_free(encCtx);
    if (decCtx != NULL)
        EVP_CIPHER_CTX_free(decCtx);

    return err;
}

/*
 * OpenSSL allows the user to call EVP_CipherInit with NULL key or IV. In the
 * past, setting the IV first (with key NULL) with wolfEngine and then setting
 * the key (with IV NULL) would result in the IV getting set to 0s on the call
 * to set the key. This was discovered in testing with OpenSSH. This is a
 * regression test to ensure we preserve the IV in this scenario.
 */
int test_aes_ctr_iv_init_regression(ENGINE *e, void *data)
{
    int err = 0;
    unsigned char iv[AES_BLOCK_SIZE];
    unsigned char key[16];
    EVP_CIPHER_CTX* encCtx = NULL;
    EVP_CIPHER_CTX* decCtx = NULL;
    const unsigned char plainText[] = "Lorem ipsum dolor sit amet";
    unsigned char encText[sizeof(plainText)];
    unsigned char decText[sizeof(plainText)];

    (void)data;

    /* Generate a random IV and key. */
    err = RAND_bytes(iv, AES_BLOCK_SIZE) != 1;
    if (err == 0) {
        err = RAND_bytes(key, 16) != 1;
    }

    /* Create encryption context. Use OpenSSL for encryption. */
    if (err == 0) {
        err = (encCtx = EVP_CIPHER_CTX_new()) == NULL;
    }
    if (err == 0) {
        err = EVP_CipherInit_ex(encCtx, EVP_aes_128_ctr(), NULL, NULL, iv, 1)
              != 1;
    }
    if (err == 0) {
        err = EVP_CipherInit_ex(encCtx, NULL, NULL, key, NULL, -1) != 1;
    }

    /* Create decryption context. Use wolfEngine for decryption. */
    if (err == 0) {
        err = (decCtx = EVP_CIPHER_CTX_new()) == NULL;
    }
    if (err == 0) {
        err = EVP_CipherInit_ex(decCtx, EVP_aes_128_ctr(), e, NULL, iv, 0) != 1;
    }
    if (err == 0) {
        err = EVP_CipherInit_ex(decCtx, NULL, e, key, NULL, -1) != 1;
    }

    /* Encrypt. */
    if (err == 0) {
        err = EVP_Cipher(encCtx, encText, plainText, sizeof(plainText)) < 0;
    }

    /* Decrypt. */
    if (err == 0) {
        err = EVP_Cipher(decCtx, decText, encText, sizeof(plainText)) < 0;
    }

    /* Ensure decrypted and plaintext match. */
    if (err == 0) {
        err = memcmp(decText, plainText, sizeof(plainText)) != 0;
    }

    if (encCtx != NULL)
        EVP_CIPHER_CTX_free(encCtx);
    if (decCtx != NULL)
        EVP_CIPHER_CTX_free(decCtx);

    return err;
}

#endif /* WE_HAVE_AESCTR */

