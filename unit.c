/* unit.c
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

#include <string.h>

#include <openssl/engine.h>
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/ssl.h>
#include <openssl/aes.h>

#include "openssl_bc.h"

#define PRINT_MSG(str)         printf("MSG: %s\n", str)
#define PRINT_ERR_MSG(str)     printf("ERR: %s\n", str)
#ifdef WOLFENGINE_DEBUG
#define PRINT_BUFFER(d, b, l)  print_buffer(d, b, l)
#else
#define PRINT_BUFFER(d, b, l)
#endif

#define TEST_DECL(func)        { #func, func, 0, 0, 0 }

typedef int (*TEST_FUNC)(ENGINE *e, void *data);
typedef struct TEST_CASE {
    const char *name;
    TEST_FUNC   func;
    int         err;
    int         run:1;
    int         done:1;
} TEST_CASE;


#ifdef WOLFENGINE_DEBUG
static void print_buffer(const char *desc, const unsigned char *buffer, int len)
{
    int i;

    printf("%s:\n", desc);
    for (i = 0; i < len; i++) {
        printf("%02x ", buffer[i]);
        if ((i % 16) == 15) {
            printf("\n");
        }
    }
    if ((i % 16) != 0) {
        printf("\n");
    }
}
#endif

/******************************************************************************/

#ifdef WE_HAVE_DIGEST

static int test_digest_op(const EVP_MD *md, ENGINE *e, unsigned char *msg,
                          size_t len, unsigned char *prev,
                          unsigned int *prevLen)
{
    int err;
    EVP_MD_CTX *ctx;
    unsigned char digest[64] = {0,};
    unsigned int dLen = sizeof(digest);

    err = (ctx = EVP_MD_CTX_new()) == NULL;
    if (err == 0) {
        err = EVP_DigestInit_ex(ctx, md, e) != 1;
    }
    if (err == 0) {
        err = EVP_DigestUpdate(ctx, msg, len/2) != 1;
    }
    if (err == 0) {
        err = EVP_DigestUpdate(ctx, msg + len/2, len - len/2) != 1;
    }
    if (err == 0) {
        err = EVP_DigestFinal_ex(ctx, digest, &dLen) != 1;
    }
    if (err == 0) {
        PRINT_BUFFER("Digest", digest, dLen);

        if (*prevLen == 0) {
            memcpy(prev, digest, dLen);
            *prevLen = dLen;
        }
        else {
            if (memcmp(digest, prev, *prevLen) != 0) {
                PRINT_ERR_MSG("Digests don't match");
                err = 1;
            }
            else {
                PRINT_MSG("Digests match");
            }
        }
    }

    EVP_MD_CTX_free(ctx);

    return err;
}

/******************************************************************************/

#ifdef WE_HAVE_SHA256

static int test_sha256(ENGINE *e, void *data)
{
    int err = 0;
    const EVP_MD *md = EVP_sha256();
    unsigned char *msg = (unsigned char *)"Test pattern";
    unsigned char longMsg[1300];
    unsigned char digest[32];
    unsigned int dLen;

    (void)data;

    RAND_bytes(longMsg, sizeof(longMsg));

    dLen = 0;
    PRINT_MSG("Digest with OpenSSL");
    test_digest_op(md, NULL, msg, strlen((char*)msg), digest, &dLen);
    PRINT_MSG("Digest With wolfengine");
    test_digest_op(md, e, msg, strlen((char*)msg), digest, &dLen);

    dLen = 0;
    PRINT_MSG("Digest with OpenSSL");
    test_digest_op(md, NULL, longMsg, sizeof(longMsg), digest, &dLen);
    PRINT_MSG("Digest With wolfengine");
    test_digest_op(md, e, longMsg, sizeof(longMsg), digest, &dLen);

    return err;
}

#endif

/******************************************************************************/

#ifdef WE_HAVE_SHA384

static int test_sha384(ENGINE *e, void *data)
{
    int err = 0;
    const EVP_MD *md = EVP_sha384();
    unsigned char *msg = (unsigned char *)"Test pattern";
    unsigned char longMsg[1300];
    unsigned char digest[48];
    unsigned int dLen;

    (void)data;

    RAND_bytes(longMsg, sizeof(longMsg));

    dLen = 0;
    PRINT_MSG("Digest with OpenSSL");
    test_digest_op(md, NULL, msg, strlen((char*)msg), digest, &dLen);
    PRINT_MSG("Digest With wolfengine");
    test_digest_op(md, e, msg, strlen((char*)msg), digest, &dLen);

    dLen = 0;
    PRINT_MSG("Digest with OpenSSL");
    test_digest_op(md, NULL, longMsg, sizeof(longMsg), digest, &dLen);
    PRINT_MSG("Digest With wolfengine");
    test_digest_op(md, e, longMsg, sizeof(longMsg), digest, &dLen);

    return err;
}

#endif

/******************************************************************************/

#ifdef WE_HAVE_SHA512

static int test_sha512(ENGINE *e, void *data)
{
    int err = 0;
    const EVP_MD *md = EVP_sha512();
    unsigned char *msg = (unsigned char *)"Test pattern";
    unsigned char longMsg[1300];
    unsigned char digest[64];
    unsigned int dLen;

    (void)data;

    RAND_bytes(longMsg, sizeof(longMsg));

    dLen = 0;
    PRINT_MSG("Digest with OpenSSL");
    test_digest_op(md, NULL, msg, strlen((char*)msg), digest, &dLen);
    PRINT_MSG("Digest With wolfengine");
    test_digest_op(md, e, msg, strlen((char*)msg), digest, &dLen);

    dLen = 0;
    PRINT_MSG("Digest with OpenSSL");
    test_digest_op(md, NULL, longMsg, sizeof(longMsg), digest, &dLen);
    PRINT_MSG("Digest With wolfengine");
    test_digest_op(md, e, longMsg, sizeof(longMsg), digest, &dLen);

    return err;
}

#endif

/******************************************************************************/

#endif /* WE_HAVE_DIGEST */

/******************************************************************************/
#ifdef WE_HAVE_AESGCM

static int test_aes_gcm_enc(ENGINE *e, const EVP_CIPHER *cipher,
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

static int test_aes_gcm_dec(ENGINE *e, const EVP_CIPHER *cipher,
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

static int test_aes128_gcm(ENGINE *e, void *data)
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

static int test_aes256_gcm(ENGINE *e, void *data)
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

static int test_aes128_gcm_fixed_enc(ENGINE *e, const EVP_CIPHER *cipher,
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

static int test_aes128_gcm_fixed_dec(ENGINE *e, const EVP_CIPHER *cipher,
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

static int test_aes128_gcm_fixed(ENGINE *e, void *data)
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

static int test_aes128_gcm_tls_enc(ENGINE *e, const EVP_CIPHER *cipher,
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

static int test_aes128_gcm_tls_dec(ENGINE *e, const EVP_CIPHER *cipher,
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

static int test_aes128_gcm_tls(ENGINE *e, void *data)
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

/******************************************************************************/

#ifdef WE_HAVE_ECC

#if defined(WE_HAVE_ECDSA) || defined(WE_HAVE_ECDH)
#ifdef WE_HAVE_EC_P256
static const unsigned char ecc_key_der_256[] = {
    0x30, 0x77, 0x02, 0x01, 0x01, 0x04, 0x20, 0x45, 0xB6, 0x69,
    0x02, 0x73, 0x9C, 0x6C, 0x85, 0xA1, 0x38, 0x5B, 0x72, 0xE8,
    0xE8, 0xC7, 0xAC, 0xC4, 0x03, 0x8D, 0x53, 0x35, 0x04, 0xFA,
    0x6C, 0x28, 0xDC, 0x34, 0x8D, 0xE1, 0xA8, 0x09, 0x8C, 0xA0,
    0x0A, 0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01,
    0x07, 0xA1, 0x44, 0x03, 0x42, 0x00, 0x04, 0xBB, 0x33, 0xAC,
    0x4C, 0x27, 0x50, 0x4A, 0xC6, 0x4A, 0xA5, 0x04, 0xC3, 0x3C,
    0xDE, 0x9F, 0x36, 0xDB, 0x72, 0x2D, 0xCE, 0x94, 0xEA, 0x2B,
    0xFA, 0xCB, 0x20, 0x09, 0x39, 0x2C, 0x16, 0xE8, 0x61, 0x02,
    0xE9, 0xAF, 0x4D, 0xD3, 0x02, 0x93, 0x9A, 0x31, 0x5B, 0x97,
    0x92, 0x21, 0x7F, 0xF0, 0xCF, 0x18, 0xDA, 0x91, 0x11, 0x02,
    0x34, 0x86, 0xE8, 0x20, 0x58, 0x33, 0x0B, 0x80, 0x34, 0x89,
    0xD8
};
#endif

#ifdef WE_HAVE_EC_P384
static const unsigned char ecc_key_der_384[] = {
    0x30, 0x81, 0xA4, 0x02, 0x01, 0x01, 0x04, 0x30, 0x7B, 0x16,
    0xE3, 0xD6, 0xD2, 0x81, 0x94, 0x6C, 0x8A, 0xDD, 0xA8, 0x78,
    0xEE, 0xC7, 0x7E, 0xB3, 0xC5, 0xD1, 0xDB, 0x2E, 0xF3, 0xED,
    0x0E, 0x48, 0x85, 0xB1, 0xF2, 0xE1, 0x7A, 0x39, 0x56, 0xC0,
    0xF1, 0x62, 0x12, 0x0F, 0x35, 0xB7, 0x39, 0xBC, 0x9C, 0x25,
    0xC0, 0x76, 0xEB, 0xFE, 0x55, 0x70, 0xA0, 0x07, 0x06, 0x05,
    0x2B, 0x81, 0x04, 0x00, 0x22, 0xA1, 0x64, 0x03, 0x62, 0x00,
    0x04, 0xEE, 0x82, 0xD4, 0x39, 0x9A, 0xB1, 0x27, 0x82, 0xF4,
    0xD7, 0xEA, 0xC6, 0xBC, 0x03, 0x1D, 0x4D, 0x83, 0x61, 0xF4,
    0x03, 0xAE, 0x7E, 0xBD, 0xD8, 0x5A, 0xA5, 0xB9, 0xF0, 0x8E,
    0xA2, 0xA5, 0xDA, 0xCE, 0x87, 0x3B, 0x5A, 0xAB, 0x44, 0x16,
    0x9C, 0xF5, 0x9F, 0x62, 0xDD, 0xF6, 0x20, 0xCD, 0x9C, 0x76,
    0x3C, 0x40, 0xB1, 0x3F, 0x97, 0x17, 0xDF, 0x59, 0xF6, 0xCD,
    0xDE, 0xCD, 0x46, 0x35, 0xC0, 0xED, 0x5E, 0x2E, 0x48, 0xB6,
    0x66, 0x91, 0x71, 0x74, 0xB7, 0x0C, 0x3F, 0xB9, 0x9A, 0xB7,
    0x83, 0xBD, 0x93, 0x3F, 0x5F, 0x50, 0x2D, 0x70, 0x3F, 0xDE,
    0x35, 0x25, 0xE1, 0x90, 0x3B, 0x86, 0xE0
};
#endif
#endif
#ifdef WE_HAVE_ECDH
#ifdef WE_HAVE_EC_P256
static const unsigned char ecc_peerkey_der_256[] = {
    0x30, 0x77, 0x02, 0x01, 0x01, 0x04, 0x20, 0xF8, 0xCF, 0x92,
    0x6B, 0xBD, 0x1E, 0x28, 0xF1, 0xA8, 0xAB, 0xA1, 0x23, 0x4F,
    0x32, 0x74, 0x18, 0x88, 0x50, 0xAD, 0x7E, 0xC7, 0xEC, 0x92,
    0xF8, 0x8F, 0x97, 0x4D, 0xAF, 0x56, 0x89, 0x65, 0xC7, 0xA0,
    0x0A, 0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01,
    0x07, 0xA1, 0x44, 0x03, 0x42, 0x00, 0x04, 0x55, 0xBF, 0xF4,
    0x0F, 0x44, 0x50, 0x9A, 0x3D, 0xCE, 0x9B, 0xB7, 0xF0, 0xC5,
    0x4D, 0xF5, 0x70, 0x7B, 0xD4, 0xEC, 0x24, 0x8E, 0x19, 0x80,
    0xEC, 0x5A, 0x4C, 0xA2, 0x24, 0x03, 0x62, 0x2C, 0x9B, 0xDA,
    0xEF, 0xA2, 0x35, 0x12, 0x43, 0x84, 0x76, 0x16, 0xC6, 0x56,
    0x95, 0x06, 0xCC, 0x01, 0xA9, 0xBD, 0xF6, 0x75, 0x1A, 0x42,
    0xF7, 0xBD, 0xA9, 0xB2, 0x36, 0x22, 0x5F, 0xC7, 0x5D, 0x7F,
    0xB4
};

static const unsigned char ecc_derived_256[] = {
    0x18, 0x5b, 0x4d, 0x35, 0x8b, 0x70, 0x0e, 0x3c, 0xfa, 0xd1,
    0xd8, 0x8c, 0x9e, 0xcc, 0xf6, 0xb3, 0xf6, 0xf5, 0x46, 0x56,
    0xdc, 0x53, 0xea, 0x06, 0x59, 0x8e, 0xfa, 0x44, 0xd8, 0xba,
    0x2d, 0x7b
};
#endif

#ifdef WE_HAVE_EC_P384
static const unsigned char ecc_peerkey_der_384[] = {
    0x30, 0x81, 0xA4, 0x02, 0x01, 0x01, 0x04, 0x30, 0x29, 0xf9,
    0x59, 0x0c, 0xa7, 0x03, 0x3b, 0xb8, 0x22, 0x56, 0x93, 0xe7,
    0xe8, 0x6d, 0x2c, 0x4b, 0xb6, 0x21, 0x76, 0x9d, 0xdf, 0xf8,
    0x60, 0x32, 0x72, 0xd8, 0x88, 0xce, 0xf8, 0x88, 0xf3, 0xa0,
    0x40, 0xc6, 0x24, 0x1e, 0x04, 0x92, 0xbd, 0x40, 0x1b, 0x16,
    0x26, 0x89, 0x2e, 0x7b, 0x21, 0x55, 0xA0, 0x07, 0x06, 0x05,
    0x2B, 0x81, 0x04, 0x00, 0x22, 0xA1, 0x64, 0x03, 0x62, 0x00,
    0x04, 0xbf, 0xe2, 0xf7, 0xd8, 0xe5, 0x80, 0x5d, 0x76, 0xf7,
    0x09, 0xb3, 0xcd, 0x55, 0x5e, 0xf9, 0xb7, 0x82, 0xac, 0x08,
    0xbf, 0x3c, 0x9c, 0x36, 0xd4, 0xf8, 0xf1, 0x94, 0x3d, 0x6e,
    0xa1, 0x89, 0x04, 0x44, 0x4c, 0x01, 0x79, 0x26, 0x3a, 0x0c,
    0xcf, 0x57, 0x3e, 0x1c, 0x48, 0x8a, 0xf7, 0xdc, 0xa7, 0xc8,
    0x28, 0x68, 0x5f, 0x82, 0x35, 0x4a, 0xc5, 0x20, 0x28, 0xad,
    0x42, 0x9f, 0x73, 0x47, 0x16, 0x7f, 0x47, 0x59, 0x66, 0x1d,
    0xd4, 0xc6, 0x95, 0xde, 0x37, 0x5c, 0x77, 0x77, 0x1b, 0x4a,
    0xde, 0x11, 0x03, 0xd7, 0x2f, 0x29, 0x7a, 0x6c, 0x2e, 0xcf,
    0x7b, 0x58, 0xba, 0xe3, 0x81, 0x6e, 0xdc
};

static const unsigned char ecc_derived_384[] = {
    0xf4, 0x7e, 0xe7, 0xdb, 0x13, 0x98, 0xb8, 0xce, 0xd0, 0x41,
    0xfa, 0xd8, 0x7a, 0xfd, 0x07, 0x77, 0x6d, 0x2c, 0x76, 0x0b,
    0x42, 0xed, 0x89, 0xdf, 0x7e, 0x24, 0xfd, 0xaf, 0x47, 0x94,
    0x6c, 0xab, 0x0f, 0x7f, 0x60, 0x3e, 0xc4, 0xc8, 0xf3, 0x0e,
    0xd1, 0x73, 0x7d, 0x3a, 0x11, 0x91, 0x6e, 0x3c
};
#endif
#endif

/******************************************************************************/

#ifdef WE_HAVE_EVP_PKEY

#ifdef WE_HAVE_ECKEYGEN

#ifdef WE_HAVE_EC_P256
static int test_eckeygen_p256_by_nid(ENGINE *e, void *data)
{
    int err;
    EVP_PKEY_CTX *ctx = NULL;
    EVP_PKEY *key = NULL;

    (void)data;

    PRINT_MSG("Create P-256 public key context");
    err = (ctx = EVP_PKEY_CTX_new_id(NID_X9_62_prime256v1, e)) == NULL;
    if (err == 0) {
        PRINT_MSG("Initialize key generation");
        err = EVP_PKEY_keygen_init(ctx) != 1;
    }
    if (err == 0) {
        PRINT_MSG("Generate key");
        err = EVP_PKEY_keygen(ctx, &key) != 1;
    }

    EVP_PKEY_free(key);
    EVP_PKEY_CTX_free(ctx);

    return err;
}

static int test_eckeygen_p256(ENGINE *e, void *data)
{
    int err;
    EVP_PKEY_CTX *ctx = NULL;
    EVP_PKEY *key = NULL;

    (void)data;

    PRINT_MSG("Create public key context");
    err = (ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, e)) == NULL;
    if (err == 0) {
        PRINT_MSG("Initialize key generation");
        err = EVP_PKEY_keygen_init(ctx) != 1;
    }
    if (err == 0) {
        PRINT_MSG("Set named curve NID");
        err = EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx,
                                                     NID_X9_62_prime256v1) != 1;
    }
    if (err == 0) {
        PRINT_MSG("Generate key");
        err = EVP_PKEY_keygen(ctx, &key) != 1;
    }

    EVP_PKEY_free(key);
    EVP_PKEY_CTX_free(ctx);

    return err;
}
#endif

#ifdef WE_HAVE_EC_P384
static int test_eckeygen_p384_by_nid(ENGINE *e, void *data)
{
    int err;
    EVP_PKEY_CTX *ctx = NULL;
    EVP_PKEY *key = NULL;

    (void)data;

    PRINT_MSG("Create P-384 public key context");
    err = (ctx = EVP_PKEY_CTX_new_id(NID_secp384r1, e)) == NULL;
    if (err == 0) {
        PRINT_MSG("Initialize key generation");
        err = EVP_PKEY_keygen_init(ctx) != 1;
    }
    if (err == 0) {
        PRINT_MSG("Generate key");
        err = EVP_PKEY_keygen(ctx, &key) != 1;
    }

    EVP_PKEY_free(key);
    EVP_PKEY_CTX_free(ctx);

    return err;
}

static int test_eckeygen_p384(ENGINE *e, void *data)
{
    int err;
    EVP_PKEY_CTX *ctx = NULL;
    EVP_PKEY *key = NULL;

    (void)data;

    PRINT_MSG("Create public key context");
    err = (ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, e)) == NULL;
    if (err == 0) {
        PRINT_MSG("Initialize key generation");
        err = EVP_PKEY_keygen_init(ctx) != 1;
    }
    if (err == 0) {
        PRINT_MSG("Set named curve NID");
        err = EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx, NID_secp384r1) != 1;
    }
    if (err == 0) {
        PRINT_MSG("Generate key");
        err = EVP_PKEY_keygen(ctx, &key) != 1;
    }

    EVP_PKEY_free(key);
    EVP_PKEY_CTX_free(ctx);

    return err;
}
#endif

#endif /* WE_HAVE_ECKEYGEN */

#ifdef WE_HAVE_ECDH

static int test_ecdh_derive(ENGINE *e, EVP_PKEY *key, EVP_PKEY *peerKey,
                            unsigned char **pSecret, size_t expLen)
{
    int err;
    EVP_PKEY_CTX *ctx = NULL;
    unsigned char *secret = NULL;
    size_t outLen;

#if OPENSSL_VERSION_NUMBER >= 0x30000000L
    err = EVP_PKEY_set1_engine(key, e) != 1;
    if (err == 0) {
        err = (ctx = EVP_PKEY_CTX_new(key, NULL)) == NULL;
    }
#else
    err = (ctx = EVP_PKEY_CTX_new(key, e)) == NULL;
#endif
    if (err == 0) {
        err = EVP_PKEY_derive_init(ctx) != 1;
    }
    if (err == 0) {
        err = EVP_PKEY_derive_set_peer(ctx, peerKey) != 1;
    }
    if (err == 0) {
        err = EVP_PKEY_derive(ctx, NULL, &outLen) != 1;
    }
    if (err == 0) {
        err = (expLen == outLen) == 0;
    }
    if (err == 0) {
        err = (secret = OPENSSL_malloc(outLen)) == NULL;
    }
    if (err == 0) {
        err = EVP_PKEY_derive(ctx, secret, &outLen) != 1;
    }
    if (err == 0) {
        *pSecret = secret;
        secret = NULL;
    }

    OPENSSL_free(secret);
    EVP_PKEY_CTX_free(ctx);

    return err;
}

#ifdef WE_HAVE_ECKEYGEN
static int test_ecdh_keygen(ENGINE *e, int nid, int len)
{
    int err;
    EVP_PKEY_CTX *kgCtx = NULL;
    EVP_PKEY *keyA = NULL;
    EVP_PKEY *keyB = NULL;
    unsigned char *secretA = NULL;
    unsigned char *secretB = NULL;

    err = (kgCtx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, e)) == NULL;
    if (err == 0) {
        err = EVP_PKEY_keygen_init(kgCtx) != 1;
    }
    if (err == 0) {
        err = EVP_PKEY_CTX_set_ec_paramgen_curve_nid(kgCtx, nid) != 1;
    }
    if (err == 0) {
        err = EVP_PKEY_keygen(kgCtx, &keyA) != 1;
    }
    if (err == 0) {
        err = EVP_PKEY_keygen(kgCtx, &keyB) != 1;
    }
    if (err == 0) {
        PRINT_MSG("Derive secret A");
        err = test_ecdh_derive(e, keyA, keyB, &secretA, len);
    }
    if (err == 0) {
        PRINT_MSG("Derive secret B");
        err = test_ecdh_derive(e, keyB, keyA, &secretB, len);
    }
    if (err == 0) {
        PRINT_BUFFER("Secret A", secretA, len);
        PRINT_BUFFER("Secret B", secretB, len);
        err = memcmp(secretA, secretB, len) != 0;
        if (err != 0) {
            PRINT_ERR_MSG("Secrets do not match!");
        }
    }

    OPENSSL_free(secretA);
    OPENSSL_free(secretB);
    EVP_PKEY_free(keyB);
    EVP_PKEY_free(keyA);
    EVP_PKEY_CTX_free(kgCtx);

    return err;
}

#ifdef WE_HAVE_EC_P256
static int test_ecdh_p256_keygen(ENGINE *e, void *data)
{
    (void)data;

    return test_ecdh_keygen(e, NID_X9_62_prime256v1, 32);
}
#endif

#ifdef WE_HAVE_EC_P384
static int test_ecdh_p384_keygen(ENGINE *e, void *data)
{
    (void)data;

    return test_ecdh_keygen(e, NID_secp384r1, 48);
}
#endif
#endif

static int test_ecdh(ENGINE *e, const unsigned char *privKey, size_t len,
                     const unsigned char *peerPrivKey, size_t peerLen,
                     const unsigned char *derived, size_t dLen)
{
    int err;
    EVP_PKEY_CTX *kgCtx = NULL;
    EVP_PKEY *keyA = NULL;
    EVP_PKEY *keyB = NULL;
    unsigned char *secretA = NULL;
    unsigned char *secretB = NULL;
    const unsigned char *p;

    p = privKey;
    err = (keyA = d2i_PrivateKey(EVP_PKEY_EC, NULL, &p, len)) == NULL;
    err = keyA == NULL;
    if (err == 0) {
        p = peerPrivKey;
        err = (keyB = d2i_PrivateKey(EVP_PKEY_EC, NULL, &p, peerLen)) == NULL;
    }
    if (err == 0) {
        PRINT_MSG("Derive secret A");
        err = test_ecdh_derive(e, keyA, keyB, &secretA, dLen);
    }
    if (err == 0) {
        PRINT_MSG("Derive secret B");
        err = test_ecdh_derive(e, keyB, keyA, &secretB, dLen);
    }
    if (err == 0) {
        PRINT_BUFFER("Secret A", secretA, dLen);
        PRINT_BUFFER("Secret B", secretB, dLen);
        err = memcmp(secretA, secretB, dLen) != 0;
        if (err != 0) {
            PRINT_ERR_MSG("Secrets do not match!");
        }
    }
    if (err == 0) {
        err = memcmp(secretA, derived, dLen) != 0;
        if (err != 0) {
            PRINT_ERR_MSG("Secret does not match, expected!");
        }
    }

    OPENSSL_free(secretA);
    OPENSSL_free(secretB);
    EVP_PKEY_free(keyB);
    EVP_PKEY_free(keyA);
    EVP_PKEY_CTX_free(kgCtx);

    return err;
}

#ifdef WE_HAVE_EC_P256
static int test_ecdh_p256(ENGINE *e, void *data)
{
    (void)data;
    return test_ecdh(e, ecc_key_der_256, sizeof(ecc_key_der_256),
                     ecc_peerkey_der_256, sizeof(ecc_peerkey_der_256),
                     ecc_derived_256, sizeof(ecc_derived_256));
}
#endif

#ifdef WE_HAVE_EC_P384
static int test_ecdh_p384(ENGINE *e, void *data)
{
    (void)data;
    return test_ecdh(e, ecc_key_der_384, sizeof(ecc_key_der_384),
                     ecc_peerkey_der_384, sizeof(ecc_peerkey_der_384),
                     ecc_derived_384, sizeof(ecc_derived_384));
}
#endif

#endif /* WE_HAVE_ECDH */

#ifdef WE_HAVE_ECDSA

static int test_ecdsa_pkey_sign(EVP_PKEY *pkey, ENGINE *e, unsigned char *hash,
                                size_t hashLen, unsigned char *ecdsaSig,
                                size_t *ecdsaSigLen)
{
    int err;
    EVP_PKEY_CTX *ctx = NULL;
    size_t sigLen = *ecdsaSigLen;

#if OPENSSL_VERSION_NUMBER >= 0x30000000L
    err = EVP_PKEY_set1_engine(pkey, e) != 1;
    if (err == 0) {
        err = (ctx = EVP_PKEY_CTX_new(pkey, NULL)) == NULL;
    }
#else
    err = (ctx = EVP_PKEY_CTX_new(pkey, e)) == NULL;
#endif
    if (err == 0) {
        err = EVP_PKEY_sign_init(ctx) != 1;
    }
    if (err == 0) {
        err = EVP_PKEY_sign(ctx, ecdsaSig, ecdsaSigLen, hash, hashLen) != 1;
    }
    if (err == 0) {
        PRINT_BUFFER("Signture", ecdsaSig, *ecdsaSigLen);
    }
    if (err == 0) {
        err = EVP_PKEY_sign_init(ctx) != 1;
    }
    if (err == 0) {
        *ecdsaSigLen = sigLen;
        err = EVP_PKEY_sign(ctx, ecdsaSig, ecdsaSigLen, hash, hashLen) != 1;
    }
    if (err == 0) {
        PRINT_BUFFER("Signture", ecdsaSig, *ecdsaSigLen);
    }

    EVP_PKEY_CTX_free(ctx);

    return err;
}

static int test_ecdsa_pkey_verify(EVP_PKEY *pkey, ENGINE *e,
                                  unsigned char *hash, size_t hashLen,
                                  unsigned char *ecdsaSig, size_t ecdsaSigLen)
{
    int err;
    EVP_PKEY_CTX *ctx = NULL;

#if OPENSSL_VERSION_NUMBER >= 0x30000000L
    err = EVP_PKEY_set1_engine(pkey, e) != 1;
    if (err == 0) {
        err = (ctx = EVP_PKEY_CTX_new(pkey, NULL)) == NULL;
    }
#else
    err = (ctx = EVP_PKEY_CTX_new(pkey, e)) == NULL;
#endif
    if (err == 0) {
        err = EVP_PKEY_verify_init(ctx) != 1;
    }
    if (err == 0) {
        err = EVP_PKEY_verify(ctx, ecdsaSig, ecdsaSigLen, hash, hashLen) != 1;
    }
    if (err == 0) {
        PRINT_MSG("Signature verified");
    }
    else {
        PRINT_MSG("Signature not verified");
    }
    if (err == 0) {
        err = EVP_PKEY_verify_init(ctx) != 1;
    }
    if (err == 0) {
        err = EVP_PKEY_verify(ctx, ecdsaSig, ecdsaSigLen, hash, hashLen) != 1;
    }
    if (err == 0) {
        PRINT_MSG("Signature verified");
    }
    else {
        PRINT_MSG("Signature not verified");
    }

    EVP_PKEY_CTX_free(ctx);

    return err;
}

#ifdef WE_HAVE_EC_P256
static int test_ecdsa_p256_pkey(ENGINE *e, void *data)
{
    int err;
    int res;
    EVP_PKEY *pkey = NULL;
    unsigned char ecdsaSig[80];
    size_t ecdsaSigLen;
    unsigned char buf[20];
    const unsigned char *p = ecc_key_der_256;

    (void)data;

    err = RAND_bytes(buf, sizeof(buf)) == 0;
    if (err == 0) {
        pkey = d2i_PrivateKey(EVP_PKEY_EC, NULL, &p, sizeof(ecc_key_der_256));
        err = pkey == NULL;
    }
    if (err == 0) {
        PRINT_MSG("Sign with OpenSSL");
        ecdsaSigLen = sizeof(ecdsaSig);
        err = test_ecdsa_pkey_sign(pkey, NULL, buf, sizeof(buf), ecdsaSig,
                                   &ecdsaSigLen);
    }
    if (err == 0) {
        PRINT_MSG("Verify with wolfengine");
        err = test_ecdsa_pkey_verify(pkey, e, buf, sizeof(buf), ecdsaSig,
                                     ecdsaSigLen);
    }
    if (err == 0) {
        PRINT_MSG("Verify bad signature with wolfengine");
        ecdsaSig[1] ^= 0x80;
        res = test_ecdsa_pkey_verify(pkey, e, buf, sizeof(buf), ecdsaSig,
                                     ecdsaSigLen);
        if (res != 1)
            err = 1;
    }
    if (err == 0) {
        PRINT_MSG("Sign with wolfengine");
        ecdsaSigLen = sizeof(ecdsaSig);
        err = test_ecdsa_pkey_sign(pkey, e, buf, sizeof(buf), ecdsaSig,
                                   &ecdsaSigLen);
    }
    if (err == 0) {
        PRINT_MSG("Verify with OpenSSL");
        err = test_ecdsa_pkey_verify(pkey, NULL, buf, sizeof(buf),
                                     ecdsaSig, ecdsaSigLen);
    }

    EVP_PKEY_free(pkey);

    return err;
}
#endif

#ifdef WE_HAVE_EC_P384
static int test_ecdsa_p384_pkey(ENGINE *e, void *data)
{
    int err;
    int res;
    EVP_PKEY *pkey = NULL;
    unsigned char ecdsaSig[120];
    size_t ecdsaSigLen;
    unsigned char buf[20];
    const unsigned char *p = ecc_key_der_384;

    (void)data;

    err = RAND_bytes(buf, sizeof(buf)) == 0;
    if (err == 0) {
        pkey = d2i_PrivateKey(EVP_PKEY_EC, NULL, &p, sizeof(ecc_key_der_384));
        err = pkey == NULL;
    }
    if (err == 0) {
        PRINT_MSG("Sign with OpenSSL");
        ecdsaSigLen = sizeof(ecdsaSig);
        err = test_ecdsa_pkey_sign(pkey, NULL, buf, sizeof(buf), ecdsaSig,
                                   &ecdsaSigLen);
    }
    if (err == 0) {
        PRINT_MSG("Verify with wolfengine");
        err = test_ecdsa_pkey_verify(pkey, e, buf, sizeof(buf), ecdsaSig,
                                     ecdsaSigLen);
    }
    if (err == 0) {
        PRINT_MSG("Verify bad signature with wolfengine");
        ecdsaSig[1] ^= 0x80;
        res = test_ecdsa_pkey_verify(pkey, e, buf, sizeof(buf), ecdsaSig,
                                     ecdsaSigLen);
        if (res != 1)
            err = 1;
    }
    if (err == 0) {
        PRINT_MSG("Sign with wolfengine");
        ecdsaSigLen = sizeof(ecdsaSig);
        err = test_ecdsa_pkey_sign(pkey, e, buf, sizeof(buf), ecdsaSig,
                                   &ecdsaSigLen);
    }
    if (err == 0) {
        PRINT_MSG("Verify with OpenSSL");
        err = test_ecdsa_pkey_verify(pkey, NULL, buf, sizeof(buf),
                                     ecdsaSig, ecdsaSigLen);
    }

    EVP_PKEY_free(pkey);

    return err;
}
#endif

/******************************************************************************/

static int test_ecdsa_sign(EVP_PKEY *pkey, ENGINE *e, unsigned char *data,
                           size_t len, const EVP_MD *md,
                           unsigned char *ecdsaSig, size_t *ecdsaSigLen)
{
    int err;
    EVP_MD_CTX *mdCtx = NULL;
    EVP_PKEY_CTX *pkeyCtx = NULL;

    err = (mdCtx = EVP_MD_CTX_new()) == NULL;
    if (err == 0) {
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
        err = EVP_PKEY_set1_engine(pkey, e) != 1;
    }
    if (err == 0) {
        err = EVP_DigestSignInit(mdCtx, &pkeyCtx, md, NULL, pkey) != 1;
#else
        err = EVP_DigestSignInit(mdCtx, &pkeyCtx, md, e, pkey) != 1;
#endif
    }
#if OPENSSL_VERSION_NUMBER >= 0x1010100fL
    if (err == 0) {
        err = EVP_DigestSign(mdCtx, ecdsaSig, ecdsaSigLen, data, len) != 1;
    }
#else
    if (err == 0) {
        err = EVP_DigestSignUpdate(mdCtx, data, len) != 1;
    }
    if (err == 0) {
        err = EVP_DigestSignFinal(mdCtx, ecdsaSig, ecdsaSigLen) != 1;
    }
#endif
    if (err == 0) {
        PRINT_BUFFER("Signture", ecdsaSig, *ecdsaSigLen);
    }

    EVP_MD_CTX_free(mdCtx);

    return err;
}

static int test_ecdsa_verify(EVP_PKEY *pkey, ENGINE *e, unsigned char *data,
                             size_t len, const EVP_MD *md,
                             unsigned char *ecdsaSig, size_t ecdsaSigLen)
{
    int err;
    EVP_MD_CTX *mdCtx = NULL;
    EVP_PKEY_CTX *pkeyCtx = NULL;

    err = (mdCtx = EVP_MD_CTX_new()) == NULL;
    if (err == 0) {
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
        err = EVP_PKEY_set1_engine(pkey, e) != 1;
    }
    if (err == 0) {
        err = EVP_DigestVerifyInit(mdCtx, &pkeyCtx, md, NULL, pkey) != 1;
#else
        err = EVP_DigestVerifyInit(mdCtx, &pkeyCtx, md, e, pkey) != 1;
#endif
    }
#if OPENSSL_VERSION_NUMBER >= 0x1010100fL
    if (err == 0) {
        err = EVP_DigestVerify(mdCtx, ecdsaSig, ecdsaSigLen, data, len) != 1;
    }
#else
    if (err == 0) {
        err = EVP_DigestVerifyUpdate(mdCtx, data, len) != 1;
    }
    if (err == 0) {
        err = EVP_DigestVerifyFinal(mdCtx, ecdsaSig, ecdsaSigLen) != 1;
    }
#endif
    if (err == 0) {
        PRINT_MSG("Signature verified");
    }
    else {
        PRINT_MSG("Signature not verified");
    }

    EVP_MD_CTX_free(mdCtx);

    return err;
}

#ifdef WE_HAVE_EC_P256
static int test_ecdsa_p256(ENGINE *e, void *data)
{
    int err;
    int res;
    EVP_PKEY *pkey = NULL;
    unsigned char ecdsaSig[80];
    size_t ecdsaSigLen;
    unsigned char buf[128];
    const unsigned char *p = ecc_key_der_256;

    (void)data;

    err = RAND_bytes(buf, sizeof(buf)) == 0;
    if (err == 0) {
        pkey = d2i_PrivateKey(EVP_PKEY_EC, NULL, &p, sizeof(ecc_key_der_256));
        err = pkey == NULL;
    }
    if (err == 0) {
        PRINT_MSG("Sign with OpenSSL");
        ecdsaSigLen = sizeof(ecdsaSig);
        err = test_ecdsa_sign(pkey, NULL, buf, sizeof(buf), EVP_sha256(),
                              ecdsaSig, &ecdsaSigLen);
    }
    if (err == 0) {
        PRINT_MSG("Verify with wolfengine");
        err = test_ecdsa_verify(pkey, e, buf, sizeof(buf), EVP_sha256(),
                                ecdsaSig, ecdsaSigLen);
    }
    if (err == 0) {
        PRINT_MSG("Verify bad signature with wolfengine");
        ecdsaSig[1] ^= 0x80;
        res = test_ecdsa_verify(pkey, e, buf, sizeof(buf), EVP_sha256(),
                                ecdsaSig, ecdsaSigLen);
        if (res != 1)
            err = 1;
    }
    if (err == 0) {
        PRINT_MSG("Sign with wolfengine");
        ecdsaSigLen = sizeof(ecdsaSig);
        err = test_ecdsa_sign(pkey, e, buf, sizeof(buf), EVP_sha256(),
                              ecdsaSig, &ecdsaSigLen);
    }
    if (err == 0) {
        PRINT_MSG("Verify with OpenSSL");
        err = test_ecdsa_verify(pkey, NULL, buf, sizeof(buf), EVP_sha256(),
                                ecdsaSig, ecdsaSigLen);
    }

    EVP_PKEY_free(pkey);

    return err;
}
#endif

#ifdef WE_HAVE_EC_P384
static int test_ecdsa_p384(ENGINE *e, void *data)
{
    int err;
    int res;
    EVP_PKEY *pkey = NULL;
    unsigned char ecdsaSig[120];
    size_t ecdsaSigLen;
    unsigned char buf[128];
    const unsigned char *p = ecc_key_der_384;

    (void)data;

    err = RAND_bytes(buf, sizeof(buf)) == 0;
    if (err == 0) {
        pkey = d2i_PrivateKey(EVP_PKEY_EC, NULL, &p, sizeof(ecc_key_der_384));
        err = pkey == NULL;
    }
    if (err == 0) {
        PRINT_MSG("Sign with OpenSSL");
        ecdsaSigLen = sizeof(ecdsaSig);
        err = test_ecdsa_sign(pkey, NULL, buf, sizeof(buf), EVP_sha384(),
                              ecdsaSig, &ecdsaSigLen);
    }
    if (err == 0) {
        PRINT_MSG("Verify with wolfengine");
        err = test_ecdsa_verify(pkey, e, buf, sizeof(buf), EVP_sha384(),
                                ecdsaSig, ecdsaSigLen);
    }
    if (err == 0) {
        PRINT_MSG("Verify bad signature with wolfengine");
        ecdsaSig[1] ^= 0x80;
        res = test_ecdsa_verify(pkey, e, buf, sizeof(buf), EVP_sha384(),
                                ecdsaSig, ecdsaSigLen);
        if (res != 1)
            err = 1;
    }
    if (err == 0) {
        PRINT_MSG("Sign with wolfengine");
        ecdsaSigLen = sizeof(ecdsaSig);
        err = test_ecdsa_sign(pkey, e, buf, sizeof(buf), EVP_sha384(),
                              ecdsaSig, &ecdsaSigLen);
    }
    if (err == 0) {
        PRINT_MSG("Verify with OpenSSL");
        err = test_ecdsa_verify(pkey, NULL, buf, sizeof(buf), EVP_sha384(),
                                ecdsaSig, ecdsaSigLen);
    }

    EVP_PKEY_free(pkey);

    return err;
}
#endif

#endif /* WE_HAVE_ECDSA */

#endif /* WE_HAVE_EVP_PKEY */

#ifdef WE_HAVE_EC_KEY

#ifdef WE_HAVE_ECKEYGEN

static int test_ec_key_keygen_by_nid(ENGINE *e, int nid)
{
    int err;
    EC_KEY *key = NULL;
    EC_GROUP *group = NULL;

    PRINT_MSG("Create group");
    err = (group = EC_GROUP_new_by_curve_name(nid)) == NULL;
    if (err == 0) {
        PRINT_MSG("Create key with engine");
        err = (key = EC_KEY_new_method(e)) == NULL;
    }
    if (err == 0) {
        PRINT_MSG("Set group");
        err = EC_KEY_set_group(key, group) != 1;
    }
    if (err == 0) {
        PRINT_MSG("Generate key");
        err = EC_KEY_generate_key(key) != 1;
    }

    EC_KEY_free(key);
    EC_GROUP_free(group);

    return err;
}

#ifdef WE_HAVE_EC_P256
static int test_ec_key_keygen_p256_by_nid(ENGINE *e, void *data)
{
    (void)data;
    return test_ec_key_keygen_by_nid(e, NID_X9_62_prime256v1);
}
#endif

#ifdef WE_HAVE_EC_P384
static int test_ec_key_keygen_p384_by_nid(ENGINE *e, void *data)
{
    (void)data;
    return test_ec_key_keygen_by_nid(e, NID_secp384r1);
}
#endif

#endif /* WE_HAVE_ECKEYGEN */

#ifdef WE_HAVE_ECDH

#ifdef WE_HAVE_ECKEYGEN
static int test_ec_key_ecdh_keygen(ENGINE *e, int nid, int len)
{
    int err;
    EC_GROUP *group = NULL;
    EC_KEY *keyA = NULL;
    EC_KEY *keyB = NULL;
    const EC_POINT *pubKeyA;
    const EC_POINT *pubKeyB;
    unsigned char secretA[48];
    unsigned char secretB[48];

    err = (group = EC_GROUP_new_by_curve_name(nid)) == NULL;
    if (err == 0) {
        err = (keyA = EC_KEY_new_method(e)) == NULL;
    }
    if (err == 0) {
        err = EC_KEY_set_group(keyA, group) != 1;
    }
    if (err == 0) {
        err = EC_KEY_generate_key(keyA) != 1;
    }
    if (err == 0) {
        err = (keyB = EC_KEY_new_method(e)) == NULL;
    }
    if (err == 0) {
        err = EC_KEY_set_group(keyB, group) != 1;
    }
    if (err == 0) {
        err = EC_KEY_generate_key(keyB) != 1;
    }
    if (err == 0) {
        err = (pubKeyA = EC_KEY_get0_public_key(keyA)) == NULL;
    }
    if (err == 0) {
        err = (pubKeyB = EC_KEY_get0_public_key(keyB)) == NULL;
    }
    if (err == 0) {
        PRINT_MSG("Derive secret A");
        err = ECDH_compute_key(secretA, len, pubKeyB, keyA, NULL) != len;
    }
    if (err == 0) {
        PRINT_MSG("Derive secret B");
        err = ECDH_compute_key(secretB, len, pubKeyA, keyB, NULL) != len;
    }
    if (err == 0) {
        PRINT_BUFFER("Secret A", secretA, len);
        PRINT_BUFFER("Secret B", secretB, len);
        err = memcmp(secretA, secretB, len) != 0;
        if (err != 0) {
            PRINT_ERR_MSG("Secrets do not match!");
        }
    }

    EC_KEY_free(keyB);
    EC_KEY_free(keyA);
    EC_GROUP_free(group);

    return err;
}

#ifdef WE_HAVE_EC_P256
static int test_ec_key_ecdh_p256_keygen(ENGINE *e, void *data)
{
    (void)data;

    return test_ec_key_ecdh_keygen(e, NID_X9_62_prime256v1, 32);
}
#endif

#ifdef WE_HAVE_EC_P384
static int test_ec_key_ecdh_p384_keygen(ENGINE *e, void *data)
{
    (void)data;

    return test_ec_key_ecdh_keygen(e, NID_secp384r1, 48);
}
#endif
#endif

static int test_ec_key_ecdh(ENGINE *e, const unsigned char *privKey, size_t len,
                            const unsigned char *peerPrivKey, size_t peerLen,
                            const unsigned char *derived, size_t dLen)
{
    int err;
    EC_KEY *keyA = NULL;
    EC_KEY *keyB = NULL;
    const EC_POINT *pubKeyA;
    const EC_POINT *pubKeyB;
    unsigned char secretA[48];
    unsigned char secretB[48];
    const unsigned char *p;

    err = (keyA = EC_KEY_new_method(e)) == NULL;
    if (err == 0) {
        p = privKey;
        err = (keyA = d2i_ECPrivateKey(&keyA, &p, len)) == NULL;
    }
    if (err == 0) {
        err = (keyB = EC_KEY_new_method(e)) == NULL;
    }
    if (err == 0) {
        p = peerPrivKey;
        err = (keyB = d2i_ECPrivateKey(&keyB, &p, peerLen)) == NULL;
    }
    if (err == 0) {
        err = (pubKeyA = EC_KEY_get0_public_key(keyA)) == NULL;
    }
    if (err == 0) {
        err = (pubKeyB = EC_KEY_get0_public_key(keyB)) == NULL;
    }
    if (err == 0) {
        PRINT_MSG("Derive secret A");
        err = ECDH_compute_key(secretA, dLen, pubKeyB, keyA, NULL) != (int)dLen;
    }
    if (err == 0) {
        PRINT_MSG("Derive secret B");
        err = ECDH_compute_key(secretB, dLen, pubKeyA, keyB, NULL) != (int)dLen;
    }
    if (err == 0) {
        PRINT_BUFFER("Secret A", secretA, dLen);
        PRINT_BUFFER("Secret B", secretB, dLen);
        err = memcmp(secretA, secretB, dLen) != 0;
        if (err != 0) {
            PRINT_ERR_MSG("Secrets do not match!");
        }
    }
    if (err == 0) {
        err = memcmp(secretA, derived, dLen) != 0;
        if (err != 0) {
            PRINT_ERR_MSG("Secret does not match, expected!");
        }
    }

    EC_KEY_free(keyB);
    EC_KEY_free(keyA);

    return err;
}

#ifdef WE_HAVE_EC_P256
static int test_ec_key_ecdh_p256(ENGINE *e, void *data)
{
    (void)data;
    return test_ec_key_ecdh(e, ecc_key_der_256, sizeof(ecc_key_der_256),
                            ecc_peerkey_der_256, sizeof(ecc_peerkey_der_256),
                            ecc_derived_256, sizeof(ecc_derived_256));
}
#endif

#ifdef WE_HAVE_EC_P384
static int test_ec_key_ecdh_p384(ENGINE *e, void *data)
{
    (void)data;
    return test_ec_key_ecdh(e, ecc_key_der_384, sizeof(ecc_key_der_384),
                            ecc_peerkey_der_384, sizeof(ecc_peerkey_der_384),
                            ecc_derived_384, sizeof(ecc_derived_384));
}
#endif

#endif /* WE_HAVE_ECDH */

/******************************************************************************/

#ifdef WE_HAVE_ECDSA

static int test_ec_key_ecdsa_sign(EC_KEY *key, unsigned char *hash,
                                  size_t hashLen, unsigned char *ecdsaSig,
                                  size_t *ecdsaSigLen)
{
    int err;
    unsigned int sigLen;

    sigLen = *ecdsaSigLen;
    err = ECDSA_sign(0, hash, hashLen, ecdsaSig, &sigLen, key) != 1;
    if (err == 0) {
        PRINT_BUFFER("Signture", ecdsaSig, sigLen);
    }
    if (err == 0) {
        sigLen = *ecdsaSigLen;
        err = ECDSA_sign(0, hash, hashLen, ecdsaSig, &sigLen, key) != 1;
    }
    if (err == 0) {
        PRINT_BUFFER("Signture", ecdsaSig, sigLen);
        *ecdsaSigLen = sigLen;
    }

    return err;
}

static int test_ec_key_ecdsa_verify(EC_KEY *key, unsigned char *hash,
                                    size_t hashLen, unsigned char *ecdsaSig,
                                    size_t ecdsaSigLen)
{
    int err;

    err = ECDSA_verify(0, hash, hashLen, ecdsaSig, ecdsaSigLen, key) != 1;
    if (err == 0) {
        PRINT_MSG("Signature verified");
    }
    else {
        PRINT_MSG("Signature not verified");
    }
    if (err == 0) {
        err = ECDSA_verify(0, hash, hashLen, ecdsaSig, ecdsaSigLen, key) != 1;
    }
    if (err == 0) {
        PRINT_MSG("Signature verified");
    }
    else {
        PRINT_MSG("Signature not verified");
    }

    return err;
}

static int test_ec_key_ecdsa(ENGINE *e, const unsigned char *privKey,
                             size_t privKeyLen)
{
    int err;
    int res;
    EC_KEY *key = NULL;
    EC_KEY *keyOSSL = NULL;
    unsigned char ecdsaSig[140];
    size_t ecdsaSigLen;
    unsigned char buf[20];
    const unsigned char *p;

    err = RAND_bytes(buf, sizeof(buf)) == 0;
    if (err == 0) {
        err = (key = EC_KEY_new_method(e)) == NULL;
    }
    if (err == 0) {
        p = privKey;
        key = d2i_ECPrivateKey(&key, &p, privKeyLen);
        err = (key == NULL);
    }
    if (err == 0) {
        p = privKey;
        keyOSSL = d2i_ECPrivateKey(NULL, &p, privKeyLen);
        err = (key == NULL);
    }
    if (err == 0) {
        PRINT_MSG("Sign with OpenSSL");
        ecdsaSigLen = sizeof(ecdsaSig);
        err = test_ec_key_ecdsa_sign(keyOSSL, buf, sizeof(buf), ecdsaSig,
                                     &ecdsaSigLen);
    }
    if (err == 0) {
        PRINT_MSG("Verify with wolfengine");
        err = test_ec_key_ecdsa_verify(key, buf, sizeof(buf), ecdsaSig,
                                       ecdsaSigLen);
    }
    if (err == 0) {
        PRINT_MSG("Verify bad signature with wolfengine");
        ecdsaSig[1] ^= 0x80;
        res = test_ec_key_ecdsa_verify(key, buf, sizeof(buf), ecdsaSig,
                                       ecdsaSigLen);
        if (res != 1)
            err = 1;
    }
    if (err == 0) {
        PRINT_MSG("Sign with wolfengine");
        ecdsaSigLen = sizeof(ecdsaSig);
        err = test_ec_key_ecdsa_sign(key, buf, sizeof(buf), ecdsaSig,
                                     &ecdsaSigLen);
    }
    if (err == 0) {
        PRINT_MSG("Verify with OpenSSL");
        err = test_ec_key_ecdsa_verify(keyOSSL, buf, sizeof(buf),
                                       ecdsaSig, ecdsaSigLen);
    }

    EC_KEY_free(keyOSSL);
    EC_KEY_free(key);

    return err;
}


#ifdef WE_HAVE_EC_P256
static int test_ec_key_ecdsa_p256(ENGINE *e, void *data)
{
    (void)data;
    return test_ec_key_ecdsa(e, ecc_key_der_256, sizeof(ecc_key_der_256));
}
#endif

#ifdef WE_HAVE_EC_P384
static int test_ec_key_ecdsa_p384(ENGINE *e, void *data)
{
    (void)data;
    return test_ec_key_ecdsa(e, ecc_key_der_384, sizeof(ecc_key_der_384));
}
#endif

#endif /* WE_HAVE_ECDSA */

#endif /* WE_HAVE_EC_KEY */

#endif /* WE_HAVE_ECC */

/******************************************************************************/

TEST_CASE test_case[] = {
#ifdef WE_HAVE_SHA256
    TEST_DECL(test_sha256),
#endif
#ifdef WE_HAVE_SHA384
    TEST_DECL(test_sha384),
#endif
#ifdef WE_HAVE_SHA512
    TEST_DECL(test_sha512),
#endif
#ifdef WE_HAVE_AESGCM
    TEST_DECL(test_aes128_gcm),
    TEST_DECL(test_aes256_gcm),
    TEST_DECL(test_aes128_gcm_fixed),
    TEST_DECL(test_aes128_gcm_tls),
#endif
#ifdef WE_HAVE_EVP_PKEY
#ifdef WE_HAVE_EC_P256
    #ifdef WE_HAVE_ECKEYGEN
        TEST_DECL(test_eckeygen_p256_by_nid),
        TEST_DECL(test_eckeygen_p256),
    #endif
    #ifdef WE_HAVE_ECDH
    #ifdef WE_HAVE_ECKEYGEN
        TEST_DECL(test_ecdh_p256_keygen),
    #endif
        TEST_DECL(test_ecdh_p256),
    #endif
    #ifdef WE_HAVE_ECDSA
        TEST_DECL(test_ecdsa_p256_pkey),
        TEST_DECL(test_ecdsa_p256),
    #endif
#endif
#ifdef WE_HAVE_EC_P384
    #ifdef WE_HAVE_ECKEYGEN
        TEST_DECL(test_eckeygen_p384_by_nid),
        TEST_DECL(test_eckeygen_p384),
    #endif
    #ifdef WE_HAVE_ECDH
    #ifdef WE_HAVE_ECKEYGEN
        TEST_DECL(test_ecdh_p384_keygen),
    #endif
        TEST_DECL(test_ecdh_p384),
    #endif
    #ifdef WE_HAVE_ECDSA
        TEST_DECL(test_ecdsa_p384_pkey),
        TEST_DECL(test_ecdsa_p384),
    #endif
#endif
#endif /* WE_HAVE_EVP_PKEY */
#ifdef WE_HAVE_EC_KEY
#ifdef WE_HAVE_EC_P256
    #ifdef WE_HAVE_ECKEYGEN
        TEST_DECL(test_ec_key_keygen_p256_by_nid),
    #endif
    #ifdef WE_HAVE_ECDH
    #ifdef WE_HAVE_ECKEYGEN
        TEST_DECL(test_ec_key_ecdh_p256_keygen),
    #endif
        TEST_DECL(test_ec_key_ecdh_p256),
    #endif
    #ifdef WE_HAVE_ECDSA
        TEST_DECL(test_ec_key_ecdsa_p256),
    #endif
#endif
#ifdef WE_HAVE_EC_P384
    #ifdef WE_HAVE_ECKEYGEN
        TEST_DECL(test_ec_key_keygen_p384_by_nid),
    #endif
    #ifdef WE_HAVE_ECDH
    #ifdef WE_HAVE_ECKEYGEN
        TEST_DECL(test_ec_key_ecdh_p384_keygen),
    #endif
        TEST_DECL(test_ec_key_ecdh_p384),
    #endif
    #ifdef WE_HAVE_ECDSA
        TEST_DECL(test_ec_key_ecdsa_p384),
    #endif
#endif
#endif /* WE_HAVE_EC_KEY */
};
#define TEST_CASE_CNT   (int)(sizeof(test_case) / sizeof(*test_case))

static void usage()
{
    printf("\n");
    printf("Usage: unit.test [options]\n");
    printf("  --help          Show this usage information.\n");
    printf("  --dir <path>    Location of wolfengine shared library.\n");
    printf("                  Default: .libs\n");
    printf("  --engine <str>  Name of wolfsslengine. Default: libwolfengine\n");
    printf("  --list          Display all test cases\n");
    printf("  <num>           Run this test case, but not all\n");
}

int main(int argc, char* argv[])
{
    int err = 0;
    ENGINE *e = NULL;
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
    const char *name = "libwolfengine";
#else
    const char *name = "wolfengine";
#endif
    const char *dir = ".libs";
    int i;
    int runAll = 1;
    int runTests = 1;

    for (--argc, ++argv; argc > 0; argc--, argv++) {
        if (strncmp(*argv, "--help", 6) == 0) {
            usage();
            runAll = 0;
            break;
        }
        else if (strncmp(*argv, "--dir", 6) == 0) {
            argc--;
            argv++;
            if (argc == 0) {
                printf("\n");
                printf("Missing directory argument\n");
                usage();
                err = 1;
                break;
            }
            dir = *argv;
            printf("Engine directory: %s\n", dir);
        }
        else if (strncmp(*argv, "--engine", 9) == 0) {
            argc--;
            argv++;
            if (argc == 0) {
                printf("\n");
                printf("Missing engine argument\n");
                usage();
                err = 1;
                break;
            }
            name = *argv;
            printf("Engine: %s\n", name);
        }
        else if (strncmp(*argv, "--list", 7) == 0) {
            for (i = 0; i < TEST_CASE_CNT; i++) {
                printf("%2d: %s\n", i + 1, test_case[i].name);
            }
            runTests = 0;
        }
        else if ((i = atoi(*argv)) > 0) {
            if (i > TEST_CASE_CNT) {
                printf("Test case %d not found\n", i);
                err = 1;
                break;
            }
            
            printf("Run test case: %d\n", i);
            test_case[i-1].run = 1;
            runAll = 0;
        }
        else {
            printf("\n");
            printf("Unrecognisze option: %s\n", *argv);
            usage();
            err = 1;
            break;
        }
    }

    if (err == 0 && runTests) {
        printf("\n");

        /* Set directory where wolfsslengine library is stored */
        setenv("OPENSSL_ENGINES", dir, 1);

    #if OPENSSL_VERSION_NUMBER >= 0x10100000L
        OPENSSL_init_ssl(OPENSSL_INIT_ENGINE_ALL_BUILTIN |
                         OPENSSL_INIT_LOAD_CONFIG, NULL);
    #else
        ENGINE_load_builtin_engines();
    #endif

        e = ENGINE_by_id(name);
        if (e == NULL) {
            PRINT_ERR_MSG("Failed to find engine!\n");
            err = 1;
        }
    }

    if (err == 0 && runTests) {
        printf("###### TESTSUITE START\n");
        printf("\n");

        if (err == 0) {
            for (i = 0; i < TEST_CASE_CNT; i++) {
                if (!runAll && !test_case[i].run) {
                    continue;
                }

                printf("#### Start: %d - %s\n", i + 1, test_case[i].name);

                test_case[i].err = test_case[i].func(e, NULL);
                test_case[i].done = 1;

                if (!test_case[i].err)
                    printf("#### SUCCESS: %d - %s\n", i + 1, test_case[i].name);
                else
                    printf("#### FAILED: %d - %s\n", i + 1, test_case[i].name);
                printf("\n");
            }

            for (i = 0; i < TEST_CASE_CNT; i++) {
                if (test_case[i].done && test_case[i].err != 0) {
                    err = test_case[i].err;
                    break;
                }
            }
        }

        if (err == 0) {
            printf("###### TESTSUITE SUCCESS\n");
        }
        else {
            for (i = 0; i < TEST_CASE_CNT; i++) {
                if (test_case[i].err) {
                    printf("## FAIL: %d: %s\n", i + 1, test_case[i].name);
                }
            }
            printf("###### TESTSUITE FAILED\n");
        }

        ENGINE_free(e);
    #if OPENSSL_VERSION_NUMBER >= 0x10100000L
        OPENSSL_cleanup();
    #endif
    }

    return err;
}

