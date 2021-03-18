/* bench.c
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

#include <stdio.h>
#include <sys/time.h>
#include <string.h>

#include <openssl/engine.h>
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/ssl.h>
#include <openssl/aes.h>

#include "openssl_bc.h"

#define BENCH_DECL(alg, func)        { alg, func, 0 }

typedef int (*BENCH_FUNC)(ENGINE *e);
typedef struct BENCH_ALG {
    const char *alg;
    BENCH_FUNC  func;
    int         run;
} BENCH_ALG;

#define BENCH_DECLS     struct timeval start, end
#define BENCH_START()   gettimeofday(&start, NULL)
#define BENCH_COND(t)   ((gettimeofday(&end, NULL) == 0) &&   \
                         ((end.tv_sec < ((t)+start.tv_sec)) || \
                          (end.tv_usec < start.tv_usec)))
#define BENCH_SECS()    end.tv_sec - start.tv_sec + \
                        (end.tv_usec - start.tv_usec) / 1000000.0;

#if defined(WE_HAVE_DIGEST) || defined(WE_HAVE_AESGCM)
static unsigned char data[16384];
#endif

#ifdef WE_HAVE_DIGEST
static size_t dgst_len[] = { 16, 64, 256, 1024, 8192, 16384 };
#define DGST_LEN_SIZE    (sizeof(dgst_len) / sizeof(*dgst_len))

static int digest_bench(ENGINE *e, const char *alg, const EVP_MD *md,
                        size_t len)
{
    int err = 0;
    unsigned int i;
    unsigned int max = 16384 / len;
    unsigned char digest[64];
    unsigned int cnt = 0;
    double secs;
    BENCH_DECLS;

    BENCH_START();
    do {
        for (i = 0; i < max; i++) {
            err |= EVP_Digest(data, len, digest, NULL, md, e) != 1;
        }
        cnt += i;
    }
    while (BENCH_COND(1));

    secs = BENCH_SECS();
    printf("%-14s %5ld B/op  %10.2f kB/sec %14.6f us/B\n", alg, len,
           (len * cnt) / secs / 1000.0, secs * 1000000.0 / (len * cnt));

    return err;
}

#ifdef WE_HAVE_SHA256
static int sha256_bench(ENGINE *e)
{
    int err = 0;
    size_t i;

    for (i = 0; err == 0 && i < DGST_LEN_SIZE; i++) {
        err = digest_bench(e, "SHA256", EVP_sha256(), dgst_len[i]);
    }

    return err;
}
#endif

#ifdef WE_HAVE_SHA384
static int sha384_bench(ENGINE *e)
{
    int err = 0;
    size_t i;

    for (i = 0; err == 0 && i < DGST_LEN_SIZE; i++) {
        err = digest_bench(e, "SHA384", EVP_sha384(), dgst_len[i]);
    }

    return err;
}
#endif

#ifdef WE_HAVE_SHA512
static int sha512_bench(ENGINE *e)
{
    int err = 0;
    size_t i;

    for (i = 0; err == 0 && i < DGST_LEN_SIZE; i++) {
        err = digest_bench(e, "SHA512", EVP_sha512(), dgst_len[i]);
    }

    return err;
}
#endif

#ifdef WE_HAVE_SHA3_224
static int sha3_224_bench(ENGINE *e)
{
    int err = 0;
    size_t i;

    for (i = 0; err == 0 && i < DGST_LEN_SIZE; i++) {
        err = digest_bench(e, "SHA3-224", EVP_sha3_224(), dgst_len[i]);
    }

    return err;
}
#endif

#ifdef WE_HAVE_SHA3_256
static int sha3_256_bench(ENGINE *e)
{
    int err = 0;
    size_t i;

    for (i = 0; err == 0 && i < DGST_LEN_SIZE; i++) {
        err = digest_bench(e, "SHA3-256", EVP_sha3_256(), dgst_len[i]);
    }

    return err;
}
#endif

#ifdef WE_HAVE_SHA3_384
static int sha3_384_bench(ENGINE *e)
{
    int err = 0;
    size_t i;

    for (i = 0; err == 0 && i < DGST_LEN_SIZE; i++) {
        err = digest_bench(e, "SHA3-384", EVP_sha3_384(), dgst_len[i]);
    }

    return err;
}
#endif

#ifdef WE_HAVE_SHA3_512
static int sha3_512_bench(ENGINE *e)
{
    int err = 0;
    size_t i;

    for (i = 0; err == 0 && i < DGST_LEN_SIZE; i++) {
        err = digest_bench(e, "SHA3-512", EVP_sha3_512(), dgst_len[i]);
    }

    return err;
}
#endif

#endif /* WE_HAVE_DIGEST */

#ifdef WE_HAVE_AESGCM
static size_t aesgcm_len[] = { 2, 31, 136, 1024, 8192, 16384 };
#define AEGCM_LEN_SIZE    (sizeof(aesgcm_len) / sizeof(*aesgcm_len))

static int aesgcm_enc_bench(const char *alg, EVP_CIPHER_CTX *ctx, size_t len)
{
    int err = 0;
    unsigned int i;
    unsigned int max = 16384 / len;
    unsigned char aad[13];
    unsigned char iv[12];
    unsigned char tag[16];
    int outLen;
    unsigned int cnt = 0;
    double secs;
    BENCH_DECLS;

    RAND_bytes(aad, sizeof(aad));
    RAND_bytes(iv, sizeof(iv));
    RAND_bytes(tag, sizeof(tag));

    BENCH_START();
    do {
        for (i = 0; i < max; i++) {
            outLen = sizeof(data);
            err |= EVP_EncryptInit_ex(ctx, NULL, NULL, NULL, iv) != 1;
            err |= EVP_EncryptUpdate(ctx, NULL, &outLen, aad, sizeof(aad)) != 1;
            err |= EVP_EncryptUpdate(ctx, data, &outLen, data, len) != 1;
            err |= EVP_EncryptFinal_ex(ctx, data + outLen, &outLen) != 1;
            err |= EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, sizeof(tag),
                                       tag) != 1;
        }
        cnt += i;
    }
    while (BENCH_COND(1));

    secs = BENCH_SECS();
    printf("%-8s enc %5ld B/op  %10.2f kB/sec %14.6f us/B\n", alg, len,
           (len * cnt) / secs / 1000.0, secs * 1000000.0 / (len * cnt));

    return err;
}

static int aesgcm_dec_bench(const char *alg, EVP_CIPHER_CTX *ctx, size_t len)
{
    int err = 0;
    unsigned int i;
    unsigned int max = 16384 / len;
    unsigned char aad[13];
    unsigned char iv[12];
    unsigned char tag[16];
    int outLen;
    unsigned int cnt = 0;
    double secs;
    BENCH_DECLS;

    RAND_bytes(aad, sizeof(aad));
    RAND_bytes(iv, sizeof(iv));
    RAND_bytes(tag, sizeof(tag));

    BENCH_START();
    do {
        for (i = 0; i < max; i++) {
            outLen = sizeof(data);
            err |= EVP_DecryptInit_ex(ctx, NULL, NULL, NULL, iv) != 1;
            err |= EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, sizeof(tag),
                                       tag) != 1;
            err |= EVP_DecryptUpdate(ctx, NULL, &outLen, aad, sizeof(aad)) != 1;
            err |= EVP_DecryptUpdate(ctx, data, &outLen, data, len) != 1;
            EVP_DecryptFinal_ex(ctx, data + outLen, &outLen);
            /* Ignore error as the tag doesn't match the data. */
        }
        cnt += i;
    }
    while (BENCH_COND(1));

    secs = BENCH_SECS();
    printf("%-8s dec %5ld B/op  %10.2f kB/sec %14.6f us/B\n", alg, len,
           (len * cnt) / secs / 1000.0, secs * 1000000.0 / (len * cnt));

    return err;
}

static int aes128_gcm_bench(ENGINE *e)
{
    int err = 0;
    EVP_CIPHER_CTX *ctx = NULL;
    unsigned char key[16] = {0,};
    size_t i;

    err = RAND_bytes(key, sizeof(key)) == 0;

    if (err == 0) {
        err = (ctx = EVP_CIPHER_CTX_new()) == NULL;
    }
    if (err == 0) {
        err = EVP_CipherInit_ex(ctx, EVP_aes_128_gcm(), e, key, NULL, 1) != 1;
    }
    if (err == 0) {
        for (i = 0; err == 0 && i < DGST_LEN_SIZE; i++) {
            err = aesgcm_enc_bench("AES128-GCM", ctx, aesgcm_len[i]);
        }
    }
    if (err == 0) {
        err = EVP_CipherInit_ex(ctx, EVP_aes_128_gcm(), e, key, NULL, 0) != 1;
    }
    if (err == 0) {
        for (i = 0; err == 0 && i < DGST_LEN_SIZE; i++) {
            err = aesgcm_dec_bench("AES128-GCM", ctx, aesgcm_len[i]);
        }
    }

    EVP_CIPHER_CTX_free(ctx);

    return err;
}

static int aes256_gcm_bench(ENGINE *e)
{
    int err = 0;
    EVP_CIPHER_CTX *ctx = NULL;
    unsigned char key[32] = {0,};
    size_t i;

    err = RAND_bytes(key, sizeof(key)) == 0;

    if (err == 0) {
        err = (ctx = EVP_CIPHER_CTX_new()) == NULL;
    }
    if (err == 0) {
        err = EVP_CipherInit_ex(ctx, EVP_aes_256_gcm(), e, key, NULL, 1) != 1;
    }
    if (err == 0) {
        for (i = 0; err == 0 && i < DGST_LEN_SIZE; i++) {
            err = aesgcm_enc_bench("AES256-GCM", ctx, aesgcm_len[i]);
        }
    }
    if (err == 0) {
        err = EVP_CipherInit_ex(ctx, EVP_aes_256_gcm(), e, key, NULL, 0) != 1;
    }
    if (err == 0) {
        for (i = 0; err == 0 && i < DGST_LEN_SIZE; i++) {
            err = aesgcm_dec_bench("AES256-GCM", ctx, aesgcm_len[i]);
        }
    }

    EVP_CIPHER_CTX_free(ctx);

    return err;
}
#endif

#ifdef WE_HAVE_EVP_PKEY

#ifdef WE_HAVE_ECKEYGEN
static int eckg_bench(ENGINE *e, int nid, const char *curve)
{
    int err;
    EVP_PKEY_CTX *ctx;
    EVP_PKEY *key;
    unsigned int cnt = 0;
    double secs;
    BENCH_DECLS;

    err = (ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, e)) == NULL;
    if (err == 0) {
        err = EVP_PKEY_keygen_init(ctx) != 1;
    }
    if (err == 0) {
        err = EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx, nid) != 1;
    }
    if (err == 0) {
        BENCH_START();
        do {
            key = NULL;
            err |= EVP_PKEY_keygen(ctx, &key) != 1;
            EVP_PKEY_free(key);
            cnt++;
        }
        while (BENCH_COND(1));

        secs = BENCH_SECS();
        printf("%-5s EVP keygen %10.2f ops/sec %12.3f us/op\n", curve,
               cnt / secs, secs / cnt * 1000000);
    }

    EVP_PKEY_CTX_free(ctx);

    return err;
}

#ifdef WE_HAVE_EC_P256
static int eckg_p256_bench(ENGINE *e)
{
    return eckg_bench(e, NID_X9_62_prime256v1, "P-256");
}
#endif

#ifdef WE_HAVE_EC_P384
static int eckg_p384_bench(ENGINE *e)
{
    return eckg_bench(e, NID_secp384r1, "P-384");
}
#endif
#endif

#ifdef WE_HAVE_ECDH
static int ecdh_bench(ENGINE *e, int nid, const char *curve)
{
    int err;
    EVP_PKEY_CTX *kgCtx;
    EVP_PKEY_CTX *ctx = NULL;
    EVP_PKEY *key = NULL;
    EVP_PKEY *peerKey = NULL;
    unsigned char secret[48];
    size_t outLen;
    unsigned int cnt = 0;
    double secs;
    BENCH_DECLS;

    err = (kgCtx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, e)) == NULL;
    if (err == 0) {
        err = EVP_PKEY_keygen_init(kgCtx) != 1;
    }
    if (err == 0) {
        err = EVP_PKEY_CTX_set_ec_paramgen_curve_nid(kgCtx, nid) != 1;
    }
    if (err == 0) {
        err = EVP_PKEY_keygen(kgCtx, &key) != 1;
    }
    if (err == 0) {
        err = EVP_PKEY_keygen(kgCtx, &peerKey) != 1;
    }
    if (err == 0) {
        err = (ctx = EVP_PKEY_CTX_new(key, e)) == NULL;
    }
    if (err == 0) {
        err = EVP_PKEY_derive_init(ctx) != 1;
    }
    if (err == 0) {
        err = EVP_PKEY_derive_set_peer(ctx, peerKey) != 1;
    }
    if (err == 0) {
        BENCH_START();
        do {
            outLen = sizeof(secret);
            err |= EVP_PKEY_derive(ctx, secret, &outLen) != 1;
            cnt++;
        }
        while (BENCH_COND(1));

        secs = BENCH_SECS();
        printf("%-5s EVP derive %10.2f ops/sec %12.3f us/op\n", curve,
               cnt / secs, secs / cnt * 1000000);
    }

    EVP_PKEY_free(peerKey);
    EVP_PKEY_free(key);
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_CTX_free(kgCtx);

    return err;
}

#ifdef WE_HAVE_EC_P256
static int ecdh_p256_bench(ENGINE *e)
{
    return ecdh_bench(e, NID_X9_62_prime256v1, "P-256");
}
#endif

#ifdef WE_HAVE_EC_P384
static int ecdh_p384_bench(ENGINE *e)
{
    return ecdh_bench(e, NID_secp384r1, "P-384");
}
#endif
#endif

#ifdef WE_HAVE_ECDSA
static int ecdsa_sign_bench(ENGINE *e, EVP_PKEY *pkey, const EVP_MD* md,
                            const char* curve, unsigned char *sig, size_t *len)
{
    int err = 0;
    unsigned char buf[20] = {0,};
    unsigned char ecdsaSig[120];
    size_t ecdsaSigLen = 0;
    EVP_MD_CTX *mdCtx;
    EVP_PKEY_CTX *pkeyCtx = NULL;
    unsigned int cnt = 0;
    double secs;
    BENCH_DECLS;

    err = (mdCtx = EVP_MD_CTX_new()) == NULL;
    if (err == 0) {
        BENCH_START();
        do {
            ecdsaSigLen = sizeof(ecdsaSig);
            err |= EVP_DigestSignInit(mdCtx, &pkeyCtx, md, e, pkey) != 1;
#if OPENSSL_VERSION_NUMBER >= 0x1010100fL
            err |= EVP_DigestSign(mdCtx, ecdsaSig, &ecdsaSigLen, buf,
                                  sizeof(buf)) != 1;
#else
            err |= EVP_DigestSignUpdate(mdCtx, buf, sizeof(buf)) != 1;
            err |= EVP_DigestSignFinal(mdCtx, ecdsaSig, &ecdsaSigLen) != 1;
#endif
            cnt++;
        }
        while (BENCH_COND(1));

        secs = BENCH_SECS();
        printf("%-5s EVP sign   %10.2f ops/sec %12.3f us/op\n", curve,
               cnt / secs, secs / cnt * 1000000);
    }

    if (err == 0) {
        memcpy(sig, ecdsaSig, ecdsaSigLen);
        *len = ecdsaSigLen;
    }
    
    EVP_MD_CTX_free(mdCtx);

    return err;
}

static int ecdsa_verify_bench(ENGINE *e, EVP_PKEY *pkey, const EVP_MD* md,
                              const char* curve, unsigned char* sig, size_t len)
{
    int err = 0;
    unsigned char buf[20] = {0,};
    EVP_MD_CTX *mdCtx;
    EVP_PKEY_CTX *pkeyCtx = NULL;
    unsigned int cnt = 0;
    double secs;
    BENCH_DECLS;

    err = (mdCtx = EVP_MD_CTX_new()) == NULL;
    if (err == 0) {
        BENCH_START();
        do {
            err |= EVP_DigestVerifyInit(mdCtx, &pkeyCtx, md, e, pkey) != 1;
#if OPENSSL_VERSION_NUMBER >= 0x1010100fL
            err |= EVP_DigestVerify(mdCtx, sig, len, buf, sizeof(buf)) != 1;
#else
            err |= EVP_DigestVerifyUpdate(mdCtx, buf, sizeof(buf)) != 1;
            err |= EVP_DigestVerifyFinal(mdCtx, sig, len) != 1;
#endif
            cnt++;
        }
        while (BENCH_COND(1));

        secs = BENCH_SECS();
        printf("%-5s EVP verify %10.2f ops/sec %12.3f us/op\n", curve,
               cnt / secs, secs / cnt * 1000000);
    }

    EVP_MD_CTX_free(mdCtx);

    return err;
}

#ifdef WE_HAVE_EC_P256
static int ecdsa_p256_bench(ENGINE *e)
{
    int err;
    unsigned char sig[100];
    size_t len;
    EVP_PKEY_CTX *kgCtx;
    EVP_PKEY *key = NULL;

    err = (kgCtx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, e)) == NULL;
    if (err == 0) {
        err = EVP_PKEY_keygen_init(kgCtx) != 1;
    }
    if (err == 0) {
        err = EVP_PKEY_CTX_set_ec_paramgen_curve_nid(kgCtx,
                                                     NID_X9_62_prime256v1) != 1;
    }
    if (err == 0) {
        err = EVP_PKEY_keygen(kgCtx, &key) != 1;
    }
    if (err == 0) {
        err = ecdsa_sign_bench(e, key, EVP_sha256(), "P-256", sig, &len);
    }
    if (err == 0) {
        err = ecdsa_verify_bench(e, key, EVP_sha256(), "P-256", sig, len);
    }

    EVP_PKEY_free(key);
    EVP_PKEY_CTX_free(kgCtx);

    return err;
}
#endif

#ifdef WE_HAVE_EC_P384
static int ecdsa_p384_bench(ENGINE *e)
{
    int err;
    unsigned char sig[120];
    size_t len;
    EVP_PKEY_CTX *kgCtx;
    EVP_PKEY *key = NULL;

    err = (kgCtx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, e)) == NULL;
    if (err == 0) {
        err = EVP_PKEY_keygen_init(kgCtx) != 1;
    }
    if (err == 0) {
        err = EVP_PKEY_CTX_set_ec_paramgen_curve_nid(kgCtx, NID_secp384r1) != 1;
    }
    if (err == 0) {
        err = EVP_PKEY_keygen(kgCtx, &key) != 1;
    }
    if (err == 0) {
        err = ecdsa_sign_bench(e, key, EVP_sha384(), "P-384", sig, &len);
    }
    if (err == 0) {
        err = ecdsa_verify_bench(e, key, EVP_sha384(), "P-384", sig, len);
    }

    EVP_PKEY_free(key);
    EVP_PKEY_CTX_free(kgCtx);

    return err;
}
#endif
#endif

#endif /* WE_HAVE_EVP_PKEY */

#ifdef WE_HAVE_EC_KEY

#ifdef WE_HAVE_ECKEYGEN
static int eckg_ec_key_bench(ENGINE *e, int nid, const char *curve)
{
    int err;
    EC_GROUP *group = NULL;
    EC_KEY *key = NULL;
    unsigned int cnt = 0;
    double secs;
    BENCH_DECLS;

    err = (group = EC_GROUP_new_by_curve_name(nid)) == NULL;
    if (err == 0) {
        err = (key = EC_KEY_new_method(e)) == NULL;
    }
    if (err == 0) {
        err = EC_KEY_set_group(key, group) != 1;
    }

    if (err == 0) {
        BENCH_START();
        do {
            err |= EC_KEY_generate_key(key) != 1;
            cnt++;
        }
        while (BENCH_COND(1));

        secs = BENCH_SECS();
        printf("%-5s KEY keygen %10.2f ops/sec %12.3f us/op\n", curve,
               cnt / secs, secs / cnt * 1000000);
    }

    EC_KEY_free(key);
    EC_GROUP_free(group);

    return err;
}

#ifdef WE_HAVE_EC_P256
static int eckg_ec_key_p256_bench(ENGINE *e)
{
    return eckg_ec_key_bench(e, NID_X9_62_prime256v1, "P-256");
}
#endif

#ifdef WE_HAVE_EC_P384
static int eckg_ec_key_p384_bench(ENGINE *e)
{
    return eckg_ec_key_bench(e, NID_secp384r1, "P-384");
}
#endif
#endif

#ifdef WE_HAVE_ECDH
static int ecdh_ec_key_bench(ENGINE *e, int nid, const char *curve, int len)
{
    int err;
    EC_GROUP *group = NULL;
    EC_KEY *key = NULL;
    EC_KEY *peerKey = NULL;
    const EC_POINT *pubKey = NULL;
    unsigned char secret[48];
    size_t outLen;
    unsigned int cnt = 0;
    double secs;
    BENCH_DECLS;

    err = (group = EC_GROUP_new_by_curve_name(nid)) == NULL;
    if (err == 0) {
        err = (key = EC_KEY_new_method(e)) == NULL;
    }
    if (err == 0) {
        err = EC_KEY_set_group(key, group) != 1;
    }
    if (err == 0) {
        err = EC_KEY_generate_key(key) != 1;
    }
    if (err == 0) {
        err = (peerKey = EC_KEY_new_method(e)) == NULL;
    }
    if (err == 0) {
        err = EC_KEY_set_group(peerKey, group) != 1;
    }
    if (err == 0) {
        err = EC_KEY_generate_key(peerKey) != 1;
    }
    if (err == 0) {
        err = (pubKey = EC_KEY_get0_public_key(peerKey)) == NULL;
    }

    if (err == 0) {
        BENCH_START();
        do {
            outLen = sizeof(secret);
            err |=  ECDH_compute_key(secret, outLen, pubKey, key, NULL) != len;
            cnt++;
        }
        while (BENCH_COND(1));

        secs = BENCH_SECS();
        printf("%-5s KEY derive %10.2f ops/sec %12.3f us/op\n", curve,
               cnt / secs, secs / cnt * 1000000);
    }

    EC_KEY_free(peerKey);
    EC_KEY_free(key);

    return err;
}

#ifdef WE_HAVE_EC_P256
static int ecdh_ec_key_p256_bench(ENGINE *e)
{
    return ecdh_ec_key_bench(e, NID_X9_62_prime256v1, "P-256", 32);
}
#endif

#ifdef WE_HAVE_EC_P384
static int ecdh_ec_key_p384_bench(ENGINE *e)
{
    return ecdh_ec_key_bench(e, NID_secp384r1, "P-384", 48);
}
#endif
#endif

#ifdef WE_HAVE_ECDSA
static int ecdsa_ec_key_sign_bench(EC_KEY *key, const char* curve, int dLen,
                                   unsigned char *sig, size_t *len)
{
    int err = 0;
    unsigned char dgst[48] = {0,};
    unsigned char ecdsaSig[120];
    unsigned int ecdsaSigLen = 0;
    unsigned int cnt = 0;
    double secs;
    BENCH_DECLS;

    if (err == 0) {
        BENCH_START();
        do {
            ecdsaSigLen = sizeof(ecdsaSig);
            err |= ECDSA_sign(0, dgst, dLen, ecdsaSig, &ecdsaSigLen, key) != 1;
            cnt++;
        }
        while (BENCH_COND(1));

        secs = BENCH_SECS();
        printf("%-5s KEY sign   %10.2f ops/sec %12.3f us/op\n", curve,
               cnt / secs, secs / cnt * 1000000);
    }

    if (err == 0) {
        memcpy(sig, ecdsaSig, ecdsaSigLen);
        *len = ecdsaSigLen;
    }
    
    return err;
}

static int ecdsa_ec_key_verify_bench(EC_KEY *key, const char* curve, int dLen,
                                     unsigned char* sig, size_t len)
{
    int err = 0;
    unsigned char dgst[48] = {0,};
    unsigned int cnt = 0;
    double secs;
    BENCH_DECLS;

    if (err == 0) {
        BENCH_START();
        do {
            err |= ECDSA_verify(0, dgst, dLen, sig, (int)len, key) != 1;
            cnt++;
        }
        while (BENCH_COND(1));

        secs = BENCH_SECS();
        printf("%-5s KEY verify %10.2f ops/sec %12.3f us/op\n", curve,
               cnt / secs, secs / cnt * 1000000);
    }

    return err;
}

#ifdef WE_HAVE_EC_P256
static int ecdsa_ec_key_p256_bench(ENGINE *e)
{
    int err;
    unsigned char sig[100];
    size_t len;
    EC_GROUP *group = NULL;
    EC_KEY *key = NULL;

    err = (group = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1)) == NULL;
    if (err == 0) {
        err = (key = EC_KEY_new_method(e)) == NULL;
    }
    if (err == 0) {
        err = EC_KEY_set_group(key, group) != 1;
    }
    if (err == 0) {
        err = EC_KEY_generate_key(key) != 1;
    }
    if (err == 0) {
        err = ecdsa_ec_key_sign_bench(key, "P-256", 32, sig, &len);
    }
    if (err == 0) {
        err = ecdsa_ec_key_verify_bench(key, "P-256", 32, sig, len);
    }

    EC_KEY_free(key);
    EC_GROUP_free(group);

    return err;
}
#endif

#ifdef WE_HAVE_EC_P384
static int ecdsa_ec_key_p384_bench(ENGINE *e)
{
    int err;
    unsigned char sig[140];
    size_t len;
    EC_GROUP *group = NULL;
    EC_KEY *key = NULL;

    err = (group = EC_GROUP_new_by_curve_name(NID_secp384r1)) == NULL;
    if (err == 0) {
        err = (key = EC_KEY_new_method(e)) == NULL;
    }
    if (err == 0) {
        err = EC_KEY_set_group(key, group) != 1;
    }
    if (err == 0) {
        err = EC_KEY_generate_key(key) != 1;
    }
    if (err == 0) {
        err = ecdsa_ec_key_sign_bench(key, "P-384", 48, sig, &len);
    }
    if (err == 0) {
        err = ecdsa_ec_key_verify_bench(key, "P-384", 48, sig, len);
    }

    EC_KEY_free(key);
    EC_GROUP_free(group);

    return err;
}
#endif
#endif

#endif /* WE_HAVE_EVP_PKEY */

BENCH_ALG bench_alg[] = {
#ifdef WE_HAVE_SHA256
    BENCH_DECL("SHA256", sha256_bench),
#endif
#ifdef WE_HAVE_SHA384
    BENCH_DECL("SHA384", sha384_bench),
#endif
#ifdef WE_HAVE_SHA512
    BENCH_DECL("SHA512", sha512_bench),
#endif
#ifdef WE_HAVE_SHA3_224
    BENCH_DECL("SHA3_224", sha3_224_bench),
#endif
#ifdef WE_HAVE_SHA3_256
    BENCH_DECL("SHA3_256", sha3_256_bench),
#endif
#ifdef WE_HAVE_SHA3_384
    BENCH_DECL("SHA3_384", sha3_384_bench),
#endif
#ifdef WE_HAVE_SHA3_512
    BENCH_DECL("SHA3_512", sha3_512_bench),
#endif
#ifdef WE_HAVE_AESGCM
    BENCH_DECL("AES128-GCM", aes128_gcm_bench),
    BENCH_DECL("AES256-GCM", aes256_gcm_bench),
#endif
#ifdef WE_HAVE_EVP_PKEY
#ifdef WE_HAVE_EC_P256
    #ifdef WE_HAVE_ECKEYGEN
        BENCH_DECL("ECKG-P256", eckg_p256_bench),
    #endif
    #ifdef WE_HAVE_ECDH
        BENCH_DECL("ECDH-P256", ecdh_p256_bench),
    #endif
    #ifdef WE_HAVE_ECDSA
        BENCH_DECL("ECDSA-P256", ecdsa_p256_bench),
    #endif
#endif
#ifdef WE_HAVE_EC_P384
    #ifdef WE_HAVE_ECKEYGEN
        BENCH_DECL("ECKG-P384", eckg_p384_bench),
    #endif
    #ifdef WE_HAVE_ECDH
        BENCH_DECL("ECDH-P384", ecdh_p384_bench),
    #endif
    #ifdef WE_HAVE_ECDSA
        BENCH_DECL("ECDSA-P384", ecdsa_p384_bench),
    #endif
#endif
#endif
#ifdef WE_HAVE_EC_KEY
#ifdef WE_HAVE_EC_P256
    #ifdef WE_HAVE_ECKEYGEN
        BENCH_DECL("ECKG-ECKEY-P256", eckg_ec_key_p256_bench),
    #endif
    #ifdef WE_HAVE_ECDH
        BENCH_DECL("ECDH-ECKEY-P256", ecdh_ec_key_p256_bench),
    #endif
    #ifdef WE_HAVE_ECDSA
        BENCH_DECL("ECDSA-ECKEY-P256", ecdsa_ec_key_p256_bench),
    #endif
#endif
#ifdef WE_HAVE_EC_P384
    #ifdef WE_HAVE_ECKEYGEN
        BENCH_DECL("ECKG-ECKEY-P384", eckg_ec_key_p384_bench),
    #endif
    #ifdef WE_HAVE_ECDH
        BENCH_DECL("ECDH-ECKEY-P384", ecdh_ec_key_p384_bench),
    #endif
    #ifdef WE_HAVE_ECDSA
        BENCH_DECL("ECDSA-ECKEY-P384", ecdsa_ec_key_p384_bench),
    #endif
#endif
#endif
};
#define BENCH_ALG_COUNT  (int)(sizeof(bench_alg) / sizeof(*bench_alg))

static void usage()
{
    printf("\n");
    printf("Usage: bench [options]\n");
    printf("  --help          Show this usage information.\n");
    printf("  --dir <path>    Location of wolfengine shared library.\n");
    printf("                  Default: .libs\n");
    printf("  --engine <str>  Name of wolfsslengine. Default: libwolfengine\n");
    printf("  --no-engine     Do not use an engine - use OpenSSL direct\n");
    printf("  --list          Display all algorithms\n");
    printf("  <num>           Run this bench case, but not all\n");
    printf("  <name>          Run this bench case, but not all\n");
}

int main(int argc, char *argv[])
{
    int err = 0;
    ENGINE *e = NULL;
#if OPENSSL_VERSION_NUMBER >= 0x10101004L
    const char *name = "libwolfengine";
#else
    const char *name = "wolfengine";
#endif
    const char *dir = ".libs";
    int i;
    int runAll = 1;
    int runBench = 1;

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
        else if (strncmp(*argv, "--no-engine", 9) == 0) {
            name = NULL;
        }
        else if (strncmp(*argv, "--list", 7) == 0) {
            for (i = 0; i < BENCH_ALG_COUNT; i++) {
                printf("%2d: %s\n", i + 1, bench_alg[i].alg);
            }
            runBench = 0;
        }
        else if ((i = atoi(*argv)) > 0) {
            if (i > BENCH_ALG_COUNT) {
                printf("Test case %d not found\n", i);
                err = 1;
                break;
            }

            printf("Run bench: %d - %s\n", i, bench_alg[i-1].alg);
            bench_alg[i-1].run = 1;
            runAll = 0;
        }
        else {
            for (i = 0; i < BENCH_ALG_COUNT; i++) {
                if (strncmp(*argv, bench_alg[i].alg,
                            strlen(bench_alg[i].alg)) == 0) {
                    bench_alg[i].run = 1;
                    runAll = 0;
                    break;
                }
            }
            if (i == BENCH_ALG_COUNT) {
                printf("\n");
                printf("Unrecognisze option: %s\n", *argv);
                usage();
                err = 1;
                break;
            }
        }
    }

    if (err == 0 && runBench && name != NULL) {
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
            printf("ERR: Failed to find engine!");
            err = 1;
        }
    }
    else if (err == 0 && runBench) {
        printf("\n");

        OPENSSL_init();
    }

    if (err == 0 && runBench) {
        for (i = 0; i < BENCH_ALG_COUNT; i++) {
            if (!runAll && !bench_alg[i].run) {
                continue;
            }

            if (bench_alg[i].func(e) != 0) {
                printf("Error during benchmark operation\n");
            }
        }

        ENGINE_free(e);
    #if OPENSSL_VERSION_NUMBER >= 0x10100000L
        OPENSSL_cleanup();
    #endif
    }

    return err;
}
