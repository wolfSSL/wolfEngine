/* test_hmac.c
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
#include <stdint.h>
#include <wolfssl/wolfcrypt/hmac.h>
#include <wolfengine/we_internal.h>

#ifdef WE_HAVE_HMAC

#if defined(WOLF_CRYPTO_CB) && defined(WOLF_CRYPTO_CB_FIND) && \
    !defined(TEST_MULTITHREADED)
#include <openssl/hmac.h>
#include <wolfssl/wolfcrypt/cryptocb.h>

#define TEST_HMAC_CB_DEVID 27182

typedef struct TestHmacCallback {
    byte expectedKey[64];
    uintptr_t sourceKey;
    int stage;
} TestHmacCallback;

static TestHmacCallback* testHmacCallback;

static int test_hmac_find_device(int devId, int algoType)
{
    if (testHmacCallback != NULL && algoType == WC_ALGO_TYPE_HMAC &&
            devId == INVALID_DEVID) {
        return TEST_HMAC_CB_DEVID;
    }
    return devId;
}

static int test_hmac_crypto_callback(int devId, wc_CryptoInfo* info,
    void* context)
{
    static const byte message[] = "Hi There";
    TestHmacCallback* state = (TestHmacCallback*)context;
    const byte* key;
    unsigned int macLen = 0;

    if (info == NULL || info->algo_type != WC_ALGO_TYPE_HMAC)
        return CRYPTOCB_UNAVAILABLE;
    if (devId != TEST_HMAC_CB_DEVID || state == NULL ||
            info->hmac.hmac == NULL || info->hmac.macType != WC_SHA256)
        return BAD_FUNC_ARG;

    key = info->hmac.hmac->keyRaw;
    if (key == NULL || info->hmac.hmac->keyLen != sizeof(state->expectedKey) ||
            memcmp(key, state->expectedKey, sizeof(state->expectedKey)) != 0)
        return BAD_FUNC_ARG;

    if (state->stage == 0 && info->hmac.digest == NULL &&
            info->hmac.inSz == 3 && memcmp(info->hmac.in, "Hi ", 3) == 0) {
        state->sourceKey = (uintptr_t)key;
        state->stage = 1;
        return 0;
    }
    if (state->stage == 1 && info->hmac.digest == NULL &&
            info->hmac.inSz == 5 && memcmp(info->hmac.in, "There", 5) == 0 &&
            (uintptr_t)key != state->sourceKey) {
        state->stage = 2;
        return 0;
    }
    if (state->stage == 2 && info->hmac.in == NULL &&
            info->hmac.digest != NULL &&
            HMAC(EVP_sha256(), key, info->hmac.hmac->keyLen, message,
                sizeof(message) - 1, info->hmac.digest, &macLen) != NULL &&
            macLen == 32) {
        state->stage = 3;
        return 0;
    }
    return BAD_FUNC_ARG;
}

static int test_hmac_callback_copy(ENGINE* e, void* data)
{
    static const byte expected[32] = {
        0xb0, 0x34, 0x4c, 0x61, 0xd8, 0xdb, 0x38, 0x53,
        0x5c, 0xa8, 0xaf, 0xce, 0xaf, 0x0b, 0xf1, 0x2b,
        0x88, 0x1d, 0xc2, 0x00, 0xc9, 0x83, 0x3d, 0xa7,
        0x26, 0xe9, 0x37, 0x6c, 0x2e, 0x32, 0xcf, 0xf7
    };
    byte key[20];
    byte mac[sizeof(expected)];
    size_t macLen = sizeof(mac);
    TestHmacCallback state;
    EVP_MD_CTX *source = NULL, *copy = NULL;
    EVP_PKEY* pkey = NULL;
    int registered = 0, ret = -1;

    (void)data;
    if (e == NULL)
        return -1;
    memset(&state, 0, sizeof(state));
    memset(key, 0x0b, sizeof(key));
    memset(state.expectedKey, 0x0b, sizeof(key));

    if (wc_CryptoCb_RegisterDevice(TEST_HMAC_CB_DEVID,
            test_hmac_crypto_callback, &state) != 0) {
        goto exit;
    }
    registered = 1;
    testHmacCallback = &state;
    wc_CryptoCb_SetDeviceFindCb(test_hmac_find_device);

    source = EVP_MD_CTX_new();
    copy = EVP_MD_CTX_new();
    pkey = EVP_PKEY_new_mac_key(EVP_PKEY_HMAC, e, key, sizeof(key));
    if (source == NULL || copy == NULL || pkey == NULL ||
            EVP_DigestSignInit(source, NULL, EVP_sha256(), e, pkey) != 1 ||
            EVP_DigestSignUpdate(source, "Hi ", 3) != 1 ||
            EVP_MD_CTX_copy_ex(copy, source) != 1) {
        goto exit;
    }

    EVP_MD_CTX_free(source);
    source = NULL;
    EVP_PKEY_free(pkey);
    pkey = NULL;

    if (EVP_DigestSignUpdate(copy, "There", 5) == 1 &&
            EVP_DigestSignFinal(copy, mac, &macLen) == 1 &&
            state.stage == 3 && macLen == sizeof(expected) &&
            memcmp(mac, expected, sizeof(expected)) == 0)
        ret = 0;

exit:
    EVP_MD_CTX_free(copy);
    EVP_MD_CTX_free(source);
    EVP_PKEY_free(pkey);
    if (registered) {
        wc_CryptoCb_SetDeviceFindCb(NULL);
        testHmacCallback = NULL;
        wc_CryptoCb_UnRegisterDevice(TEST_HMAC_CB_DEVID);
    }
    return ret;
}
#endif

static int test_mac_generation(ENGINE *e, const EVP_MD *md, int pkeyType,
                           unsigned char *pswd, int pswdSz, unsigned char *msg,
                           int len, unsigned char *mac, int *macLen)
{
    int err;
    EVP_MD_CTX *ctx;
    EVP_PKEY   *pkey = NULL;

    err = (ctx = EVP_MD_CTX_new()) == NULL;
    if (err == 0) {
        err = (pkey = EVP_PKEY_new_mac_key(pkeyType, e, pswd, pswdSz))
            == NULL;
    }
    if (err == 0) {
        err = EVP_DigestSignInit(ctx, NULL, md, e, pkey) != 1;
    }
    if (err == 0) {
        err = EVP_DigestSignUpdate(ctx, msg, len/2) != 1;
    }
    if (err == 0) {
        err = EVP_DigestSignUpdate(ctx, msg + len/2, len - len/2) != 1;
    }
    if (err == 0) {
        size_t mlen = (size_t)*macLen;

        err = EVP_DigestSignFinal(ctx, mac, &mlen) != 1;
        *macLen = (int)mlen;
    }
    if (err == 0) {
        PRINT_BUFFER("MAC", mac, *macLen);
    }

    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(pkey);

    return err;
}


static int test_hmac_create_helper(ENGINE *e, void *data, const EVP_MD *md,
    unsigned char* pswd, int pswdSz)
{
    int ret;

    unsigned char exp[128];
    int expLen;

    unsigned char mac[128];
    int macLen;

    unsigned char msg[] = "Test message";
    int len;

    (void)data;
    len    = sizeof(msg);
    macLen = sizeof(mac);
    expLen = sizeof(exp);

    /* generate mac using OpenSSL */
    ret = test_mac_generation(NULL, md, EVP_PKEY_HMAC, pswd, pswdSz, msg,
            len, exp, &expLen);
    if (ret != 0) {
        PRINT_MSG("Generate MAC using OpenSSL failed");
    }

    if (ret == 0) {
        memset(mac, 0, sizeof(mac));
        ret = test_mac_generation(e, md, EVP_PKEY_HMAC, pswd, pswdSz, msg,
            len, mac, &macLen);
        if (ret != 0) {
            PRINT_MSG("Generate MAC using wolfSSL failed");
        }
    }

    if (ret == 0) {
        if (macLen != expLen) {
            PRINT_MSG("generated length and expected length differ");
            ret = -1;
        }
        else {
            if (memcmp(mac, exp, expLen) != 0) {
                PRINT_MSG("generated mac and expected mac differ");
                ret = -1;
            }
        }
    }

    return ret;
}

static int test_hmac_cipher_ctrl(ENGINE *e)
{
    int err = 0;
    EVP_PKEY_CTX *ctx = NULL;

    ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HMAC, e);
    if (ctx == NULL) {
        err = 1;
    }
    if (err == 0) {
        err = EVP_PKEY_keygen_init(ctx) != 1;
    }
    if (err == 0) {
        err = EVP_PKEY_CTX_ctrl(ctx, -1, EVP_PKEY_OP_KEYGEN,
            EVP_PKEY_CTRL_CIPHER, 0, (void *)EVP_aes_128_cbc()) != 1;
    }

    EVP_PKEY_CTX_free(ctx);

    return err;
}

static int test_hmac_copy_without_key(ENGINE *e)
{
#if OPENSSL_VERSION_NUMBER >= 0x10100000L && \
    !defined(TEST_MULTITHREADED) && !defined(WE_NO_OPENSSL_MALLOC)
    int err = 0;
    int allocationFailed;
    EVP_PKEY_CTX *ctx = NULL;
    EVP_PKEY_CTX *copy = NULL;

    if (!test_openssl_mem_has_source()) {
        PRINT_MSG("Skipping allocation-callsite check without source filenames");
        return 0;
    }
    ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HMAC, e);
    if (ctx == NULL) {
        err = 1;
    }
    if (err == 0) {
        err = EVP_PKEY_keygen_init(ctx) != 1;
    }
    if (err == 0) {
        test_openssl_mem_fail_once(1);
        copy = EVP_PKEY_CTX_dup(ctx);
        /* The incomplete context cannot copy its HMAC state, but it must not
         * try to allocate storage for a key that was never configured. */
        allocationFailed = test_openssl_mem_failure_triggered();
        err = (copy != NULL) || allocationFailed;
    }

    EVP_PKEY_CTX_free(copy);
    EVP_PKEY_CTX_free(ctx);

    return err;
#else
    (void)e;
    return 0;
#endif
}

static int test_hmac_key_replacement_failure(ENGINE *e)
{
#if OPENSSL_VERSION_NUMBER >= 0x10100000L && \
    !defined(TEST_MULTITHREADED) && !defined(WE_NO_OPENSSL_MALLOC)
    int err = 0;
    unsigned char oldKey[] = "original key";
    unsigned char newKey[] = "replacement key";
    const unsigned char *key = NULL;
    size_t keySz = 0;
    EVP_PKEY_CTX *ctx = NULL;
    EVP_PKEY *pkey = NULL;

    if (!test_openssl_mem_has_source()) {
        PRINT_MSG("Skipping allocation-callsite check without source filenames");
        return 0;
    }
    ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HMAC, e);
    if (ctx == NULL) {
        err = 1;
    }
    if (err == 0) {
        err = EVP_PKEY_keygen_init(ctx) != 1;
    }
    if (err == 0) {
        err = EVP_PKEY_CTX_ctrl(ctx, -1, EVP_PKEY_OP_KEYGEN,
            EVP_PKEY_CTRL_SET_MAC_KEY, sizeof(oldKey), oldKey) != 1;
    }
    if (err == 0) {
        test_openssl_mem_fail_once(sizeof(newKey) + 1);
        err = EVP_PKEY_CTX_ctrl(ctx, -1, EVP_PKEY_OP_KEYGEN,
            EVP_PKEY_CTRL_SET_MAC_KEY, sizeof(newKey), newKey) > 0;
        if (!test_openssl_mem_failure_triggered()) {
            err = 1;
        }
    }
    if (err == 0) {
        err = EVP_PKEY_keygen(ctx, &pkey) != 1;
    }
    if (err == 0) {
        key = EVP_PKEY_get0_hmac(pkey, &keySz);
        err = (key == NULL) || (keySz != sizeof(oldKey)) ||
            (XMEMCMP(key, oldKey, sizeof(oldKey)) != 0);
    }

    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(ctx);

    return err;
#else
    (void)e;
    return 0;
#endif
}

static int test_hmac_short_key_init(ENGINE *e)
{
#if OPENSSL_VERSION_NUMBER >= 0x10100000L && \
    !defined(TEST_MULTITHREADED) && !defined(WE_NO_OPENSSL_MALLOC)
    int err = 0;
    int allocationFailed;
    unsigned char key[] = "short HMAC key";
    EVP_MD_CTX *ctx = NULL;
    EVP_PKEY *pkey = NULL;

    if (!test_openssl_mem_has_source()) {
        PRINT_MSG("Skipping allocation-callsite check without source filenames");
        return 0;
    }
    ctx = EVP_MD_CTX_new();
    if (ctx == NULL) {
        err = 1;
    }
    if (err == 0) {
        pkey = EVP_PKEY_new_mac_key(EVP_PKEY_HMAC, e, key, sizeof(key));
        err = pkey == NULL;
    }
    if (err == 0) {
        test_openssl_mem_fail_once(64);
        err = EVP_DigestSignInit(ctx, NULL, EVP_sha256(), e, pkey) != 1;
        allocationFailed = test_openssl_mem_failure_triggered();
        if (allocationFailed) {
            err = 1;
        }
    }

    EVP_PKEY_free(pkey);
    EVP_MD_CTX_free(ctx);

    return err;
#else
    (void)e;
    return 0;
#endif
}

static int test_hmac_failed_copy_cleanup(ENGINE *e)
{
#if OPENSSL_VERSION_NUMBER >= 0x10100000L && \
    !defined(TEST_MULTITHREADED) && !defined(WE_NO_OPENSSL_MALLOC)
    int err = 0;
    unsigned char key[] = "duplicate key";
    size_t allocations;
    EVP_PKEY_CTX *ctx = NULL;
    EVP_PKEY_CTX *copy = NULL;

    if (!test_openssl_mem_has_source()) {
        PRINT_MSG("Skipping allocation-callsite check without source filenames");
        return 0;
    }
    ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HMAC, e);
    if (ctx == NULL) {
        err = 1;
    }
    if (err == 0) {
        err = EVP_PKEY_keygen_init(ctx) != 1;
    }
    if (err == 0) {
        err = EVP_PKEY_CTX_ctrl(ctx, -1, EVP_PKEY_OP_KEYGEN,
            EVP_PKEY_CTRL_SET_MAC_KEY, sizeof(key), key) != 1;
    }
    if (err == 0) {
        allocations = test_openssl_mem_active();
        test_openssl_mem_expect_next_clear(sizeof(key) + 1);
        copy = EVP_PKEY_CTX_dup(ctx);
        err = (copy != NULL) ||
            (test_openssl_mem_active() != allocations) ||
            (test_openssl_mem_clear_result() != 1);
    }

    EVP_PKEY_CTX_free(copy);
    EVP_PKEY_CTX_free(ctx);

    return err;
#else
    (void)e;
    return 0;
#endif
}

static int test_hmac_alignment_buffer_cleanup(void)
{
#if OPENSSL_VERSION_NUMBER >= 0x10100000L && \
    defined(WE_ALIGNMENT_SAFETY) && !defined(TEST_MULTITHREADED) && \
    !defined(WE_NO_OPENSSL_MALLOC) && \
    ((!defined(WOLFENGINE_DLL) && !defined(HAVE_VISIBILITY)) || \
     defined(WE_MAC_STATIC_TEST))
    int err = 0;
    unsigned char key[32] = { 0 };
    unsigned char data[257] = { 0 };
    Hmac hmac;

    if (!test_openssl_mem_has_source()) {
        PRINT_MSG("Skipping allocation-callsite check without source filenames");
        return 0;
    }
    err = wc_HmacInit(&hmac, NULL, INVALID_DEVID) != 0;
    if (err == 0) {
        err = wc_HmacSetKey(&hmac, WC_SHA512, key, sizeof(key)) != 0;
    }
    if (err == 0) {
        test_openssl_mem_expect_next_clear(WC_SHA512_BLOCK_SIZE);
        err = we_hmac_update(&hmac, data + 1, sizeof(data) - 1) != 1;
    }
    if (err == 0) {
        err = test_openssl_mem_clear_result() != 1;
    }

    wc_HmacFree(&hmac);
    return err;
#else
    return 0;
#endif
}

#if !defined(TEST_MULTITHREADED) && !defined(WE_NO_OPENSSL_MALLOC) && \
    ((!defined(WOLFENGINE_DLL) && !defined(HAVE_VISIBILITY)) || \
     defined(WE_MAC_STATIC_TEST))
static int test_hmac_init_failure(Hmac *hmac, void *heap, int devId)
{
    (void)hmac;
    (void)heap;
    (void)devId;

    return MEMORY_E;
}
#endif

static int test_hmac_failed_init_cleanup(void)
{
#if !defined(TEST_MULTITHREADED) && !defined(WE_NO_OPENSSL_MALLOC) && \
    ((!defined(WOLFENGINE_DLL) && !defined(HAVE_VISIBILITY)) || \
     defined(WE_MAC_STATIC_TEST))
    int err = 0;
    size_t allocations;
    void *data = NULL;
    void *originalData = NULL;
    EVP_PKEY_CTX *ctx = NULL;

    ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    if (ctx == NULL) {
        err = 1;
    }
    if (err == 0) {
        originalData = EVP_PKEY_CTX_get_data(ctx);
        EVP_PKEY_CTX_set_data(ctx, NULL);
        allocations = test_openssl_mem_active();
        err = we_hmac_pkey_init_ex(ctx, test_hmac_init_failure) != 0;
        data = EVP_PKEY_CTX_get_data(ctx);
        if ((data != NULL) ||
                (test_openssl_mem_active() != allocations)) {
            err = 1;
        }
    }

    if (data != NULL) {
        EVP_PKEY_CTX_set_data(ctx, NULL);
        OPENSSL_free(data);
    }
    if (ctx != NULL) {
        EVP_PKEY_CTX_set_data(ctx, originalData);
    }
    EVP_PKEY_CTX_free(ctx);

    return err;
#else
    return 0;
#endif
}

int test_hmac_create(ENGINE *e, void *data)
{
    int ret = 0;
    unsigned char pswd[] = "My empire of dirt";
    unsigned char bigPswd[100];

    XMEMSET(bigPswd, 0, sizeof(bigPswd));

    PRINT_MSG("Testing with SHA1");
    ret = test_hmac_create_helper(e, data, EVP_sha1(), pswd, sizeof(pswd));
#ifndef HAVE_FIPS
    if (ret == 0) {
        PRINT_MSG("Testing with SHA1, 0 length key");
        ret = test_hmac_create_helper(e, data, EVP_sha1(), pswd, 0);
    }
#endif
    if (ret == 0) {
        PRINT_MSG("Testing with SHA1, key length larger than block size");
        RAND_bytes(bigPswd, sizeof(bigPswd));
        ret = test_hmac_create_helper(e, data, EVP_sha1(), bigPswd,
                  sizeof(bigPswd));
    }

    if (ret == 0) {
        PRINT_MSG("Testing with SHA224");
        ret = test_hmac_create_helper(e, data, EVP_sha224(), pswd, sizeof(pswd));
        if (ret == 0) {
            /* EVP_PKEY_new_mac_key() can be called with -1, OpenSSL expects
             * engine implementations to use strlen() to find string length */
            ret = test_hmac_create_helper(e, data, EVP_sha224(), pswd, -1);
        }
    }

    if (ret == 0) {
        PRINT_MSG("Testing with SHA256");
        ret = test_hmac_create_helper(e, data, EVP_sha256(), pswd, sizeof(pswd));
        if (ret == 0) {
            ret = test_hmac_create_helper(e, data, EVP_sha256(), pswd, -1);
        }
    }

    if (ret == 0) {
        PRINT_MSG("Testing with SHA384");
        ret = test_hmac_create_helper(e, data, EVP_sha384(), pswd, sizeof(pswd));
        if (ret == 0) {
            ret = test_hmac_create_helper(e, data, EVP_sha384(), pswd, -1);
        }
    }

    if (ret == 0) {
        PRINT_MSG("Testing with SHA512");
        ret = test_hmac_create_helper(e, data, EVP_sha512(), pswd, sizeof(pswd));
        if (ret == 0) {
            ret = test_hmac_create_helper(e, data, EVP_sha512(), pswd, -1);
        }
    }

#ifdef WE_HAVE_SHA3_224
    if (ret == 0) {
        PRINT_MSG("Testing with SHA3-224");
        ret = test_hmac_create_helper(e, data, EVP_sha3_224(), pswd, sizeof(pswd));
        if (ret == 0) {
            ret = test_hmac_create_helper(e, data, EVP_sha3_224(), pswd, -1);
        }
    }
#endif
#ifdef WE_HAVE_SHA3_256
    if (ret == 0) {
        PRINT_MSG("Testing with SHA3-256");
        ret = test_hmac_create_helper(e, data, EVP_sha3_256(), pswd, sizeof(pswd));
        if (ret == 0) {
            ret = test_hmac_create_helper(e, data, EVP_sha3_256(), pswd, -1);
        }
    }
#endif
#ifdef WE_HAVE_SHA3_384
    if (ret == 0) {
        PRINT_MSG("Testing with SHA3-384");
        ret = test_hmac_create_helper(e, data, EVP_sha3_384(), pswd, sizeof(pswd));
        if (ret == 0) {
            ret = test_hmac_create_helper(e, data, EVP_sha3_384(), pswd, -1);
        }
    }
#endif
#ifdef WE_HAVE_SHA3_512
    if (ret == 0) {
        PRINT_MSG("Testing with SHA3-512");
        ret = test_hmac_create_helper(e, data, EVP_sha3_512(), pswd, sizeof(pswd));
        if (ret == 0) {
            ret = test_hmac_create_helper(e, data, EVP_sha3_512(), pswd, -1);
        }
    }
#endif
    if (ret == 0) {
        ret = test_hmac_cipher_ctrl(e);
    }
    if (ret == 0) {
        ret = test_hmac_copy_without_key(e);
    }
    if (ret == 0) {
        ret = test_hmac_key_replacement_failure(e);
    }
    if (ret == 0) {
        ret = test_hmac_short_key_init(e);
    }
    if (ret == 0) {
        ret = test_hmac_failed_copy_cleanup(e);
    }
    if (ret == 0) {
        ret = test_hmac_alignment_buffer_cleanup();
    }
    if (ret == 0) {
        ret = test_hmac_failed_init_cleanup();
    }
#if defined(WOLF_CRYPTO_CB) && defined(WOLF_CRYPTO_CB_FIND) && \
    !defined(TEST_MULTITHREADED)
    if (ret == 0) {
        ret = test_hmac_callback_copy(e, data);
    }
#endif
    return ret;
}

int test_hmac_output_size(ENGINE *e, void *data)
{
    int ret = 0;
    int i;
    unsigned char key[] = "My empire of dirt";
    unsigned char msg[] = "Test message";
    unsigned char mac[EVP_MAX_MD_SIZE];
    size_t macLen = 1;
    EVP_MD_CTX *ctx = NULL;
    EVP_PKEY *pkey = NULL;

    (void)data;
    XMEMSET(mac, 0xa5, sizeof(mac));

    ctx = EVP_MD_CTX_new();
    if (ctx == NULL)
        ret = -1;
    if (ret == 0) {
        pkey = EVP_PKEY_new_mac_key(EVP_PKEY_HMAC, e, key, sizeof(key));
        if (pkey == NULL)
            ret = -1;
    }
    if (ret == 0) {
        ret = EVP_DigestSignInit(ctx, NULL, EVP_sha256(), e, pkey) != 1;
    }
    if (ret == 0) {
        ret = EVP_DigestSignUpdate(ctx, msg, sizeof(msg)) != 1;
    }
    if (ret == 0) {
        if (EVP_DigestSignFinal(ctx, mac, &macLen) == 1)
            ret = -1;
    }
    if ((ret == 0) && (macLen != SHA256_DIGEST_LENGTH))
        ret = -1;
    for (i = 0; (ret == 0) && (i < (int)sizeof(mac)); i++) {
        if (mac[i] != 0xa5)
            ret = -1;
    }

    EVP_PKEY_free(pkey);
    EVP_MD_CTX_free(ctx);

    return ret;
}

int test_hmac_pkey_size(ENGINE *e, void *data)
{
    int ret = 0;
    unsigned char key[] = "My empire of dirt";
    EVP_PKEY *pkey;

    (void)data;
    pkey = EVP_PKEY_new_mac_key(EVP_PKEY_HMAC, e, key, sizeof(key));
    if (pkey == NULL)
        ret = -1;
    if ((ret == 0) && (EVP_PKEY_size(pkey) != WC_MAX_DIGEST_SIZE))
        ret = -1;

    EVP_PKEY_free(pkey);

    return ret;
}

int test_hmac_update_size(ENGINE *e, void *data)
{
    int ret = 0;
    unsigned char key[] = "My empire of dirt";
    unsigned char msg = 0;
    EVP_MD_CTX *ctx = NULL;
    EVP_PKEY *pkey = NULL;

    (void)data;
    ctx = EVP_MD_CTX_new();
    if (ctx == NULL)
        ret = -1;
    if (ret == 0) {
        pkey = EVP_PKEY_new_mac_key(EVP_PKEY_HMAC, e, key, sizeof(key));
        if (pkey == NULL)
            ret = -1;
    }
    if (ret == 0) {
        ret = EVP_DigestSignInit(ctx, NULL, EVP_sha256(), e, pkey) != 1;
    }
    if (ret == 0) {
        if (sizeof(size_t) > sizeof(word32)) {
            size_t updateLen = UINT32_MAX;

            updateLen++;
            if (EVP_DigestSignUpdate(ctx, &msg, updateLen) == 1)
                ret = -1;
        }
    }

    EVP_PKEY_free(pkey);
    EVP_MD_CTX_free(ctx);

    return ret;
}

#if OPENSSL_VERSION_NUMBER >= 0x10101000L && !defined(TEST_MULTITHREADED)
int test_hmac_raw_key_output_size(ENGINE *e, void *data)
{
    int ret = 0;
    int i;
    int registered = 0;
    unsigned char key[] = "My empire of dirt";
    unsigned char out[sizeof(key)];
    size_t outLen = 0;
    EVP_PKEY *pkey = NULL;

    (void)data;
    if (ENGINE_register_pkey_asn1_meths(e) != 1)
        ret = -1;
    else
        registered = 1;
    if (ret == 0) {
        pkey = EVP_PKEY_new_raw_private_key(EVP_PKEY_HMAC, NULL, key,
                sizeof(key));
        if (pkey == NULL)
            ret = -1;
    }
    if (registered)
        ENGINE_unregister_pkey_asn1_meths(e);
#if OPENSSL_VERSION_NUMBER >= 0x1010103fL
    if ((ret == 0) && (EVP_PKEY_get0_engine(pkey) != e))
        ret = -1;
#else
    if ((ret == 0) && ((EVP_PKEY_get0_asn1(pkey) == NULL) ||
            (EVP_PKEY_get0_asn1(pkey) !=
             ENGINE_get_pkey_asn1_meth(e, EVP_PKEY_HMAC))))
        ret = -1;
#endif
    if (ret == 0) {
        ret = EVP_PKEY_get_raw_private_key(pkey, NULL, &outLen) != 1;
    }
    if ((ret == 0) && (outLen != sizeof(key)))
        ret = -1;
    if (ret == 0) {
        XMEMSET(out, 0xa5, sizeof(out));
        outLen = 1;
        if (EVP_PKEY_get_raw_private_key(pkey, out, &outLen) == 1)
            ret = -1;
    }
    if ((ret == 0) && (outLen != sizeof(key)))
        ret = -1;
    for (i = 0; (ret == 0) && (i < (int)sizeof(out)); i++) {
        if (out[i] != 0xa5)
            ret = -1;
    }

    EVP_PKEY_free(pkey);

    return ret;
}
#endif /* OPENSSL_VERSION_NUMBER >= 0x10101000L && !TEST_MULTITHREADED */

#endif /* WE_HAVE_HMAC */


