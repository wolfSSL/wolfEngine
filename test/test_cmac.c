/* test_cmac.c
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
#undef AES_BLOCK_SIZE
#ifndef WOLFENGINE_USER_SETTINGS
#include <wolfssl/options.h>
#endif
#include <wolfssl/wolfcrypt/cmac.h>
#include <openssl/cmac.h>
#include <wolfengine/we_logging.h>

#ifdef WE_HAVE_CMAC

#ifdef WOLFENGINE_DEBUG
static char cmacLog[WOLFENGINE_MAX_LOG_WIDTH];
#ifndef TEST_MULTITHREADED
static int cmacWolfCryptBackend;
#endif

static void test_cmac_logging_cb(const int level, const int component,
        const char *const message)
{
    (void)component;

    if ((level == WE_LOG_ERROR) && (XSTRSTR(message, "wc_InitCmac") != NULL)) {
        XSTRNCPY(cmacLog, message, sizeof(cmacLog) - 1);
        cmacLog[sizeof(cmacLog) - 1] = '\0';
    }
    #ifndef TEST_MULTITHREADED
    if ((level == WE_LOG_INFO) &&
            (XSTRCMP(message, "CMAC backend: wolfCrypt") == 0)) {
        cmacWolfCryptBackend = 1;
    }
    #endif
}
#endif

static int test_cmac_generation(ENGINE *e, const EVP_CIPHER *c,
    unsigned char *key, int keySz, unsigned char *msg, int len,
    unsigned char *out, int *outLen)
{
    int err;
    EVP_MD_CTX   *ctx;
    EVP_PKEY_CTX *pctx = NULL;
    EVP_PKEY     *pkey = NULL;

    err = (ctx = EVP_MD_CTX_new()) == NULL;
    if (err == 0) {
        pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_CMAC, e);
        if (pctx == NULL)
            err = -1;
    }
    if (err == 0) {
        EVP_PKEY_keygen_init(pctx);
        err = EVP_PKEY_CTX_ctrl(pctx, -1, EVP_PKEY_OP_KEYGEN,
                EVP_PKEY_CTRL_CIPHER, 0, (void*)c) != 1;
    }
    if (err == 0) {
        err = EVP_PKEY_CTX_ctrl(pctx, -1, EVP_PKEY_OP_KEYGEN,
                EVP_PKEY_CTRL_SET_MAC_KEY, keySz, key) != 1;
    }
    if (err == 0) {
        err = EVP_PKEY_keygen(pctx, &pkey) != 1;
    }
    if (err == 0) {
        err = EVP_DigestSignInit(ctx, NULL, NULL, e, pkey) != 1;
    }
    if (err == 0) {
        err = EVP_DigestSignUpdate(ctx, msg, len/2) != 1;
    }
    if (err == 0) {
        err = EVP_DigestSignUpdate(ctx, msg + len/2, len - len/2) != 1;
    }
    if (err == 0) {
        size_t mlen = (size_t)*outLen;

        err = EVP_DigestSignFinal(ctx, out, &mlen) != 1;
        *outLen = (int)mlen;
    }
    if (err == 0) {
        PRINT_BUFFER("CMAC", out, *outLen);
    }

    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(pctx);

    return err;
}


static int test_cmac_create_helper(ENGINE *e, unsigned char *in,
        int inSz, unsigned char *key, int keySz, const EVP_CIPHER *c,
        unsigned long flags)
{
    int ret;
    ENGINE *tmpe = NULL;

    unsigned char exp[16];
    int expLen;

    unsigned char mac[16];
    int macLen;

    macLen = sizeof(mac);
    expLen = sizeof(exp);

    if (flags & WE_VALGRIND_TEST) {
        tmpe = e; /* use only wolfSSL version for valgrind test */
    }

    /* generate mac using OpenSSL */
    ret = test_cmac_generation(tmpe, c, key, keySz, in, inSz, exp, &expLen);
    if (ret != 0) {
        PRINT_MSG("Generate MAC using OpenSSL failed");
    }

    if (ret == 0) {
        memset(mac, 0, sizeof(mac));
        ret = test_cmac_generation(e, c, key, keySz, in, inSz, mac, &macLen);
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

static int test_cmac_bad_cipher(ENGINE *e)
{
    int err = 0;
    EVP_PKEY_CTX *ctx = NULL;

    ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_CMAC, e);
    if (ctx == NULL) {
        err = 1;
    }
    if (err == 0) {
        err = EVP_PKEY_keygen_init(ctx) != 1;
    }
    if (err == 0) {
        err = EVP_PKEY_CTX_ctrl(ctx, -1, EVP_PKEY_OP_KEYGEN,
            EVP_PKEY_CTRL_CIPHER, 0, (void *)EVP_aes_128_ecb()) > 0;
    }

    EVP_PKEY_CTX_free(ctx);

    return err;
}

int test_cmac_create(ENGINE *e, void *data)
{
    int ret = 0;
    unsigned char in[] = "I'm gonna break my rusty cage and run";
    int inSz;

    unsigned char key[] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07
    };
    int keySz;
    unsigned long flags;

    flags = *(unsigned long*)data;
    inSz  = sizeof(in);

    if (flags & WE_VALGRIND_TEST) {
        PRINT_MSG("Running wolfSSL only for valgrind test");
    }

    PRINT_MSG("Testing with 256 bit KEY");
    keySz = 32;
#if defined(WOLFENGINE_DEBUG) && !defined(TEST_MULTITHREADED)
    cmacWolfCryptBackend = 0;
    ret = wolfEngine_SetLoggingCb(test_cmac_logging_cb) != 0;
    ret |= wolfEngine_SetLogLevel(WE_LOG_INFO) != 0;
    ret |= wolfEngine_SetLogComponents(WE_LOG_MAC) != 0;
    ret |= wolfEngine_Debugging_ON() != 0;
#endif
    if (ret == 0) {
        ret = test_cmac_create_helper(e, in, inSz, key, keySz,
                EVP_aes_256_cbc(), flags);
    }
#if defined(WOLFENGINE_DEBUG) && !defined(TEST_MULTITHREADED)
    wolfEngine_Debugging_OFF();
    wolfEngine_SetLoggingCb(NULL);
    wolfEngine_SetLogLevel(WE_LOG_LEVEL_DEFAULT);
    wolfEngine_SetLogComponents(WE_LOG_COMPONENTS_DEFAULT);
    if ((ret == 0) && (!cmacWolfCryptBackend))
        ret = -1;
#endif

    if (ret == 0) {
        PRINT_MSG("Testing with 128 bit KEY");
        keySz = 16;
        ret = test_cmac_create_helper(e, in, inSz, key, keySz,
                EVP_aes_128_cbc(), flags);
    }

    if (ret == 0) {
        PRINT_MSG("Testing with a 192 bit KEY");
        keySz = 24;
        ret = test_cmac_create_helper(e, in, inSz, key, keySz,
                EVP_aes_192_cbc(), flags);
    }
    if (ret == 0) {
        ret = test_cmac_bad_cipher(e);
    }

    return ret;
}

int test_cmac_output_size(ENGINE *e, void *data)
{
    int ret = 0;
    int i;
    unsigned char key[16] = { 0 };
    unsigned char msg[] = "Test message";
    unsigned char mac[WC_CMAC_TAG_MAX_SZ];
    size_t macLen = 1;
    EVP_MD_CTX *ctx = NULL;
    EVP_PKEY_CTX *pctx = NULL;
    EVP_PKEY *pkey = NULL;

    (void)data;
    XMEMSET(mac, 0xa5, sizeof(mac));

    ctx = EVP_MD_CTX_new();
    if (ctx == NULL)
        ret = -1;
    if (ret == 0) {
        pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_CMAC, e);
        if (pctx == NULL)
            ret = -1;
    }
    if (ret == 0)
        ret = EVP_PKEY_keygen_init(pctx) != 1;
    if (ret == 0) {
        ret = EVP_PKEY_CTX_ctrl(pctx, -1, EVP_PKEY_OP_KEYGEN,
                EVP_PKEY_CTRL_CIPHER, 0, (void*)EVP_aes_128_cbc()) != 1;
    }
    if (ret == 0) {
        ret = EVP_PKEY_CTX_ctrl(pctx, -1, EVP_PKEY_OP_KEYGEN,
                EVP_PKEY_CTRL_SET_MAC_KEY, sizeof(key), key) != 1;
    }
    if (ret == 0)
        ret = EVP_PKEY_keygen(pctx, &pkey) != 1;
    if (ret == 0)
        ret = EVP_DigestSignInit(ctx, NULL, NULL, e, pkey) != 1;
    if (ret == 0)
        ret = EVP_DigestSignUpdate(ctx, msg, sizeof(msg)) != 1;
    if (ret == 0) {
        if (EVP_DigestSignFinal(ctx, mac, &macLen) == 1)
            ret = -1;
    }
    if ((ret == 0) && (macLen != WC_CMAC_TAG_MAX_SZ))
        ret = -1;
    for (i = 0; (ret == 0) && (i < (int)sizeof(mac)); i++) {
        if (mac[i] != 0xa5)
            ret = -1;
    }

    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(pctx);
    EVP_MD_CTX_free(ctx);

    return ret;
}

int test_cmac_update_size(ENGINE *e, void *data)
{
    int ret = 0;
    unsigned char key[16] = { 0 };
    unsigned char msg = 0;
    EVP_MD_CTX *ctx = NULL;
    EVP_PKEY_CTX *pctx = NULL;
    EVP_PKEY *pkey = NULL;

    (void)data;
    ctx = EVP_MD_CTX_new();
    if (ctx == NULL)
        ret = -1;
    if (ret == 0) {
        pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_CMAC, e);
        if (pctx == NULL)
            ret = -1;
    }
    if (ret == 0)
        ret = EVP_PKEY_keygen_init(pctx) != 1;
    if (ret == 0) {
        ret = EVP_PKEY_CTX_ctrl(pctx, -1, EVP_PKEY_OP_KEYGEN,
                EVP_PKEY_CTRL_CIPHER, 0, (void*)EVP_aes_128_cbc()) != 1;
    }
    if (ret == 0) {
        ret = EVP_PKEY_CTX_ctrl(pctx, -1, EVP_PKEY_OP_KEYGEN,
                EVP_PKEY_CTRL_SET_MAC_KEY, sizeof(key), key) != 1;
    }
    if (ret == 0)
        ret = EVP_PKEY_keygen(pctx, &pkey) != 1;
    if (ret == 0)
        ret = EVP_DigestSignInit(ctx, NULL, NULL, e, pkey) != 1;
    if (ret == 0) {
        if (sizeof(size_t) > sizeof(word32)) {
            size_t updateLen = UINT32_MAX;

            updateLen++;
            if (EVP_DigestSignUpdate(ctx, &msg, updateLen) == 1)
                ret = -1;
        }
    }

    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(pctx);
    EVP_MD_CTX_free(ctx);

    return ret;
}

int test_cmac_copy_error(ENGINE *e, void *data)
{
    int ret = 0;
#ifdef WOLFENGINE_DEBUG
    unsigned char key = 0;
    EVP_PKEY_CTX *ctx = NULL;
    EVP_PKEY_CTX *copy = NULL;

    (void)data;
    XMEMSET(cmacLog, 0, sizeof(cmacLog));

    ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_CMAC, e);
    if (ctx == NULL)
        ret = -1;
    if (ret == 0)
        ret = EVP_PKEY_keygen_init(ctx) != 1;
    if (ret == 0) {
        ret = EVP_PKEY_CTX_ctrl(ctx, -1, EVP_PKEY_OP_KEYGEN,
                EVP_PKEY_CTRL_SET_MAC_KEY, sizeof(key), &key) != 1;
    }
    if (ret == 0) {
        ret = wolfEngine_SetLoggingCb(test_cmac_logging_cb) != 0;
        ret |= wolfEngine_SetLogLevel(WE_LOG_ERROR) != 0;
        ret |= wolfEngine_SetLogComponents(WE_LOG_MAC) != 0;
        ret |= wolfEngine_Debugging_ON() != 0;
    }
    if (ret == 0) {
        copy = EVP_PKEY_CTX_dup(ctx);
        if (copy != NULL)
            ret = -1;
    }
    wolfEngine_Debugging_OFF();
    wolfEngine_SetLoggingCb(NULL);
    wolfEngine_SetLogLevel(WE_LOG_LEVEL_DEFAULT);
    wolfEngine_SetLogComponents(WE_LOG_COMPONENTS_DEFAULT);

    if ((ret == 0) && (XSTRSTR(cmacLog, "ret = -") == NULL))
        ret = -1;

    EVP_PKEY_CTX_free(copy);
    EVP_PKEY_CTX_free(ctx);
#else
    (void)e;
    (void)data;
#endif

    return ret;
}

int test_cmac_copy(ENGINE *e, void *data)
{
    int ret = 0;
    unsigned char key[16] = { 0 };
    unsigned char prefix[] = "shared prefix";
    unsigned char suffix[] = "original";
    unsigned char msg[] = "shared prefixoriginal";
    unsigned char prefixMac[WC_CMAC_TAG_MAX_SZ];
    unsigned char fullMac[WC_CMAC_TAG_MAX_SZ];
    unsigned char expPrefix[WC_CMAC_TAG_MAX_SZ];
    unsigned char expFull[WC_CMAC_TAG_MAX_SZ];
    size_t prefixMacSz = sizeof(prefixMac);
    size_t fullMacSz = sizeof(fullMac);
    int expPrefixSz = sizeof(expPrefix);
    int expFullSz = sizeof(expFull);
    EVP_PKEY_CTX *pctx = NULL;
    EVP_PKEY *pkey = NULL;
    EVP_MD_CTX *ctx = NULL;

    (void)data;
    pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_CMAC, e);
    if (pctx == NULL)
        ret = -1;
    if (ret == 0)
        ret = EVP_PKEY_keygen_init(pctx) != 1;
    if (ret == 0) {
        ret = EVP_PKEY_CTX_ctrl(pctx, -1, EVP_PKEY_OP_KEYGEN,
                EVP_PKEY_CTRL_CIPHER, 0, (void*)EVP_aes_128_cbc()) != 1;
    }
    if (ret == 0) {
        ret = EVP_PKEY_CTX_ctrl(pctx, -1, EVP_PKEY_OP_KEYGEN,
                EVP_PKEY_CTRL_SET_MAC_KEY, sizeof(key), key) != 1;
    }
    if (ret == 0)
        ret = EVP_PKEY_keygen(pctx, &pkey) != 1;
    if (ret == 0) {
        ctx = EVP_MD_CTX_new();
        if (ctx == NULL)
            ret = -1;
    }
    if (ret == 0)
        ret = EVP_DigestSignInit(ctx, NULL, NULL, e, pkey) != 1;
    if (ret == 0) {
        ret = EVP_DigestSignUpdate(ctx, prefix, sizeof(prefix) - 1) != 1;
    }
    if (ret == 0)
        ret = EVP_DigestSignFinal(ctx, prefixMac, &prefixMacSz) != 1;
    if (ret == 0)
        ret = EVP_DigestSignUpdate(ctx, suffix, sizeof(suffix) - 1) != 1;
    if (ret == 0)
        ret = EVP_DigestSignFinal(ctx, fullMac, &fullMacSz) != 1;
    if (ret == 0) {
        ret = test_cmac_generation(NULL, EVP_aes_128_cbc(), key, sizeof(key),
                prefix, sizeof(prefix) - 1, expPrefix, &expPrefixSz);
    }
    if (ret == 0) {
        ret = test_cmac_generation(NULL, EVP_aes_128_cbc(), key, sizeof(key),
                msg, sizeof(msg) - 1, expFull, &expFullSz);
    }
    if ((ret == 0) && ((prefixMacSz != (size_t)expPrefixSz) ||
            (XMEMCMP(prefixMac, expPrefix, prefixMacSz) != 0))) {
        ret = -1;
    }
    if ((ret == 0) && ((fullMacSz != (size_t)expFullSz) ||
            (XMEMCMP(fullMac, expFull, fullMacSz) != 0))) {
        ret = -1;
    }

    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(pctx);

    return ret;
}

int test_cmac_keygen_reuse(ENGINE *e, void *data)
{
    int ret = 0;
    unsigned char key[16] = { 0 };
    unsigned char oldKey[16] = { 1 };
    EVP_PKEY_CTX *ctx = NULL;
    EVP_PKEY *pkey = NULL;
    CMAC_CTX *cmac = NULL;
    EVP_CIPHER_CTX *cipherCtx = NULL;

    (void)data;
    pkey = EVP_PKEY_new_mac_key(EVP_PKEY_HMAC, e, oldKey, sizeof(oldKey));
    if (pkey == NULL)
        ret = -1;
    if (ret == 0) {
        ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_CMAC, e);
        if (ctx == NULL)
            ret = -1;
    }
    if (ret == 0)
        ret = EVP_PKEY_keygen_init(ctx) != 1;
    if (ret == 0) {
        ret = EVP_PKEY_CTX_ctrl(ctx, -1, EVP_PKEY_OP_KEYGEN,
                EVP_PKEY_CTRL_SET_MAC_KEY, sizeof(key), key) != 1;
    }
    if (ret == 0)
        ret = EVP_PKEY_keygen(ctx, &pkey) != 1;
    if ((ret == 0) && (EVP_PKEY_base_id(pkey) != EVP_PKEY_CMAC))
        ret = -1;
    if ((ret == 0) && (e != NULL)) {
        cmac = (CMAC_CTX *)EVP_PKEY_get0(pkey);
        if (cmac != NULL)
            cipherCtx = CMAC_CTX_get0_cipher_ctx(cmac);
        if ((cipherCtx == NULL) ||
                (EVP_CIPHER_CTX_nid(cipherCtx) != NID_cmac)) {
            ret = -1;
        }
    }

    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(ctx);

    return ret;
}

int test_cmac_unregistered_engine(ENGINE *e, void *data)
{
    int ret = 0;
    int removed = 0;
    unsigned char key[16] = { 0 };
    unsigned char msg[] = "Test message";
    unsigned char mac[WC_CMAC_TAG_MAX_SZ];
    int macSz = sizeof(mac);

    (void)data;
    if (ENGINE_remove(e) != 1)
        ret = -1;
    else
        removed = 1;
    if (ret == 0) {
        ret = test_cmac_generation(e, EVP_aes_128_cbc(), key, sizeof(key),
                msg, sizeof(msg), mac, &macSz);
    }
    if ((removed == 1) && (ENGINE_add(e) != 1))
        ret = -1;

    return ret;
}

int test_cmac_asn1_registry(ENGINE *e, void *data)
{
    int ret = 0;
    int i;
    int count;
    const int *nids = NULL;
    EVP_PKEY_ASN1_METHOD *method = NULL;
    ENGINE_PKEY_ASN1_METHS_PTR methods;

    (void)data;
    methods = ENGINE_get_pkey_asn1_meths(e);
    if (methods == NULL)
        ret = -1;
    if (ret == 0) {
        count = methods(e, NULL, &nids, 0);
        if ((count <= 0) || (nids == NULL))
            ret = -1;
    }
    for (i = 0; (ret == 0) && (i < count); i++) {
        if ((methods(e, &method, NULL, nids[i]) != 1) || (method == NULL))
            ret = -1;
    }

    return ret;
}

#endif /* WE_HAVE_CMAC */

#if defined(WE_HAVE_HMAC) || defined(WE_HAVE_CMAC)
int test_mac_asn1_ownership(ENGINE *e, void *data)
{
    int ret = 0;
    int i;
    int count;
    const int *nids = NULL;
    const EVP_PKEY_ASN1_METHOD *globalMethod;
    EVP_PKEY_ASN1_METHOD *engineMethod = NULL;
    ENGINE_PKEY_ASN1_METHS_PTR methods;

    (void)data;
    methods = ENGINE_get_pkey_asn1_meths(e);
    if (methods == NULL)
        ret = -1;
    if (ret == 0) {
        count = methods(e, NULL, &nids, 0);
        if ((count <= 0) || (nids == NULL))
            ret = -1;
    }
    for (i = 0; (ret == 0) && (i < count); i++) {
        if ((methods(e, &engineMethod, NULL, nids[i]) != 1) ||
                (engineMethod == NULL)) {
            ret = -1;
        }
        if (ret == 0) {
            globalMethod = EVP_PKEY_asn1_find(NULL, nids[i]);
            if (globalMethod == engineMethod)
                ret = -1;
        }
    }

    return ret;
}

#endif /* WE_HAVE_HMAC || WE_HAVE_CMAC */


