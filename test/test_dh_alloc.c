/* test_dh_alloc.c
 *
 * Copyright (C) 2026 wolfSSL Inc.
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <wolfengine/we_wolfengine.h>
#ifdef WOLFENGINE_USER_SETTINGS
#include <user_settings.h>
#else
#include <wolfssl/options.h>
#endif
#include <wolfssl/wolfcrypt/dh.h>
#include <openssl/engine.h>
#include <openssl/evp.h>
#include <openssl/dh.h>
#include <openssl/err.h>
#include <wolfengine/we_openssl_bc.h>

#if defined(WE_HAVE_DH) && defined(WE_HAVE_EVP_PKEY) && \
    defined(HAVE_PUBLIC_FFDHE) && defined(HAVE_FFDHE_2048) && \
    !defined(HAVE_FFDHE_Q) && !defined(TEST_MULTITHREADED) && \
    !defined(WE_NO_OPENSSL_MALLOC) && !defined(OPENSSL_NO_FILENAMES)

static int dhAllocTracking = 0;
static size_t dhAllocSizes[32];
static int dhAllocCount = 0;

static void* dh_alloc_malloc(size_t len, const char* file, int line)
{
    (void)line;

    if (dhAllocTracking && (file != NULL) &&
        (strstr(file, "we_dh.c") != NULL) &&
        (dhAllocCount < (int)(sizeof(dhAllocSizes) / sizeof(*dhAllocSizes)))) {
        dhAllocSizes[dhAllocCount++] = len;
    }

    return malloc(len);
}

static void* dh_alloc_realloc(void* ptr, size_t len, const char* file, int line)
{
    (void)file;
    (void)line;

    return realloc(ptr, len);
}

#if OPENSSL_VERSION_NUMBER >= 0x10100000L
static void dh_alloc_free(void* ptr, const char* file, int line)
{
    (void)file;
    (void)line;

    free(ptr);
}
#else
static void dh_alloc_free_legacy(void* ptr)
{
    free(ptr);
}
#endif

int main(void)
{
    int err = 0;
    int matched = 0;
    int i;
    ENGINE* e = NULL;
    EVP_PKEY_CTX* ctx = NULL;
    EVP_PKEY* key = NULL;
    const DH* keyDh = NULL;
    const BIGNUM* keyG = NULL;

    /* Memory hooks must precede all OpenSSL initialization in this process. */
#if OPENSSL_VERSION_NUMBER < 0x10100000L
    err = CRYPTO_set_mem_ex_functions(dh_alloc_malloc, dh_alloc_realloc,
                                     dh_alloc_free_legacy) != 1;
#else
    err = CRYPTO_set_mem_functions(dh_alloc_malloc, dh_alloc_realloc,
                                  dh_alloc_free) != 1;
#endif
    if (err == 0) {
        ENGINE_load_wolfengine();
        e = ENGINE_by_id(wolfengine_id);
        err = e == NULL;
    }
    if (err == 0) {
        ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_DH, e);
        err = ctx == NULL;
    }
    if (err == 0) {
        err = EVP_PKEY_paramgen_init(ctx) != 1;
    }
    if (err == 0) {
        err = EVP_PKEY_CTX_ctrl_str(ctx, "dh_param", "ffdhe2048") != 1;
    }
    if (err == 0) {
        err = EVP_PKEY_keygen_init(ctx) != 1;
    }
    if (err == 0) {
        dhAllocTracking = 1;
        err = EVP_PKEY_keygen(ctx, &key) != 1;
        dhAllocTracking = 0;
    }
    if (err == 0) {
        keyDh = EVP_PKEY_get0_DH(key);
        if (keyDh != NULL)
            keyG = DH_get0_g(keyDh);
        err = keyG == NULL;
    }
    if (err == 0) {
        for (i = 0; !matched && (i + 2 < dhAllocCount); i++) {
            matched = (dhAllocSizes[i] == (size_t)DH_size(keyDh)) &&
                      (dhAllocSizes[i + 1] == 1) &&
                      (dhAllocSizes[i + 2] == (size_t)BN_num_bytes(keyG));
        }
        err = !matched;
    }

    EVP_PKEY_free(key);
    EVP_PKEY_CTX_free(ctx);
    ENGINE_free(e);
#if OPENSSL_VERSION_NUMBER < 0x10100000L
    EVP_cleanup();
    ENGINE_cleanup();
    ERR_free_strings();
#endif

    if (err != 0)
        fprintf(stderr, "DH encoded allocation lengths failed\n");
    else
        printf("DH encoded allocation lengths passed\n");

    return err;
}

#else

int main(void)
{
    printf("DH allocation tracking unavailable in this configuration\n");
    return 77;
}

#endif
