/* unit.c
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

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#ifdef TEST_MULTITHREADED
#include <unistd.h>
#endif

#include <stdlib.h>


#include <wolfengine/we_wolfengine.h>
#include <wolfengine/we_internal.h>
#if !defined(_MSC_VER) && !defined(__MINGW32__) && !defined(__CYGWIN__) && \
    !defined(_WIN32_WCE)
#define WE_TEST_INTERNAL_GLOBALS
#endif
#include <wolfengine/we_logging.h>

#include "unit.h"

#if !defined(WE_SINGLE_THREADED) && defined(HAVE_PTHREAD)
#include <pthread.h>
#endif

#ifndef TEST_MULTITHREADED
#if OPENSSL_VERSION_NUMBER < 0x1000209fL
#include <stdint.h>
#endif
#ifdef HAVE_VALGRIND_MEMCHECK_H
#include <stdint.h>
#include <valgrind/memcheck.h>
#endif

typedef union test_MemHeader {
    long double align;
    void *ptr;
    size_t size;
} test_MemHeader;

static void *testClearPtr = NULL;
static size_t testClearNextSize = 0;
static int testClearResult = -1;
static size_t testFailSize = 0;
static int testFailCount = 0;
static size_t testActiveAllocs = 0;

#if OPENSSL_VERSION_NUMBER >= 0x10100000L
static int test_mac_allocation_source(const char *file)
{
    const char *name = file;

    if (file == NULL)
        return 0;
    while (*file != '\0') {
        if ((*file == '/') || (*file == '\\')) {
            name = file + 1;
        }
        file++;
    }
    return strcmp(name, "we_mac.c") == 0;
}

static void *test_openssl_malloc(size_t size, const char *file, int line)
#else
static void *test_openssl_malloc(size_t size)
#endif
{
    test_MemHeader *header;

#if OPENSSL_VERSION_NUMBER >= 0x10100000L
    (void)line;

    if ((testFailCount > 0) && (size == testFailSize) &&
            test_mac_allocation_source(file)) {
        testFailCount--;
        return NULL;
    }
#endif

    header = (test_MemHeader *)malloc(sizeof(*header) + size);
    if (header != NULL) {
        header->size = size;
        header++;
#ifdef HAVE_VALGRIND_MEMCHECK_H
        VALGRIND_MEMPOOL_ALLOC(&testActiveAllocs, header, size);
#endif
        testActiveAllocs++;
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
        if ((size == testClearNextSize) && test_mac_allocation_source(file)) {
            testClearPtr = header;
            testClearNextSize = 0;
        }
#endif
    }

    return header;
}

#if OPENSSL_VERSION_NUMBER >= 0x10100000L
static void *test_openssl_realloc(void *ptr, size_t size, const char *file,
    int line)
#else
static void *test_openssl_realloc(void *ptr, size_t size)
#endif
{
    test_MemHeader *header;
#ifdef HAVE_VALGRIND_MEMCHECK_H
    uintptr_t oldAddress = (uintptr_t)ptr;
#endif

#if OPENSSL_VERSION_NUMBER >= 0x10100000L
    (void)file;
    (void)line;
#endif

    if (ptr == NULL) {
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
        return test_openssl_malloc(size, file, line);
#else
        return test_openssl_malloc(size);
#endif
    }

    header = (test_MemHeader *)ptr - 1;
    header = (test_MemHeader *)realloc(header, sizeof(*header) + size);
    if (header != NULL) {
        header->size = size;
        header++;
#ifdef HAVE_VALGRIND_MEMCHECK_H
        /* realloc preserves the payload's definedness when it moves. */
        VALGRIND_MEMPOOL_CHANGE(&testActiveAllocs, oldAddress, header, size);
#endif
    }

    return header;
}

static int test_openssl_mem_is_clear(const void *ptr, size_t size)
{
    const unsigned char *data = (const unsigned char *)ptr;
    size_t i;
#if OPENSSL_VERSION_NUMBER < 0x1000209fL
    unsigned char ctr;
#endif

    for (i = 0; i < size; i++) {
        if (data[i] != 0)
            break;
    }
    if (i == size)
        return 1;

#if OPENSSL_VERSION_NUMBER < 0x1000209fL
    /* Before 1.0.2i, portable OPENSSL_cleanse used a counter pattern. */
    if (size < 2)
        return 0;
    ctr = data[0];
    for (i = 0; i < size; i++) {
        if (data[i] != ctr)
            return 0;
        ctr = (unsigned char)(ctr + 17 +
                ((uintptr_t)(data + i + 1) & 0xf));
    }
    return 1;
#else
    return 0;
#endif
}

static int test_openssl_mem_clear_check(void)
{
    unsigned char data[32];

    memset(data, 0xa5, sizeof(data));
    if (test_openssl_mem_is_clear(data, sizeof(data)) ||
            test_openssl_mem_is_clear(data, 1)) {
        return 0;
    }
    OPENSSL_cleanse(data, sizeof(data));
    if (!test_openssl_mem_is_clear(data, sizeof(data)))
        return 0;
    data[sizeof(data) / 2] ^= 1;
    if (test_openssl_mem_is_clear(data, sizeof(data)))
        return 0;
    memset(data, 0, sizeof(data));
    if (!test_openssl_mem_is_clear(data, sizeof(data)))
        return 0;
    data[sizeof(data) / 2] = 1;
    return !test_openssl_mem_is_clear(data, sizeof(data));
}

#if OPENSSL_VERSION_NUMBER >= 0x10100000L
static void test_openssl_free(void *ptr, const char *file, int line)
#else
static void test_openssl_free(void *ptr)
#endif
{
    test_MemHeader *header;

#if OPENSSL_VERSION_NUMBER >= 0x10100000L
    (void)file;
    (void)line;
#endif

    if (ptr == NULL) {
        return;
    }

    header = (test_MemHeader *)ptr - 1;
    if (ptr == testClearPtr) {
        testClearResult = test_openssl_mem_is_clear(ptr, header->size);
        testClearPtr = NULL;
    }
#ifdef HAVE_VALGRIND_MEMCHECK_H
    VALGRIND_MEMPOOL_FREE(&testActiveAllocs, ptr);
#endif
    testActiveAllocs--;
    free(header);
}

void test_openssl_mem_expect_clear(void *ptr)
{
    testClearPtr = ptr;
    testClearResult = -1;
}

void test_openssl_mem_expect_next_clear(size_t size)
{
    testClearPtr = NULL;
    testClearNextSize = size;
    testClearResult = -1;
}

int test_openssl_mem_clear_result(void)
{
    return testClearResult;
}

void test_openssl_mem_fail_once(size_t size)
{
    testFailSize = size;
    testFailCount = 1;
}

int test_openssl_mem_failure_triggered(void)
{
    int triggered = testFailCount == 0;

    testFailCount = 0;
    return triggered;
}

size_t test_openssl_mem_active(void)
{
    return testActiveAllocs;
}

int test_openssl_mem_has_source(void)
{
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
    return OPENSSL_FILE[0] != '\0';
#else
    return 0;
#endif
}
#endif /* !TEST_MULTITHREADED */

#ifdef WOLFENGINE_DEBUG
void print_buffer(const char *desc, const unsigned char *buffer, size_t len)
{
    size_t i;

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

static int debug = 1;
#else
static int debug = 0;
#endif /* WOLFENGINE_DEBUG */
static unsigned long flags = 0;

static int test_engine(ENGINE *e, void *data)
{
    int err = 0;

    (void)data;

#if defined(WE_HAVE_ECC) && !defined(WE_HAVE_ECDSA) && \
    defined(WE_HAVE_SHA1)
    {
        ENGINE_DIGESTS_PTR digests = ENGINE_get_digests(e);
        const int *nids = NULL;
        int count;
        int i;

        if (digests == NULL) {
            PRINT_ERR_MSG("Engine digest callback is not set");
            err = 1;
        }
        if (err == 0) {
            count = digests(e, NULL, &nids, 0);
            for (i = 0; i < count; i++) {
                if (nids[i] == NID_ecdsa_with_SHA1) {
                    PRINT_ERR_MSG("ECDSA-with-SHA1 advertised without ECDSA");
                    err = 1;
                }
            }
        }
    }
#else
    (void)e;
#endif

    return err;
}

#if !defined(WE_NO_DYNAMIC_ENGINE) && defined(WE_HAVE_SHARED_LIBRARY)
static int test_engine_id_match(const char *dir)
{
    int err = 0;
    int len;
    ENGINE *engine = NULL;
    FILE *file = NULL;
    char id[80];
    char path[256];

    len = snprintf(id, sizeof(id), "%s-suffix", wolfengine_id);
    if ((len < 0) || ((size_t)len >= sizeof(id))) {
        PRINT_ERR_MSG("Failed to construct mismatched engine identifier");
        err = 1;
    }
    #if defined(__CYGWIN__)
    len = snprintf(path, sizeof(path), "%s/cygwolfengine-1.dll", dir);
    #elif defined(__MINGW32__)
    len = snprintf(path, sizeof(path), "%s/libwolfengine-1.dll", dir);
    #elif defined(_WIN32)
    len = snprintf(path, sizeof(path), "%s/wolfEngine.dll", dir);
    #elif defined(__APPLE__)
    len = snprintf(path, sizeof(path), "%s/libwolfengine.dylib", dir);
    #else
    len = snprintf(path, sizeof(path), "%s/libwolfengine.so", dir);
    #endif
    if ((len < 0) || ((size_t)len >= sizeof(path))) {
        PRINT_ERR_MSG("Failed to construct engine library path");
        err = 1;
    }
    if (err == 0) {
        file = fopen(path, "rb");
        if (file == NULL) {
            PRINT_ERR_MSG("Failed to open engine library for identifier test");
            err = 1;
        }
    }
    if (file != NULL) {
        fclose(file);
    }
    if (err == 0) {
        engine = ENGINE_by_id("dynamic");
    }
    if ((err == 0) && (engine == NULL)) {
        PRINT_ERR_MSG("Failed to load dynamic engine support");
        err = 1;
    }
    if ((err == 0) &&
        (ENGINE_ctrl_cmd_string(engine, "SO_PATH", path, 0) != 1)) {
        PRINT_ERR_MSG("Failed to set engine library path");
        err = 1;
    }
    if ((err == 0) &&
        (ENGINE_ctrl_cmd_string(engine, "ID", id, 0) != 1)) {
        PRINT_ERR_MSG("Failed to set mismatched engine identifier");
        err = 1;
    }
    if ((err == 0) &&
        (ENGINE_ctrl_cmd_string(engine, "LIST_ADD", "0", 0) != 1)) {
        PRINT_ERR_MSG("Failed to configure dynamic engine loading");
        err = 1;
    }
    if ((err == 0) &&
        (ENGINE_ctrl_cmd_string(engine, "LOAD", NULL, 0) != 0)) {
        PRINT_ERR_MSG("Accepted an engine identifier with a suffix");
        err = 1;
    }

    if (engine != NULL) {
        ENGINE_free(engine);
    }
    ERR_clear_error();
    return err;
}

static int test_engine_bind_rollback(const char *dir)
{
    int err = 0;
    int len;
    int rc;
    ENGINE *engine = NULL;
    const char *name;
    char path[256];

#if defined(__CYGWIN__)
    len = snprintf(path, sizeof(path), "%s/cygwolfengine-1.dll", dir);
#elif defined(__MINGW32__)
    len = snprintf(path, sizeof(path), "%s/libwolfengine-1.dll", dir);
#elif defined(_WIN32)
    len = snprintf(path, sizeof(path), "%s/wolfEngine.dll", dir);
#elif defined(__APPLE__)
    len = snprintf(path, sizeof(path), "%s/libwolfengine.dylib", dir);
#else
    len = snprintf(path, sizeof(path), "%s/libwolfengine.so", dir);
#endif
    if ((len < 0) || ((size_t)len >= sizeof(path))) {
        PRINT_ERR_MSG("Failed to construct engine library path");
        err = 1;
    }
    if (err == 0) {
        engine = ENGINE_by_id("dynamic");
    }
    if ((err == 0) && (engine == NULL)) {
        PRINT_ERR_MSG("Failed to load dynamic engine support");
        err = 1;
    }
    if ((err == 0) &&
        (ENGINE_ctrl_cmd_string(engine, "SO_PATH", path, 0) != 1)) {
        PRINT_ERR_MSG("Failed to set engine library path");
        err = 1;
    }
    if ((err == 0) &&
        (ENGINE_ctrl_cmd_string(engine, "ID", wolfengine_id, 0) != 1)) {
        PRINT_ERR_MSG("Failed to set engine identifier");
        err = 1;
    }
    if ((err == 0) &&
        (ENGINE_ctrl_cmd_string(engine, "LIST_ADD", "0", 0) != 1)) {
        PRINT_ERR_MSG("Failed to configure dynamic engine loading");
        err = 1;
    }
    if (err == 0) {
        name = wolfengine_name;
        wolfengine_name = NULL;
        rc = ENGINE_ctrl_cmd_string(engine, "LOAD", NULL, 0);
        wolfengine_name = name;
        if (rc != 0) {
            PRINT_ERR_MSG("Accepted an incomplete engine binding");
            err = 1;
        }
    }

    if (engine != NULL) {
        ENGINE_free(engine);
    }
    ERR_clear_error();
    return err;
}

#endif /* !WE_NO_DYNAMIC_ENGINE && WE_HAVE_SHARED_LIBRARY */

#ifndef WE_NO_DYNAMIC_ENGINE
extern int bind_engine(ENGINE *engine, const char *id,
                       const dynamic_fns *functions);

#ifdef WOLFENGINE_DEBUG
static ENGINE *we_logging_bind_engine;
static dynamic_fns we_logging_bind_functions;
static int we_logging_bind_phase;
static int we_logging_bind_calls[2];
static int we_logging_bind_err;
static int we_logging_bind_inside;

static void test_engine_bind_logging_cb(int level, int component,
    const char *const message)
{
    (void)level;
    (void)component;
    (void)message;

    if (we_logging_bind_inside != 0)
        return;
    we_logging_bind_inside = 1;
    we_logging_bind_calls[we_logging_bind_phase]++;
    if (bind_engine(we_logging_bind_engine, wolfengine_id,
                    &we_logging_bind_functions) != 0) {
        we_logging_bind_err = 1;
    }
    ENGINE_load_wolfengine();
    we_logging_bind_inside = 0;
}

static int test_engine_logging_bind(void)
{
    int err = 0;
    ENGINE *engine = ENGINE_new();

    we_logging_bind_engine = ENGINE_new();
    if ((engine == NULL) || (we_logging_bind_engine == NULL)) {
        err = 1;
    }
    memset(&we_logging_bind_functions, 0, sizeof(we_logging_bind_functions));
    we_logging_bind_functions.static_state = ENGINE_get_static_state();
    we_logging_bind_phase = 0;
    we_logging_bind_calls[0] = 0;
    we_logging_bind_calls[1] = 0;
    we_logging_bind_err = 0;
    we_logging_bind_inside = 0;
    if (err == 0) {
        wolfEngine_SetLogLevel(WE_LOG_LEVEL_DEFAULT);
        wolfEngine_SetLogComponents(WE_LOG_COMPONENTS_ALL);
        wolfEngine_SetLoggingCb(test_engine_bind_logging_cb);
        wolfEngine_Debugging_ON();
        if (bind_engine(engine, wolfengine_id,
                         &we_logging_bind_functions) != 1) {
            err = 1;
        }
        we_logging_bind_phase = 1;
        ENGINE_free(engine);
        engine = NULL;
        wolfEngine_Debugging_OFF();
        wolfEngine_SetLoggingCb(NULL);
        if ((we_logging_bind_calls[0] == 0) ||
            (we_logging_bind_calls[1] == 0) || (we_logging_bind_err != 0)) {
            PRINT_ERR_MSG("Logging did not preserve engine lifecycle ownership");
            err = 1;
        }
    }
    ENGINE_free(engine);
    ENGINE_free(we_logging_bind_engine);
    we_logging_bind_engine = NULL;
    ERR_clear_error();
    return err;
}
#endif /* WOLFENGINE_DEBUG */

#if !defined(WE_SINGLE_THREADED) && defined(HAVE_PTHREAD) && \
    OPENSSL_VERSION_NUMBER >= 0x10100000L
#define WE_BIND_TEST_THREADS 8

typedef struct we_bind_test_ctx {
    ENGINE *engine;
    const dynamic_fns *functions;
    pthread_mutex_t *mutex;
    pthread_cond_t *condition;
    int *ready;
    int *start;
    int result;
} we_bind_test_ctx;

static void *test_engine_bind_thread(void *arg)
{
    we_bind_test_ctx *ctx = (we_bind_test_ctx *)arg;

    pthread_mutex_lock(ctx->mutex);
    (*ctx->ready)++;
    pthread_cond_broadcast(ctx->condition);
    while (*ctx->start == 0) {
        pthread_cond_wait(ctx->condition, ctx->mutex);
    }
    pthread_mutex_unlock(ctx->mutex);

    ctx->result = bind_engine(ctx->engine, wolfengine_id, ctx->functions);
    return NULL;
}

static int test_engine_concurrent_bind(void)
{
    int err = 0;
    int ready = 0;
    int start = 0;
    int created = 0;
    int success = 0;
    int i;
    pthread_t threads[WE_BIND_TEST_THREADS];
    pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
    pthread_cond_t condition = PTHREAD_COND_INITIALIZER;
    dynamic_fns functions;
    we_bind_test_ctx ctx[WE_BIND_TEST_THREADS];

    memset(&functions, 0, sizeof(functions));
    functions.static_state = ENGINE_get_static_state();
    memset(ctx, 0, sizeof(ctx));
    for (i = 0; (err == 0) && (i < WE_BIND_TEST_THREADS); i++) {
        ctx[i].engine = ENGINE_new();
        ctx[i].functions = &functions;
        ctx[i].mutex = &mutex;
        ctx[i].condition = &condition;
        ctx[i].ready = &ready;
        ctx[i].start = &start;
        if (ctx[i].engine == NULL) {
            PRINT_ERR_MSG("Failed to allocate concurrent engine binding");
            err = 1;
        }
    }
    for (i = 0; (err == 0) && (i < WE_BIND_TEST_THREADS); i++) {
        if (pthread_create(&threads[i], NULL, test_engine_bind_thread,
                           &ctx[i]) != 0) {
            PRINT_ERR_MSG("Failed to create engine binding thread");
            err = 1;
        }
        else {
            created++;
        }
    }
    pthread_mutex_lock(&mutex);
    while ((err == 0) && (ready != WE_BIND_TEST_THREADS)) {
        pthread_cond_wait(&condition, &mutex);
    }
    start = 1;
    pthread_cond_broadcast(&condition);
    pthread_mutex_unlock(&mutex);

    for (i = 0; i < created; i++) {
        pthread_join(threads[i], NULL);
    }
    if (err == 0) {
        for (i = 0; i < WE_BIND_TEST_THREADS; i++) {
            success += ctx[i].result == 1;
        }
        if (success != 1) {
            PRINT_ERR_MSG("Concurrent engine binding did not select one owner");
            err = 1;
        }
    }
    for (i = 0; i < WE_BIND_TEST_THREADS; i++) {
        if (ctx[i].engine != NULL) {
            ENGINE_free(ctx[i].engine);
        }
    }
    pthread_cond_destroy(&condition);
    pthread_mutex_destroy(&mutex);
    ERR_clear_error();
    return err;
}
#endif

static int test_engine_bind_lifecycle(const char *dir)
{
    int err = 0;
    int ran = 0;

    (void)dir;
    OpenSSL_add_all_ciphers();
    OpenSSL_add_all_digests();
#ifdef WE_HAVE_SHARED_LIBRARY
    ENGINE_load_dynamic();
    PRINT_MSG("Engine binding rollback and identifiers");
    ran = 1;
    err = test_engine_bind_rollback(dir);
    if (err == 0) {
        err = test_engine_id_match(dir);
    }
#endif
#ifdef WOLFENGINE_DEBUG
    if (err == 0) {
        PRINT_MSG("Engine logging lifecycle ownership");
        ran = 1;
        err = test_engine_logging_bind();
    }
#endif
#if !defined(WE_SINGLE_THREADED) && defined(HAVE_PTHREAD) && \
    OPENSSL_VERSION_NUMBER >= 0x10100000L
    if (err == 0) {
        PRINT_MSG("Concurrent engine binding ownership");
        ran = 1;
        err = test_engine_concurrent_bind();
    }
#endif
    return ran ? err : 77;
}
#endif /* !WE_NO_DYNAMIC_ENGINE */
#if OPENSSL_VERSION_NUMBER >= 0x10100000L && \
    (defined(WE_HAVE_HMAC) || defined(WE_HAVE_CMAC))
static int mac_asn1_methods_cleared(void)
{
    int ret = 1;

#ifdef WE_HAVE_HMAC
    if (we_hmac_pkey_asn1_method != NULL)
        ret = 0;
#endif
#ifdef WE_HAVE_CMAC
    if ((we_cmac_pkey_asn1_method != NULL) ||
            (we_cmac_we_pkey_asn1_method != NULL)) {
        ret = 0;
    }
#endif

    return ret;
}
#endif

#if defined(WE_TEST_INTERNAL_GLOBALS) && \
    OPENSSL_VERSION_NUMBER >= 0x10100000L
static int test_engine_destroyed(void)
{
    int err = 0;

#ifdef WE_HAVE_HMAC
    if (we_hmac_pkey_method != NULL) {
        err = 1;
    }
#endif
#ifdef WE_HAVE_CMAC
    if ((we_cmac_pkey_method != NULL) ||
            (we_cmac_we_pkey_method != NULL)) {
        err = 1;
    }
#endif
#if defined(WE_HAVE_TLS1_PRF) && defined(WE_HAVE_EVP_PKEY)
    if (we_tls1_prf_method != NULL) {
        err = 1;
    }
#endif
#if defined(WE_HAVE_HKDF) && defined(WE_HAVE_EVP_PKEY)
    if (we_hkdf_method != NULL) {
        err = 1;
    }
#endif
#if defined(WE_HAVE_DH) && defined(WE_HAVE_EVP_PKEY)
    if (we_dh_pkey_method != NULL) {
        err = 1;
    }
#endif
#if defined(WE_HAVE_RSA) && defined(WE_HAVE_EVP_PKEY)
    if (we_rsa_pkey_method != NULL) {
        err = 1;
    }
#endif
#if defined(WE_HAVE_ECC) && defined(WE_HAVE_EVP_PKEY)
    if (we_ec_method != NULL) {
        err = 1;
    }
#ifdef WE_HAVE_ECKEYGEN
#ifdef WE_HAVE_EC_P192
    if (we_ec_p192_method != NULL) {
        err = 1;
    }
#endif
#ifdef WE_HAVE_EC_P224
    if (we_ec_p224_method != NULL) {
        err = 1;
    }
#endif
#ifdef WE_HAVE_EC_P256
    if (we_ec_p256_method != NULL) {
        err = 1;
    }
#endif
#ifdef WE_HAVE_EC_P384
    if (we_ec_p384_method != NULL) {
        err = 1;
    }
#endif
#ifdef WE_HAVE_EC_P521
    if (we_ec_p521_method != NULL) {
        err = 1;
    }
#endif
#endif /* WE_HAVE_ECKEYGEN */
#endif /* WE_HAVE_ECC && WE_HAVE_EVP_PKEY */

    if (err != 0) {
        PRINT_ERR_MSG("Engine PKEY methods remain allocated after teardown");
    }

    return err;
}
#endif

TEST_CASE test_case[] = {
    TEST_DECL(test_logging, &debug),
#if OPENSSL_VERSION_NUMBER < 0x10100000L
    TEST_DECL(test_openssl_bc_method_name, &flags),
    TEST_DECL(test_openssl_bc_public_ec_key, NULL),
    TEST_DECL(test_openssl_bc_ec_private_padding, NULL),
#endif
#ifdef WE_HAVE_SHA1
    TEST_DECL(test_sha, NULL),
#endif
#ifdef WE_HAVE_SHA224
    TEST_DECL(test_sha224, NULL),
#endif
#ifdef WE_HAVE_SHA256
    TEST_DECL(test_sha256, NULL),
#endif
#ifdef WE_HAVE_SHA384
    TEST_DECL(test_sha384, NULL),
#endif
#ifdef WE_HAVE_SHA512
    TEST_DECL(test_sha512, NULL),
#endif
#ifdef WE_HAVE_AESCCM
    TEST_DECL(test_aes_ccm_keyed_reinit, NULL),
#endif
#ifdef WE_HAVE_SHA3_224
    TEST_DECL(test_sha3_224, NULL),
#endif
#ifdef WE_HAVE_SHA3_256
    TEST_DECL(test_sha3_256, NULL),
#endif
#ifdef WE_HAVE_SHA3_384
    TEST_DECL(test_sha3_384, NULL),
#endif
#ifdef WE_HAVE_SHA3_512
    TEST_DECL(test_sha3_512, NULL),
#endif
#ifdef WE_HAVE_HMAC
    TEST_DECL(test_hmac_create, NULL),
    TEST_DECL(test_hmac_output_size, NULL),
    TEST_DECL(test_hmac_pkey_size, NULL),
    TEST_DECL(test_hmac_update_size, NULL),
    #if OPENSSL_VERSION_NUMBER >= 0x10101000L && \
        !defined(TEST_MULTITHREADED)
    TEST_DECL(test_hmac_raw_key_output_size, NULL),
    #endif
#endif
#ifdef WE_HAVE_CMAC
    TEST_DECL(test_cmac_create, &flags),
    TEST_DECL(test_cmac_output_size, NULL),
    TEST_DECL(test_cmac_update_size, NULL),
    #ifndef TEST_MULTITHREADED
    TEST_DECL(test_cmac_copy_error, NULL),
    #endif
    TEST_DECL(test_cmac_copy, NULL),
    TEST_DECL(test_cmac_keygen_reuse, NULL),
    #ifndef TEST_MULTITHREADED
    TEST_DECL(test_cmac_unregistered_engine, NULL),
    #endif
    TEST_DECL(test_cmac_asn1_registry, NULL),
#endif
#if defined(WE_HAVE_HMAC) || defined(WE_HAVE_CMAC)
    TEST_DECL(test_mac_asn1_ownership, NULL),
#endif
#ifdef WE_HAVE_TLS1_PRF
    TEST_DECL(test_tls1_prf, NULL),
    TEST_DECL(test_tls1_prf_bad_md, NULL),
    TEST_DECL(test_tls1_prf_secret_failure, &debug),
    TEST_DECL(test_tls1_prf_output_size, NULL),
#endif
#ifdef WE_HAVE_HKDF
    TEST_DECL(test_hkdf, NULL),
    TEST_DECL(test_hkdf_bad_md, NULL),
#endif
#ifdef WE_HAVE_DES3CBC
    TEST_DECL(test_des3_cbc, NULL),
    TEST_DECL(test_des3_cbc_stream, NULL),
    TEST_DECL(test_des3_cbc_iv_bounds, NULL),
    TEST_DECL(test_des3_cbc_decrypt_error_log, &debug),
    TEST_DECL(test_des3_cbc_rekey_cleanup, NULL),
#endif
#ifdef WE_HAVE_AESECB
    TEST_DECL(test_aes128_ecb, NULL),
    TEST_DECL(test_aes192_ecb, NULL),
    TEST_DECL(test_aes256_ecb, NULL),
    TEST_DECL(test_aes128_ecb_stream, NULL),
    TEST_DECL(test_aes192_ecb_stream, NULL),
    TEST_DECL(test_aes256_ecb_stream, NULL),
#endif
#ifdef WE_HAVE_AESCBC
    TEST_DECL(test_aes128_cbc, NULL),
    TEST_DECL(test_aes192_cbc, NULL),
    TEST_DECL(test_aes256_cbc, NULL),
    TEST_DECL(test_aes128_cbc_stream, NULL),
    TEST_DECL(test_aes192_cbc_stream, NULL),
    TEST_DECL(test_aes256_cbc_stream, NULL),
    TEST_DECL(test_aes128_cbc_hmac_tls_short, NULL),
    TEST_DECL(test_aes128_cbc_hmac_staged_init, NULL),
    TEST_DECL(test_aes128_cbc_hmac_plain_encrypt, NULL),
    TEST_DECL(test_aes128_cbc_hmac_tls_bad_length_reset, NULL),
    TEST_DECL(test_aes128_cbc_hmac_encrypt_error, NULL),
    TEST_DECL(test_aes128_cbc_hmac_ctrl_error, NULL),
    TEST_DECL(test_aes128_cbc_hmac_tls_empty, NULL),
    TEST_DECL(test_aes128_cbc_hmac_reinit_state, NULL),
    TEST_DECL(test_aes128_cbc_hmac_cleanup, NULL),
    TEST_DECL(test_aes128_cbc_hmac_tls_lengths, NULL),
    TEST_DECL(test_aes128_cbc_hmac_no_tls_mac, NULL),
    TEST_DECL(test_aes128_cbc_hmac_tls_extended_padding, NULL),
    TEST_DECL(test_aes128_cbc_hmac_tls_retry_after_bad_padding, NULL),
    TEST_DECL(test_aes128_cbc_hmac_tls_padding_range, NULL),
#endif
#ifdef WE_HAVE_AESCTR
    TEST_DECL(test_aes128_ctr_stream, NULL),
    TEST_DECL(test_aes192_ctr_stream, NULL),
    TEST_DECL(test_aes256_ctr_stream, NULL),
    TEST_DECL(test_aes_ctr_leftover_data_regression, NULL),
    TEST_DECL(test_aes_ctr_iv_init_regression, NULL),
#endif
#ifdef WE_HAVE_AESGCM
    TEST_DECL(test_aes128_gcm, NULL),
    TEST_DECL(test_aes192_gcm, NULL),
    TEST_DECL(test_aes256_gcm, NULL),
    TEST_DECL(test_aes128_gcm_fixed, NULL),
    TEST_DECL(test_aes128_gcm_tls, NULL),
    TEST_DECL(test_aes_gcm_tls_multi_record, NULL),
    TEST_DECL(test_aes_gcm_tls_input_bounds, NULL),
    TEST_DECL(test_aes_gcm_tls_bad_iv_len, NULL),
    TEST_DECL(test_aes_gcm_tls_fixed_iv_required, NULL),
    TEST_DECL(test_aes_gcm_evp_cipher, NULL),
    TEST_DECL(test_aes128_gcm_iv_gen_bounds, NULL),
    TEST_DECL(test_aes_gcm_ctx_copy_rejected, NULL),
    TEST_DECL(test_aes_gcm_keyed_reinit, NULL),
    TEST_DECL(test_aes_gcm_cleanup_empty_ctx, NULL),
    TEST_DECL(test_aes_gcm_aad_length_bounds, NULL),
    TEST_DECL(test_aes_gcm_auth_error_queue, NULL),
    TEST_DECL(test_aes_gcm_ctrl_output_buffers, NULL),
#endif
#ifdef WE_HAVE_AESCCM
    TEST_DECL(test_aes128_ccm, NULL),
    TEST_DECL(test_aes192_ccm, NULL),
    TEST_DECL(test_aes256_ccm, NULL),
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
    TEST_DECL(test_aes128_ccm_tls, NULL),
    TEST_DECL(test_aes_ccm_tls_multi_record, NULL),
    TEST_DECL(test_aes_ccm_tls_input_bounds, NULL),
    TEST_DECL(test_aes_ccm_tls_bad_iv_len, NULL),
#endif
#endif
#ifdef WE_HAVE_RANDOM
    TEST_DECL(test_random, NULL),
#endif
#ifdef WE_HAVE_RSA
    TEST_DECL(test_rsa_ctrl_str,        NULL),
    TEST_DECL(test_rsa_direct_key_gen,  NULL),
    TEST_DECL(test_rsa_direct_priv_enc, NULL),
    TEST_DECL(test_rsa_direct_priv_dec, NULL),
    TEST_DECL(test_rsa_direct_pub_enc,  NULL),
    TEST_DECL(test_rsa_direct_pub_dec,  NULL),
#endif /* WE_HAVE_RSA */
#ifdef WE_HAVE_DH
    TEST_DECL(test_dh_pgen, NULL),
    TEST_DECL(test_dh, NULL),
    TEST_DECL(test_dh_priv_key_length, NULL),
#ifdef WE_HAVE_EVP_PKEY
    TEST_DECL(test_dh_pgen_pkey, NULL),
    TEST_DECL(test_dh_pkey, NULL),
    TEST_DECL(test_dh_ctrl, NULL),
#if !defined(WE_SINGLE_THREADED) && defined(_WIN32)
    TEST_DECL(test_dh_key_gen_multithreaded, NULL),
#endif /* !WE_SINGLE_THREADED && _WIN32 */
#endif /* WE_HAVE_EVP_PKEY */
#endif /* WE_HAVE_DH */
#if OPENSSL_VERSION_NUMBER < 0x10100000L
#if defined(WE_HAVE_ECDH)
    #ifdef WE_HAVE_EC_P192
        TEST_DECL(test_ecdh_direct_p192, NULL),
    #endif
    #ifdef WE_HAVE_EC_P256
        TEST_DECL(test_ecdh_direct_p256, NULL),
    #endif
    #ifdef WE_HAVE_EC_P384
        TEST_DECL(test_ecdh_direct_p384, NULL),
    #endif
    #ifdef WE_HAVE_EC_P521
        TEST_DECL(test_ecdh_direct_p521, NULL),
    #endif
#endif /* WE_HAVE_EDCH */
#endif /* OPENSSL_VERSION_NUMBER < 0x10100000L */
#ifdef WE_HAVE_EVP_PKEY
#ifdef WE_HAVE_RSA
    TEST_DECL(test_rsa_sign_sha1, NULL),
    TEST_DECL(test_rsa_sign_verify_pkcs1, NULL),
#ifdef WE_HAVE_RSA_X931
    TEST_DECL(test_rsa_sign_verify_x931, NULL),
#endif /* WE_HAVE_RSA_X931 */
    TEST_DECL(test_rsa_sign_verify_no_pad, NULL),
    TEST_DECL(test_rsa_sign_verify_pss, NULL),
    TEST_DECL(test_rsa_enc_dec_pkcs1, NULL),
    TEST_DECL(test_rsa_enc_dec_no_pad, NULL),
    TEST_DECL(test_rsa_dec_no_pad_size_query, NULL),
    TEST_DECL(test_rsa_enc_dec_oaep, NULL),
    TEST_DECL(test_rsa_oaep_label, NULL),
    TEST_DECL(test_rsa_pkey_keygen, NULL),
    TEST_DECL(test_rsa_pkey_large_exponent, NULL),
    TEST_DECL(test_rsa_pkey_sign_missing_data, NULL),
    TEST_DECL(test_rsa_pkey_sign_digest_length, NULL),
    TEST_DECL(test_rsa_verify_recover_digest, NULL),
    TEST_DECL(test_rsa_pkey_invalid_key_size, NULL),
#endif /* WE_HAVE_RSA */
#ifdef WE_HAVE_EC_P192
    #ifdef WE_HAVE_ECKEYGEN
        TEST_DECL(test_eckeygen_p192_by_nid, NULL),
        TEST_DECL(test_eckeygen_p192, NULL),
    #endif
    #ifdef WE_HAVE_ECDH
    #ifdef WE_HAVE_ECKEYGEN
        TEST_DECL(test_ecdh_p192_keygen, NULL),
    #endif
        TEST_DECL(test_ecdh_p192, NULL),
    #endif
    #ifdef WE_HAVE_ECDSA
        TEST_DECL(test_ecdsa_p192_pkey, NULL),
        TEST_DECL(test_ecdsa_p192, NULL),
    #endif
#endif
#ifdef WE_HAVE_EC_P224
    #ifdef WE_HAVE_ECKEYGEN
        TEST_DECL(test_eckeygen_p224_by_nid, NULL),
        TEST_DECL(test_eckeygen_p224, NULL),
    #endif
    #ifdef WE_HAVE_ECDH
    #ifdef WE_HAVE_ECKEYGEN
        TEST_DECL(test_ecdh_p224_keygen, NULL),
    #endif
        TEST_DECL(test_ecdh_p224, NULL),
    #endif
    #ifdef WE_HAVE_ECDSA
        TEST_DECL(test_ecdsa_p224_pkey, NULL),
        TEST_DECL(test_ecdsa_p224, NULL),
    #endif
#endif
#ifdef WE_HAVE_EC_P256
    #ifdef WE_HAVE_ECKEYGEN
        TEST_DECL(test_eckeygen_p256_by_nid, NULL),
        TEST_DECL(test_eckeygen_p256, NULL),
    #endif
    #ifdef WE_HAVE_ECDH
    #ifdef WE_HAVE_ECKEYGEN
        TEST_DECL(test_ecdh_p256_keygen, NULL),
    #endif
        TEST_DECL(test_ecdh_p256, NULL),
    #endif
    #ifdef WE_HAVE_ECDSA
        TEST_DECL(test_ecdsa_p256_pkey, NULL),
        TEST_DECL(test_ecdsa_p256, NULL),
    #endif
#endif
#ifdef WE_HAVE_EC_P384
    #ifdef WE_HAVE_ECKEYGEN
        TEST_DECL(test_eckeygen_p384_by_nid, NULL),
        TEST_DECL(test_eckeygen_p384, NULL),
    #endif
    #ifdef WE_HAVE_ECDH
    #ifdef WE_HAVE_ECKEYGEN
        TEST_DECL(test_ecdh_p384_keygen, NULL),
    #endif
        TEST_DECL(test_ecdh_p384, NULL),
    #endif
    #ifdef WE_HAVE_ECDSA
        TEST_DECL(test_ecdsa_p384_pkey, NULL),
        TEST_DECL(test_ecdsa_p384, NULL),
    #endif
#endif
#ifdef WE_HAVE_EC_P521
    #ifdef WE_HAVE_ECKEYGEN
        TEST_DECL(test_eckeygen_p521_by_nid, NULL),
        TEST_DECL(test_eckeygen_p521, NULL),
    #endif
    #ifdef WE_HAVE_ECDH
    #ifdef WE_HAVE_ECKEYGEN
        TEST_DECL(test_ecdh_p521_keygen, NULL),
    #endif
        TEST_DECL(test_ecdh_p521, NULL),
    #endif
    #ifdef WE_HAVE_ECDSA
        TEST_DECL(test_ecdsa_p521_pkey, NULL),
        TEST_DECL(test_ecdsa_p521, NULL),
    #endif
#endif
#endif /* WE_HAVE_EVP_PKEY */
#ifdef WE_HAVE_EC_KEY
#ifdef WE_HAVE_EC_P192
    #ifdef WE_HAVE_ECKEYGEN
        TEST_DECL(test_ec_key_keygen_p192_by_nid, NULL),
    #endif
    #ifdef WE_HAVE_ECDH
    #ifdef WE_HAVE_ECKEYGEN
        TEST_DECL(test_ec_key_ecdh_p192_keygen, NULL),
    #endif
        TEST_DECL(test_ec_key_ecdh_p192, NULL),
    #endif
    #ifdef WE_HAVE_ECDSA
        TEST_DECL(test_ec_key_ecdsa_p192, NULL),
    #endif
#endif
#ifdef WE_HAVE_EC_P224
    #ifdef WE_HAVE_ECKEYGEN
        TEST_DECL(test_ec_key_keygen_p224_by_nid, NULL),
    #endif
    #ifdef WE_HAVE_ECDH
    #ifdef WE_HAVE_ECKEYGEN
        TEST_DECL(test_ec_key_ecdh_p224_keygen, NULL),
    #endif
        TEST_DECL(test_ec_key_ecdh_p224, NULL),
    #endif
    #ifdef WE_HAVE_ECDSA
        TEST_DECL(test_ec_key_ecdsa_p224, NULL),
    #endif
#endif
#ifdef WE_HAVE_EC_P256
    #ifdef WE_HAVE_ECKEYGEN
        TEST_DECL(test_ec_key_keygen_p256_by_nid, NULL),
    #endif
    #ifdef WE_HAVE_ECDH
    #ifdef WE_HAVE_ECKEYGEN
        TEST_DECL(test_ec_key_ecdh_p256_keygen, NULL),
    #endif
        TEST_DECL(test_ec_key_ecdh_p256, NULL),
    #endif
    #ifdef WE_HAVE_ECDSA
        TEST_DECL(test_ec_key_ecdsa_p256, NULL),
    #endif
#endif
#ifdef WE_HAVE_EC_P384
    #ifdef WE_HAVE_ECKEYGEN
        TEST_DECL(test_ec_key_keygen_p384_by_nid, NULL),
    #endif
    #ifdef WE_HAVE_ECDH
    #ifdef WE_HAVE_ECKEYGEN
        TEST_DECL(test_ec_key_ecdh_p384_keygen, NULL),
    #endif
        TEST_DECL(test_ec_key_ecdh_p384, NULL),
    #endif
    #ifdef WE_HAVE_ECDSA
        TEST_DECL(test_ec_key_ecdsa_p384, NULL),
    #endif
#endif
#ifdef WE_HAVE_EC_P521
    #ifdef WE_HAVE_ECKEYGEN
        TEST_DECL(test_ec_key_keygen_p521_by_nid, NULL),
    #endif
    #ifdef WE_HAVE_ECDH
    #ifdef WE_HAVE_ECKEYGEN
        TEST_DECL(test_ec_key_ecdh_p521_keygen, NULL),
    #endif
        TEST_DECL(test_ec_key_ecdh_p521, NULL),
    #endif
    #ifdef WE_HAVE_ECDSA
        TEST_DECL(test_ec_key_ecdsa_p521, NULL),
    #endif
#endif
#endif /* WE_HAVE_EC_KEY */

#ifdef WE_HAVE_ECDSA
#if OPENSSL_VERSION_NUMBER < 0x10100000L
    TEST_DECL(test_ecdsa, NULL),
#endif
#endif /* WE_HAVE_ECDSA */

#ifdef WE_HAVE_PBE
    TEST_DECL(test_pbe_invalid_params, NULL),
    TEST_DECL(test_pbe, NULL),
#endif
    TEST_DECL(test_engine, NULL),
};
#define TEST_CASE_CNT   (int)(sizeof(test_case) / sizeof(*test_case))

static void usage(void)
{
    printf("\n");
    printf("Usage: unit.test [options]\n");
    printf("  --help          Show this usage information.\n");
    printf("  --static        Run the tests using the static engine.\n");
    printf("  --bind-lifecycle Run the engine lifecycle checks only.\n");
    printf("  --dir <path>    Location of wolfengine shared library.\n");
    printf("                  Default: .libs\n");
    printf("  --engine <str>  Name of wolfsslengine. Default: libwolfengine\n");
#ifdef TEST_MULTITHREADED
    printf("  --secs <num>    Number of seconds to run for. Default: 10\n");
#endif
    printf("  --no-debug      Disable debug logging\n");
    printf("  --list          Display all test cases\n");
    printf("  --valgrind      Run wolfSSL only tests for Valgrind where OpenSSL "
                              "has issues\n");
    printf("  <num>           Run this test case, but not all\n");
}

#ifdef TEST_MULTITHREADED

static CRYPTO_RWLOCK *testLock = NULL;
static ENGINE *testEngine = NULL;
static int stop = 0;
static int secs = 10;

static int LockInit(void)
{
    int err = 0;

    testLock = CRYPTO_THREAD_lock_new();
    if (testLock == NULL) {
        err = 1;
    }

    return err;
}

static void LockFree(void)
{
    CRYPTO_THREAD_lock_free(testLock);
}

static int LockRW(void)
{
    return CRYPTO_THREAD_write_lock(testLock) != 1;
}

static int UnlockRW(void)
{
    return CRYPTO_THREAD_unlock(testLock) != 1;
}

static int LockRO(void)
{
    return CRYPTO_THREAD_read_lock(testLock) != 1;
}

static int UnlockRO(void)
{
    return CRYPTO_THREAD_unlock(testLock) != 1;
}

static void *run_test(void *args)
{
    TEST_CASE *testCase = (TEST_CASE *)args;

    if (LockRO() != 0) {
        fprintf(stderr, "Locking failed\n");
    }
    else {
        while (!stop && !testCase->err) {
            testCase->err = testCase->func(testEngine, testCase->data);
            testCase->cnt++;
        }
        testCase->done = 1;

        UnlockRO();
    }

    return NULL;
}

static int run_tests(ENGINE *e, int runAll)
{
    int err = 0;
    int i;

    err = LockInit();
    if (err != 0)
        fprintf(stderr, "Failed to initialize mutex!\n");
    else {
        err = LockRW();
        if (err != 0)
            fprintf(stderr, "Failed to lock mutex!\n");
        else {
            testEngine = e;

            for (i = 0; i < TEST_CASE_CNT; i++) {
                test_case[i].attempted = 0;

                if (!runAll && !test_case[i].run)
                    continue;

                if (err == 0) {
                    test_case[i].attempted = 1;

                    fprintf(stderr, "%d: %s ...\n", i + 1, test_case[i].name);

                    err = pthread_create(&test_case[i].thread, NULL, run_test,
                                                                 &test_case[i]);
                    if (err != 0)
                        fprintf(stderr, "Failed to create thread for: %d\n", i);
                }
            }

            UnlockRW();
        }
    }

    fprintf(stderr, "Running test cases for %d seconds\n", secs);
    for (i = 0; i < secs; i++) {
        sleep(1);
        fprintf(stderr, ".");
    }
    fprintf(stderr, "\n");

    stop = 1;
    for (i = 0; i < TEST_CASE_CNT; i++) {
        if (!test_case[i].attempted)
            continue;

        pthread_join(test_case[i].thread, 0);
        fprintf(stderr, "%d: %s ... %d ... ", i + 1, test_case[i].name,
                                                              test_case[i].cnt);
        if (!test_case[i].err)
            fprintf(stderr, "PASSED\n");
        else
            fprintf(stderr, "FAILED\n");
        }

    LockFree();
    stop = 0;

    for (i = 0; i < TEST_CASE_CNT; i++) {
        if (test_case[i].done && test_case[i].err != 0) {
            err = test_case[i].err;
            break;
        }
    }

    ENGINE_free(e);
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
    OPENSSL_cleanup();
    #if defined(WE_HAVE_HMAC) || defined(WE_HAVE_CMAC)
    if (!mac_asn1_methods_cleared()) {
        fprintf(stderr, "MAC ASN.1 methods not cleared at teardown\n");
        err = 1;
    }
    #endif
#ifdef WE_TEST_INTERNAL_GLOBALS
    if (test_engine_destroyed() != 0) {
        err = 1;
    }
#endif
#endif

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

    return err;
}

#else

static int run_tests(ENGINE *e, int runAll)
{
    int err = 0;
    int i;

    printf("###### TESTSUITE START\n");
    if (flags) {
        printf("Using flags value %lx\n", flags);
    }
    printf("\n");

    for (i = 0; i < TEST_CASE_CNT; i++) {
        if (!runAll && !test_case[i].run) {
            continue;
        }

        printf("#### Start: %d - %s\n", i + 1, test_case[i].name);

        test_case[i].err = 0;
        test_case[i].err = test_case[i].func(e, test_case[i].data);
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

    ENGINE_free(e);
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
    OPENSSL_cleanup();
    #if defined(WE_HAVE_HMAC) || defined(WE_HAVE_CMAC)
    if (!mac_asn1_methods_cleared()) {
        fprintf(stderr, "MAC ASN.1 methods not cleared at teardown\n");
        err = 1;
    }
    #endif
#ifdef WE_TEST_INTERNAL_GLOBALS
    if (test_engine_destroyed() != 0) {
        err = 1;
    }
#endif
#endif

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

    return err;
}

#endif

int main(int argc, char* argv[])
{
    int err = 0;
    ENGINE *e = NULL;
#if defined(WE_NO_DYNAMIC_ENGINE) || !defined(WE_HAVE_SHARED_LIBRARY)
    int staticTest = 1;
#else
    int staticTest = 0;
#endif /* WE_NO_DYNAMIC_ENGINE */
    const char *name = wolfengine_id;
    const char *dir = ".libs";
    int i;
    int runAll = 1;
    int runTests = 1;

#ifndef TEST_MULTITHREADED
    if (!test_openssl_mem_clear_check()) {
        fprintf(stderr, "Memory clearing observer failed\n");
        return 1;
    }
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
    if (!test_mac_allocation_source("src/we_mac.c") ||
        !test_mac_allocation_source("..\\src\\we_mac.c") ||
        !test_mac_allocation_source("we_mac.c") ||
        test_mac_allocation_source("other_we_mac.c") ||
        test_mac_allocation_source("") || test_mac_allocation_source(NULL)) {
        fprintf(stderr, "Allocation callsite matching failed\n");
        return 1;
    }
#endif
#ifdef HAVE_VALGRIND_MEMCHECK_H
    VALGRIND_CREATE_MEMPOOL(&testActiveAllocs, 0, 0);
#endif
    if (CRYPTO_set_mem_functions(test_openssl_malloc, test_openssl_realloc,
            test_openssl_free) != 1) {
        fprintf(stderr, "Unable to install test memory functions\n");
        return 1;
    }
#endif

#if defined(WOLF_CRYPTO_CB) && defined(WOLF_CRYPTO_CB_FIND)
    if (wolfCrypt_Init() != 0) {
        return 1;
    }
#endif

    for (--argc, ++argv; argc > 0; argc--, argv++) {
        if (strncmp(*argv, "--help", 6) == 0) {
            usage();
            runAll = 0;
            break;
        }
        else if (strncmp(*argv, "--static", 9) == 0) {
            staticTest = 1;
        }
        else if (strncmp(*argv, "--valgrind", 11) == 0) {
            flags = flags | WE_VALGRIND_TEST;
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
#ifdef TEST_MULTITHREADED
        else if (strncmp(*argv, "--secs", 7) == 0) {
            argc--;
            argv++;
            if (argc == 0) {
                printf("\n");
                printf("Missing seconds argument\n");
                usage();
                err = 1;
                break;
            }
            secs = atoi(*argv);
            printf("Running tests for %d seconds\n", secs);
        }
#endif
        else if (strcmp(*argv, "--bind-lifecycle") == 0) {
        #ifndef WE_NO_DYNAMIC_ENGINE
            return test_engine_bind_lifecycle(dir);
        #else
            return 77;
        #endif
        }
        else if (strncmp(*argv, "--no-debug", 11) == 0) {
            debug = 0;
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
            printf("Unrecognized option: %s\n", *argv);
            usage();
            err = 1;
            break;
        }
    }

    OpenSSL_add_all_ciphers();
    OpenSSL_add_all_digests();

    if (err == 0 && runTests) {
        printf("\n");

        /* Set directory where wolfsslengine library is stored */
#if !defined(_MSC_VER) && !defined(__MINGW32__) && !defined(__CYGWIN__) && !defined(_WIN32_WCE)
        setenv("OPENSSL_ENGINES", dir, 1);
#endif

        if (staticTest == 1) {
            printf("Running tests using static engine.\n");
            if (err == 0) {
                ENGINE_load_wolfengine();
                name = wolfengine_id;
            }
        }
    #ifndef WE_NO_DYNAMIC_ENGINE
        else {
            printf("Running tests using dynamic engine.\n");
        #if OPENSSL_VERSION_NUMBER >= 0x10100000L
            OPENSSL_init_ssl(OPENSSL_INIT_ENGINE_DYNAMIC |
                             OPENSSL_INIT_LOAD_CONFIG,
                             NULL);
        #else
            ENGINE_load_dynamic();
        #endif
        }
    #endif /* WE_NO_DYNAMIC_ENGINE */

        {
            ENGINE* eList;
            for (eList = ENGINE_get_first(); eList != NULL; 
                 eList = ENGINE_get_next(eList)) {
                printf("Found engine %s : %s\n", ENGINE_get_id(eList),
                    ENGINE_get_name(eList));
            }
        }

        e = ENGINE_by_id(name);
        if (e == NULL) {
            PRINT_ERR_MSG("Failed to find engine!\n");
            printf("Looking for %s\n", name);
            err = 1;
        }
    }

    if ((err == 0) && runTests && debug) {
        if (ENGINE_ctrl_cmd(e, "enable_debug", 1, NULL, NULL, 0) != 1) {
            PRINT_ERR_MSG("Failed to enable debug logging");
            err = 1;
        }
    }

#if defined(WE_HAVE_PBE) && (OPENSSL_VERSION_NUMBER < 0x10100000L)
    OpenSSL_add_all_algorithms();
#endif

    if (err == 0 && runTests) {
        err = run_tests(e, runAll);
    }

#if OPENSSL_VERSION_NUMBER < 0x10100000L
    EVP_cleanup();
    ENGINE_cleanup();
    CRYPTO_cleanup_all_ex_data();
    ERR_remove_thread_state(NULL);
    ERR_free_strings();
#endif

#if defined(WOLF_CRYPTO_CB) && defined(WOLF_CRYPTO_CB_FIND)
    wolfCrypt_Cleanup();
#endif

    return err;
}

