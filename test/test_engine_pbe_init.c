/* test_engine_pbe_init.c
 *
 * Copyright (C) 2006-2026 wolfSSL Inc.
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

#include <config.h>
#include <wolfengine/we_wolfengine.h>
#include <wolfengine/we_openssl_bc.h>
#include <openssl/engine.h>
#include <openssl/err.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#ifdef WOLFENGINE_USER_SETTINGS
#include "user_settings.h"
#else
#include <wolfssl/options.h>
#endif
#include <wolfssl/wolfcrypt/settings.h>

#if defined(WE_HAVE_PBE) && !defined(NO_PWDBASED) && \
    !defined(WE_NO_DYNAMIC_ENGINE)
extern int bind_engine(ENGINE *engine, const char *id,
                       const dynamic_fns *functions);

static int test_failure_enabled;
static int test_pbe_failures;
static int test_method_failures;
static int test_pbe_attempts;
static int test_source_missing;
static int test_method_attempts;
static int test_method_failure_at;
static int test_methods_live;
static void *test_methods[128];
static int test_method_sequence[128];
static unsigned int test_method_failed_classes;

enum {
    TEST_METHOD_EVP = 1,
    TEST_METHOD_ASN1 = 2,
    TEST_METHOD_RSA = 4,
    TEST_METHOD_DH = 8,
    TEST_METHOD_EC_KEY = 16,
    TEST_METHOD_ECDSA = 32
};

static const int test_pbe_types[] = { EVP_PBE_TYPE_OUTER,
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
    EVP_PBE_TYPE_KDF,
#else
    EVP_PBE_TYPE_OUTER,
#endif
    EVP_PBE_TYPE_OUTER };
static const int test_pbe_nids[] = { NID_id_pbkdf2,
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
    NID_id_pbkdf2,
#else
    NID_pbes2,
#endif
    NID_pbe_WithSHA1And3_Key_TripleDES_CBC };

static void test_pbe_callbacks(EVP_PBE_KEYGEN **callbacks)
{
    int i;

    for (i = 0; i < 3; i++) {
        callbacks[i] = NULL;
        EVP_PBE_find(test_pbe_types[i], test_pbe_nids[i], NULL, NULL,
                     &callbacks[i]);
    }
}

static int test_pbe_callbacks_equal(EVP_PBE_KEYGEN **expected)
{
    int i;
    EVP_PBE_KEYGEN *current[3];

    test_pbe_callbacks(current);
    for (i = 0; i < 3; i++) {
        if (current[i] != expected[i])
            return 0;
    }
    return 1;
}

static int test_pbe_callback_result(int expected)
{
    static const unsigned char parameters[] = {
        0x30, 0x24, 0x04, 0x10,
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x02, 0x02, 0x08, 0x00,
        0x30, 0x0c, 0x06, 0x08, 0x2a, 0x86, 0x48, 0x86,
        0xf7, 0x0d, 0x02, 0x09, 0x05, 0x00
    };
    int err = 1;
    EVP_PBE_KEYGEN *callback = NULL;
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    ASN1_TYPE *param = ASN1_TYPE_new();
    ASN1_STRING *sequence = ASN1_STRING_type_new(V_ASN1_SEQUENCE);

    if ((ctx == NULL) || (param == NULL) || (sequence == NULL)) {
        goto cleanup;
    }
    if (ASN1_STRING_set(sequence, parameters, sizeof(parameters)) != 1) {
        goto cleanup;
    }
    ASN1_TYPE_set(param, V_ASN1_SEQUENCE, sequence);
    sequence = NULL;
    if ((EVP_PBE_find(EVP_PBE_TYPE_OUTER, NID_id_pbkdf2, NULL, NULL,
                      &callback) != 1) || (callback == NULL)) {
        goto cleanup;
    }
    if (EVP_CipherInit_ex(ctx, EVP_aes_128_cbc(), NULL, NULL, NULL, 1) != 1) {
        goto cleanup;
    }
    err = callback(ctx, "initialization-check", 20, param, NULL, NULL, 1) !=
        expected;
cleanup:
    ASN1_STRING_free(sequence);
    ASN1_TYPE_free(param);
    EVP_CIPHER_CTX_free(ctx);
    return err;
}

static const char *test_allocation_source(const char *file)
{
    const char *name;
    const char *windowsName;

    name = (file == NULL) ? "" : file;
    windowsName = strrchr(name, '\\');
    if (windowsName != NULL)
        name = windowsName + 1;
    file = strrchr(name, '/');
    if (file != NULL)
        name = file + 1;
    return name;
}

static unsigned int test_method_source(const char *file)
{
    const char *name = test_allocation_source(file);

    if ((strcmp(name, "evp_lib.c") == 0) ||
        (strcmp(name, "cmeth_lib.c") == 0) ||
        (strcmp(name, "pmeth_lib.c") == 0) ||
        (strcmp(name, "we_openssl_bc.c") == 0)) {
        return TEST_METHOD_EVP;
    }
    if (strcmp(name, "ameth_lib.c") == 0)
        return TEST_METHOD_ASN1;
    if (strcmp(name, "rsa_meth.c") == 0)
        return TEST_METHOD_RSA;
    if (strcmp(name, "dh_meth.c") == 0)
        return TEST_METHOD_DH;
    if (strcmp(name, "ec_kmeth.c") == 0)
        return TEST_METHOD_EC_KEY;
    if (strcmp(name, "ecs_lib.c") == 0)
        return TEST_METHOD_ECDSA;
    return 0;
}

static void test_method_registry_aliases(void)
{
    const EVP_PKEY_ASN1_METHOD *method;
    int flags;
    int i;
    int j;

    /* Callback-free aliases belong to OpenSSL's process-wide registry. */
    for (i = 0; i < EVP_PKEY_asn1_get_count(); i++) {
        method = EVP_PKEY_asn1_get0(i);
        flags = 0;
        if ((EVP_PKEY_asn1_get0_info(NULL, NULL, &flags, NULL, NULL,
                                   method) == 1) &&
            ((flags & ASN1_PKEY_ALIAS) != 0)) {
            for (j = 0; j < 128; j++) {
                if (test_methods[j] == method) {
                    test_methods[j] = NULL;
                    test_methods_live--;
                    break;
                }
            }
        }
    }
}

static int test_allocation_allowed(const char *file)
{
    const char *name;

    if (test_failure_enabled == 0)
        return 1;
    name = test_allocation_source(file);
    if (name[0] == '\0') {
        test_source_missing = 1;
        return 1;
    }
    if (test_method_source(file)) {
        test_method_attempts++;
        if ((test_failure_enabled == 1) ||
            ((test_failure_enabled == 4) &&
             (test_method_attempts == test_method_failure_at))) {
            test_method_failures++;
            if (test_failure_enabled == 4)
                test_method_failed_classes |= test_method_source(file);
            return 0;
        }
    }
    if (strcmp(name, "evp_pbe.c") == 0) {
        test_pbe_attempts++;
        if ((test_failure_enabled == 2) ||
            ((test_failure_enabled == 3) && (test_pbe_attempts == 2))) {
            test_pbe_failures++;
            return 0;
        }
    }
    return 1;
}

static void *test_openssl_malloc(size_t size, const char *file, int line)
{
    void *ptr;
    int i;

    (void)line;
    ptr = test_allocation_allowed(file) ? malloc(size) : NULL;
    if ((ptr != NULL) && (test_failure_enabled == 4) &&
        test_method_source(file)) {
        for (i = 0; i < 128; i++) {
            if (test_methods[i] == NULL) {
                test_methods[i] = ptr;
                test_method_sequence[i] = test_method_attempts;
                test_methods_live++;
                break;
            }
        }
        if (i == 128) {
            free(ptr);
            ptr = NULL;
        }
    }
    return ptr;
}

static void *test_openssl_realloc(void *ptr, size_t size,
    const char *file, int line)
{
    (void)line;
    return test_allocation_allowed(file) ? realloc(ptr, size) : NULL;
}

#if OPENSSL_VERSION_NUMBER >= 0x10100000L
static void test_openssl_free(void *ptr, const char *file, int line)
#else
static void test_openssl_free(void *ptr)
#endif
{
    int i;

#if OPENSSL_VERSION_NUMBER >= 0x10100000L
    (void)file;
    (void)line;
#endif
    for (i = 0; (ptr != NULL) && (i < 128); i++) {
        if (test_methods[i] == ptr) {
            test_methods[i] = NULL;
            test_methods_live--;
            break;
        }
    }
    free(ptr);
}
#endif

int main(void)
{
#if defined(WE_HAVE_PBE) && !defined(NO_PWDBASED) && \
    !defined(WE_NO_DYNAMIC_ENGINE)
    int err = 0;
    int attempt;
    int rc;
    ENGINE *engine;
    ENGINE *pendingEngine = NULL;
    EVP_PKEY_CTX *keyCtx = NULL;
    ENGINE_PKEY_METHS_PTR keyMethods;
    const int *keyNids = NULL;
    EVP_PKEY_METHOD *method;
    dynamic_fns functions;
    EVP_PBE_KEYGEN *original[3];
    int targets[128];
    int targetCount = 0;
    unsigned int expectedClasses = 0;

#if OPENSSL_VERSION_NUMBER >= 0x10100000L
    rc = CRYPTO_set_mem_functions(test_openssl_malloc,
                                 test_openssl_realloc, test_openssl_free);
#else
    rc = CRYPTO_set_mem_ex_functions(test_openssl_malloc,
                                    test_openssl_realloc, test_openssl_free);
#endif
    if (rc != 1) {
        fprintf(stderr, "Failed to install PBE allocation test callbacks\n");
        return 1;
    }
    test_failure_enabled = 1;
    method = EVP_PKEY_meth_new(EVP_PKEY_HMAC, 0);
    test_failure_enabled = 0;
    if (test_source_missing != 0) {
        EVP_PKEY_meth_free(method);
        fprintf(stderr, "SKIP: OpenSSL allocation source names unavailable\n");
        return 77;
    }
    if ((method != NULL) || (test_method_failures != 1)) {
        EVP_PKEY_meth_free(method);
        fprintf(stderr, "Method allocation failure hook did not run\n");
        return 1;
    }
    test_method_failures = 0;
    memset(&functions, 0, sizeof(functions));
    functions.static_state = ENGINE_get_static_state();
    ERR_put_error(ERR_LIB_EVP, 0, ERR_R_MALLOC_FAILURE, __FILE__, __LINE__);
    ERR_clear_error();
    test_pbe_callbacks(original);

    for (attempt = 0; (attempt < 3) && (err == 0); attempt++) {
        engine = ENGINE_new();
        if (engine == NULL)
            return 1;
        test_failure_enabled = 1;
        rc = bind_engine(engine, wolfengine_id, &functions);
        test_failure_enabled = 0;
        if ((rc != 0) || (test_method_failures != attempt + 1) ||
            (test_pbe_attempts != 0) || !test_pbe_callbacks_equal(original)) {
            fprintf(stderr, "Failed engine initialization changed PBE callbacks\n");
            err = 1;
        }
        ENGINE_free(engine);
        ERR_clear_error();
    }
    for (attempt = 0; (attempt < 3) && (err == 0); attempt++) {
        engine = ENGINE_new();
        if (engine == NULL)
            return 1;
        test_failure_enabled = 2;
        rc = bind_engine(engine, wolfengine_id, &functions);
        test_failure_enabled = 0;
        if ((rc != 0) || (test_pbe_failures != attempt + 1) ||
            !test_pbe_callbacks_equal(original)) {
            fprintf(stderr, "Failed PBE setup changed registry callbacks\n");
            err = 1;
        }
        if ((rc == 0) && ((ENGINE_get_pkey_meths(engine) != NULL) ||
                (ENGINE_get_pkey_asn1_meths(engine) != NULL))) {
            fprintf(stderr, "Failed bind retained key method callbacks\n");
            err = 1;
        }
        ENGINE_free(engine);
        ERR_clear_error();
    }
    if (err == 0) {
        engine = ENGINE_new();
        if (engine == NULL)
            return 1;
        test_pbe_attempts = 0;
        test_failure_enabled = 3;
        rc = bind_engine(engine, wolfengine_id, &functions);
        test_failure_enabled = 0;
        if ((rc != 0) || (test_pbe_attempts != 2) ||
            (test_pbe_failures != 4) || (test_pbe_callback_result(0) != 0)) {
            fprintf(stderr, "Incomplete PBE registration enabled callbacks\n");
            err = 1;
        }
        if ((rc == 0) && ((ENGINE_get_pkey_meths(engine) != NULL) ||
                (ENGINE_get_pkey_asn1_meths(engine) != NULL))) {
            fprintf(stderr, "Failed bind retained key method callbacks\n");
            err = 1;
        }
        pendingEngine = engine;
        ERR_clear_error();
    }
    if (err == 0) {
        engine = ENGINE_new();
        if ((engine == NULL) ||
            (bind_engine(engine, wolfengine_id, &functions) != 1)) {
            fprintf(stderr, "Engine did not recover after PBE setup failure\n");
            err = 1;
        }
        ENGINE_free(pendingEngine);
        pendingEngine = NULL;
        if (err == 0) {
            keyMethods = ENGINE_get_pkey_meths(engine);
            if ((keyMethods != NULL) &&
                    (keyMethods(engine, NULL, &keyNids, 0) > 0)) {
                keyCtx = EVP_PKEY_CTX_new_id(keyNids[0], engine);
                if (keyCtx == NULL) {
                    fprintf(stderr, "Accepted key method is unavailable\n");
                    err = 1;
                }
                EVP_PKEY_CTX_free(keyCtx);
            }
        }
        ENGINE_free(engine);
        if ((err == 0) && (test_pbe_callback_result(1) != 0)) {
            fprintf(stderr, "Accepted PBE callbacks did not retain their lifetime\n");
            err = 1;
        }
    }
    ENGINE_free(pendingEngine);
    if (err == 0) {
        engine = ENGINE_new();
        test_method_attempts = 0;
        test_method_failure_at = 0;
        test_failure_enabled = 4;
        rc = (engine == NULL) ? 0 :
            bind_engine(engine, wolfengine_id, &functions);
        test_failure_enabled = 0;
        if (rc != 1) {
            fprintf(stderr, "Failed to collect engine method allocations\n");
            err = 1;
        }
        test_method_registry_aliases();
        for (attempt = 0; attempt < 128; attempt++) {
            if (test_methods[attempt] != NULL)
                targets[targetCount++] = test_method_sequence[attempt];
        }
        ENGINE_free(engine);
        if (test_methods_live != 0) {
            fprintf(stderr, "Accepted engine retained method allocations\n");
            err = 1;
        }
        ERR_clear_error();
    }
#if defined(WE_HAVE_HMAC) || defined(WE_HAVE_CMAC)
    expectedClasses |= TEST_METHOD_ASN1;
#endif
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
#ifdef WE_HAVE_RSA
    expectedClasses |= TEST_METHOD_RSA;
#endif
#ifdef WE_HAVE_DH
    expectedClasses |= TEST_METHOD_DH;
#endif
#if defined(WE_HAVE_ECC) && defined(WE_HAVE_EC_KEY)
    expectedClasses |= TEST_METHOD_EC_KEY;
#endif
#else
#if defined(WE_HAVE_RSA) || defined(WE_HAVE_DH)
    expectedClasses |= TEST_METHOD_EVP;
#endif
#if defined(WE_HAVE_ECC) && defined(WE_HAVE_ECDSA)
    expectedClasses |= TEST_METHOD_ECDSA;
#endif
#if defined(WE_HAVE_ECC) && defined(WE_HAVE_ECDH)
    expectedClasses |= TEST_METHOD_EVP;
#endif
#endif
    for (attempt = 0; (attempt < targetCount) && (err == 0); attempt++) {
        engine = ENGINE_new();
        if (engine == NULL)
            return 1;
        test_method_attempts = 0;
        test_method_failures = 0;
        test_method_failure_at = targets[attempt];
        test_failure_enabled = 4;
        rc = bind_engine(engine, wolfengine_id, &functions);
        test_failure_enabled = 0;
        ENGINE_free(engine);
        test_method_registry_aliases();
        if ((rc != 0) || (test_methods_live != 0) ||
            (test_method_failures != 1)) {
            fprintf(stderr, "Method rollback returned %d with %d failures "
                    "and %d live allocations\n", rc, test_method_failures,
                    test_methods_live);
            err = 1;
        }
        ERR_clear_error();
        if (err != 0)
            break;
        engine = ENGINE_new();
        if ((engine == NULL) ||
            (bind_engine(engine, wolfengine_id, &functions) != 1)) {
            fprintf(stderr, "Engine did not recover after method setup failure\n");
            err = 1;
        }
        ENGINE_free(engine);
        ERR_clear_error();
    }
    if ((err == 0) && ((test_method_failed_classes & expectedClasses) !=
                      expectedClasses)) {
        fprintf(stderr, "Method allocation sweep missed enabled constructors\n");
        err = 1;
    }
    if (err == 0) {
        printf("PASS: initialization rollback and retry across %d method "
               "allocation failures, constructor classes 0x%x\n", targetCount,
               test_method_failed_classes);
    }
    EVP_PBE_cleanup();
    ERR_clear_error();
    return err;
#else
    return 77;
#endif
}
