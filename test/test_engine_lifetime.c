/* test_engine_lifetime.c
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

#if defined(__linux__) && !defined(_GNU_SOURCE)
#define _GNU_SOURCE
#endif
#include <config.h>
#ifdef WOLFENGINE_USER_SETTINGS
#include "user_settings.h"
#endif
#include <stdio.h>
#include <openssl/engine.h>
#include <openssl/err.h>
#ifdef HAVE_DLFCN_H
#include <dlfcn.h>
#endif

#if defined(WE_HAVE_SHARED_LIBRARY) && !defined(WE_NO_DYNAMIC_ENGINE) && \
    !defined(WE_HAVE_PBE) && OPENSSL_VERSION_NUMBER < 0x10100000L && \
    defined(HAVE_PTHREAD) && \
    !defined(WE_SINGLE_THREADED)
#include <pthread.h>
static pthread_mutex_t test_openssl_locks[CRYPTO_NUM_LOCKS];

static void test_openssl_lock(int mode, int index, const char *file, int line)
{
    (void)file;
    (void)line;
    if ((mode & CRYPTO_LOCK) != 0)
        pthread_mutex_lock(&test_openssl_locks[index]);
    else
        pthread_mutex_unlock(&test_openssl_locks[index]);
}
#endif

int main(void)
{
#if defined(WE_HAVE_SHARED_LIBRARY) && !defined(WE_NO_DYNAMIC_ENGINE) && \
    !defined(WE_HAVE_PBE)
    ENGINE *engine;
    const char *id;
    const char *path;
    int i;
    int ret = 1;
#if OPENSSL_VERSION_NUMBER < 0x10100000L && defined(HAVE_PTHREAD) && \
    !defined(WE_SINGLE_THREADED)
    int initialized = 0;

    for (i = 0; i < CRYPTO_NUM_LOCKS; i++) {
        if (pthread_mutex_init(&test_openssl_locks[i], NULL) != 0)
            goto cleanup;
        initialized++;
    }
    CRYPTO_set_locking_callback(test_openssl_lock);
#endif
#if defined(HAVE_DLFCN_H) && defined(RTLD_NOLOAD)
    void *module;
#endif

#ifdef _WIN32
    id = "wolfEngine";
#elif OPENSSL_VERSION_NUMBER >= 0x10100000L
    id = "libwolfengine";
#else
    id = "wolfengine";
#endif
#if defined(__CYGWIN__)
    path = ".libs/cygwolfengine-1.dll";
#elif defined(__MINGW32__)
    path = ".libs/libwolfengine-1.dll";
#elif defined(_WIN32)
    path = ".libs/wolfEngine.dll";
#elif defined(__APPLE__)
    path = ".libs/libwolfengine.dylib";
#else
    path = ".libs/libwolfengine.so";
#endif

    ENGINE_load_dynamic();
    for (i = 0; i < 100; i++) {
        engine = ENGINE_by_id("dynamic");
        if ((engine == NULL) ||
            (ENGINE_ctrl_cmd_string(engine, "SO_PATH", path, 0) != 1) ||
            (ENGINE_ctrl_cmd_string(engine, "ID", id, 0) != 1) ||
            (ENGINE_ctrl_cmd_string(engine, "LIST_ADD",
                                    (i % 2 == 0) ? "0" : "1", 0) != 1) ||
            (ENGINE_ctrl_cmd_string(engine, "LOAD", NULL, 0) != 1)) {
            ENGINE_free(engine);
            fprintf(stderr, "Failed to load engine in lifetime test\n");
            goto cleanup;
        }
        if (ENGINE_free(engine) != 1) {
            fprintf(stderr, "Failed to release engine in lifetime test\n");
            goto cleanup;
        }
        if ((i % 2 != 0) && (ENGINE_remove(engine) != 1)) {
            fprintf(stderr, "Failed to remove engine in lifetime test\n");
            goto cleanup;
        }
#if defined(HAVE_DLFCN_H) && defined(RTLD_NOLOAD)
        module = dlopen(path, RTLD_NOW | RTLD_NOLOAD);
        if (module != NULL) {
            dlclose(module);
            fprintf(stderr, "Engine module remained loaded after release\n");
            goto cleanup;
        }
#endif
    }
    ret = 0;
cleanup:
#if OPENSSL_VERSION_NUMBER < 0x10100000L
    ENGINE_cleanup();
#endif
    ERR_clear_error();
#if OPENSSL_VERSION_NUMBER < 0x10100000L && defined(HAVE_PTHREAD) && \
    !defined(WE_SINGLE_THREADED)
    CRYPTO_set_locking_callback(NULL);
    for (i = 0; i < initialized; i++)
        pthread_mutex_destroy(&test_openssl_locks[i]);
#endif
    return ret;
#else
    return 77;
#endif
}
