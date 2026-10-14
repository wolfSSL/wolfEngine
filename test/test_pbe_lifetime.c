/* test_pbe_lifetime.c
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

#include <stdio.h>
#ifdef WE_PBE_STATIC_LINK
#include <wolfengine/we_wolfengine.h>
#endif
#include <openssl/engine.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#ifdef WOLFENGINE_USER_SETTINGS
#include "user_settings.h"
#else
#include <wolfssl/options.h>
#endif
#include <wolfssl/wolfcrypt/settings.h>

#if defined(_WIN32)
#include <windows.h>
#elif defined(WE_HAVE_DLADDR)
#include <dlfcn.h>
#endif

#if defined(WE_HAVE_PBE) && !defined(NO_PWDBASED) && \
    (defined(WE_PBE_STATIC_LINK) || (defined(WE_HAVE_SHARED_LIBRARY) && \
                                   !defined(WE_NO_DYNAMIC_ENGINE)))
static int test_pbe_callback_owner(ENGINE *engine, EVP_PBE_KEYGEN *keygen)
{
    ENGINE_GEN_INT_FUNC_PTR destroy = ENGINE_get_destroy_function(engine);
#if defined(_WIN32)
    HMODULE engineModule = NULL;
    HMODULE callbackModule = NULL;
    DWORD flags = GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                  GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT;
#elif defined(WE_HAVE_DLADDR)
    Dl_info engineInfo;
    Dl_info callbackInfo;
#endif

    if ((keygen == NULL) || (destroy == NULL))
        return 0;
#if defined(_WIN32)
    return (GetModuleHandleExA(flags, (LPCSTR)(const void *)destroy,
                              &engineModule) != 0) &&
           (GetModuleHandleExA(flags, (LPCSTR)(const void *)keygen,
                              &callbackModule) != 0) &&
           (engineModule == callbackModule);
#elif defined(WE_HAVE_DLADDR)
    return (dladdr((const void *)destroy, &engineInfo) != 0) &&
           (dladdr((const void *)keygen, &callbackInfo) != 0) &&
           (engineInfo.dli_fbase != NULL) &&
           (engineInfo.dli_fbase == callbackInfo.dli_fbase);
#elif defined(WE_PBE_STATIC_LINK) && defined(WE_NO_DYNAMIC_ENGINE)
    /* Static callbacks replace the built-in entries in the main executable. */
    return 1;
#else
    return 0;
#endif
}

static ENGINE *test_load_pbe_engine(void)
{
    ENGINE *engine = NULL;

#ifdef WE_PBE_STATIC_LINK
    ENGINE_load_wolfengine();
    engine = ENGINE_by_id(wolfengine_id);
    if ((engine != NULL) && (ENGINE_remove(engine) != 1)) {
        ENGINE_free(engine);
        engine = NULL;
    }
#else
    const char *id;
    const char *path;

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
    engine = ENGINE_by_id("dynamic");
    if ((engine == NULL) ||
        (ENGINE_ctrl_cmd_string(engine, "SO_PATH", path, 0) != 1) ||
        (ENGINE_ctrl_cmd_string(engine, "ID", id, 0) != 1) ||
        (ENGINE_ctrl_cmd_string(engine, "LIST_ADD", "0", 0) != 1) ||
        (ENGINE_ctrl_cmd_string(engine, "LOAD", NULL, 0) != 1)) {
        if (engine != NULL)
            ENGINE_free(engine);
        engine = NULL;
    }
#endif
    return engine;
}
#endif

int main(void)
{
#if defined(WE_HAVE_PBE) && !defined(NO_PWDBASED) && \
    (defined(WE_PBE_STATIC_LINK) || (defined(WE_HAVE_SHARED_LIBRARY) && \
                                   !defined(WE_NO_DYNAMIC_ENGINE)))
    int err = 0;
    int cipherNid = 0;
    int digestNid = 0;
    int attempt;
    int i;
    const int nids[] = { NID_id_pbkdf2,
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
        NID_id_pbkdf2,
#else
        NID_pbes2,
#endif
        NID_pbe_WithSHA1And3_Key_TripleDES_CBC };
    const int types[] = { EVP_PBE_TYPE_OUTER,
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
        EVP_PBE_TYPE_KDF,
#else
        EVP_PBE_TYPE_OUTER,
#endif
        EVP_PBE_TYPE_OUTER };
    ENGINE *engine = NULL;
    EVP_CIPHER_CTX *ctx = NULL;
    EVP_PBE_KEYGEN *keygen = NULL;
    EVP_PBE_KEYGEN *builtin[3] = { NULL, NULL, NULL };
    EVP_PBE_KEYGEN *expected[3] = { NULL, NULL, NULL };

    ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL) {
        fprintf(stderr, "Failed to create PBE cipher context\n");
        return 1;
    }
    for (i = 0; i < 3; i++) {
        (void)EVP_PBE_find(types[i], nids[i], &cipherNid, &digestNid,
                          &builtin[i]);
    }
    for (attempt = 0; (attempt < 2) && (err == 0); attempt++) {
        engine = test_load_pbe_engine();
        if (engine == NULL) {
            fprintf(stderr, "Failed to load PBE engine\n");
            err = 1;
        }
        for (i = 0; (i < 3) && (err == 0); i++) {
            keygen = NULL;
            if ((EVP_PBE_find(types[i], nids[i], &cipherNid, &digestNid,
                             &keygen) != 1) || (keygen == NULL)) {
                fprintf(stderr, "Failed to find registered PBE callback\n");
                err = 1;
            }
            else if ((keygen == builtin[i]) ||
                     !test_pbe_callback_owner(engine, keygen)) {
                fprintf(stderr, "PBE callback does not belong to the engine\n");
                err = 1;
            }
            else if (attempt == 0) {
                expected[i] = keygen;
            }
            else if (keygen != expected[i]) {
                fprintf(stderr, "PBE callback changed after registry cleanup\n");
                err = 1;
            }
        }
        if (engine != NULL)
            ENGINE_free(engine);
        if ((err == 0) &&
            (expected[0](ctx, "password", 8, NULL, NULL, NULL, 1) != 0)) {
            fprintf(stderr, "PBKDF2 callback accepted missing parameters\n");
            err = 1;
        }
        if (attempt == 0)
            EVP_PBE_cleanup();
    }
    EVP_CIPHER_CTX_free(ctx);
    ERR_clear_error();
    return err;
#else
    return 77;
#endif
}
