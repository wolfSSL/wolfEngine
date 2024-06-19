/* test_hkdf.c
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

#ifdef WE_HAVE_HKDF

static int test_hkdf_calc(ENGINE *e, unsigned char *key, int keyLen,
                          const EVP_MD *md, int mode)
{
    int err = 0;
    EVP_PKEY_CTX *ctx = NULL;
    unsigned char inKey[32] = { 0, };
    unsigned char salt[32] = { 0, };
    unsigned char info[32] = { 0, };
    size_t len = keyLen;

    (void)mode;

    XMEMSET(inKey, 0, sizeof(inKey));
    XMEMSET(salt, 0, sizeof(salt));
    XMEMSET(info, 0, sizeof(info));

    ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, e);
    if (ctx == NULL) {
        err = 1;
    }
    if (err == 0) {
        if (EVP_PKEY_derive_init(ctx) != 1) {
            err = 1;
        }
    }
#if OPENSSL_VERSION_NUMBER >= 0x10101000L
    if (err == 0) {
        if (EVP_PKEY_CTX_hkdf_mode(ctx, mode) != 1) {
            err = 1;
        }
    }
#endif
    if (err == 0) {
        if (EVP_PKEY_CTX_set_hkdf_md(ctx, md) != 1) {
            err = 1;
        }
    }
    if (err == 0) {
        if (EVP_PKEY_CTX_set1_hkdf_key(ctx, inKey, sizeof(inKey)) != 1) {
            err = 1;
        }
    }
    if ((err == 0) && (mode != EVP_PKEY_HKDEF_MODE_EXPAND_ONLY)) {
        if (EVP_PKEY_CTX_set1_hkdf_salt(ctx, salt, sizeof(salt)) != 1) {
            err = 1;
        }
    }
    if ((err == 0) && (mode != EVP_PKEY_HKDEF_MODE_EXTRACT_ONLY)) {
        if (EVP_PKEY_CTX_add1_hkdf_info(ctx, info, sizeof(info)) != 1) {
            err = 1;
        }
    }
    if (err == 0) {
        if (EVP_PKEY_derive(ctx, key, &len) != 1) {
            err = 1;
        }
    }

    if ((err == 0) && (mode != EVP_PKEY_HKDEF_MODE_EXTRACT_ONLY)) {
        if (len != (size_t)keyLen) {
            err = 1;
        }
    }
    else {
        if (len != (size_t)EVP_MD_size(md)) {
            err = 1;
        }
    }

    EVP_PKEY_CTX_free(ctx);
    return err;
}

static int test_hkdf_md(ENGINE *e, const EVP_MD *md, int mode)
{
    int err = 0;
    unsigned char oKey[128];
    unsigned char wKey[128];

    memset(oKey, 0, sizeof(oKey));
    memset(wKey, 0, sizeof(wKey));

    PRINT_MSG("Calc with OpenSSL");
    err = test_hkdf_calc(NULL, oKey, sizeof(oKey), md, mode);
    if (err == 1) {
        PRINT_MSG("FAILED OpenSSL");
    }

    if (err == 0) {
        PRINT_MSG("Calc with wolfSSL");
        err = test_hkdf_calc(e, wKey, sizeof(wKey), md, mode);
        if (err == 1) {
            PRINT_MSG("FAILED wolfSSL");
        }
    }


    if ((err == 0) && (memcmp(oKey, wKey, sizeof(oKey)) != 0)) {
        PRINT_BUFFER("OpenSSL key", oKey, sizeof(oKey));
        PRINT_BUFFER("wolfSSL key", wKey, sizeof(wKey));
        err = 1;
    }

    return err;
}

static int test_hkdf_str_calc(ENGINE *e, unsigned char *key, int keyLen,
                                  const char *md, const char *mode)
{
    int err = 0;
    EVP_PKEY_CTX *ctx = NULL;
    const char* inKey = "0123456789abcf";
    const char* salt = "Salt of at least 14 bytes";
    const char* info = "Some info";
    size_t len = keyLen;

    ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, e);
    if (ctx == NULL) {
        err = 1;
    }
    if (err == 0) {
        if (EVP_PKEY_derive_init(ctx) != 1) {
            err = 1;
        }
    }
#if OPENSSL_VERSION_NUMBER >= 0x10101000L
    if (err == 0) {
        if (EVP_PKEY_CTX_ctrl_str(ctx, "mode", mode) != 1) {
            err = 1;
        }
    }
#endif
    if (err == 0) {
        if (EVP_PKEY_CTX_ctrl_str(ctx, "md", md) != 1) {
            err = 1;
        }
    }
    if (err == 0) {
        if (EVP_PKEY_CTX_ctrl_str(ctx, "key", inKey) != 1) {
            err = 1;
        }
    }
    if ((err == 0) && (strncmp(mode, "EXPAND_ONLY", 12) != 0)) {
        if (EVP_PKEY_CTX_ctrl_str(ctx, "salt", salt) != 1) {
            err = 1;
        }
    }
    if ((err == 0) && (strncmp(mode, "EXTRACT_ONLY", 13) != 0)) {
        if (EVP_PKEY_CTX_ctrl_str(ctx, "info", info) != 1) {
            err = 1;
        }
    }
    if (err == 0) {
        if (EVP_PKEY_derive(ctx, key, &len) != 1) {
            err = 1;
        }
    }

    if ((err == 0) && (strncmp(mode, "EXTRACT_ONLY", 13) != 0)) {
        if (len != (size_t)keyLen) {
            err = 1;
        }
    }
    else {
        if (len != (size_t)EVP_MD_size(EVP_get_digestbyname(md))) {
            err = 1;
        }
    }

    EVP_PKEY_CTX_free(ctx);
    return err;
}

static int test_hkdf_hexstr_calc(ENGINE *e, unsigned char *key, int keyLen,
                                     const char *md, const char *mode)
{
    int err = 0;
    EVP_PKEY_CTX *ctx = NULL;
    const char* inKey = "00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00";
    const char* salt = "00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00";
    const char* info = "00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00";
    size_t len = keyLen;

    ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, e);
    if (ctx == NULL) {
        err = 1;
    }
    if (err == 0) {
        if (EVP_PKEY_derive_init(ctx) != 1) {
            err = 1;
        }
    }
#if OPENSSL_VERSION_NUMBER >= 0x10101000L
    if (err == 0) {
        if (EVP_PKEY_CTX_ctrl_str(ctx, "mode", mode) != 1) {
            err = 1;
        }
    }
#endif
    if (err == 0) {
        if (EVP_PKEY_CTX_ctrl_str(ctx, "md", md) != 1) {
            err = 1;
        }
    }
    if (err == 0) {
        if (EVP_PKEY_CTX_ctrl_str(ctx, "hexkey", inKey) != 1) {
            err = 1;
        }
    }
    /* Set key twice to ensure no memory leak. */
    if (err == 0) {
        if (EVP_PKEY_CTX_ctrl_str(ctx, "hexkey", inKey) != 1) {
            err = 1;
        }
    }
    if ((err == 0) && (strncmp(mode, "EXPAND_ONLY", 12) != 0)) {
        if (EVP_PKEY_CTX_ctrl_str(ctx, "hexsalt", salt) != 1) {
            err = 1;
        }
    }
    /* Set salt twice to ensure no memory leak. */
    if ((err == 0) && (strncmp(mode, "EXPAND_ONLY", 12) != 0)) {
        if (EVP_PKEY_CTX_ctrl_str(ctx, "hexsalt", salt) != 1) {
            err = 1;
        }
    }
    if ((err == 0) && (strncmp(mode, "EXTRACT_ONLY", 13) != 0)) {
        if (EVP_PKEY_CTX_ctrl_str(ctx, "hexinfo", info) != 1) {
            err = 1;
        }
    }
    if (err == 0) {
        if (EVP_PKEY_derive(ctx, key, &len) != 1) {
            err = 1;
        }
    }

    if ((err == 0) && (strncmp(mode, "EXTRACT_ONLY", 13) != 0)) {
        if (len != (size_t)keyLen) {
            err = 1;
        }
    }
    else {
        if (len != (size_t)EVP_MD_size(EVP_get_digestbyname(md))) {
            err = 1;
        }
    }

    EVP_PKEY_CTX_free(ctx);
    return err;
}

static int test_hkdf_str_md(ENGINE *e, const char *md, const char *mode)
{
    int err = 0;
    unsigned char oKey[128];
    unsigned char wKey[128];

    XMEMSET(oKey, 0, sizeof(oKey));
    XMEMSET(wKey, 0, sizeof(wKey));

    PRINT_MSG("Calc with strings OpenSSL");
    err = test_hkdf_str_calc(NULL, oKey, sizeof(oKey), md, mode);
    if (err == 1) {
        PRINT_MSG("FAILED OpenSSL");
    }

    if (err == 0) {
        PRINT_MSG("Calc with strings wolfSSL");
        err = test_hkdf_str_calc(e, wKey, sizeof(wKey), md, mode);
        if (err == 1) {
            PRINT_MSG("FAILED wolfSSL");
        }
    }


    if ((err == 0) && (memcmp(oKey, wKey, sizeof(oKey)) != 0)) {
        PRINT_BUFFER("OpenSSL key", oKey, sizeof(oKey));
        PRINT_BUFFER("wolfSSL key", wKey, sizeof(wKey));
        err = 1;
    }

    if (err == 0) {
        PRINT_MSG("Calc with hex strings OpenSSL");
        err = test_hkdf_hexstr_calc(NULL, oKey, sizeof(oKey), md, mode);
        if (err == 1) {
            PRINT_MSG("FAILED OpenSSL");
        }
    }

    if (err == 0) {
        PRINT_MSG("Calc with hex strings wolfSSL");
        err = test_hkdf_hexstr_calc(e, wKey, sizeof(wKey), md, mode);
        if (err == 1) {
            PRINT_MSG("FAILED wolfSSL");
        }
    }


    if ((err == 0) && (memcmp(oKey, wKey, sizeof(oKey)) != 0)) {
        PRINT_BUFFER("OpenSSL key", oKey, sizeof(oKey));
        PRINT_BUFFER("wolfSSL key", wKey, sizeof(wKey));
        err = 1;
    }
    return err;
}

static int test_hkdf_fail_calc(ENGINE *e)
{
    int err = 0;
    EVP_PKEY_CTX *ctx = NULL;
    unsigned char key[1] = { 0 };

    if (EVP_PKEY_CTX_ctrl_str(NULL, "md", "sha256") == 1) {
        err = 1;
    }
    if (err == 0) {
        ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, e);
        if (ctx == NULL) {
            err = 1;
        }
    }
    if (err == 0) {
        if (EVP_PKEY_derive_init(ctx) != 1) {
            err = 1;
        }
    }
    if (err == 0) {
        /* Invalid control value. */
        if (EVP_PKEY_CTX_ctrl(ctx, -1, EVP_PKEY_OP_DERIVE,
                              EVP_PKEY_CTRL_TLS_SEED, 0, NULL) == 1) {
            err = 1;
        }
    }
#if OPENSSL_VERSION_NUMBER >= 0x10101000L
    if ((err == 0) && (e != NULL)) {
        /* Invalid mode. */
        if (EVP_PKEY_CTX_hkdf_mode(ctx, -1) == 1) {
            err = 1;
        }
    }
#endif
    if (err == 0) {
        /* Negative key length. */
        if (EVP_PKEY_CTX_set1_hkdf_key(ctx, key, -1) == 1) {
            err = 1;
        }
    }
    if (err == 0) {
        /* Negative salt length. */
        if (EVP_PKEY_CTX_set1_hkdf_salt(ctx, key, -1) == 1) {
            err = 1;
        }
    }
    if (err == 0) {
        /* Negative info length. */
        if (EVP_PKEY_CTX_add1_hkdf_info(ctx, key, -1) == 1) {
            err = 1;
        }
    }
    if (err == 0) {
        /* Invalid control type string. */
        if (EVP_PKEY_CTX_ctrl_str(ctx, "invalid", "") == 1) {
            err = 1;
        }
    }
    if (err == 0) {
        /* Empty digest string. */
        if (EVP_PKEY_CTX_ctrl_str(ctx, "md", NULL) == 1) {
            err = 1;
        }
    }

    EVP_PKEY_CTX_free(ctx);
    return err;
}

static int test_hkdf_fail(ENGINE *e)
{
    int err;

    PRINT_MSG("Failure cases with OpenSSL");
    err = test_hkdf_fail_calc(NULL);
    if (err == 0) {
        PRINT_MSG("Failure cases with wolfSSL");
        err = test_hkdf_fail_calc(e);
    }

    return err;
}

#if OPENSSL_VERSION_NUMBER >= 0x10101000L
#define NUM_MODES     3
#else
#define NUM_MODES     1
#endif

int test_hkdf(ENGINE *e, void *data)
{
    int err = 0;
    int i;
    int mode[] = {
        EVP_PKEY_HKDEF_MODE_EXTRACT_AND_EXPAND,
        EVP_PKEY_HKDEF_MODE_EXTRACT_ONLY,
        EVP_PKEY_HKDEF_MODE_EXPAND_ONLY
    };
    const char *modeStr[] = {
        "EXTRACT_AND_EXPAND",
        "EXTRACT_ONLY",
        "EXPAND_ONLY"
    };

    (void)data;

    for (i = 0; (err == 0) && (i < NUM_MODES); i++) {
        err = test_hkdf_md(e, EVP_sha256(), mode[i]);
        if (err == 0) {
            err = test_hkdf_md(e, EVP_sha384(), mode[i]);
        }
    }
    for (i = 0; (err == 0) && (i < NUM_MODES); i++) {
        err = test_hkdf_str_md(e, "sha256", modeStr[i]);
    }
    if (err == 0) {
        err = test_hkdf_fail(e);
    }

    return err;
}

#endif /* WE_HAVE_HKDF */


