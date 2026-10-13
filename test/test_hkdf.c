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

typedef struct test_HkdfState {
    int mode;
    int mdType;
    unsigned char *key;
    size_t keySz;
    unsigned char *salt;
    size_t saltSz;
} test_HkdfState;

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

#if OPENSSL_VERSION_NUMBER >= 0x10101000L
static int test_hkdf_extract_size_calc(ENGINE *e)
{
    int err = 0;
    EVP_PKEY_CTX *ctx = NULL;
    unsigned char inKey[32] = { 0, };
    size_t len = 0;

    ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, e);
    if (ctx == NULL) {
        err = 1;
    }
    if ((err == 0) && (EVP_PKEY_derive_init(ctx) != 1)) {
        err = 1;
    }
    if ((err == 0) &&
            (EVP_PKEY_CTX_hkdf_mode(ctx,
                EVP_PKEY_HKDEF_MODE_EXTRACT_ONLY) != 1)) {
        err = 1;
    }
    if ((err == 0) &&
            (EVP_PKEY_CTX_set_hkdf_md(ctx, EVP_sha256()) != 1)) {
        err = 1;
    }
    if ((err == 0) &&
            (EVP_PKEY_CTX_set1_hkdf_key(ctx, inKey, sizeof(inKey)) != 1)) {
        err = 1;
    }
    if ((err == 0) && (EVP_PKEY_derive(ctx, NULL, &len) != 1)) {
        err = 1;
    }
    if ((err == 0) && (len != (size_t)EVP_MD_size(EVP_sha256()))) {
        err = 1;
    }

    EVP_PKEY_CTX_free(ctx);
    return err;
}

static int test_hkdf_extract_size(ENGINE *e)
{
    int err;

    PRINT_MSG("Extract size with OpenSSL");
    err = test_hkdf_extract_size_calc(NULL);
    if (err == 0) {
        PRINT_MSG("Extract size with wolfSSL");
        err = test_hkdf_extract_size_calc(e);
    }

    return err;
}

#if defined(WE_HAVE_SHA256) || defined(WE_HAVE_SHA512)
static int test_hkdf_extract_capacity(ENGINE *e, const EVP_MD *md)
{
    int err = 0;
    int i;
    int rc;
    EVP_PKEY_CTX *ctx = NULL;
    unsigned char inKey[32] = { 0 };
    unsigned char salt[32] = { 0 };
    unsigned char reference[EVP_MAX_MD_SIZE];
    unsigned char out[EVP_MAX_MD_SIZE + 3];
    unsigned char expected[sizeof(out)];
    size_t digestSz = (size_t)EVP_MD_size(md);
    size_t capacities[4];
    size_t len = 0;

    capacities[0] = 0;
    capacities[1] = digestSz - 1;
    capacities[2] = digestSz;
    capacities[3] = digestSz + 1;
    err = test_hkdf_calc(NULL, reference, (int)digestSz, md,
                        EVP_PKEY_HKDEF_MODE_EXTRACT_ONLY);
    ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, e);
    if ((ctx == NULL) || (EVP_PKEY_derive_init(ctx) != 1) ||
        (EVP_PKEY_CTX_hkdf_mode(ctx,
            EVP_PKEY_HKDEF_MODE_EXTRACT_ONLY) != 1) ||
        (EVP_PKEY_CTX_set_hkdf_md(ctx, md) != 1) ||
        (EVP_PKEY_CTX_set1_hkdf_key(ctx, inKey, sizeof(inKey)) != 1) ||
        (EVP_PKEY_CTX_set1_hkdf_salt(ctx, salt, sizeof(salt)) != 1)) {
        err = 1;
    }
    if ((err == 0) &&
        ((EVP_PKEY_derive(ctx, NULL, &len) != 1) || (len != digestSz))) {
        err = 1;
    }
    for (i = 0; (err == 0) && (i < 4); i++) {
        memset(out, 0xa5, sizeof(out));
        memset(expected, 0xa5, sizeof(expected));
        len = capacities[i];
        rc = EVP_PKEY_derive(ctx, out + 1, &len);
        if (capacities[i] < digestSz) {
            if ((rc != 0) || (len != capacities[i])) {
                PRINT_MSG("Extract accepted insufficient output capacity");
                err = 1;
            }
        }
        else {
            memcpy(expected + 1, reference, digestSz);
            if ((rc != 1) || (len != digestSz)) {
                err = 1;
            }
        }
        if (memcmp(out, expected, sizeof(out)) != 0) {
            PRINT_MSG("Extract changed data outside its output capacity");
            err = 1;
        }
    }

    EVP_PKEY_CTX_free(ctx);
    return err;
}
#endif

#endif

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

static int test_hkdf_key_failure_state(ENGINE *e)
{
    int err = 0;
    int i;
    EVP_PKEY_CTX *ctx = NULL;
    unsigned char key[1] = { 0 };
    unsigned char out[32];
    unsigned char unchanged[sizeof(out)];
    size_t len = 0;

    ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, e);
    if (ctx == NULL) {
        err = 1;
    }
    if ((err == 0) && (EVP_PKEY_derive_init(ctx) != 1)) {
        err = 1;
    }
#if OPENSSL_VERSION_NUMBER >= 0x10101000L
    if ((err == 0) &&
            (EVP_PKEY_CTX_hkdf_mode(ctx,
                EVP_PKEY_HKDEF_MODE_EXTRACT_ONLY) != 1)) {
        err = 1;
    }
#endif
    if ((err == 0) &&
            (EVP_PKEY_CTX_set_hkdf_md(ctx, EVP_sha256()) != 1)) {
        err = 1;
    }
    memset(unchanged, 0xa5, sizeof(unchanged));
    for (i = 0; (err == 0) && (i < 2); i++) {
        if (EVP_PKEY_CTX_set1_hkdf_key(ctx, key, sizeof(key)) != 1) {
            err = 1;
        }
        len = sizeof(out);
        if ((err == 0) && (EVP_PKEY_derive(ctx, out, &len) != 1)) {
            err = 1;
        }
        if ((err == 0) &&
                (EVP_PKEY_CTX_set1_hkdf_key(ctx, i == 0 ? NULL : key,
                                           i == 0 ? 1 : -1) != 0)) {
            err = 1;
        }
        len = 0;
        if ((err == 0) && (EVP_PKEY_derive(ctx, NULL, &len) != 0)) {
            err = 1;
        }
        memcpy(out, unchanged, sizeof(out));
        len = sizeof(out);
        if ((err == 0) && ((EVP_PKEY_derive(ctx, out, &len) != 0) ||
                (len != sizeof(out)) ||
                (memcmp(out, unchanged, sizeof(out)) != 0))) {
            err = 1;
        }
    }
    if ((err == 0) &&
            (EVP_PKEY_CTX_set1_hkdf_key(ctx, key, sizeof(key)) != 1)) {
        err = 1;
    }
    len = sizeof(out);
    if ((err == 0) && ((EVP_PKEY_derive(ctx, out, &len) != 1) ||
            (len != sizeof(out)))) {
        err = 1;
    }
    if ((err == 0) &&
            (EVP_PKEY_CTX_set1_hkdf_key(ctx, NULL, 0) == 1)) {
        err = 1;
    }
    if ((err == 0) && (EVP_PKEY_derive(ctx, NULL, &len) == 1)) {
        err = 1;
    }

    EVP_PKEY_CTX_free(ctx);
    return err;
}

static int test_hkdf_salt_failure_state(ENGINE *e)
{
    int err = 0;
    int i;
    EVP_PKEY_CTX *ctx = NULL;
    EVP_PKEY_CTX *reference = NULL;
    test_HkdfState *state = NULL;
    unsigned char key[32] = { 0 };
    unsigned char salt[32] = { 1 };
    unsigned char out[32];
    unsigned char expected[sizeof(out)];
    size_t len = sizeof(out);

    reference = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);
    if ((reference == NULL) || (EVP_PKEY_derive_init(reference) != 1) ||
            (EVP_PKEY_CTX_set_hkdf_md(reference, EVP_sha256()) != 1) ||
            (EVP_PKEY_CTX_set1_hkdf_key(reference, key, sizeof(key)) != 1) ||
            (EVP_PKEY_derive(reference, expected, &len) != 1) ||
            (len != sizeof(expected))) {
        err = 1;
    }
    ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, e);
    if (ctx == NULL) {
        err = 1;
    }
    if ((err == 0) && (EVP_PKEY_derive_init(ctx) != 1)) {
        err = 1;
    }
    if ((err == 0) &&
            (EVP_PKEY_CTX_set_hkdf_md(ctx, EVP_sha256()) != 1)) {
        err = 1;
    }
    if ((err == 0) &&
            (EVP_PKEY_CTX_set1_hkdf_key(ctx, key, sizeof(key)) != 1)) {
        err = 1;
    }
    for (i = 0; (err == 0) && (i < 2); i++) {
        if (EVP_PKEY_CTX_set1_hkdf_salt(ctx, salt, sizeof(salt)) != 1) {
            err = 1;
        }
        if ((err == 0) &&
                (EVP_PKEY_CTX_set1_hkdf_salt(ctx, i == 0 ? NULL : salt,
                                            i == 0 ? 1 : -1) != 0)) {
            err = 1;
        }
        if (err == 0) {
            state = (test_HkdfState *)EVP_PKEY_CTX_get_data(ctx);
            if ((state == NULL) || (state->salt != NULL) ||
                    (state->saltSz != 0)) {
                err = 1;
            }
        }
        len = sizeof(out);
        if ((err == 0) && ((EVP_PKEY_derive(ctx, out, &len) != 1) ||
                (len != sizeof(out)) ||
                (memcmp(out, expected, sizeof(out)) != 0))) {
            err = 1;
        }
    }

    EVP_PKEY_CTX_free(reference);
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
    if (err == 0) {
        PRINT_MSG("Key failure state with wolfSSL");
        err = test_hkdf_key_failure_state(e);
    }
    if (err == 0) {
        PRINT_MSG("Salt failure state with wolfSSL");
        err = test_hkdf_salt_failure_state(e);
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
#if OPENSSL_VERSION_NUMBER >= 0x10101000L
    if (err == 0) {
        err = test_hkdf_extract_size(e);
    }
#ifdef WE_HAVE_SHA256
    if (err == 0) {
        PRINT_MSG("Extract capacity with SHA-256");
        err = test_hkdf_extract_capacity(e, EVP_sha256());
    }
#endif
#ifdef WE_HAVE_SHA512
    if (err == 0) {
        PRINT_MSG("Extract capacity with SHA-512");
        err = test_hkdf_extract_capacity(e, EVP_sha512());
    }
#endif
#endif

    return err;
}

int test_hkdf_bad_md(ENGINE *e, void *data)
{
#if defined(HAVE_FIPS) || defined(HAVE_FIPS_VERSION)
    (void)e;
    (void)data;
    return 0;
#else
    int err = 0;
    EVP_PKEY_CTX *ctx = NULL;

    (void)data;

    ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, e);
    err = ctx == NULL;
    if (err == 0) {
        err = EVP_PKEY_derive_init(ctx) != 1;
    }
    if (err == 0) {
        /* Unknown digest name must fail, not dereference a NULL digest. */
        err = EVP_PKEY_CTX_ctrl_str(ctx, "md", "notadigest") > 0;
    }

    EVP_PKEY_CTX_free(ctx);

    return err;
#endif
}

#endif /* WE_HAVE_HKDF */


