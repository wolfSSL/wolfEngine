/* test_tls1_prf.c
 *
 * Copyright (C) 2019-2021 wolfSSL Inc.
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

#ifdef WE_HAVE_TLS1_PRF

static int test_tls1_prf_calc(ENGINE *e, unsigned char *key, int keyLen,
                              const EVP_MD *md)
{
    int err = 0;
    EVP_PKEY_CTX *ctx = NULL;
    unsigned char secret[32] = { 0, };
    unsigned char label[5] = "Label";
    unsigned char seed[32] = { 0, };
    size_t len = keyLen;

    ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_TLS1_PRF, e);
    if (ctx == NULL) {
        err = 1;
    }
    if (err == 0) {
        if (EVP_PKEY_derive_init(ctx) != 1) {
            err = 1;
        }
    }
    if (err == 0) {
        if (EVP_PKEY_CTX_set_tls1_prf_md(ctx, md) != 1) {
            err = 1;
        }
    }
    if (err == 0) {
        if (EVP_PKEY_CTX_set1_tls1_prf_secret(ctx, secret,
                                              sizeof(secret)) != 1) {
            err = 1;
        }
    }
    if (err == 0) {
        if (EVP_PKEY_CTX_add1_tls1_prf_seed(ctx, label, sizeof(label)) != 1) {
            err = 1;
        }
    }
    if (err == 0) {
        if (EVP_PKEY_CTX_add1_tls1_prf_seed(ctx, seed, sizeof(seed)) != 1) {
            err = 1;
        }
    }
    if (err == 0) {
        if (EVP_PKEY_CTX_add1_tls1_prf_seed(ctx, NULL, 0) != 1) {
            err = 1;
        }
    }
    if (err == 0) {
        if (EVP_PKEY_CTX_add1_tls1_prf_seed(ctx, seed, 0) != 1) {
            err = 1;
        }
    }
    if (err == 0) {
        if (EVP_PKEY_derive(ctx, key, &len) != 1) {
            err = 1;
        }
    }

    if (len != (size_t)keyLen) {
        err = 1;
    }

    EVP_PKEY_CTX_free(ctx);
    return err;
}

static int test_tls1_prf_md(ENGINE *e, const EVP_MD *md)
{
    int err = 0;
    unsigned char oKey[128];
    unsigned char wKey[128];

    PRINT_MSG("Calc with OpenSSL");
    err = test_tls1_prf_calc(NULL, oKey, sizeof(oKey), md);
    if (err == 1) {
        PRINT_MSG("FAILED OpenSSL");
    }

    if (err == 0) {
        PRINT_MSG("Calc with wolfSSL");
        err = test_tls1_prf_calc(e, wKey, sizeof(wKey), md);
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

static int test_tls1_prf_str_calc(ENGINE *e, unsigned char *key, int keyLen,
                                  const char *md)
{
    int err = 0;
    EVP_PKEY_CTX *ctx = NULL;
    /* FIPS min key length is 14 */
    const char* secret = "0123456789abcf";
    const char* label = "Label";
    const char* seed = "A seed";
    size_t len = keyLen;

    ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_TLS1_PRF, e);
    if (ctx == NULL) {
        err = 1;
    }
    if (err == 0) {
        if (EVP_PKEY_derive_init(ctx) != 1) {
            err = 1;
        }
    }
    if (err == 0) {
        if (EVP_PKEY_CTX_ctrl_str(ctx, "md", md) != 1) {
            err = 1;
        }
    }
    if (err == 0) {
        if (EVP_PKEY_CTX_ctrl_str(ctx, "secret", secret) != 1) {
            err = 1;
        }
    }
    if (err == 0) {
        if (EVP_PKEY_CTX_ctrl_str(ctx, "seed", label) != 1) {
            err = 1;
        }
    }
    if (err == 0) {
        if (EVP_PKEY_CTX_ctrl_str(ctx, "seed", seed) != 1) {
            err = 1;
        }
    }
    if (err == 0) {
        if (EVP_PKEY_CTX_ctrl_str(ctx, "seed", "") != 1) {
            err = 1;
        }
    }
    if (err == 0) {
        if (EVP_PKEY_derive(ctx, key, &len) != 1) {
            err = 1;
        }
    }

    if (len != (size_t)keyLen) {
        err = 1;
    }

    EVP_PKEY_CTX_free(ctx);
    return err;
}

static int test_tls1_prf_hexstr_calc(ENGINE *e, unsigned char *key, int keyLen,
                                     const char *md)
{
    int err = 0;
    EVP_PKEY_CTX *ctx = NULL;
    const char* secret = "00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00";
    const char* label = "31:32:33:34:34:35:36";
    const char* seed = "00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00";
    size_t len = keyLen;

    ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_TLS1_PRF, e);
    if (ctx == NULL) {
        err = 1;
    }
    if (err == 0) {
        if (EVP_PKEY_derive_init(ctx) != 1) {
            err = 1;
        }
    }
    if (err == 0) {
        if (EVP_PKEY_CTX_ctrl_str(ctx, "md", md) != 1) {
            err = 1;
        }
    }
    if (err == 0) {
        if (EVP_PKEY_CTX_ctrl_str(ctx, "hexsecret", secret) != 1) {
            err = 1;
        }
    }
    if (err == 0) {
        if (EVP_PKEY_CTX_ctrl_str(ctx, "hexsecret", secret) != 1) {
            err = 1;
        }
    }
    if (err == 0) {
        if (EVP_PKEY_CTX_ctrl_str(ctx, "hexseed", label) != 1) {
            err = 1;
        }
    }
    if (err == 0) {
        if (EVP_PKEY_CTX_ctrl_str(ctx, "hexseed", seed) != 1) {
            err = 1;
        }
    }
    if (err == 0) {
        if (EVP_PKEY_derive(ctx, key, &len) != 1) {
            err = 1;
        }
    }

    if (len != (size_t)keyLen) {
        err = 1;
    }

    EVP_PKEY_CTX_free(ctx);
    return err;
}

static int test_tls1_prf_str_md(ENGINE *e, const char *md)
{
    int err = 0;
    unsigned char oKey[128];
    unsigned char wKey[128];

    PRINT_MSG("Calc with strings OpenSSL");
    err = test_tls1_prf_str_calc(NULL, oKey, sizeof(oKey), md);
    if (err == 1) {
        PRINT_MSG("FAILED OpenSSL");
    }

    if (err == 0) {
        PRINT_MSG("Calc with strings wolfSSL");
        err = test_tls1_prf_str_calc(e, wKey, sizeof(wKey), md);
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
        err = test_tls1_prf_hexstr_calc(NULL, oKey, sizeof(oKey), md);
        if (err == 1) {
            PRINT_MSG("FAILED OpenSSL");
        }
    }

    if (err == 0) {
        PRINT_MSG("Calc with hex strings wolfSSL");
        err = test_tls1_prf_hexstr_calc(e, wKey, sizeof(wKey), md);
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

static int test_tls1_prf_fail_calc(ENGINE *e)
{
    int err = 0;
    EVP_PKEY_CTX *ctx = NULL;
    unsigned char secret[1] = { 0 };
    unsigned char label[1] = { 0 };

    if (EVP_PKEY_CTX_ctrl_str(NULL, "md", "sha256") == 1) {
        err = 1;
    }
    if (err == 0) {
        ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_TLS1_PRF, e);
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
                              EVP_PKEY_CTRL_HKDF_SALT, 0, NULL) == 1) {
            err = 1;
        }
    }
    if (err == 0) {
        /* Negative secret length. */
        if (EVP_PKEY_CTX_set1_tls1_prf_secret(ctx, secret, -1) == 1) {
            err = 1;
        }
    }
    if (err == 0) {
        /* Negative seed length. */
        if (EVP_PKEY_CTX_add1_tls1_prf_seed(ctx, label, -1) == 1) {
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

static int test_tls1_prf_fail(ENGINE *e)
{
    int err;

    PRINT_MSG("Failure cases with OpenSSL");
    err = test_tls1_prf_fail_calc(NULL);
    if (err == 0) {
        PRINT_MSG("Failure cases with wolfSSL");
        err = test_tls1_prf_fail_calc(e);
    }

    return err;
}

int test_tls1_prf(ENGINE *e, void *data)
{
    int err;

    (void)data;

    err = test_tls1_prf_md(e, EVP_md5_sha1());
#if defined(NO_MD5) || defined(NO_SHA)
    err = (err != 1);
#endif
    if (err == 0) {
        err = test_tls1_prf_md(e, EVP_sha256());
    }
    if (err == 0) {
        err = test_tls1_prf_md(e, EVP_sha384());
    }
    if (err == 0) {
        err = test_tls1_prf_str_md(e, "sha256");
    }
    if (err == 0) {
        err = test_tls1_prf_fail(e);
    }

    return err;
}

#endif /* WE_HAVE_TLS1_PRF */


