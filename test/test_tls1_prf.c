/* test_tls1_prf.c
 *
 * Copyright (C) 2019-2021 wolfSSL Inc.
 *
 * This file is part of wolfengine.
 *
 * wolfengine is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
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

    PRINT_BUFFER("OpenSSL key", oKey, sizeof(oKey));
    PRINT_BUFFER("wolfSSL key", wKey, sizeof(wKey));

    if ((err == 0) && (memcmp(oKey, wKey, sizeof(oKey)) != 0)) {
        err = 1;
    }

    return err;
}

int test_tls1_prf(ENGINE *e, void *data)
{
    int err;

    (void)data;

    err = test_tls1_prf_md(e, EVP_md5_sha1());
    if (err == 0) {
        err = test_tls1_prf_md(e, EVP_sha256());
    }
    if (err == 0) {
        err = test_tls1_prf_md(e, EVP_sha384());
    }

    return err;
}

#endif /* WE_HAVE_TLS1_PRF */


