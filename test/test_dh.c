/* test_dh.c
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

#ifdef WE_HAVE_DH

/* dh1024 p */
static const unsigned char dh_p[] =
{
    0xE6, 0x96, 0x9D, 0x3D, 0x49, 0x5B, 0xE3, 0x2C, 0x7C, 0xF1, 0x80, 0xC3,
    0xBD, 0xD4, 0x79, 0x8E, 0x91, 0xB7, 0x81, 0x82, 0x51, 0xBB, 0x05, 0x5E,
    0x2A, 0x20, 0x64, 0x90, 0x4A, 0x79, 0xA7, 0x70, 0xFA, 0x15, 0xA2, 0x59,
    0xCB, 0xD5, 0x23, 0xA6, 0xA6, 0xEF, 0x09, 0xC4, 0x30, 0x48, 0xD5, 0xA2,
    0x2F, 0x97, 0x1F, 0x3C, 0x20, 0x12, 0x9B, 0x48, 0x00, 0x0E, 0x6E, 0xDD,
    0x06, 0x1C, 0xBC, 0x05, 0x3E, 0x37, 0x1D, 0x79, 0x4E, 0x53, 0x27, 0xDF,
    0x61, 0x1E, 0xBB, 0xBE, 0x1B, 0xAC, 0x9B, 0x5C, 0x60, 0x44, 0xCF, 0x02,
    0x3D, 0x76, 0xE0, 0x5E, 0xEA, 0x9B, 0xAD, 0x99, 0x1B, 0x13, 0xA6, 0x3C,
    0x97, 0x4E, 0x9E, 0xF1, 0x83, 0x9E, 0xB5, 0xDB, 0x12, 0x51, 0x36, 0xF7,
    0x26, 0x2E, 0x56, 0xA8, 0x87, 0x15, 0x38, 0xDF, 0xD8, 0x23, 0xC6, 0x50,
    0x50, 0x85, 0xE2, 0x1F, 0x0D, 0xD5, 0xC8, 0x6B,
};

/* dh1024 g */
static const unsigned char dh_g[] =
{
  0x02,
};

static int test_dh_keygen(DH *dhOpenSSL, DH *dhWolfEngine)
{
    int err = 0;
    unsigned char *secretOpenSSL = NULL;
    int secretLenOpenSSL = 0;
    unsigned char *secretWolfEngine = NULL;
    int secretLenWolfEngine = 0;

    PRINT_MSG("Generate a DH key pair with OpenSSL");
    if (err == 0) {
        err = DH_generate_key(dhOpenSSL) == 0;
    }
    PRINT_MSG("Generate a DH key pair with wolfEngine");
    if (err == 0) {
        err = DH_generate_key(dhWolfEngine) == 0;
    }

    if (err == 0) {
        PRINT_MSG("Compute shared secret with OpenSSL private key and "
                  "wolfEngine public key.");
        secretOpenSSL = (unsigned char*)OPENSSL_malloc(DH_size(dhOpenSSL));
        err = secretOpenSSL == NULL;
    }
    if (err == 0) {
        secretLenOpenSSL = DH_compute_key(secretOpenSSL,
                                          DH_get0_pub_key(dhWolfEngine),
                                          dhOpenSSL);
        err = secretLenOpenSSL == -1;
    }

    if (err == 0) {
        PRINT_MSG("Compute shared secret with wolfEngine private key and "
                  "OpenSSL public key.");
        secretWolfEngine = (unsigned char*)OPENSSL_malloc(DH_size(
                                                          dhWolfEngine));
        err = secretWolfEngine == NULL;
    }
    if (err == 0) {
        secretLenWolfEngine = DH_compute_key(secretWolfEngine,
                                             DH_get0_pub_key(dhOpenSSL),
                                             dhWolfEngine);
        err = secretLenWolfEngine == -1;
    }

    if (err == 0) {
        PRINT_MSG("Ensure shared secrets are the same.");
        err = secretLenOpenSSL != secretLenWolfEngine;
    }
    if (err == 0) {
        err = memcmp(secretOpenSSL, secretWolfEngine, secretLenOpenSSL) != 0;
    }

    OPENSSL_free(secretOpenSSL);
    OPENSSL_free(secretWolfEngine);

    return err;
}

int test_dh_pgen(ENGINE *e, void *data)
{
    int err;
    DH *dhWolfEngine;
    DH *dhOpenSSL = NULL;
    const DH_METHOD *method = NULL;
    const BIGNUM *p = NULL;
    const BIGNUM *q = NULL;
    const BIGNUM *g = NULL;

    (void)data;

    PRINT_MSG("Generate DH parameters with wolfEngine");

    dhWolfEngine = DH_new();
    err = dhWolfEngine == NULL;
    if (err == 0) {
        method = ENGINE_get_DH(e);
        err = method == NULL;
    }
    if (err == 0) {
        DH_set_method(dhWolfEngine, method);
    }
    if (err == 0) {
        /* Generator and callback (last param) ignored by wolfEngine. */
        err = DH_generate_parameters_ex(dhWolfEngine, 1024, DH_GENERATOR_5,
                                        NULL) != 1;
    }

    if (err == 0) {
        DH_get0_pqg(dhWolfEngine, &p, &q, &g);

        dhOpenSSL = DH_new();
        err = (dhOpenSSL == NULL);
    }
    if (err == 0) {
        err = DH_set0_pqg(dhOpenSSL, BN_dup(p), BN_dup(q), BN_dup(g)) != 1;
    }

    if (err == 0) {
        err = test_dh_keygen(dhOpenSSL, dhWolfEngine);
    }

    DH_free(dhOpenSSL);
    DH_free(dhWolfEngine);

    return err;
}

int test_dh(ENGINE *e, void *data)
{
    int err;
    DH *dhOpenSSL;
    DH *dhWolfEngine = NULL;
    const DH_METHOD *method = NULL;
    BIGNUM *p = NULL;
    BIGNUM *g = NULL;

    (void)data;

    dhOpenSSL = DH_new();
    err = (dhOpenSSL == NULL);
    if (err == 0) {
        p = BN_bin2bn(dh_p, sizeof(dh_p), NULL);
        err = p == NULL;
    }
    if (err == 0) {
        g = BN_bin2bn(dh_g, sizeof(dh_g), NULL);
        err = g == NULL;
    }
    if (err == 0) {
        err = DH_set0_pqg(dhOpenSSL, p, NULL, g) == 0;
    }
    if (err == 0) {
        dhWolfEngine = DH_new();
        err = (dhWolfEngine == NULL);
    }
    if (err == 0) {
        method = ENGINE_get_DH(e);
        err = method == NULL;
    }
    if (err == 0) {
        DH_set_method(dhWolfEngine, method);
    }
    if (err == 0) {
        p = BN_bin2bn(dh_p, sizeof(dh_p), NULL);
        err = p == NULL;
    }
    if (err == 0) {
        g = BN_bin2bn(dh_g, sizeof(dh_g), NULL);
        err = g == NULL;
    }
    if (err == 0) {
        err = DH_set0_pqg(dhWolfEngine, p, NULL, g) == 0;
    }

    if (err == 0) {
        err = test_dh_keygen(dhOpenSSL, dhWolfEngine);
    }

    DH_free(dhOpenSSL);
    DH_free(dhWolfEngine);

    return err;
}

#ifdef WE_HAVE_EVP_PKEY

static int test_dh_pkey_keygen(ENGINE *e, EVP_PKEY *params)
{
    int err;
    EVP_PKEY_CTX *ctx = NULL;
    EVP_PKEY *keyOpenSSL = NULL;
    EVP_PKEY *keyWolfEngine = NULL;
    unsigned char *secretOpenSSL = NULL;
    size_t secretLenOpenSSL = 0;
    unsigned char *secretWolfEngine = NULL;
    size_t secretLenWolfEngine = 0;

    ctx = EVP_PKEY_CTX_new(params, e);
    err = ctx == NULL;
    if (err == 0) {
        err = EVP_PKEY_keygen_init(ctx) != 1;
    }
    if (err == 0) {
        err = EVP_PKEY_keygen(ctx, &keyWolfEngine) != 1;
    }

    if (err == 0) {
        PRINT_MSG("Generate DH key pair with OpenSSL and params from "
                  "wolfEngine");
        EVP_PKEY_CTX_free(ctx);
        ctx = EVP_PKEY_CTX_new(params, NULL);
        err = ctx == NULL;
    }
    if (err == 0) {
        err = EVP_PKEY_keygen_init(ctx) != 1;
    }
    if (err == 0) {
        err = EVP_PKEY_keygen(ctx, &keyOpenSSL) != 1;
    }

    if (err == 0) {
        PRINT_MSG("Compute shared secret with OpenSSL private key and "
                  "wolfEngine public key.");
        EVP_PKEY_CTX_free(ctx);
        ctx = EVP_PKEY_CTX_new(keyOpenSSL, NULL);
        err = ctx == NULL;
    }
    if (err == 0) {
        err = EVP_PKEY_derive_init(ctx) <= 0;
    }
    if (err == 0) {
        err = EVP_PKEY_derive_set_peer(ctx, keyWolfEngine) <= 0;
    }
    if (err == 0) {
        err = EVP_PKEY_derive(ctx, NULL, &secretLenOpenSSL) <= 0;
    }
    if (err == 0) {
        secretOpenSSL = (unsigned char*)OPENSSL_malloc(secretLenOpenSSL);
        err = secretOpenSSL == NULL;
    }
    if (err == 0) {
        err = EVP_PKEY_derive(ctx, secretOpenSSL, &secretLenOpenSSL) <= 0;
    }

    if (err == 0) {
        PRINT_MSG("Compute shared secret with wolfEngine private key and "
                  "OpenSSL public key.");
        EVP_PKEY_CTX_free(ctx);
        ctx = EVP_PKEY_CTX_new(keyWolfEngine, e);
        err = ctx == NULL;
    }
    if (err == 0) {
        err = EVP_PKEY_derive_init(ctx) <= 0;
    }
    if (err == 0) {
        err = EVP_PKEY_derive_set_peer(ctx, keyOpenSSL) <= 0;
    }
    if (err == 0) {
        err = EVP_PKEY_derive(ctx, NULL, &secretLenWolfEngine) <= 0;
    }
    if (err == 0) {
        secretWolfEngine = (unsigned char*)OPENSSL_malloc(secretLenWolfEngine);
        err = secretWolfEngine == NULL;
    }
    if (err == 0) {
        err = EVP_PKEY_derive(ctx, secretWolfEngine, &secretLenWolfEngine) <= 0;
    }

    if (err == 0) {
        PRINT_MSG("Ensure shared secrets are the same.");
        err = secretLenOpenSSL != secretLenWolfEngine;
    }
    if (err == 0) {
        err = memcmp(secretOpenSSL, secretWolfEngine, secretLenOpenSSL) != 0;
    }

    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(keyOpenSSL);
    EVP_PKEY_free(keyWolfEngine);

    if (secretWolfEngine != NULL)
        OPENSSL_free(secretWolfEngine);
    if (secretOpenSSL != NULL)
        OPENSSL_free(secretOpenSSL);

    return err;
}

int test_dh_pgen_pkey(ENGINE *e, void *data)
{
    int err;
    EVP_PKEY_CTX *ctx = NULL;
    EVP_PKEY *params = NULL;

    (void)data;

    PRINT_MSG("Generate DH parameters and key pair with wolfEngine");
    err = (ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_DH, e)) == NULL;
    if (err == 0) {
        err = EVP_PKEY_paramgen_init(ctx) != 1;
    }
    if (err == 0) {
        err = EVP_PKEY_paramgen(ctx, &params) != 1;
    }

    if (err == 0) {
        err = test_dh_pkey_keygen(e, params);
    }

    EVP_PKEY_free(params);
    EVP_PKEY_CTX_free(ctx);

    return err;
}

#if !defined(WE_SINGLE_THREADED) && defined(_WIN32)

typedef struct {
    ENGINE* e;
    EVP_PKEY* params;
} DH_KEYGEN_THREAD_VARS;

static DWORD WINAPI DhKeyGenThreadFunc(LPVOID arg)
{
    DH_KEYGEN_THREAD_VARS* vars = (DH_KEYGEN_THREAD_VARS*)arg;

    return test_dh_pgen_pkey(vars->e, vars->params);
}

/* Regression test for problem in multi-threaded Windows environment where only
   initial thread has private key read access while additionally created
   threads do not */
int test_dh_key_gen_multithreaded(ENGINE* e, EVP_PKEY* params)
{
    DH_KEYGEN_THREAD_VARS vars;
    HANDLE hThread;
    DWORD dwThreadId;

    DWORD dwThreadErr = 0;
    int err = 0;

    vars.e = e;
    vars.params = params;

    hThread = CreateThread(
        NULL,
        0,
        DhKeyGenThreadFunc,
        &vars,
        0,
        &dwThreadId);

    if (hThread == NULL) {
        err = 1;
    }

    if (err == 0) {
        WaitForSingleObject(hThread, INFINITE);
        if (GetExitCodeThread(hThread, &dwThreadErr) == 0) {
            err = 1;
        }
        else {
            err = dwThreadErr;
        }
    }

    if (hThread != NULL) {
        CloseHandle(hThread);
    }

    return err;
}

#endif /* !WE_SINGLE_THREADED && _WIN32 */

int test_dh_pkey(ENGINE* e, void* data)
{
    int err;
    DH *dh;
    const DH_METHOD *method = NULL;
    EVP_PKEY *params = NULL;
    BIGNUM *p = NULL;
    BIGNUM *g = NULL;

    (void)data;

    dh = DH_new();
    err = (dh == NULL);
    if (err == 0) {
        method = ENGINE_get_DH(e);
        err = method == NULL;
    }
    if (err == 0) {
        DH_set_method(dh, method);
    }
    if (err == 0) {
        p = BN_bin2bn(dh_p, sizeof(dh_p), NULL);
        err = p == NULL;
    }
    if (err == 0) {
        g = BN_bin2bn(dh_g, sizeof(dh_g), NULL);
        err = g == NULL;
    }
    if (err == 0) {
        err = DH_set0_pqg(dh, p, NULL, g) == 0;
    }
    if (err == 0) {
        err = (params = EVP_PKEY_new()) == NULL;
    }
    if (err == 0) {
        err = EVP_PKEY_set1_DH(params, dh) != 1;
    }

    if (err == 0) {
        err = test_dh_pkey_keygen(e, params);
    }

    EVP_PKEY_free(params);
    DH_free(dh);

    return err;
}

#endif /* WE_HAVE_EVP_PKEY */

#endif /* WE_HAVE_DH */
