/* test_dh.c
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

#ifdef WE_HAVE_DH

#ifndef WE_DH_EX_DATA_IDX
#define WE_DH_EX_DATA_IDX 0
#endif

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

#if defined(WE_DH_USE_GLOBAL_RNG) && defined(WE_HAVE_EVP_PKEY) && \
    !defined(WE_SINGLE_THREADED) && !defined(TEST_MULTITHREADED) && \
    !defined(_WIN32)
extern wolfSSL_Mutex* we_rng_mutex;

static int test_dh_failed_rng_lock(ENGINE* e)
{
    int err = 0;
    int attrInit = 0;
    int mutexInit = 0;
    int mutexLocked = 0;
    int rc;
    pthread_mutexattr_t attr;
    wolfSSL_Mutex mutex;
    wolfSSL_Mutex* savedMutex = we_rng_mutex;
    EVP_PKEY_CTX* ctx = NULL;
    EVP_PKEY* params = NULL;

    ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_DH, e);
    err = ctx == NULL;
    if (err == 0)
        err = EVP_PKEY_paramgen_init(ctx) != 1;

    if (err == 0) {
        rc = pthread_mutexattr_init(&attr);
        err = rc != 0;
        attrInit = rc == 0;
    }
    if (err == 0) {
        rc = pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_ERRORCHECK);
        err = rc != 0;
    }
    if (err == 0) {
        rc = pthread_mutex_init(&mutex, &attr);
        err = rc != 0;
        mutexInit = rc == 0;
    }
    if (err == 0) {
        rc = pthread_mutex_lock(&mutex);
        err = rc != 0;
        mutexLocked = rc == 0;
    }
    if (err == 0) {
        we_rng_mutex = &mutex;
        rc = EVP_PKEY_paramgen(ctx, &params);
        we_rng_mutex = savedMutex;
        err = rc != 0;
    }
    if (err == 0) {
        rc = pthread_mutex_trylock(&mutex);
        if (rc == 0) {
            pthread_mutex_unlock(&mutex);
            mutexLocked = 0;
            err = 1;
        }
    }
    if (mutexInit) {
        if (mutexLocked)
            pthread_mutex_unlock(&mutex);
        pthread_mutex_destroy(&mutex);
    }
    if (attrInit)
        pthread_mutexattr_destroy(&attr);
    EVP_PKEY_free(params);
    EVP_PKEY_CTX_free(ctx);

    return err;
}
#endif

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

static int test_dh_parameter_refresh(ENGINE *e)
{
    int err;
    DH *dhWithQ = NULL;
    DH *dhWithoutQ = NULL;
    const DH_METHOD *method = ENGINE_get_DH(e);
    BIGNUM *p = NULL;
    BIGNUM *q = NULL;
    BIGNUM *g = NULL;
    BIGNUM *priv = NULL;
    BIGNUM *peerPub = NULL;
    void *withQData = NULL;
    void *withoutQData = NULL;
    unsigned char secret[sizeof(dh_p)];
    unsigned char privateKey[64];
    int i;

    for (i = 0; i < (int)sizeof(privateKey); i++)
        privateKey[i] = (unsigned char)(i + 1);

    err = method == NULL;
    if (err == 0) {
        dhWithQ = DH_new();
        dhWithoutQ = DH_new();
        err = (dhWithQ == NULL) || (dhWithoutQ == NULL);
    }
    if (err == 0) {
        err = (DH_set_method(dhWithQ, method) != 1) ||
              (DH_set_method(dhWithoutQ, method) != 1);
    }
    if (err == 0) {
        p = BN_bin2bn(dh_p, sizeof(dh_p), NULL);
        q = BN_dup(p);
        g = BN_new();
        err = (p == NULL) || (q == NULL) || (g == NULL);
    }
    if (err == 0) {
        err = (BN_sub_word(q, 1) != 1) || (BN_rshift1(q, q) != 1) ||
              (BN_set_word(g, 4) != 1);
    }
    if (err == 0) {
        err = DH_set0_pqg(dhWithQ, p, q, g) != 1;
        if (err == 0) {
            p = NULL;
            q = NULL;
            g = NULL;
        }
    }
    if (err == 0) {
        priv = BN_bin2bn(privateKey, sizeof(privateKey), NULL);
        err = priv == NULL;
    }
    if (err == 0) {
        err = DH_set0_key(dhWithQ, NULL, priv) != 1;
        if (err == 0)
            priv = NULL;
    }
    if (err == 0)
        err = DH_generate_key(dhWithQ) != 1;

    if (err == 0) {
        p = BN_bin2bn(dh_p, sizeof(dh_p), NULL);
        g = BN_bin2bn(dh_g, sizeof(dh_g), NULL);
        err = (p == NULL) || (g == NULL);
    }
    if (err == 0) {
        peerPub = BN_new();
        err = (peerPub == NULL) || (BN_set_word(peerPub, 2) != 1);
    }
    if (err == 0) {
        err = DH_set0_pqg(dhWithoutQ, p, NULL, g) != 1;
        if (err == 0) {
            p = NULL;
            g = NULL;
        }
    }
    if (err == 0)
        err = DH_generate_key(dhWithoutQ) != 1;

    if (err == 0) {
        withQData = DH_get_ex_data(dhWithQ, WE_DH_EX_DATA_IDX);
        withoutQData = DH_get_ex_data(dhWithoutQ, WE_DH_EX_DATA_IDX);
        err = (withQData == NULL) || (withoutQData == NULL);
    }
    if (err == 0) {
        err = DH_set_ex_data(dhWithQ, WE_DH_EX_DATA_IDX, withoutQData) != 1;
    }
    if (err == 0) {
        if (DH_set_ex_data(dhWithoutQ, WE_DH_EX_DATA_IDX, withQData) != 1) {
            (void)DH_set_ex_data(dhWithQ, WE_DH_EX_DATA_IDX, withQData);
            err = 1;
        }
    }
    if (err == 0) {
        PRINT_MSG("Clear cached q when refreshing q-less DH parameters");
        err = DH_compute_key(secret, peerPub, dhWithoutQ) <= 0;
    }

    BN_free(peerPub);
    BN_clear_free(priv);
    BN_free(g);
    BN_free(q);
    BN_free(p);
    DH_free(dhWithoutQ);
    DH_free(dhWithQ);

    return err;
}

#ifndef HAVE_FIPS
static int test_dh_paramgen_cb(int event, int iteration, BN_GENCB *cb)
{
#if OPENSSL_VERSION_NUMBER < 0x10100000L
    int *count = (int *)cb->arg;
#else
    int *count = (int *)BN_GENCB_get_arg(cb);
#endif

    (void)event;
    (void)iteration;
    (*count)++;

    return 1;
}
#endif

int test_dh_pgen(ENGINE *e, void *data)
{
    int err;
    DH *dhOpenSSL = NULL;
    DH *dhWolfEngine;
    const DH_METHOD *method = NULL;
#ifndef HAVE_FIPS
    const BIGNUM *p = NULL;
    const BIGNUM *q = NULL;
    const BIGNUM *g = NULL;
    const BIGNUM *oldP = NULL;
    const BIGNUM *oldQ = NULL;
    const BIGNUM *oldG = NULL;
    BIGNUM *copyP = NULL;
    BIGNUM *copyQ = NULL;
    BIGNUM *copyG = NULL;
    BIGNUM *existingQ = NULL;
    BN_GENCB *cb = NULL;
#if OPENSSL_VERSION_NUMBER < 0x10100000L
    BN_GENCB cbData;
#endif
    int callbackCount = 0;
#endif

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
#if defined(WE_DH_USE_GLOBAL_RNG) && defined(WE_HAVE_EVP_PKEY) && \
    !defined(WE_SINGLE_THREADED) && !defined(TEST_MULTITHREADED) && \
    !defined(_WIN32)
    if (err == 0) {
        PRINT_MSG("Keep RNG mutex ownership when locking fails");
        err = test_dh_failed_rng_lock(e);
    }
#endif
    if (err == 0) {
        PRINT_MSG("Reject unsupported DH parameter generators");
        err = DH_generate_parameters_ex(dhWolfEngine, 1024, 1, NULL) > 0;
    }
#ifdef HAVE_FIPS
    if (err == 0) {
        PRINT_MSG("Reject legacy DH parameter generation in FIPS mode");
        err = DH_generate_parameters_ex(dhWolfEngine, 1024, DH_GENERATOR_2,
                                        NULL) > 0;
    }
#else
    if (err == 0) {
#if OPENSSL_VERSION_NUMBER < 0x10100000L
        cb = &cbData;
#else
        cb = BN_GENCB_new();
        err = cb == NULL;
#endif
    }
    if (err == 0) {
        BN_GENCB_set(cb, test_dh_paramgen_cb, &callbackCount);
        PRINT_MSG("Honor the requested DH generator");
        err = DH_generate_parameters_ex(dhWolfEngine, 1024, DH_GENERATOR_2,
                                        cb) != 1;
    }
    if (err == 0) {
        PRINT_MSG("Forward the DH parameter generation callback");
        err = callbackCount == 0;
    }
    if (err == 0) {
        DH_get0_pqg(dhWolfEngine, &p, &q, &g);
        PRINT_MSG("Check generated DH parameters");
        err = (p == NULL) || (g == NULL) ||
              (BN_get_word(g) != DH_GENERATOR_2);
    }
    if (err == 0) {
        dhOpenSSL = DH_new();
        err = dhOpenSSL == NULL;
    }
    if (err == 0) {
        PRINT_MSG("Copy generated DH parameters");
        copyP = BN_dup(p);
        if (q != NULL)
            copyQ = BN_dup(q);
        copyG = BN_dup(g);
        err = (copyP == NULL) || ((q != NULL) && (copyQ == NULL)) ||
              (copyG == NULL);
    }
    if (err == 0) {
        err = DH_set0_pqg(dhOpenSSL, copyP, copyQ, copyG) != 1;
        if (err == 0) {
            copyP = NULL;
            copyQ = NULL;
            copyG = NULL;
        }
    }
    if (err == 0) {
        PRINT_MSG("Use generated DH parameters");
        err = test_dh_keygen(dhOpenSSL, dhWolfEngine);
    }
    if (err == 0) {
        existingQ = BN_new();
        err = (existingQ == NULL) || (BN_set_word(existingQ, 23) != 1);
    }
    if (err == 0) {
        err = DH_set0_pqg(dhWolfEngine, NULL, existingQ, NULL) != 1;
        if (err == 0)
            existingQ = NULL;
    }
    if (err == 0) {
        DH_get0_pqg(dhWolfEngine, &oldP, &oldQ, &oldG);
        PRINT_MSG("Reject replacing DH parameters that contain q");
        err = DH_generate_parameters_ex(dhWolfEngine, 1024, DH_GENERATOR_2,
                                        NULL) > 0;
    }
    if (err == 0) {
        DH_get0_pqg(dhWolfEngine, &p, &q, &g);
        err = (p != oldP) || (q != oldQ) || (g != oldG);
    }
#endif
    if (err == 0) {
        err = test_dh_parameter_refresh(e);
    }

#ifndef HAVE_FIPS
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
    BN_GENCB_free(cb);
#endif
    BN_free(existingQ);
    BN_free(copyG);
    BN_free(copyQ);
    BN_free(copyP);
#endif
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

int test_dh_priv_key_length(ENGINE *e, void *data)
{
    int err;
    int i;
    DH *dhWolfEngine = NULL;
    DH *dhOpenSSL = NULL;
    const DH_METHOD *method = NULL;
    BIGNUM *p = NULL;
    BIGNUM *g = NULL;
    BIGNUM *priv = NULL;
    unsigned char bigPriv[sizeof(dh_p) + 8];
    unsigned char validPriv[64];

    (void)data;

    /* Larger than the prime "p". */
    for (i = 0; i < (int)sizeof(bigPriv); i++) {
        bigPriv[i] = 0xAB;
    }
    /* Smaller than the prime "p". */
    for (i = 0; i < (int)sizeof(validPriv); i++) {
        validPriv[i] = (unsigned char)(i + 1);
    }

    method = ENGINE_get_DH(e);
    err = method == NULL;

    /* A pre-set private key larger than the prime must be rejected. */
    if (err == 0) {
        dhWolfEngine = DH_new();
        err = dhWolfEngine == NULL;
    }
    if (err == 0) {
        DH_set_method(dhWolfEngine, method);
        p = BN_bin2bn(dh_p, sizeof(dh_p), NULL);
        g = BN_bin2bn(dh_g, sizeof(dh_g), NULL);
        err = (p == NULL) || (g == NULL);
    }
    if (err == 0) {
        err = DH_set0_pqg(dhWolfEngine, p, NULL, g) == 0;
    }
    if (err == 0) {
        p = NULL;
        g = NULL;
        priv = BN_bin2bn(bigPriv, sizeof(bigPriv), NULL);
        err = priv == NULL;
    }
    if (err == 0) {
        err = DH_set0_key(dhWolfEngine, NULL, priv) != 1;
    }
    if (err == 0) {
        priv = NULL;
        PRINT_MSG("Reject a private key larger than the prime");
        err = DH_generate_key(dhWolfEngine) != 0;
    }

    /* A valid pre-set private key must still match OpenSSL's public key. */
    if (err == 0) {
        DH_free(dhWolfEngine);
        dhWolfEngine = DH_new();
        dhOpenSSL = DH_new();
        err = (dhWolfEngine == NULL) || (dhOpenSSL == NULL);
    }
    if (err == 0) {
        DH_set_method(dhWolfEngine, method);
        p = BN_bin2bn(dh_p, sizeof(dh_p), NULL);
        g = BN_bin2bn(dh_g, sizeof(dh_g), NULL);
        err = (p == NULL) || (g == NULL);
    }
    if (err == 0) {
        err = DH_set0_pqg(dhWolfEngine, p, NULL, g) == 0;
    }
    if (err == 0) {
        p = BN_bin2bn(dh_p, sizeof(dh_p), NULL);
        g = BN_bin2bn(dh_g, sizeof(dh_g), NULL);
        err = (p == NULL) || (g == NULL);
    }
    if (err == 0) {
        err = DH_set0_pqg(dhOpenSSL, p, NULL, g) == 0;
    }
    if (err == 0) {
        p = NULL;
        g = NULL;
        priv = BN_bin2bn(validPriv, sizeof(validPriv), NULL);
        err = priv == NULL;
    }
    if (err == 0) {
        err = DH_set0_key(dhWolfEngine, NULL, priv) != 1;
    }
    if (err == 0) {
        priv = BN_bin2bn(validPriv, sizeof(validPriv), NULL);
        err = priv == NULL;
    }
    if (err == 0) {
        err = DH_set0_key(dhOpenSSL, NULL, priv) != 1;
    }
    if (err == 0) {
        priv = NULL;
        PRINT_MSG("Accept a valid pre-set private key");
        err = DH_generate_key(dhWolfEngine) != 1;
    }
    if (err == 0) {
        err = DH_generate_key(dhOpenSSL) != 1;
    }
    if (err == 0) {
        PRINT_MSG("wolfEngine and OpenSSL public keys must match");
        err = BN_cmp(DH_get0_pub_key(dhWolfEngine),
                     DH_get0_pub_key(dhOpenSSL)) != 0;
    }

    BN_free(p);
    BN_free(g);
    BN_clear_free(priv);
    DH_free(dhWolfEngine);
    DH_free(dhOpenSSL);

    return err;
}

#ifdef WE_HAVE_EVP_PKEY

static int test_dh_pkey_nonzero_padding(ENGINE *e, EVP_PKEY *params,
                                        int useStringControl)
{
    static const unsigned char privateKey[] = {
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
        0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
        0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20,
        0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28,
        0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F, 0x30,
        0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38,
        0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x3E, 0x00, 0x64
    };
    int err;
    DH *ourDh = NULL;
    DH *peerDh = NULL;
    BIGNUM *priv = NULL;
    BIGNUM *pub = NULL;
    EVP_PKEY *ourKey = NULL;
    EVP_PKEY *peerKey = NULL;
    EVP_PKEY_CTX *ctx = NULL;
    unsigned char *secret = NULL;
    size_t secretLen = 0;
    DH *paramsDh = (DH *)EVP_PKEY_get0_DH(params);

    err = paramsDh == NULL;
    if (err == 0) {
        ourDh = DHparams_dup(paramsDh);
        peerDh = DHparams_dup(paramsDh);
        err = (ourDh == NULL) || (peerDh == NULL);
    }
    if (err == 0) {
        priv = BN_bin2bn(privateKey, sizeof(privateKey), NULL);
        pub = BN_new();
        err = (priv == NULL) || (pub == NULL);
    }
    if (err == 0) {
        err = BN_set_word(pub, 2) != 1;
    }
    if (err == 0) {
        err = DH_set0_key(ourDh, NULL, priv) != 1;
        if (err == 0)
            priv = NULL;
    }
    if (err == 0) {
        err = DH_set0_key(peerDh, pub, NULL) != 1;
        if (err == 0)
            pub = NULL;
    }
    if (err == 0) {
        ourKey = EVP_PKEY_new();
        peerKey = EVP_PKEY_new();
        err = (ourKey == NULL) || (peerKey == NULL);
    }
    if (err == 0) {
        err = EVP_PKEY_assign_DH(ourKey, ourDh) != 1;
        if (err == 0)
            ourDh = NULL;
    }
    if (err == 0) {
        err = EVP_PKEY_assign_DH(peerKey, peerDh) != 1;
        if (err == 0)
            peerDh = NULL;
    }
    if (err == 0) {
        ctx = EVP_PKEY_CTX_new(ourKey, e);
        err = ctx == NULL;
    }
    if (err == 0)
        err = EVP_PKEY_derive_init(ctx) <= 0;
    if (err == 0)
        err = EVP_PKEY_derive_set_peer(ctx, peerKey) <= 0;
    if ((err == 0) && useStringControl) {
        err = EVP_PKEY_CTX_ctrl_str(ctx, "dh_pad", "2") <= 0;
    }
    else if (err == 0) {
        err = EVP_PKEY_CTX_ctrl(ctx, EVP_PKEY_DH, EVP_PKEY_OP_DERIVE,
                               EVP_PKEY_CTRL_DH_PAD, 2, NULL) <= 0;
    }
    if (err == 0) {
        secretLen = (size_t)EVP_PKEY_size(ourKey);
        secret = (unsigned char *)OPENSSL_malloc(secretLen);
        err = secret == NULL;
    }
    if (err == 0)
        err = EVP_PKEY_derive(ctx, secret, &secretLen) <= 0;
    if (err == 0)
        err = secretLen != (size_t)EVP_PKEY_size(ourKey);
    if (err == 0)
        err = secret[0] != 0;

    OPENSSL_free(secret);
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(peerKey);
    EVP_PKEY_free(ourKey);
    BN_free(pub);
    BN_clear_free(priv);
    DH_free(peerDh);
    DH_free(ourDh);

    return err;
}

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
    unsigned char *paddedSecret = NULL;
    unsigned char *shortSecret = NULL;
    size_t paddedSecretLen = 0;
    size_t shortSecretLen = 0;
    size_t expectedSecretLen = 0;

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

    if (err == 0) {
        PRINT_MSG("Pad DH secret to the modulus size");
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
        err = EVP_PKEY_CTX_ctrl(ctx, EVP_PKEY_DH, EVP_PKEY_OP_DERIVE,
                  EVP_PKEY_CTRL_DH_PAD, 1, NULL) <= 0;
    }
    if (err == 0) {
        expectedSecretLen = (size_t)EVP_PKEY_size(keyWolfEngine);
        paddedSecretLen = expectedSecretLen + 8;
        paddedSecret = (unsigned char*)OPENSSL_malloc(paddedSecretLen);
        err = paddedSecret == NULL;
    }
    if (err == 0) {
        err = EVP_PKEY_derive(ctx, paddedSecret, &paddedSecretLen) <= 0;
    }
    if (err == 0) {
        err = paddedSecretLen != expectedSecretLen;
    }
    if (err == 0) {
        shortSecret = (unsigned char*)OPENSSL_malloc(expectedSecretLen + 1);
        err = shortSecret == NULL;
    }
    if (err == 0) {
        XMEMSET(shortSecret, 0xa5, expectedSecretLen + 1);
        shortSecretLen = expectedSecretLen - 1;
        PRINT_MSG("Reject a short padded DH secret buffer");
        err = EVP_PKEY_derive(ctx, shortSecret + 1, &shortSecretLen) > 0;
    }
    if (err == 0) {
        err = (shortSecret[0] != 0xa5) ||
              (shortSecret[expectedSecretLen] != 0xa5);
    }
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(keyOpenSSL);
    EVP_PKEY_free(keyWolfEngine);

    if (secretWolfEngine != NULL)
        OPENSSL_free(secretWolfEngine);
    if (secretOpenSSL != NULL)
        OPENSSL_free(secretOpenSSL);
    if (paddedSecret != NULL)
        OPENSSL_free(paddedSecret);
    if (shortSecret != NULL)
        OPENSSL_free(shortSecret);

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

#define TEST_MT_TIMEOUT 5000 /* Multi-threaded test timeout (ms) */

typedef struct {
    ENGINE* e;
    EVP_PKEY* params;
} DH_KEYGEN_THREAD_VARS;

/* Windows thread entry function which will test private key read access. */
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
    DH_KEYGEN_THREAD_VARS vars = {.e = e, .params = params};
    HANDLE thread;
    DWORD threadErr = 0;
    int err = 1;

    thread = CreateThread(NULL, 0, DhKeyGenThreadFunc, &vars, 0, NULL);
    if (thread && (WaitForSingleObject(thread, TEST_MT_TIMEOUT) == WAIT_OBJECT_0)) {
        err = (GetExitCodeThread(thread, &threadErr) == 0 ? 1 : threadErr);
        CloseHandle(thread);
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
    if (err == 0) {
        PRINT_MSG("Treat every nonzero DH padding control value as enabled");
        err = test_dh_pkey_nonzero_padding(e, params, 0);
    }
    if (err == 0) {
        err = test_dh_pkey_nonzero_padding(e, params, 1);
    }

    EVP_PKEY_free(params);
    DH_free(dh);

    return err;
}

int test_dh_ctrl(ENGINE* e, void* data)
{
    int err;
    EVP_PKEY_CTX* ctx = NULL;
    EVP_PKEY* key = NULL;
    int primeLengths[] = {1024, 2048, 3072};
    word32 i;

    (void)data;

    err = (ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_DH, e)) == NULL;
    if (err == 0){
        err = EVP_PKEY_paramgen_init(ctx) <= 0;
    }

    for (i = 0; err == 0 && i < sizeof(primeLengths)/sizeof(*primeLengths);
         ++i) {
        /* Set valid prime lengths. */
        err = EVP_PKEY_CTX_ctrl(ctx, EVP_PKEY_DH, EVP_PKEY_OP_PARAMGEN,
                  EVP_PKEY_CTRL_DH_PARAMGEN_PRIME_LEN, primeLengths[i],
                  NULL) <= 0;
    }
    if (err == 0) {
        /* Set an invalid prime length. */
        err = EVP_PKEY_CTX_ctrl(ctx, EVP_PKEY_DH, EVP_PKEY_OP_PARAMGEN,
                  EVP_PKEY_CTRL_DH_PARAMGEN_PRIME_LEN, 512, NULL) > 0;
    }
    if (err == 0) {
        /* Set a valid prime length via control string. */
        err = EVP_PKEY_CTX_ctrl_str(ctx, "dh_paramgen_prime_len", "2048") <= 0;
    }

    if (err == 0) {
        /* Set the generator (not supported by wolfCrypt). */
        err = EVP_PKEY_CTX_ctrl(ctx, EVP_PKEY_DH, EVP_PKEY_OP_PARAMGEN,
                  EVP_PKEY_CTRL_DH_PARAMGEN_GENERATOR, 2, NULL) > 0;
    }

    if (err == 0) {
        /* Zero pad secret. */
        err = EVP_PKEY_CTX_ctrl(ctx, EVP_PKEY_DH, EVP_PKEY_OP_PARAMGEN,
                  EVP_PKEY_CTRL_DH_PAD, 1, NULL) <= 0;
    }
    if (err == 0) {
        /* Same as above but using a control string. */
        err = EVP_PKEY_CTX_ctrl_str(ctx, "dh_pad", "1") <= 0;
    }

    if (err == 0) {
        /* Set peer key for shared secret. No-op internally. */
        err = EVP_PKEY_CTX_ctrl(ctx, EVP_PKEY_DH, EVP_PKEY_OP_PARAMGEN,
                  EVP_PKEY_CTRL_PEER_KEY, 0, NULL) <= 0;
    }

#ifdef HAVE_PUBLIC_FFDHE
    /* Set parameters to different named parameter sets. */
    #ifdef HAVE_FFDHE_2048
    if (err == 0) {
        err = EVP_PKEY_CTX_ctrl_str(ctx, "dh_param", "ffdhe2048") <= 0;
    }
    #ifndef HAVE_FFDHE_Q
    if (err == 0) {
        PRINT_MSG("Generate a key with named DH parameters");
        err = EVP_PKEY_keygen_init(ctx) != 1;
    }
    if (err == 0) {
        err = EVP_PKEY_keygen(ctx, &key) != 1;
    }
    #endif
    #else
    if (err == 0) {
        err = EVP_PKEY_CTX_ctrl_str(ctx, "dh_param", "ffdhe2048") > 0;
    }
    #endif /* HAVE_FFDHE_2048 */

    #ifdef HAVE_FFDHE_3072
    if (err == 0) {
        err = EVP_PKEY_CTX_ctrl_str(ctx, "dh_param", "ffdhe3072") <= 0;
    }
    #else
    if (err == 0) {
        err = EVP_PKEY_CTX_ctrl_str(ctx, "dh_param", "ffdhe3072") > 0;
    }
    #endif /* HAVE_FFDHE_3072 */

    #ifdef HAVE_FFDHE_4096
    if (err == 0) {
        err = EVP_PKEY_CTX_ctrl_str(ctx, "dh_param", "ffdhe4096") <= 0;
    }
    #else
    if (err == 0) {
        err = EVP_PKEY_CTX_ctrl_str(ctx, "dh_param", "ffdhe4096") > 0;
    }
    #endif /* HAVE_FFDHE_4096 */
#endif /* HAVE_PUBLIC_FFDHE */

    EVP_PKEY_free(key);
    EVP_PKEY_CTX_free(ctx);

    return err;
}

#endif /* WE_HAVE_EVP_PKEY */

#endif /* WE_HAVE_DH */
