/* test_dh.c
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

int test_dh(ENGINE *e, void *data)
{
    const DH_METHOD *method = NULL;
    int err = 0;
    DH *dhWolfEngine = NULL;
    DH *dhOpenSSL = NULL;
    BIGNUM *p = NULL;
    BIGNUM *g = NULL;
    unsigned char *secretOpenSSL = NULL;
    int secretLenOpenSSL = 0;
    unsigned char *secretWolfEngine = NULL;
    int secretLenWolfEngine = 0;

    (void)data;

    PRINT_MSG("Generate a DH key-pair with OpenSSL");  
    dhOpenSSL = DH_new();
    err = dhOpenSSL == NULL;
    if (err == 0) {
        p = BN_bin2bn(dh_p, sizeof(dh_p), NULL);
        err = p == NULL;
    }
    if (err == 0) {
        dhOpenSSL->p = p;
        g = BN_bin2bn(dh_g, sizeof(dh_g), NULL);
        err = g == NULL;
    }
    if (err == 0) {
        dhOpenSSL->g = g;
        err = DH_generate_key(dhOpenSSL) == 0;
    }

    if (err == 0) {
        PRINT_MSG("Generate a DH key-pair with wolfEngine");
        dhWolfEngine = DH_new();
        err = dhWolfEngine == NULL;
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
        dhWolfEngine->p = p;
        g = BN_bin2bn(dh_g, sizeof(dh_g), NULL);
        err = g == NULL;
    }
    if (err == 0) {
        dhWolfEngine->g = g;
        err = DH_generate_key(dhWolfEngine) == 0;
    }

    if (err == 0) {
        PRINT_MSG("Compute shared secret with OpenSSL private key and wolfEngine public key.");
        secretOpenSSL = (unsigned char*)OPENSSL_malloc(DH_size(dhOpenSSL));
        err = secretOpenSSL == NULL;
    }
    if (err == 0) {
        secretLenOpenSSL = DH_compute_key(secretOpenSSL, dhWolfEngine->pub_key,
                                          dhOpenSSL);
        err = secretLenOpenSSL == -1;
    }

    if (err == 0) {
        PRINT_MSG("Compute shared secret with wolfEngine private key and OpenSSL "
                  "public key.");
        secretWolfEngine = (unsigned char*)OPENSSL_malloc(DH_size(dhWolfEngine));
        err = secretWolfEngine == NULL;
    }
    if (err == 0) {
        secretLenWolfEngine = DH_compute_key(secretWolfEngine,
                                             dhOpenSSL->pub_key, dhWolfEngine);
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
    DH_free(dhOpenSSL);
    DH_free(dhWolfEngine);

    return err;
}

#endif /* WE_HAVE_DH */
