/* test_openssl_bc.c
 *
 * Copyright (C) 2026 wolfSSL Inc.
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1335,
 * USA
 */

#include "unit.h"

#if OPENSSL_VERSION_NUMBER < 0x10100000L

int test_openssl_bc_method_name(ENGINE *e, void *data)
{
    int err = 0;
    RSA_METHOD *rsaMethod = NULL;
    DH_METHOD *dhMethod = NULL;

    (void)e;
    (void)data;

    rsaMethod = RSA_meth_new(NULL, 0);
    if (rsaMethod != NULL) {
        PRINT_ERR_MSG("RSA method accepted a NULL name");
        err = 1;
    }
    RSA_meth_free(rsaMethod);

    dhMethod = DH_meth_new(NULL, 0);
    if (dhMethod != NULL) {
        PRINT_ERR_MSG("DH method accepted a NULL name");
        err = 1;
    }
    DH_meth_free(dhMethod);

    return err;
}

int test_openssl_bc_public_ec_key(ENGINE *e, void *data)
{
    int err = 0;
    EC_KEY *key = NULL;
    unsigned char *buf = NULL;

    (void)e;
    (void)data;

    key = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    if (key == NULL) {
        PRINT_ERR_MSG("EC key allocation failed");
        err = 1;
    }
    if ((err == 0) && (EC_KEY_priv2buf(key, &buf) != 0)) {
        PRINT_ERR_MSG("Public EC key produced private bytes");
        err = 1;
    }
    if (buf != NULL) {
        PRINT_ERR_MSG("Public EC key allocated a private buffer");
        err = 1;
    }

    OPENSSL_free(buf);
    EC_KEY_free(key);
    return err;
}

static int test_openssl_bc_ec_private_scalar(int nid, size_t expectedLen)
{
    int err = 0;
    size_t i;
    size_t len = 0;
    EC_KEY *key = NULL;
    BIGNUM *priv = NULL;
    unsigned char *buf = NULL;

    key = EC_KEY_new_by_curve_name(nid);
    priv = BN_new();
    if ((key == NULL) || (priv == NULL)) {
        PRINT_ERR_MSG("EC private key allocation failed");
        err = 1;
    }
    if ((err == 0) && (BN_set_word(priv, 1) != 1)) {
        PRINT_ERR_MSG("EC private scalar setup failed");
        err = 1;
    }
    if ((err == 0) && (EC_KEY_set_private_key(key, priv) != 1)) {
        PRINT_ERR_MSG("EC private key setup failed");
        err = 1;
    }
    if (err == 0) {
        len = EC_KEY_priv2buf(key, &buf);
        if ((len != expectedLen) || (buf == NULL)) {
            PRINT_ERR_MSG("EC private scalar has the wrong encoded length");
            err = 1;
        }
    }
    if (err == 0) {
        for (i = 0; i < len - 1; i++) {
            if (buf[i] != 0) {
                PRINT_ERR_MSG("EC private scalar has invalid leading padding");
                err = 1;
                break;
            }
        }
        if ((err == 0) && (buf[len - 1] != 1)) {
            PRINT_ERR_MSG("EC private scalar has the wrong encoded value");
            err = 1;
        }
    }

    OPENSSL_clear_free(buf, len);
    BN_clear_free(priv);
    EC_KEY_free(key);
    return err;
}

int test_openssl_bc_ec_private_padding(ENGINE *e, void *data)
{
    int err = 0;
    size_t len = 0;
    EC_KEY *key = NULL;
    BIGNUM *priv = NULL;
    unsigned char *buf = NULL;

    (void)e;
    (void)data;

    err = test_openssl_bc_ec_private_scalar(NID_X9_62_prime256v1, 32);
    if (err == 0) {
        err = test_openssl_bc_ec_private_scalar(NID_secp521r1, 66);
    }
    if (err == 0) {
        key = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
        priv = BN_new();
        if ((key == NULL) || (priv == NULL)) {
            PRINT_ERR_MSG("EC private key allocation failed");
            err = 1;
        }
    }
    if (err == 0) {
        BN_zero(priv);
        if (EC_KEY_set_private_key(key, priv) != 1) {
            PRINT_ERR_MSG("Zero EC private scalar setup failed");
            err = 1;
        }
    }
    if (err == 0) {
        len = EC_KEY_priv2buf(key, &buf);
        if ((len != 0) || (buf != NULL)) {
            PRINT_ERR_MSG("Zero EC private scalar was encoded");
            err = 1;
        }
    }

    OPENSSL_clear_free(buf, len);
    BN_clear_free(priv);
    EC_KEY_free(key);
    return err;
}

#endif /* OPENSSL_VERSION_NUMBER < 0x10100000L */
