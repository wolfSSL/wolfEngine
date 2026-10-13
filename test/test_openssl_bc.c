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

#endif /* OPENSSL_VERSION_NUMBER < 0x10100000L */
