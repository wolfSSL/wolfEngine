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

#endif /* OPENSSL_VERSION_NUMBER < 0x10100000L */
