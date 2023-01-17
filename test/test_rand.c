/* test_rand.c
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

#ifdef WE_HAVE_RANDOM

static int test_random_api(void)
{
    int err;
    unsigned char buf[128];

    err = RAND_status() != 1;
#if OPENSSL_VERSION_NUMBER < 0x10100000L
    if (err == 0) {
        err = RAND_pseudo_bytes(buf, sizeof(buf)) != 1;
        PRINT_BUFFER("Pseudo", buf, sizeof(buf));
    }
    if (err == 0) {
        err = RAND_bytes(buf, sizeof(buf)) != 1;
        PRINT_BUFFER("True random", buf, sizeof(buf));
    }
    if (err == 0) {
        RAND_seed(buf, sizeof(buf));

        RAND_add(buf, sizeof(buf), 128);

        err = RAND_pseudo_bytes(buf, sizeof(buf)) != 1;
        PRINT_BUFFER("Seeded Pseudo", buf, sizeof(buf));
    }
#else
    if (err == 0) {
    #if OPENSSL_VERSION_NUMBER < 0x10101000L
        err = RAND_bytes(buf, sizeof(buf)) != 1;
    #else
        err = RAND_priv_bytes(buf, sizeof(buf)) != 1;
    #endif
        PRINT_BUFFER("True random", buf, sizeof(buf));
    }
    if (err == 0) {
        RAND_seed(buf, sizeof(buf));

        RAND_add(buf, sizeof(buf), 128);

        err = RAND_bytes(buf, sizeof(buf)) != 1;
        PRINT_BUFFER("Seeded", buf, sizeof(buf));
    }
#endif
    if (err == 0) {
        err = RAND_status() != 1;
    }

    return err;
}

int test_random(ENGINE *e, void *data)
{
    int err;

    (void)data;

    err = test_random_api();
    if (err == 0) {
        err = RAND_set_rand_engine(e) != 1;
    }
    if (err == 0) {
        err = test_random_api();
    }

    return err;
}

#endif /* WE_HAVE_DH */
