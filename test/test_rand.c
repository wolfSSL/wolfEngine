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
#if !defined(_WIN32) && !defined(TEST_MULTITHREADED)
#include <sys/wait.h>
#include <unistd.h>
#endif

#ifdef WE_HAVE_RANDOM

static int test_random_seed_failure(ENGINE *e)
{
    const RAND_METHOD *method = ENGINE_get_RAND(e);

    if (method == NULL || method->seed == NULL) {
        return 1;
    }

#if OPENSSL_VERSION_NUMBER >= 0x10100000L
    return method->seed(NULL, 1) != 0;
#else
    return 0;
#endif
}

static int test_random_status_after_teardown(ENGINE *e)
{
#if !defined(_WIN32) && !defined(TEST_MULTITHREADED)
    const RAND_METHOD *method = ENGINE_get_RAND(e);
    ENGINE_GEN_INT_FUNC_PTR destroy = ENGINE_get_destroy_function(e);
    int status;
    pid_t pid;

    if (method == NULL || method->status == NULL || destroy == NULL) {
        return 1;
    }

    pid = fork();
    if (pid == -1) {
        return 1;
    }
    if (pid == 0) {
        if (destroy(e) != 1) {
            _exit(1);
        }
        _exit(method->status() != 0);
    }

    if (waitpid(pid, &status, 0) != pid) {
        return 1;
    }

    return !WIFEXITED(status) || WEXITSTATUS(status) != 0;
#else
    (void)e;
    return 0;
#endif
}

static int test_random_api(void)
{
    int err;
    unsigned char buf[128];

    XMEMSET(buf, 0, sizeof(buf));

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
        err = test_random_seed_failure(e);
    }
    if (err == 0) {
        err = test_random_api();
    }
    if (err == 0) {
        err = test_random_status_after_teardown(e);
    }

    return err;
}

#endif /* WE_HAVE_RANDOM */
