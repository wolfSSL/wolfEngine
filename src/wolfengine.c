/* wolfengine.c
 *
 * Copyright (C) 2006-2019 wolfSSL Inc.
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

#include "wolfengine.h"
#include "internal.h"

#if OPENSSL_VERSION_NUMBER >= 0x10100000L
/* This is the ID expected by OpenSSL when loading wolfEngine dynamically. */
const char *wolfengine_lib = "libwolfengine";
#else
const char *wolfengine_lib = "wolfengine";
#endif
/* Engine id - implementation uses wolfSSL */
const char *wolfengine_id = "wolfSSL";
/* Engine name ... or description.  */
const char *wolfengine_name = "An engine using wolfSSL";

/**
 * Allocate and bind a wolfEngine ENGINE and return a pointer to it.
 *
 * @returns  NULL on failure, valid pointer on success.
 */
static ENGINE *engine_wolfengine(void)
{
    ENGINE *ret = ENGINE_new();
    if (ret == NULL)
        return NULL;
    if (wolfengine_bind(ret, wolfengine_lib) == 0) {
        ENGINE_free(ret);
        return NULL;
    }
    return ret;
}

/**
 * Load an instance of wolfEngine into OpenSSL's engine list.
 */
void ENGINE_load_wolfengine(void)
{
    WOLFENGINE_MSG("Load");

    ENGINE *toadd = engine_wolfengine();
    if (!toadd)
        return;
    ENGINE_add(toadd);
    ENGINE_free(toadd);
    ERR_clear_error();
}

#ifndef WE_NO_DYNAMIC_ENGINE
/** Define implementation of common bind function in OpenSSL engines. */
IMPLEMENT_DYNAMIC_BIND_FN(wolfengine_bind)
/** Define implementation of common checking function in OpenSSL engines. */
IMPLEMENT_DYNAMIC_CHECK_FN()
#endif /* WE_NO_DYNAMIC_ENGINE */
