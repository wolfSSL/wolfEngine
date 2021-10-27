/* we_wolfengine.c
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

#include <wolfengine/we_internal.h>
#include <wolfengine/we_wolfengine.h>

#ifdef _WIN32
WOLFENGINE_API const char *wolfengine_id = "wolfEngine.dll";
#elif OPENSSL_VERSION_NUMBER >= 0x10100000L
/* Engine id - implementation uses wolfSSL */
WOLFENGINE_API const char *wolfengine_id = "libwolfengine";
#else
WOLFENGINE_API const char *wolfengine_id = "wolfengine";
#endif
/* Engine name ... or description.  */
WOLFENGINE_API const char *wolfengine_name = "An engine using wolfSSL";

/**
 * Allocate and bind a wolfEngine ENGINE and return a pointer to it.
 *
 * @returns  NULL on failure, valid pointer on success.
 */
static ENGINE *engine_wolfengine(void)
{
    int rc;
    ENGINE *ret;

    WOLFENGINE_ENTER(WE_LOG_ENGINE, "engine_wolfengine");

    ret = ENGINE_new();
    if (ret == NULL) {
        WOLFENGINE_ERROR_FUNC_NULL(WE_LOG_ENGINE, "ENGINE_new", ret);
        return NULL;
    }
    rc = wolfengine_bind(ret, wolfengine_id);
    if (rc == 0) {
        WOLFENGINE_ERROR_FUNC(WE_LOG_ENGINE, "wolfengine_bind", rc);
        ENGINE_free(ret);
        return NULL;
    }

    WOLFENGINE_LEAVE(WE_LOG_ENGINE, "engine_wolfengine", 1);

    return ret;
}

/**
 * Load an instance of wolfEngine into OpenSSL's engine list.
 */
void ENGINE_load_wolfengine(void)
{
    ENGINE *toadd = engine_wolfengine();

    WOLFENGINE_ENTER(WE_LOG_ENGINE, "ENGINE_load_wolfengine");

    if (!toadd)
        return;
    ENGINE_add(toadd);
    ENGINE_free(toadd);
    ERR_clear_error();

    WOLFENGINE_LEAVE(WE_LOG_ENGINE, "ENGINE_load_wolfengine", 1);
}

#ifndef WE_NO_DYNAMIC_ENGINE
/** Define implementation of common bind function in OpenSSL engines. */
IMPLEMENT_DYNAMIC_BIND_FN(wolfengine_bind)
/** Define implementation of common checking function in OpenSSL engines. */
IMPLEMENT_DYNAMIC_CHECK_FN()
#endif /* WE_NO_DYNAMIC_ENGINE */
