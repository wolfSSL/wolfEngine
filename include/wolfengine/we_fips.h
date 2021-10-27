/* we_fips.h
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

#ifndef WE_FIPS_H
#define WE_FIPS_H

#ifdef WOLFENGINE_USER_SETTINGS
    #include "user_settings.h"
#else
    #include <wolfssl/options.h>
#endif

#include <wolfengine/we_visibility.h>


enum wolfEngine_FipsCheck {
    /* check that RSA key size is valid */
    WE_FIPS_CHECK_RSA_KEY_SIZE   = 0x0001,
    /* check that P-192 usage is valid */
    WE_FIPS_CHECK_P192           = 0x0002,
    /* check that RSA signature with SHA-1 digest is valid  */
    WE_FIPS_CHECK_RSA_SHA1       = 0x0004,

    /* default FIPS checks (all with wolfCrypt FIPS, none without) */
#if defined(HAVE_FIPS) || defined(HAVE_FIPS_VERSION)
    WE_FIPS_CHECKS_DEFAULT = (WE_FIPS_CHECK_RSA_KEY_SIZE
                            | WE_FIPS_CHECK_P192
                            | WE_FIPS_CHECK_RSA_SHA1)
#else
    WE_FIPS_CHECKS_DEFAULT = 0
#endif /* HAVE_FIPS || HAVE_FIPS_VERSION */
};

/* Set FIPS checks, bitmask of wolfEngine_FipsCheck. */
WOLFENGINE_API void wolfEngine_SetFipsChecks(long checksMask);
/* Get FIPS checks mask. */
WOLFENGINE_API long wolfEngine_GetFipsChecks(void);

#endif /* WE_FIPS_H */
