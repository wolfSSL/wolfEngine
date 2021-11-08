/* we_fips.c
 *
 * Copyright (C) 2006-2021 wolfSSL Inc.
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

#include <wolfengine/we_fips.h>

/* Bitmask of FIPS checks in wolfEngine_FipsCheck. Can be set by application
 * through ENGINE_ctrl command. Defaults to all checks if using wolfCrypt FIPS
 * and no checks if not. */
static long fipsChecks = WE_FIPS_CHECKS_DEFAULT;

/**
 * Set wolfEngine FIPS checks.
 * Default FIPS checks for wolfEngine is WE_FIPS_CHECKS_DEFAULT.
 *
 * @param checksMask  [in]  Bitmask of FIPS checks from wolfEngine_FipsCheck in
 *                          we_fips.h.
 */
void wolfEngine_SetFipsChecks(long checksMask)
{
    fipsChecks = checksMask;
}

/**
 * Get wolfEngine FIPS checks mask.
 *
 * @return  The FIPS checks mask.
 */
long wolfEngine_GetFipsChecks()
{
    return fipsChecks;
}