/* we_wolfengine.h
 *
 * Copyright (C) 2019-2021 wolfSSL Inc.
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

#ifndef WOLFENGINE_H
#define WOLFENGINE_H

/* OpenSSL 3.0.0 has deprecated the ENGINE API. */
#define OPENSSL_API_COMPAT      10101

#define WOLFENGINE_SUCCESS      1
#define WOLFENGINE_FAILURE      0
#define WOLFENGINE_FATAL_ERROR -1

/* Engine id - implementation uses wolfSSL */
extern const char *wolfengine_id;
/* Engine name ... or description.  */
extern const char *wolfengine_name;

void ENGINE_load_wolfengine(void);

#endif /* WOLFENGINE_H */
