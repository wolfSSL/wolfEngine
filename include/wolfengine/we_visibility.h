/* we_visibility.h
 *
 * Copyright (C) 2019-2023 wolfSSL Inc.
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

#ifndef WE_VISIBILITY_H
#define WE_VISIBILITY_H

#if defined(BUILDING_WOLFENGINE)
    #if defined(_MSC_VER) || defined(__MINGW32__) || defined(__CYGWIN__) || \
            defined(_WIN32_WCE)
        #if defined(WOLFENGINE_DLL)
            #define WOLFENGINE_API __declspec(dllexport)
        #else
            #define WOLFENGINE_API
        #endif
        #define WOLFENGINE_LOCAL
    #elif defined(HAVE_VISIBILITY) && HAVE_VISIBILITY
        #define WOLFENGINE_API   __attribute__ ((visibility("default")))
        #define WOLFENGINE_LOCAL __attribute__ ((visibility("hidden")))
    #elif defined(__SUNPRO_C) && (__SUNPRO_C >= 0x550)
        #define WOLFENGINE_API   __global
        #define WOLFENGINE_LOCAL __hidden
    #else
        #define WOLFENGINE_API
        #define WOLFENGINE_LOCAL
    #endif /* HAVE_VISIBILITY */
#else /* BUILDING_WOLFENGINE */
    #if defined(_MSC_VER) || defined(__MINGW32__) || defined(__CYGWIN__) || \
            defined(_WIN32_WCE)
        #if defined(WOLFENGINE_DLL)
            #define WOLFENGINE_API __declspec(dllimport)
        #else
            #define WOLFENGINE_API
        #endif
        #define WOLFENGINE_LOCAL
    #else
        #define WOLFENGINE_API
        #define WOLFENGINE_LOCAL
    #endif
#endif /* BUILDING_WOLFENGINE */

#endif /* WE_VISIBILITY_H */
