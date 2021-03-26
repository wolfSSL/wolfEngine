/* we_logging.h
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

#ifndef WE_LOGGING_H
#define WE_LOGGING_H

#ifndef WOLFENGINE_MAX_ERROR_SZ
#define WOLFENGINE_MAX_ERROR_SZ 80
#endif

/* Possible debug/logging options:
 *
 * WOLFENGINE_DEBUG       Define to enable debug logging (or --enable-debug)
 * WOLFENGINE_USER_LOG    Defines name of function for log output. By default
 *                        wolfEngine will log with fprintf to stderr. Users
 *                        can define this to a custom log function to be used
 *                        in place of fprintf. Alternatively, users can
 *                        register a logging callback for custom logging.
 * WOLFENGINE_LOG_PRINTF  Define to Use printf instead of fprintf (to stderr)
 *                        for logs. Not applicable if using WOLFENGINE_USER_LOG
 *                        or custom logging callback.
 */

enum wolfEngine_LogType {
    WE_LOG_ERROR = 0,
    WE_LOG_ENTER,
    WE_LOG_LEAVE,
    WE_LOG_INFO,
    WE_LOG_VERBOSE
};

typedef void (*wolfEngine_Logging_cb)(const int logLevel,
                                      const char *const logMessage);
int wolfEngine_SetLoggingCb(wolfEngine_Logging_cb logF);

/* turn logging on, only if compiled in */
int  wolfEngine_Debugging_ON(void);
/* turn logging off */
void wolfEngine_Debugging_OFF(void);

#ifdef WOLFENGINE_DEBUG

void WOLFENGINE_ENTER(const char* msg);
void WOLFENGINE_LEAVE(const char* msg, int ret);
void WOLFENGINE_MSG(const char* msg);
void WOLFENGINE_ERROR(int err);
void WOLFENGINE_ERROR_MSG(const char* msg);
void WOLFENGINE_ERROR_FUNC(const char* funcName, int ret);
void WOLFENGINE_ERROR_FUNC_NULL(const char* funcName, void *ret);
void WOLFENGINE_BUFFER(const unsigned char* buffer, unsigned int length);

#else

#define WOLFENGINE_ENTER(m)
#define WOLFENGINE_LEAVE(m, r)
#define WOLFENGINE_MSG(m)
#define WOLFENGINE_ERROR(e)
#define WOLFENGINE_ERROR_MSG(e)
#define WOLFENGINE_ERROR_FUNC(f, r)
#define WOLFENGINE_ERROR_FUNC_NULL(f, r)
#define WOLFENGINE_BUFFER(b, l)

#endif /* WOLFENGINE_DEBUG */

#endif /* WE_LOGGING_H */

