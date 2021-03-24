/* we_logging.c
 *
 * Copyright (C) 2006-2021 wolfSSL Inc.
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

/* Possible debug/logging options:
 *
 * WOLFENGINE_DEBUG       Define to enable debug logging (or --enable-debug)
 * WOLFENGINE_USER_LOG    Defines name of function for log output
 * WOLFENGINE_LOG_PRINTF  Use printf instead of fprintf to stderr for logs
 */

#ifdef WOLFENGINE_DEBUG

#ifdef WOLFENGINE_USER_LOG
    /* user includes their own headers */
#else
    #include <stdio.h>  /* for default printf/fprintf */
#endif

static wolfEngine_Logging_cb log_function = NULL;
static int loggingEnabled = 0;

#endif /* DEBUG_WOLFSSL */


/* Allow cb to be set to NULL, so logs can be redirected to default output */
int wolfEngine_SetLoggingCb(wolfEngine_Logging_cb f)
{
#ifdef WOLFENGINE_DEBUG
    log_function = f;
    return 0;
#else
    (void)f;
    return NOT_COMPILED_IN;
#endif
}

int wolfEngine_Debugging_ON(void)
{
#ifdef WOLFENGINE_DEBUG
    loggingEnabled = 1;
    return 0;
#else
    return NOT_COMPILED_IN;
#endif
}

void wolfEngine_Debugging_OFF(void)
{
#ifdef WOLFENGINE_DEBUG
    loggingEnabled = 0;
#endif
}

#ifdef WOLFENGINE_DEBUG

static void wolfengine_log(const int logLevel, const char *const logMessage)
{
    if (log_function) {
        log_function(logLevel, logMessage);
    } else {
#if defined(WOLFENGINE_USER_LOG)
        WOLFENGINE_USER_LOG(logMessage);
#elif defined(WOLFENGINE_LOG_PRINTF)
        printf("%s\n", logMessage);
#else
        fprintf(stderr, "%s\n", logMessage);
#endif
    }
}

void WOLFENGINE_MSG(const char* msg)
{
    if (loggingEnabled) {
        wolfengine_log(WE_LOG_INFO, msg);
    }
}

void WOLFENGINE_ENTER(const char* msg)
{
    if (loggingEnabled) {
        char buffer[WOLFENGINE_MAX_ERROR_SZ];
        XSNPRINTF(buffer, sizeof(buffer), "wolfEngine Entering %s", msg);
        wolfengine_log(WE_LOG_ENTER, buffer);
    }
}

void WOLFENGINE_LEAVE(const char* msg, int ret)
{
    if (loggingEnabled) {
        char buffer[WOLFENGINE_MAX_ERROR_SZ];
        XSNPRINTF(buffer, sizeof(buffer), "wolfEngine Leaving %s, return %d",
                  msg, ret);
        wolfengine_log(WE_LOG_LEAVE, buffer);
    }
}

void WOLFENGINE_ERROR(int error)
{
    if (loggingEnabled) {
        char buffer[WOLFENGINE_MAX_ERROR_SZ];
        XSNPRINTF(buffer, sizeof(buffer),
                  "wolfEngine error occurred, error = %d", error);
        wolfengine_log(WE_LOG_ERROR, buffer);
    }
}

void WOLFENGINE_ERROR_MSG(const char* msg)
{
    if (loggingEnabled) {
        wolfengine_log(WE_LOG_ERROR, msg);
    }
}

#endif /* WOLFENGINE_DEBUG */

