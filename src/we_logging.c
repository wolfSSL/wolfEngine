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

#ifdef WOLFENGINE_DEBUG

#ifdef WOLFENGINE_USER_LOG
    /* user includes their own headers */
#else
    #include <stdio.h>  /* for default printf/fprintf */
#endif

static wolfEngine_Logging_cb log_function = NULL;
static int loggingEnabled = 0;

#endif /* DEBUG_WOLFSSL */


/**
 * Registers wolfEngine logging callback.
 * Callback will be used by wolfEngine for debug/log messages.
 *
 * @param f Callback function, prototyped by wolfEngine_Logging_cb. Callback
 *          function may be NULL to reset logging redirection back to default
 *          output.
 * @return 0 on success, NOT_COMPILED_IN if debugging has
 *         not been enabled.
 */
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

/**
 * Enable debug logging.
 *
 * @return 0 on success, NOT_COMPILED_IN if debugging has
 *         not been enabled.
 */
int wolfEngine_Debugging_ON(void)
{
#ifdef WOLFENGINE_DEBUG
    loggingEnabled = 1;
    return 0;
#else
    return NOT_COMPILED_IN;
#endif
}

/**
 * Disable debug logging.
 */
void wolfEngine_Debugging_OFF(void)
{
#ifdef WOLFENGINE_DEBUG
    loggingEnabled = 0;
#endif
}

#ifdef WOLFENGINE_DEBUG

/**
 * Logging function used by wolfEngine.
 * Calls either default log mechanism or application-registered logging
 * callback.
 *
 * @param logLevel   [IN] Log level.
 * @param logMessage [IN] Log message.
 */
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

/**
 * Log function for general messages.
 *
 * @param msg  [IN] Log message.
 */
void WOLFENGINE_MSG(const char* msg)
{
    if (loggingEnabled) {
        wolfengine_log(WE_LOG_INFO, msg);
    }
}

/**
 * Log function used to record function entry.
 *
 * @param msg  [IN] Log message.
 */
void WOLFENGINE_ENTER(const char* msg)
{
    if (loggingEnabled) {
        char buffer[WOLFENGINE_MAX_ERROR_SZ];
        XSNPRINTF(buffer, sizeof(buffer), "wolfEngine Entering %s", msg);
        wolfengine_log(WE_LOG_ENTER, buffer);
    }
}

/**
 * Log function used to record function exit.
 *
 * @param msg  [IN] Log message.
 * @param ret  [IN] Value that function will be returning.
 */
void WOLFENGINE_LEAVE(const char* msg, int ret)
{
    if (loggingEnabled) {
        char buffer[WOLFENGINE_MAX_ERROR_SZ];
        XSNPRINTF(buffer, sizeof(buffer), "wolfEngine Leaving %s, return %d",
                  msg, ret);
        wolfengine_log(WE_LOG_LEAVE, buffer);
    }
}

/**
 * Log function for error code, general error message.
 *
 * @param error  [IN] error code to be logged.
 */
void WOLFENGINE_ERROR(int error)
{
    if (loggingEnabled) {
        char buffer[WOLFENGINE_MAX_ERROR_SZ];
        XSNPRINTF(buffer, sizeof(buffer),
                  "wolfEngine error occurred, error = %d", error);
        wolfengine_log(WE_LOG_ERROR, buffer);
    }
}

/**
 * Log function for error message.
 *
 * @param msg  [IN] Error message.
 */
void WOLFENGINE_ERROR_MSG(const char* msg)
{
    if (loggingEnabled) {
        wolfengine_log(WE_LOG_ERROR, msg);
    }
}

#endif /* WOLFENGINE_DEBUG */

