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

#include "internal.h"

#ifdef WOLFENGINE_DEBUG

#ifdef WOLFENGINE_USER_LOG
    /* user includes their own headers */
#else
    #include <stdio.h>  /* for default printf/fprintf */
#endif

/* Application callback function, set with wolfEngine_SetLoggingCb() */
static wolfEngine_Logging_cb log_function = NULL;

/* Flag indicating if logging is enabled, controlled via
 * wolfEngine_Debugging_ON() and wolfEngine_Debugging_OFF() */
static int loggingEnabled = 0;

#endif /* WOLFENGINE_DEBUG */


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

/**
 * Log function to convey function name and error for functions returning an
 * integer return code.
 *
 * @param funcName  [IN]  Name of function called.
 * @param ret       [IN]  Return of function.
 */
void WOLFENGINE_ERROR_FUNC(const char* funcName, int ret)
{
    if (loggingEnabled) {
        char buffer[WOLFENGINE_MAX_ERROR_SZ];
        XSNPRINTF(buffer, sizeof(buffer),
                  "Error calling %s: ret = %d", funcName, ret);
        wolfengine_log(WE_LOG_ERROR, buffer);
    }
}

/**
 * Log function to convey function name and error for functions returning a
 * pointer.
 *
 * @param funcName  [IN]  Name of function called.
 * @param ret       [IN]  Return of function.
 */
void WOLFENGINE_ERROR_FUNC_NULL(const char* funcName, void *ret)
{
    if (loggingEnabled) {
        char buffer[WOLFENGINE_MAX_ERROR_SZ];
        XSNPRINTF(buffer, sizeof(buffer),
                  "Error calling %s: ret = %p", funcName, ret);
        wolfengine_log(WE_LOG_ERROR, buffer);
    }
}

/* Macro to control line length of WOLFENGINE_BUFFER, for number of
 * both bytes and chars to print on one line. */
#ifndef WOLFENGINE_LINE_LEN
#define WOLFENGINE_LINE_LEN 16
#endif

/**
 * Log function to print buffer.
 *
 * @param buffer  [IN] Buffer to print.
 * @param length  [IN] Length of buffer, octets.
 */
void WOLFENGINE_BUFFER(const unsigned char* buffer, unsigned int length)
{
    int i, buflen = (int)length, bufidx;
    char line[(WOLFENGINE_LINE_LEN * 4) + 3]; /* \t00..0F | chars...chars\0 */

    if (!loggingEnabled) {
        return;
    }

    if (!buffer) {
        wolfengine_log(WE_LOG_VERBOSE, "\tNULL");
        return;
    }

    while (buflen > 0) {
        bufidx = 0;
        XSNPRINTF(&line[bufidx], sizeof(line)-bufidx, "\t");
        bufidx++;

        for (i = 0; i < WOLFENGINE_LINE_LEN; i++) {
            if (i < buflen) {
                XSNPRINTF(&line[bufidx], sizeof(line)-bufidx, "%02x ",
                          buffer[i]);
            }
            else {
                XSNPRINTF(&line[bufidx], sizeof(line)-bufidx, "   ");
            }
            bufidx += 3;
        }

        XSNPRINTF(&line[bufidx], sizeof(line)-bufidx, "| ");
        bufidx++;

        for (i = 0; i < WOLFENGINE_LINE_LEN; i++) {
            if (i < buflen) {
                XSNPRINTF(&line[bufidx], sizeof(line)-bufidx,
                     "%c", 31 < buffer[i] && buffer[i] < 127 ? buffer[i] : '.');
                bufidx++;
            }
        }

        wolfengine_log(WE_LOG_VERBOSE, line);
        buffer += WOLFENGINE_LINE_LEN;
        buflen -= WOLFENGINE_LINE_LEN;
    }
}

#endif /* WOLFENGINE_DEBUG */

