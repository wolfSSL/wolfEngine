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

#include <wolfengine/we_internal.h>

#ifdef WOLFENGINE_DEBUG

#ifdef WOLFENGINE_USER_LOG
    /* user includes their own headers */
#else
    #include <stdio.h>  /* for default printf/fprintf */
#endif

/* Used for variable arguments in WOLFENGINE_MSG and WOLFENGINE_MSG_VERBOSE */
#include <stdarg.h>

/* Application callback function, set with wolfEngine_SetLoggingCb() */
static wolfEngine_Logging_cb log_function = NULL;

/* Flag indicating if logging is enabled, controlled via
 * wolfEngine_Debugging_ON() and wolfEngine_Debugging_OFF() */
static int loggingEnabled = 0;

/* Logging level. Bitmask of logging levels in wolfEngine_LogType.
 * Can be set by application through ENGINE_ctrl command. Default log
 * level includes error, enter/leave, and info. Does not turn on verbose
 * by default. */
static int engineLogLevel = WE_LOG_LEVEL_DEFAULT;

/* Components which will be logged when debug enabled. Bitmask of components
 * in wolfEngine_LogComponents. Can be set by application through ENGINE_ctrl
 * command. Default components include all. */
static int engineLogComponents = WE_LOG_COMPONENTS_DEFAULT;

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

/**
 * Set wolfEngine logging level.
 * Deafult logging level for wolfEngine is WE_LOG_LEVEL_DEFAULT.
 *
 * @param levelMask [IN] Bitmask of logging levels from wolfEngine_LogType
 *                  in we_logging.h.
 * @return 0 on success, NOT_COMPILED_IN if debugging has not been enabled.
 */
int wolfEngine_SetLogLevel(int levelMask)
{
#ifdef WOLFENGINE_DEBUG
    engineLogLevel = levelMask;
    return 0;
#else
    (void)levelMask;
    return NOT_COMPILED_IN;
#endif
}

/**
 * Set which components to log in wolfEngine debug logs.
 * Default component level for wolfEngine is WE_LOG_COMPONENT_DEFAULT.
 *
 * @param componentMask [IN] Bitmask of components from
 *                      wolfEngine_LogComponents in we_logging.h.
 * @return 0 on success, NOT_COMPILED_IN if debugging has not been enabled.
 */
int wolfEngine_SetLogComponents(int componentMask)
{
#ifdef WOLFENGINE_DEBUG
    engineLogComponents = componentMask;
    return 0;
#else
    (void)componentMask;
    return NOT_COMPILED_IN;
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
static void wolfengine_log(const int logLevel, const int component,
                           const char *const logMessage)
{
    /* Don't log messages that do not match our current logging level */
    if ((engineLogLevel & logLevel) != logLevel)
        return;

    /* Don't log messages from components that do not match enabled list */
    if ((engineLogComponents & component) != component)
        return;

    if (log_function) {
        log_function(logLevel, component, logMessage);
    }
    else {
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
 * Internal log function for printing varg messages to a specific
 * log level. Used by WOLFENGINE_MSG and WOLFENGINE_MSG_VERBOSE.
 *
 * @param component [IN] Component type, from wolfEngine_LogComponents enum.
 * @param logLevel [IN] Log level, from wolfEngine_LogType enum.
 * @param fmt   [IN] Log message format string.
 * @param vargs [IN] Variable arguments, used with format string, fmt.
 */
WE_PRINTF_FUNC(3, 0)
static void wolfengine_msg_internal(int component, int logLevel,
                                    const char* fmt, va_list vlist)
{
    char msgStr[WOLFENGINE_MAX_LOG_WIDTH];

    if (loggingEnabled) {
        XVSNPRINTF(msgStr, sizeof(msgStr), fmt, vlist);
        wolfengine_log(logLevel, component, msgStr);
    }
}

/**
 * Log function for general messages.
 *
 * @param component [IN] Component type, from wolfEngine_LogComponents enum.
 * @param fmt   [IN] Log message format string.
 * @param vargs [IN] Variable arguments, used with format string, fmt.
 */
WE_PRINTF_FUNC(2, 3)
void WOLFENGINE_MSG(int component, const char* fmt, ...)
{
    va_list vlist;
    va_start(vlist, fmt);
    wolfengine_msg_internal(component, WE_LOG_INFO, fmt, vlist);
    va_end(vlist);
}

/**
 * Log function for general messages, prints to WE_LOG_VERBOSE level.
 *
 * @param component [IN] Component type, from wolfEngine_LogComponents enum.
 * @param fmt   [IN] Log message format string.
 * @param vargs [IN] Variable arguments, used with format string, fmt.
 */
WE_PRINTF_FUNC(2, 3)
void WOLFENGINE_MSG_VERBOSE(int component, const char* fmt, ...)
{
    va_list vlist;
    va_start(vlist, fmt);
    wolfengine_msg_internal(component, WE_LOG_VERBOSE, fmt, vlist);
    va_end(vlist);
}

/**
 * Log function used to record function entry.
 *
 * @param component [IN] Component type, from wolfEngine_LogComponents enum.
 * @param msg  [IN] Log message.
 */
void WOLFENGINE_ENTER(int component, const char* msg)
{
    if (loggingEnabled) {
        char buffer[WOLFENGINE_MAX_LOG_WIDTH];
        XSNPRINTF(buffer, sizeof(buffer), "wolfEngine Entering %s", msg);
        wolfengine_log(WE_LOG_ENTER, component, buffer);
    }
}

/**
 * Log function used to record function exit.
 *
 * @param component [IN] Component type, from wolfEngine_LogComponents enum.
 * @param msg  [IN] Log message.
 * @param ret  [IN] Value that function will be returning.
 */
void WOLFENGINE_LEAVE(int component, const char* msg, int ret)
{
    if (loggingEnabled) {
        char buffer[WOLFENGINE_MAX_LOG_WIDTH];
        XSNPRINTF(buffer, sizeof(buffer), "wolfEngine Leaving %s, return %d",
                  msg, ret);
        wolfengine_log(WE_LOG_LEAVE, component, buffer);
    }
}

/**
 * Log function for error code, general error message.
 *
 * @param component [IN] Component type, from wolfEngine_LogComponents enum.
 * @param error  [IN] error code to be logged.
 * @param file   [IN] Source file where error is called. 
 * @param line   [IN] Line in source file where error is called. 
 */
void WOLFENGINE_ERROR_LINE(int component, int error, const char* file, int line)
{
    if (loggingEnabled) {
        char buffer[WOLFENGINE_MAX_LOG_WIDTH];
        XSNPRINTF(buffer, sizeof(buffer),
                  "%s:%d - wolfEngine error occurred, error = %d", file, line,
                  error);
        wolfengine_log(WE_LOG_ERROR, component, buffer);
    }
}

/**
 * Log function for error message.
 *
 * @param component [IN] Component type, from wolfEngine_LogComponents enum.
 * @param msg  [IN] Error message.
 * @param file [IN] Source file where error is called. 
 * @param line [IN] Line in source file where error is called. 
 */
void WOLFENGINE_ERROR_MSG_LINE(int component, const char* msg,
                               const char* file, int line)
{
    if (loggingEnabled) {
        char buffer[WOLFENGINE_MAX_LOG_WIDTH];
        XSNPRINTF(buffer, sizeof(buffer), "%s:%d - wolfEngine Error %s",
                  file, line, msg);
        wolfengine_log(WE_LOG_ERROR, component, buffer);
    }
}

/**
 * Log function to convey function name and error for functions returning an
 * integer return code.
 *
 * @param component [IN] Component type, from wolfEngine_LogComponents enum.
 * @param funcName  [IN] Name of function called.
 * @param ret       [IN] Return of function.
 * @param file      [IN] Source file where error is called. 
 * @param line      [IN] Line in source file where error is called. 
 */
void WOLFENGINE_ERROR_FUNC_LINE(int component, const char* funcName, int ret,
                                const char* file, int line)
{
    if (loggingEnabled) {
        char buffer[WOLFENGINE_MAX_LOG_WIDTH];
        XSNPRINTF(buffer, sizeof(buffer),
                  "%s:%d - Error calling %s: ret = %d", file, line, funcName,
                  ret);
        wolfengine_log(WE_LOG_ERROR, component, buffer);
    }
}

/**
 * Log function to convey function name and error for functions returning a
 * pointer.
 *
 * @param component [IN] Component type, from wolfEngine_LogComponents enum.
 * @param funcName  [IN] Name of function called.
 * @param ret       [IN] Return of function.
 * @param file      [IN] Source file where error is called. 
 * @param line      [IN] Line in source file where error is called. 
 */
void WOLFENGINE_ERROR_FUNC_NULL_LINE(int component, const char* funcName,
                                     const void *ret, const char* file,
                                     int line)
{
    if (loggingEnabled) {
        char buffer[WOLFENGINE_MAX_LOG_WIDTH];
        XSNPRINTF(buffer, sizeof(buffer),
                  "%s:%d - Error calling %s: ret = %p", file, line, funcName,
                  ret);
        wolfengine_log(WE_LOG_ERROR, component, buffer);
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
 * @param component [IN] Component type, from wolfEngine_LogComponents enum.
 * @param buffer  [IN] Buffer to print.
 * @param length  [IN] Length of buffer, octets.
 */
void WOLFENGINE_BUFFER(int component, const unsigned char* buffer,
                       unsigned int length)
{
    int i, buflen = (int)length, bufidx;
    char line[(WOLFENGINE_LINE_LEN * 4) + 3]; /* \t00..0F | chars...chars\0 */

    if (!loggingEnabled) {
        return;
    }

    if (!buffer) {
        wolfengine_log(WE_LOG_VERBOSE, component, "\tNULL");
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

        wolfengine_log(WE_LOG_VERBOSE, component, line);
        buffer += WOLFENGINE_LINE_LEN;
        buflen -= WOLFENGINE_LINE_LEN;
    }
}

#endif /* WOLFENGINE_DEBUG */

