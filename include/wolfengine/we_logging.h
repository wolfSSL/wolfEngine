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

#ifdef WOLFENGINE_USER_SETTINGS
    #include "user_settings.h"
#endif

#ifndef WOLFENGINE_MAX_ERROR_SZ
#define WOLFENGINE_MAX_ERROR_SZ 80
#endif

/* wolfEngine debug logging support can be compiled in by defining
 * WOLFENGINE_DEBUG or by using the --enable-debug configure option.
 *
 * wolfEngine supports the log levels as mentioned in wolfEngine_LogType
 * enum below. The default logging level when debug logging is compiled in
 * and enabled at runtime is WE_LOG_LEVEL_DEFAULT.
 *
 * wolfEngine supports log message control per-component/algorithm type,
 * with all possible logging components in wolfEngine_LogComponents enum
 * below. The default logging level when debug logging is compiled in and
 * enabled at runtime is WE_LOG_COMPONENTS_DEFAULT.
 *
 */

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
    WE_LOG_ERROR   = 0x0001,  /* logs errors */
    WE_LOG_ENTER   = 0x0002,  /* logs function enter*/
    WE_LOG_LEAVE   = 0x0004,  /* logs function leave */
    WE_LOG_INFO    = 0x0008,  /* logs informative messages */
    WE_LOG_VERBOSE = 0x0010,  /* logs encrypted/decrypted/digested data */

    /* default log level when logging is turned on, all but verbose */
    WE_LOG_LEVEL_DEFAULT = (WE_LOG_ERROR
                          | WE_LOG_ENTER
                          | WE_LOG_LEAVE
                          | WE_LOG_INFO),

    /* log all, including verbose */
    WE_LOG_LEVEL_ALL = (WE_LOG_ERROR
                      | WE_LOG_ENTER
                      | WE_LOG_LEAVE
                      | WE_LOG_INFO
                      | WE_LOG_VERBOSE)
};

enum wolfEngine_LogComponents {
    WE_LOG_RNG    = 0x0001,  /* random number generation */
    WE_LOG_DIGEST = 0x0002,  /* digest (SHA-1/2/3) */
    WE_LOG_MAC    = 0x0004,  /* mac functions: HMAC, CMAC */
    WE_LOG_CIPHER = 0x0008,  /* cipher (AES, 3DES) */
    WE_LOG_PK     = 0x0010,  /* public key algorithms (RSA, ECC) */
    WE_LOG_KE     = 0x0020,  /* key agreement (DH, ECDH) */
    WE_LOG_ENGINE = 0x0040,  /* all engine specific logs */

    /* log all compoenents */
    WE_LOG_COMPONENTS_ALL = (WE_LOG_RNG
                           | WE_LOG_DIGEST
                           | WE_LOG_MAC
                           | WE_LOG_CIPHER
                           | WE_LOG_PK
                           | WE_LOG_KE
                           | WE_LOG_ENGINE),

    /* default compoenents logged */
    WE_LOG_COMPONENTS_DEFAULT = WE_LOG_COMPONENTS_ALL
};

typedef void (*wolfEngine_Logging_cb)(const int logLevel,
                                      const int component,
                                      const char *const logMessage);
int wolfEngine_SetLoggingCb(wolfEngine_Logging_cb logF);

/* turn logging on, only if compiled in */
int  wolfEngine_Debugging_ON(void);
/* turn logging off */
void wolfEngine_Debugging_OFF(void);

/* Set logging level, bitmask of wolfEngine_LogType */
int wolfEngine_SetLogLevel(int levelMask);
/* Set which components are logged, bitmask of wolfEngine_LogComponents */
int wolfEngine_SetLogComponents(int componentMask);

#ifdef WOLFENGINE_DEBUG

#define WOLFENGINE_ERROR(type, err)                                     \
    WOLFENGINE_ERROR_LINE(type, err, __FILE__, __LINE__)
#define WOLFENGINE_ERROR_MSG(type, msg)                                 \
    WOLFENGINE_ERROR_MSG_LINE(type, msg, __FILE__, __LINE__)
#define WOLFENGINE_ERROR_FUNC(type, funcName, ret)                      \
    WOLFENGINE_ERROR_FUNC_LINE(type, funcName, ret, __FILE__, __LINE__)
#define WOLFENGINE_ERROR_FUNC_NULL(type, funcName, ret)                  \
    WOLFENGINE_ERROR_FUNC_NULL_LINE(type, funcName, ret, __FILE__, __LINE__)

void WOLFENGINE_ENTER(int type, const char* msg);
void WOLFENGINE_LEAVE(int type, const char* msg, int ret);
void WOLFENGINE_MSG(int type, const char* msg);
void WOLFENGINE_ERROR_LINE(int type, int err, const char* file, int line);
void WOLFENGINE_ERROR_MSG_LINE(int type, const char* msg, const char* file,
                               int line);
void WOLFENGINE_ERROR_FUNC_LINE(int type, const char* funcName, int ret,
                                const char* file, int line);
void WOLFENGINE_ERROR_FUNC_NULL_LINE(int type, const char* funcName,
                                     const void *ret, const char* file,
                                     int line);
void WOLFENGINE_BUFFER(int type, const unsigned char* buffer,
                       unsigned int length);

#else

#define WOLFENGINE_ENTER(t, m)
#define WOLFENGINE_LEAVE(t, m, r)
#define WOLFENGINE_MSG(t, m)
#define WOLFENGINE_ERROR(t, e)
#define WOLFENGINE_ERROR_MSG(t, e)
#define WOLFENGINE_ERROR_FUNC(t, f, r)
#define WOLFENGINE_ERROR_FUNC_NULL(t, f, r)
#define WOLFENGINE_BUFFER(t, b, l)

#endif /* WOLFENGINE_DEBUG */

#endif /* WE_LOGGING_H */

