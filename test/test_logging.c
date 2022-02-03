/* test_logging.c
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

#include "unit.h"
#include <wolfengine/we_logging.h>

static int log_cnt = 0;

/* Default logging level for unit tests, no enter/leave */
static int defaultLogLevel = WE_LOG_ERROR | WE_LOG_INFO;

static void my_Logging_cb(const int logLevel, const int component,
                          const char* const logMessage)
{
    (void)logLevel;
    (void)component;
    (void)logMessage;
    log_cnt++;
}

static void my_wolfSSL_log_cb(const int logLevel, const char* const logMessage)
{
    (void)logLevel;
    (void)logMessage;
    log_cnt++;
}

/******************************************************************************/

int test_logging(ENGINE *e, void *data)
{
    int err = 0, ret = 0;
    int i = 0;
    int initialDebug = 0;
#ifdef WOLFENGINE_DEBUG
    const char* msg = "Testing, testing";
#endif

    /* Save the debug value so we can restore debugging at the end of this
       test. */
    if (data != NULL) {
        initialDebug = *(int*)data;
    }
    else {
        PRINT_ERR_MSG("Expected debug ptr in parameter \"data\", was NULL.");
        err = 1;
    }

    /* test enabling debug logging */
    PRINT_MSG("Enable debug logging");
    ret = ENGINE_ctrl_cmd(e, "enable_debug", 1, NULL, NULL, 0);
#ifdef WOLFENGINE_DEBUG
    if (ret != 1) {
        PRINT_ERR_MSG("Failed to enable debug logging");
        err = 1;
    }
#else
    if (ret != 0) {
        PRINT_ERR_MSG("Allowed to enable debug when not compiled in");
        err = 1;
    }
#endif

    /* test enabling wolfSSL debug logging */
    PRINT_MSG("Enable wolfSSL debug logging");
    ret = ENGINE_ctrl_cmd(e, "enable_debug_wolfssl", 1, NULL, NULL, 0);
#ifdef DEBUG_WOLFSSL
    if (ret != 1) {
        PRINT_ERR_MSG("Failed to enable wolfSSL debug logging");
        err = 1;
    }
#else
    if (ret != 0) {
        PRINT_ERR_MSG("Allowed to enable wolfSSL debug when not compiled in");
        err = 1;
    }
#endif

    /* test setting logging level */
    PRINT_MSG("Set logging level");
    ret = ENGINE_ctrl_cmd(e, "log_level", defaultLogLevel, NULL, NULL, 0);
#ifdef WOLFENGINE_DEBUG
    if (ret != 1) {
        PRINT_ERR_MSG("Failed to set logging level");
        err = 1;
    }
#else
    if (ret != 0) {
        PRINT_ERR_MSG("Allowed to set logging level when not compiled in");
        err = 1;
    }
#endif

    /* test registering logging callback */
    PRINT_MSG("Set logging callback");
    ret = ENGINE_ctrl_cmd(e, "set_logging_cb", 0, NULL,
                (void(*)(void))my_Logging_cb, 0);
#ifdef WOLFENGINE_DEBUG
    if (ret != 1) {
        PRINT_ERR_MSG("Failed to set logging callback");
        err = 1;
    }
#else
    if (ret != 0) {
        PRINT_ERR_MSG("Allowed to register debug cb when not compiled in");
        err = 1;
    }
#endif

    /* test registering logging callback */
    PRINT_MSG("Set wolfSSL logging callback");
    ret = ENGINE_ctrl_cmd(e, "set_logging_cb_wolfssl", 0, NULL,
                (void(*)(void))my_wolfSSL_log_cb, 0);
#ifdef DEBUG_WOLFSSL
    if (ret != 1) {
        PRINT_ERR_MSG("Failed to set wolfSSL logging callback");
        err = 1;
    }
#else
    if (ret != 0) {
        PRINT_ERR_MSG("Allowed to register wolfSSL debug cb when not compiled"
                      " in");
        err = 1;
    }
#endif

    /* force a few logs to print, if debug has been enabled */
    WOLFENGINE_MSG(WE_LOG_ENGINE, msg);
    WOLFENGINE_ERROR(WE_LOG_ENGINE, -1);
    WOLFENGINE_ERROR_MSG(WE_LOG_ENGINE, msg);

    /* turn off logs */
    PRINT_MSG("Disable debug logging");
    if (ENGINE_ctrl_cmd(e, "enable_debug", 0, NULL, NULL, 0) != 1) {
        PRINT_ERR_MSG("Failed to disable debug logging");
        err = 1;
    }

#ifdef WOLFENGINE_DEBUG
    /* capture log count */
    i = log_cnt;

    /* validate no logs are output when disabled */
    WOLFENGINE_MSG(WE_LOG_ENGINE, msg);
    WOLFENGINE_ERROR(WE_LOG_ENGINE, -1);
    WOLFENGINE_ERROR_MSG(WE_LOG_ENGINE, msg);

    if (i != log_cnt) {
        PRINT_ERR_MSG("Logs were output when debug is disabled");
        err = 1;
    }

    /* test setting log level to 0, verify no logs are output */
    log_cnt = 0;
    PRINT_MSG("Enable debug logging, test setting log level to 0");
    if (ENGINE_ctrl_cmd(e, "enable_debug", 1, NULL, NULL, 0) != 1) {
        PRINT_ERR_MSG("Failed to enable debug logging");
        err = 1;
    }
    if (ENGINE_ctrl_cmd(e, "log_level", 0, NULL, NULL, 0) != 1) {
        PRINT_ERR_MSG("Failed to set log_level to 0");
        err = 1;
    }
    WOLFENGINE_MSG(WE_LOG_ENGINE, msg);
    WOLFENGINE_ERROR(WE_LOG_ENGINE, -1);
    WOLFENGINE_ERROR_MSG(WE_LOG_ENGINE, msg);

    if (log_cnt > 0) {
        PRINT_ERR_MSG("Logs are output when log level is set to 0");
        err = 1;
    }
    if (ENGINE_ctrl_cmd(e, "log_level", defaultLogLevel,
                        NULL, NULL, 0) != 1) {
        PRINT_ERR_MSG("Failed to set log_level to defaultLogLevel");
        err = 1;
    }

    /* test individual component levels can be set */
    /* test logging only WE_LOG_ENGINE */
    log_cnt = 0;
    PRINT_MSG("Testing setting log component levels");
    if (ENGINE_ctrl_cmd(e, "log_components", WE_LOG_ENGINE,
                        NULL, NULL, 0) != 1) {
        PRINT_ERR_MSG("Failed to set WE_LOG_ENGINE component logging");
        err = 1;
    }
    if (err == 0) {
        WOLFENGINE_MSG(WE_LOG_ENGINE, msg);
        WOLFENGINE_MSG(WE_LOG_CIPHER, msg);
        WOLFENGINE_MSG(WE_LOG_PK, msg);

        if (log_cnt != 1) {
            PRINT_ERR_MSG("Failed to set only WE_LOG_ENGINE component log");
            err = 1;
        }
    }

    /* test logging only WE_LOG_CIPHER and WE_LOG_PK */
    if (err == 0) {
        log_cnt = 0;
        if (ENGINE_ctrl_cmd(e, "log_components", WE_LOG_CIPHER | WE_LOG_PK,
                            NULL, NULL, 0) != 1) {
            PRINT_ERR_MSG("Failed to set WE_LOG_CIPHER | WE_LOG_PK");
            err = 1;
        }
        if (err == 0) {
            WOLFENGINE_MSG(WE_LOG_ENGINE, msg);
            WOLFENGINE_MSG(WE_LOG_CIPHER, msg);
            WOLFENGINE_MSG(WE_LOG_PK, msg);

            if (log_cnt != 2) {
                PRINT_ERR_MSG("Failed to correctly set "
                              "WE_LOG_CIPHER | WE_LOG_PK");
                err = 1;
            }
        }
    }

    if (err == 0) {
        /* reset log component levels */
        if (ENGINE_ctrl_cmd(e, "log_components", WE_LOG_COMPONENTS_DEFAULT,
                            NULL, NULL, 0) != 1) {
            PRINT_ERR_MSG("Failed to reset log component levels");
            err = 1;
        }
    }

#else
    /* verify no logs are output when debug is disabled */
    if (i != 0) {
        PRINT_ERR_MSG("Logs are output when debug is disabled");
        err = 1;
    }
#endif /* WOLFENGINE_DEBUG */

    /* restore callback */
    ret = ENGINE_ctrl_cmd(e, "set_logging_cb", 0, NULL, NULL, 0);
#ifdef WOLFENGINE_DEBUG
    if (ret != 1) {
        PRINT_ERR_MSG("Failed to set logging callback to NULL");
        err = 1;
    }
#else
    if (ret != 0) {
        PRINT_ERR_MSG("Allowed to set NULL debug cb when not compiled in");
        err = 1;
    }
#endif

    /* Restore debugging, if applicable. */
    if (initialDebug) {
        ret = ENGINE_ctrl_cmd(e, "enable_debug", 1, NULL, NULL, 0);
        if (ret != 1) {
            PRINT_ERR_MSG("Failed to restore debug logging");
            err = 1;
        }
    }

    /* Restore default unit test logging level */
    ret = ENGINE_ctrl_cmd(e, "log_level", defaultLogLevel, NULL, NULL, 0);
#ifdef WOLFENGINE_DEBUG
    if (ret != 1) {
        PRINT_ERR_MSG("Failed to set logging level");
        err = 1;
    }
#else
    if (ret != 0) {
        PRINT_ERR_MSG("Allowed to set logging level when not compiled in");
        err = 1;
    }
#endif


    return err;
}

/******************************************************************************/

