/* test_logging.c
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

#include "unit.h"
#include "we_logging.h"

static int log_cnt = 0;

static void my_Logging_cb(const int logLevel, const char* const logMessage)
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
#ifdef WOLFENGINE_DEBUG
    const char* msg = "Testing, testing";
#endif

    (void)data;

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

    /* force a few logs to print, if debug has been enabled */
    WOLFENGINE_MSG(msg);
    WOLFENGINE_ERROR(-1);
    WOLFENGINE_ERROR_MSG(msg);

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
    WOLFENGINE_MSG(msg);
    WOLFENGINE_ERROR(-1);
    WOLFENGINE_ERROR_MSG(msg);

    if (i != log_cnt) {
        PRINT_ERR_MSG("Logs were output when debug is disabled");
        err = 1;
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

    return err;
}

/******************************************************************************/

