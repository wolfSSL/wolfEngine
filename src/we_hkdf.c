/* we_hkdf.c
 *
 * Copyright (C) 2006-2023 wolfSSL Inc.
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

#include <wolfengine/we_internal.h>

#ifdef WE_HAVE_HKDF

/* Maximum info length to use with HKDF. */
#define WE_MAX_INFO_SIZE        1024

/**
 * Data used in HKDF operation.
 */
typedef struct we_Hkdf {
    /** Mode to use with HKDF. */
    int mode;
    /** Digest to use with HKDF. */
    int mdType;
    /** Key for KDF. */
    unsigned char *key;
    /** Size of key in bytes. */
    size_t keySz;
    /** Salt for KDF. */
    unsigned char *salt;
    /** Size of salt in bytes. */
    size_t saltSz;
    /** Info for KDF. */
    unsigned char info[WE_MAX_INFO_SIZE];
    /** Size of info in bytes. */
    size_t infoSz;
} we_Hkdf;

/**
 * Initialize internal HKDF object.
 *
 * @param  ctx  [in]  PKEY context.
 * @returns  1 on success and 0 on failure.
 */
static int we_hkdf_init(EVP_PKEY_CTX *ctx)
{
    int ret = 1;
    we_Hkdf *hkdf;

    WOLFENGINE_ENTER(WE_LOG_PK, "we_hkdf_init");
    WOLFENGINE_MSG_VERBOSE(WE_LOG_PK, "ARGS [ctx = %p]", ctx);

    /* Allocate memory for internal HKDF object. */
    hkdf = OPENSSL_zalloc(sizeof(*hkdf));
    if (hkdf == NULL) {
        WOLFENGINE_ERROR_FUNC_NULL(WE_LOG_PK, "OPENSSL_zalloc(hkdf)",
                                   hkdf);
        ret = 0;
    }

    if (ret == 1) {
        /* Set internal HKDF object against PKEY context. */
        EVP_PKEY_CTX_set_data(ctx, hkdf);
    }

    WOLFENGINE_LEAVE(WE_LOG_PK, "we_hkdf_init", ret);

    return ret;
}

/**
 * Cleanup internal HKDF object.
 *
 * @param  ctx  [in]  PKEY context.
 */
static void we_hkdf_cleanup(EVP_PKEY_CTX *ctx)
{
    we_Hkdf *hkdf;

    WOLFENGINE_ENTER(WE_LOG_PK, "we_hkdf_cleanup");
    WOLFENGINE_MSG_VERBOSE(WE_LOG_PK, "ARGS [ctx = %p]", ctx);

    /* Get internal HKDF object from PKEY context. */
    hkdf = (we_Hkdf *)EVP_PKEY_CTX_get_data(ctx);
    if (hkdf != NULL) {
        /* Clear and free key. */
        if (hkdf->key != NULL) {
            OPENSSL_clear_free(hkdf->key, hkdf->keySz);
        }
        /* Clear and free salt. */
        if (hkdf->salt != NULL) {
            OPENSSL_free(hkdf->salt);
        }
        /* Clear info - sensitive data. */
        OPENSSL_cleanse(hkdf->info, hkdf->infoSz);
        /* Free internal HKDF object. */
        OPENSSL_free(hkdf);
    }

    WOLFENGINE_LEAVE(WE_LOG_PK, "we_hkdf_cleanup", 1);
}

/**
 * Derive the key from the key and info.
 *
 * @param  ctx    [in]      PKEY context.
 * @param  key    [out]     Calculated key data.
 * @param  keySz  [in,out]  On in, size of key data to calculate in bytes.
 *                          On out, size of key data in bytes. When extracting
 *                          only this will be the size of the digest.
 * @returns  1 on success and 0 on failure.
 */
static int we_hkdf_derive(EVP_PKEY_CTX *ctx, unsigned char *key,
                          size_t *keySz)
{
    we_Hkdf *hkdf;
    int ret = 1;
    int rc;

    WOLFENGINE_ENTER(WE_LOG_PK, "we_hkdf_derive");
    WOLFENGINE_MSG_VERBOSE(WE_LOG_PK, "ARGS [ctx = %p, key = %p, keySz = %p]",
                           ctx, key, keySz);

    /* Get internal HKDF object from PKEY context. */
    hkdf = (we_Hkdf *)EVP_PKEY_CTX_get_data(ctx);
    /* Cannot get here without initialization succeeding. */

    /* Check a digest was set - no default. */
    if ((ret == 1) && (hkdf->mdType == 0)) {
        WOLFENGINE_ERROR_MSG(WE_LOG_PK, "No digest from app.");
        ret = 0;
    }
    /* Check a key was set - no point otherwise! */
    if ((ret == 1) && (hkdf->keySz == 0)) {
        WOLFENGINE_ERROR_MSG(WE_LOG_PK, "No key from app.");
        ret = 0;
    }
    if ((ret == 1) && (hkdf->mode == EVP_PKEY_HKDEF_MODE_EXTRACT_AND_EXPAND)) {
        rc = wc_HKDF(hkdf->mdType, hkdf->key, (word32)hkdf->keySz, hkdf->salt,
            (word32)hkdf->saltSz, hkdf->info, (word32)hkdf->infoSz, key,
            (word32)*keySz);
        if (rc != 0) {
            WOLFENGINE_ERROR_FUNC(WE_LOG_PK, "wc_HKDF", rc);
            ret = 0;
        }
    }
    else if ((ret == 1) && (hkdf->mode == EVP_PKEY_HKDEF_MODE_EXTRACT_ONLY)) {
        rc = wc_HKDF_Extract(hkdf->mdType, hkdf->salt, (word32)hkdf->saltSz,
            hkdf->key, (word32)hkdf->keySz, key);
        if (rc != 0) {
            WOLFENGINE_ERROR_FUNC(WE_LOG_PK, "wc_HKDF_Extract", rc);
            ret = 0;
        }
        if (ret == 1) {
            *keySz = (size_t)wc_HashGetDigestSize(hkdf->mdType);
        }
    }
    else if ((ret == 1) && (hkdf->mode == EVP_PKEY_HKDEF_MODE_EXPAND_ONLY)) {
        rc = wc_HKDF_Expand(hkdf->mdType, hkdf->key, (word32)hkdf->keySz,
            hkdf->info, (word32)hkdf->infoSz, key, (word32)*keySz);
        if (rc != 0) {
            WOLFENGINE_ERROR_FUNC(WE_LOG_PK, "wc_HKDF_Expand", rc);
            ret = 0;
        }
    }

    WOLFENGINE_LEAVE(WE_LOG_PK, "we_hkdf_derive", ret);

    return ret;
}

/**
 * Control function for HKDF.
 *
 * Supports:
 *    EVP_PKEY_CTRL_HKDF_MODE - whether to do extract and expand or just one of.
 *    EVP_PKEY_CTRL_HKDF_MD - set digest to use.
 *    EVP_PKEY_CTRL_HKDF_KEY - set key to use in calculation.
 *    EVP_PKEY_CTRL_HKDF_SALT - set salt to use in calculation.
 *    EVP_PKEY_CTRL_HKDF_INFO - set/add info to use in calculation.
 *
 * @param  ctx    [in]  PKEY context.
 * @param  type   [in]  Type of operation to perform.
 * @param  num    [in]  Integer argument.
 * @param  ptr    [in]  Pointer argument.
 * @returns  1 on success and 0 on failure.
 */
static int we_hkdf_ctrl(EVP_PKEY_CTX *ctx, int type, int num, void *ptr)
{
    we_Hkdf *hkdf;
    int ret = 1;
    char errBuff[WOLFENGINE_MAX_LOG_WIDTH];

    WOLFENGINE_ENTER(WE_LOG_PK, "we_hkdf_ctrl");
    WOLFENGINE_MSG_VERBOSE(WE_LOG_PK, "ARGS [ctx = %p, type = %d, num = %d, "
                           "ptr = %p]", ctx, type, num, ptr);

    /* Get internal HKDF object from PKEY context. */
    hkdf = (we_Hkdf *)EVP_PKEY_CTX_get_data(ctx);
    /* Cannot get here without initialization succeeding. */

    switch (type) {
    #if OPENSSL_VERSION_NUMBER >= 0x1010100fL
        case EVP_PKEY_CTRL_HKDF_MODE:
            WOLFENGINE_MSG(WE_LOG_PK, "type: EVP_PKEY_CTRL_HKDF_MODE");
            /* num: Mode of operation for the HHKDF. */
            if ((num != EVP_PKEY_HKDEF_MODE_EXTRACT_AND_EXPAND) &&
                (num != EVP_PKEY_HKDEF_MODE_EXTRACT_ONLY) &&
                (num != EVP_PKEY_HKDEF_MODE_EXPAND_ONLY)) {
                /* Unsupported mode. */
                XSNPRINTF(errBuff, sizeof(errBuff), "Unsupported mode %d",
                          num);
                WOLFENGINE_ERROR_MSG(WE_LOG_PK, errBuff);
                ret = 0;
            }
            else {
                hkdf->mode = num;
            }
            break;
    #endif
            
        case EVP_PKEY_CTRL_HKDF_MD:
            WOLFENGINE_MSG(WE_LOG_PK, "type: EVP_PKEY_CTRL_HKDF_MD");
            /* ptr: EVP md object. */
            /* Convert EVP_MD to  */
            hkdf->mdType = we_nid_to_wc_hash_type(EVP_MD_type(ptr));
            break;

        case EVP_PKEY_CTRL_HKDF_KEY:
            WOLFENGINE_MSG(WE_LOG_PK, "type: EVP_PKEY_CTRL_HKDF_KEY");
            /* num: Number of bytes in buffer.
             * ptr: Buffer holding key data. */
            /* Number of bytes must be positive. */
            if (num < 0) {
                WOLFENGINE_ERROR_MSG(WE_LOG_PK, "Key size must be positive");
                ret = 0;
            }
            if ((ret == 1) && (hkdf->key != NULL)) {
                /* Setting key - dispose of old key. */
                OPENSSL_clear_free(hkdf->key, hkdf->keySz);
            }
            if (ret == 1) {
                /* Clear info as this is a new operation. */
                OPENSSL_cleanse(hkdf->info, hkdf->infoSz);
                hkdf->infoSz = 0;
                /* Copy the key. */
                hkdf->key = OPENSSL_memdup(ptr, num);
                if (hkdf->key == NULL) {
                    WOLFENGINE_ERROR_FUNC_NULL(WE_LOG_PK, "OPENSSL_memdup(key)",
                                               hkdf->key);
                    ret = 0;
                }
                else {
                    /* Store size of key. */
                    hkdf->keySz  = num;
                }
            }
            break;

        case EVP_PKEY_CTRL_HKDF_SALT:
            WOLFENGINE_MSG(WE_LOG_PK, "type: EVP_PKEY_CTRL_HKDF_SALT");
            /* num: Number of bytes in buffer.
             * ptr: Buffer holding salt data. */
            /* Number of bytes must be positive. */
            if (num < 0) {
                WOLFENGINE_ERROR_MSG(WE_LOG_PK, "Seed size must be positive");
                ret = 0;
            }
            if ((ret == 1) && (hkdf->salt != NULL)) {
                /* Setting salt - dispose of old salt. */
                OPENSSL_clear_free(hkdf->salt, hkdf->saltSz);
                hkdf->salt = NULL;
            }
            if (ret == 1) {
                /* Clear info as this is a new operation. */
                OPENSSL_cleanse(hkdf->info, hkdf->infoSz);
                hkdf->infoSz = 0;
                /* Copy the salt if there not 0 length. */
                if (num != 0) {
                    hkdf->salt = OPENSSL_memdup(ptr, num);
                    if (hkdf->salt == NULL) {
                        WOLFENGINE_ERROR_FUNC_NULL(WE_LOG_PK,
                            "OPENSSL_memdup(salt)", hkdf->key);
                        ret = 0;
                    }
                }
                if (ret == 1) {
                    /* Store size of salt. */
                    hkdf->saltSz  = num;
                }
            }
            break;

        case EVP_PKEY_CTRL_HKDF_INFO:
            WOLFENGINE_MSG(WE_LOG_PK, "type: EVP_PKEY_CTRL_HKDF_INFO");
            /* num: Number of bytes in buffer.
             * ptr: Buffer holding info data. */
            /* Valid to pass in empty buffer - ignored. */
            if ((num != 0) && (ptr != NULL)) {
                /* Ensure valid number - not negative and can fit. */
                if ((num < 0) ||
                        (num > (int)(WE_MAX_INFO_SIZE - hkdf->infoSz))) {
                    WOLFENGINE_ERROR_MSG(WE_LOG_PK, "Info length invalid");
                    ret = 0;
                }
                if (ret == 1) {
                    /* Append bytes. */
                    XMEMCPY(hkdf->info + hkdf->infoSz, ptr, num);
                    hkdf->infoSz += num;
                }
            }
            break;

        default:
            /* Unsupported type. */
            XSNPRINTF(errBuff, sizeof(errBuff), "Unsupported ctrl type %d",
                      type);
            WOLFENGINE_ERROR_MSG(WE_LOG_PK, errBuff);
            ret = 0;
            break;
    }

    WOLFENGINE_LEAVE(WE_LOG_PK, "we_hkdf_ctrl", ret);

    return ret;
}

/**
 * Control function with string type for HKDF.
 *
 * Supports:
 *    "mode" - operations to perform.
 *    "md" - set digest to use.
 *    "key" - string encoding of key.
 *    "hexkey" - hex string of key.
 *    "salt" - string encoding of salt.
 *    "hexsalt" - hex string of salt.
 *    "info" - string encoding of info.
 *    "hexinfo" - hex string of info.
 *
 * @param  ctx    [in]  PKEY context.
 * @param  type   [in]  Type of operation to perform.
 * @param  value  [in]  Pointer argument.
 * @returns  1 on success and 0 on failure.
 */
static int we_hkdf_ctrl_str(EVP_PKEY_CTX *ctx, const char *type,
                                const char *value)
{
    int ret = 1;
    we_Hkdf *hkdf;
    char errBuff[WOLFENGINE_MAX_LOG_WIDTH];

    WOLFENGINE_ENTER(WE_LOG_PK, "we_hkdf_ctrl_str");
    WOLFENGINE_MSG_VERBOSE(WE_LOG_PK, "ARGS [ctx = %p, type = %p, value = %p]",
                           ctx, type, value);

    if (value == NULL) {
        WOLFENGINE_ERROR_MSG(WE_LOG_PK, "value == NULL");
        ret = 0;
    }
#if OPENSSL_VERSION_NUMBER >= 0x1010100fL
    else if (XSTRNCMP(type, "mode", 5) == 0) {
        hkdf = (we_Hkdf *)EVP_PKEY_CTX_get_data(ctx);
        /* Cannot get here without initialization succeeding. */
        if (XSTRNCMP(value, "EXTRACT_AND_EXPAND", 19) == 0) {
            hkdf->mode = EVP_PKEY_HKDEF_MODE_EXTRACT_AND_EXPAND;
        }
        else if (XSTRNCMP(value, "EXTRACT_ONLY", 13) == 0) {
            hkdf->mode = EVP_PKEY_HKDEF_MODE_EXTRACT_ONLY;
        }
        else if (XSTRNCMP(value, "EXPAND_ONLY", 12) == 0) {
            hkdf->mode = EVP_PKEY_HKDEF_MODE_EXPAND_ONLY;
        }
        else {
            /* Unsupported string for value. */
            XSNPRINTF(errBuff, sizeof(errBuff), "Unsupported mode string %s",
                      value);
            WOLFENGINE_ERROR_MSG(WE_LOG_PK, errBuff);
            ret = 0;
        }
    }
#endif
    else if (XSTRNCMP(type, "md", 3) == 0) {
        hkdf = (we_Hkdf *)EVP_PKEY_CTX_get_data(ctx);
        /* Cannot get here without initialization succeeding. */
        hkdf->mdType =
            we_nid_to_wc_hash_type(EVP_MD_type(EVP_get_digestbyname(value)));
    }
    else if (XSTRNCMP(type, "key", 4) == 0) {
        ret = EVP_PKEY_CTX_str2ctrl(ctx, EVP_PKEY_CTRL_HKDF_KEY, value);
    }
    else if (XSTRNCMP(type, "hexkey", 7) == 0) {
        ret = EVP_PKEY_CTX_hex2ctrl(ctx, EVP_PKEY_CTRL_HKDF_KEY, value);
    }
    else if (XSTRNCMP(type, "salt", 5) == 0) {
        ret = EVP_PKEY_CTX_str2ctrl(ctx, EVP_PKEY_CTRL_HKDF_SALT, value);
    }
    else if (XSTRNCMP(type, "hexsalt", 8) == 0) {
        ret = EVP_PKEY_CTX_hex2ctrl(ctx, EVP_PKEY_CTRL_HKDF_SALT, value);
    }
    else if (XSTRNCMP(type, "info", 5) == 0) {
        ret = EVP_PKEY_CTX_str2ctrl(ctx, EVP_PKEY_CTRL_HKDF_INFO, value);
    }
    else if (XSTRNCMP(type, "hexinfo", 8) == 0) {
        ret = EVP_PKEY_CTX_hex2ctrl(ctx, EVP_PKEY_CTRL_HKDF_INFO, value);
    }
    else {
        /* Unsupported string. */
        XSNPRINTF(errBuff, sizeof(errBuff), "Unsupported ctrl type %s", type);
        WOLFENGINE_ERROR_MSG(WE_LOG_PK, errBuff);
        ret = 0;
    }

    WOLFENGINE_LEAVE(WE_LOG_PK, "we_hkdf_ctrl_str", ret);

    return ret;
}

/** HKDF method using wolfSSL.  */
EVP_PKEY_METHOD *we_hkdf_method;

/**
 * Initialize the HKDF method for use with the EVP_PKEY API.
 *
 * @return  1 on success and 0 on failure.
 */
int we_init_hkdf_meth(void)
{
    int ret = 1;

    WOLFENGINE_ENTER(WE_LOG_PK, "we_init_hkdf_meth");

    we_hkdf_method = EVP_PKEY_meth_new(EVP_PKEY_HKDF, 0);
    if (we_hkdf_method == NULL) {
        WOLFENGINE_ERROR_FUNC_NULL(WE_LOG_PK,
                                   "EVP_PKEY_meth_new", we_hkdf_method);
        ret = 0;
    }

    if (ret == 1) {
        EVP_PKEY_meth_set_init(we_hkdf_method, we_hkdf_init);
        EVP_PKEY_meth_set_cleanup(we_hkdf_method, we_hkdf_cleanup);
        EVP_PKEY_meth_set_ctrl(we_hkdf_method, we_hkdf_ctrl, we_hkdf_ctrl_str);
        EVP_PKEY_meth_set_derive(we_hkdf_method, NULL, we_hkdf_derive);
    }

    if (ret == 0 && we_hkdf_method != NULL) {
        EVP_PKEY_meth_free(we_hkdf_method);
        we_hkdf_method = NULL;
    }

    WOLFENGINE_LEAVE(WE_LOG_PK, "we_init_hkdf_meth", ret);

    return ret;
}

#endif /* WE_HAVE_HKDF */

