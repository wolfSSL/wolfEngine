/* we_tls_prf.c
 *
 * Copyright (C) 2006-2019 wolfSSL Inc.
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

#ifdef WE_HAVE_TLS1_PRF

/* Maximum seed length to use with TLS v1.0 PRF. */
#define WE_MAX_SEED_SIZE        1024

/**
 * Data used in TLS1 PRF operation.
 */
typedef struct we_Tls1_Prf {
    /** Digest to use with TLS1 PRF. */
    int mdType;
    /** Secret for PRF. */
    unsigned char *secret;
    /** Size of secret in bytes. */
    size_t secretSz;
    /** Label and seed for PRF. */
    unsigned char seed[WE_MAX_SEED_SIZE];
    /** Size of label and seed in bytes. */
    size_t seedSz;
} we_Tls1_Prf;

/**
 * Initialize internal TLS1 PRF object.
 *
 * @param  ctx  [in]  PKEY context.
 * @returns  1 on success and 0 on failure.
 */
static int we_tls1_prf_init(EVP_PKEY_CTX *ctx)
{
    int ret = 1;
    we_Tls1_Prf *tls1Prf;

    WOLFENGINE_ENTER(WE_LOG_PK, "we_tls1_prf_init");
    WOLFENGINE_MSG_VERBOSE(WE_LOG_PK, "ARGS [ctx = %p]", ctx);

    /* Allocate memory for internal TLS1 PRF object. */
    tls1Prf = OPENSSL_zalloc(sizeof(*tls1Prf));
    if (tls1Prf == NULL) {
        WOLFENGINE_ERROR_FUNC_NULL(WE_LOG_PK, "OPENSSL_zalloc(tls1Prf)",
                                   tls1Prf);
        ret = 0;
    }

    if (ret == 1) {
        /* Set internal TLS1 PRF object against PKEY context. */
        EVP_PKEY_CTX_set_data(ctx, tls1Prf);
    }

    WOLFENGINE_LEAVE(WE_LOG_PK, "we_tls1_prf_init", ret);

    return ret;
}

/**
 * Cleanup internal TLS1 PRF object.
 *
 * @param  ctx  [in]  PKEY context.
 */
static void we_tls1_prf_cleanup(EVP_PKEY_CTX *ctx)
{
    we_Tls1_Prf *tls1Prf;

    WOLFENGINE_ENTER(WE_LOG_PK, "we_tls1_prf_cleanup");
    WOLFENGINE_MSG_VERBOSE(WE_LOG_PK, "ARGS [ctx = %p]", ctx);

    /* Get internal TLS1 PRF object from PKEY context. */
    tls1Prf = (we_Tls1_Prf *)EVP_PKEY_CTX_get_data(ctx);
    if (tls1Prf != NULL) {
        /* Clear and free secret. */
        if (tls1Prf->secret != NULL) {
            OPENSSL_clear_free(tls1Prf->secret, tls1Prf->secretSz);
        }
        /* Clear seed - sensitive data. */
        OPENSSL_cleanse(tls1Prf->seed, tls1Prf->seedSz);
        /* Free internal TLS1 PRF object. */
        OPENSSL_free(tls1Prf);
    }

    WOLFENGINE_LEAVE(WE_LOG_PK, "we_tls1_prf_cleanup", 1);
}

/**
 * Derive the key from the secret and label/seed.
 *
 * @param  ctx    [in]  PKEY context.
 * @param  key    [in]  Calculated key data.
 * @param  keySz  [in]  Size of key data to calculate in bytes.
 * @returns  1 on success and 0 on failure.
 */
static int we_tls1_prf_derive(EVP_PKEY_CTX *ctx, unsigned char *key,
                              size_t *keySz)
{
    we_Tls1_Prf *tls1Prf;
    int ret = 1;
    int rc;

    WOLFENGINE_ENTER(WE_LOG_PK, "we_tls1_prf_derive");
    WOLFENGINE_MSG_VERBOSE(WE_LOG_PK, "ARGS [ctx = %p, key = %p, keySz = %p]",
                           ctx, key, keySz);

    /* Get internal TLS1 PRF object from PKEY context. */
    tls1Prf = (we_Tls1_Prf *)EVP_PKEY_CTX_get_data(ctx);
    /* Cannot get here without initialization succeeding. */

    if ((ret == 1) && (tls1Prf->mdType == NID_md5_sha1)) {
         /* Calculate key.
          * Label is included in seed so pass in buffer and 0 length for label.
          */
         rc = wc_PRF_TLSv1(key, (word32)*keySz, tls1Prf->secret,
                           (word32)(tls1Prf->secretSz), (byte*)"", 0,
                           tls1Prf->seed, (word32)(tls1Prf->seedSz), NULL,
                           INVALID_DEVID);
         if (rc != 0) {
             WOLFENGINE_ERROR_FUNC(WE_LOG_PK, "wc_PRF_TLSv1", rc);
             ret = 0;
         }
    }
    else if (ret == 1) {
        rc = wc_PRF_TLS(key, (word32)*keySz, tls1Prf->secret,
                        (word32)(tls1Prf->secretSz), (byte*)"", 0,
                        tls1Prf->seed, (word32)(tls1Prf->seedSz), 1,
                        tls1Prf->mdType == NID_sha256 ? sha256_mac : sha384_mac,
                        NULL, INVALID_DEVID);
         if (rc != 0) {
             WOLFENGINE_ERROR_FUNC(WE_LOG_PK, "wc_PRF_TLS", rc);
             ret = 0;
         }
    }

    WOLFENGINE_LEAVE(WE_LOG_PK, "we_tls1_prf_derive", ret);

    return ret;
}

/**
 * Control function for TLS1 PRF.
 *
 * Supports:
 *    EVP_PKEY_CTRL_TLS_MD - set digest to use.
 *    EVP_PKEY_CTRL_TLS_SECRET - set secret to use in calculation.
 *    EVP_PKEY_CTRL_TLS_SEED - set/add label/seed to use in calculation.
 *
 * @param  ctx    [in]  PKEY context.
 * @param  type   [in]  Type of operation to perform.
 * @param  num    [in]  Integer argument.
 * @param  ptr    [in]  Pointer argument.
 * @returns  1 on success and 0 on failure.
 */
static int we_tls1_prf_ctrl(EVP_PKEY_CTX *ctx, int type, int num, void *ptr)
{
    we_Tls1_Prf *tls1Prf;
    int ret = 1;
    char errBuff[WOLFENGINE_MAX_LOG_WIDTH];

    WOLFENGINE_ENTER(WE_LOG_PK, "we_tls1_prf_ctrl");
    WOLFENGINE_MSG_VERBOSE(WE_LOG_PK, "ARGS [ctx = %p, type = %d, num = %d, "
                           "ptr = %p]", ctx, type, num, ptr);

    /* Get internal TLS1 PRF object from PKEY context. */
    tls1Prf = (we_Tls1_Prf *)EVP_PKEY_CTX_get_data(ctx);
    /* Cannot get here without initialization succeeding. */

    switch (type) {
        case EVP_PKEY_CTRL_TLS_MD:
            WOLFENGINE_MSG(WE_LOG_PK, "type: EVP_PKEY_CTRL_TLS_MD");
            /* ptr: EVP md object. */
            tls1Prf->mdType = EVP_MD_type(ptr);
            break;

        case EVP_PKEY_CTRL_TLS_SECRET:
            WOLFENGINE_MSG(WE_LOG_PK, "type: EVP_PKEY_CTRL_TLS_SECRET");
            /* num: Number of bytes in buffer.
             * ptr: Buffer holding secret data. */
            /* Number of bytes must be positive. */
            if (num < 0) {
                ret = 0;
            }
            if ((ret == 1) && (tls1Prf->secret != NULL)) {
                /* Setting secret - dispose of old secret. */
                OPENSSL_clear_free(tls1Prf->secret, tls1Prf->secretSz);
            }
            if (ret == 1) {
                /* Clear label/seed as this is a new operation. */
                OPENSSL_cleanse(tls1Prf->seed, tls1Prf->seedSz);
                tls1Prf->seedSz = 0;
                /* Copy the secret. */
                tls1Prf->secret = OPENSSL_memdup(ptr, num);
                if (tls1Prf->secret == NULL) {
                    ret = 0;
                }
                else {
                    /* Store size of secret. */
                    tls1Prf->secretSz  = num;
                }
            }
            break;

        case EVP_PKEY_CTRL_TLS_SEED:
            WOLFENGINE_MSG(WE_LOG_PK, "type: EVP_PKEY_CTRL_TLS_SEED");
            /* num: Number of bytes in buffer.
             * ptr: Buffer holding label/seed data. */
            /* Valid to pass in empty buffer - ignored. */
            if ((num != 0) && (ptr != NULL)) {
                /* Ensure valid number - not negative and can fit. */
                if ((num < 0) ||
                        (num > (int)(WE_MAX_SEED_SIZE - tls1Prf->seedSz))) {
                    ret = 0;
                }
                if (ret == 1) {
                    /* Append bytes. */
                    XMEMCPY(tls1Prf->seed + tls1Prf->seedSz, ptr, num);
                    tls1Prf->seedSz += num;
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

    WOLFENGINE_LEAVE(WE_LOG_PK, "we_tls1_prf_ctrl", ret);

    return ret;
}

/**
 * Control function with string type for TLS1 PRF.
 *
 * Supports:
 *    "md" - set digest to use
 *    "secret" - string encoding of secret.
 *    "hexsecret" - hex string of secret.
 *    "seed" - string encoding of label/seed.
 *    "hexseed" - hex string of label/seed.
 *
 * @param  ctx    [in]  PKEY context.
 * @param  type   [in]  Type of operation to perform.
 * @param  value  [in]  Pointer argument.
 * @returns  1 on success and 0 on failure.
 */
static int we_tls1_prf_ctrl_str(EVP_PKEY_CTX *ctx, const char *type,
                                const char *value)
{
    int ret = 1;

    WOLFENGINE_ENTER(WE_LOG_PK, "we_tls1_prf_ctrl_str");
    WOLFENGINE_MSG_VERBOSE(WE_LOG_PK, "ARGS [ctx = %p, type = %p, value = %p]",
                           ctx, type, value);

    if (value == NULL) {
        WOLFENGINE_ERROR_MSG(WE_LOG_PK, "value == NULL");
        ret = 0;
    }
    else if (XSTRNCMP(type, "md", 3) == 0) {
        we_Tls1_Prf *tls1Prf = (we_Tls1_Prf *)EVP_PKEY_CTX_get_data(ctx);
        /* Cannot get here without initialization succeeding. */
        tls1Prf->mdType = EVP_MD_type(EVP_get_digestbyname(value));
    }
    else if (XSTRNCMP(type, "secret", 7) == 0) {
        ret = EVP_PKEY_CTX_str2ctrl(ctx, EVP_PKEY_CTRL_TLS_SECRET, value);
    }
    else if (XSTRNCMP(type, "hexsecret", 10) == 0) {
        ret = EVP_PKEY_CTX_hex2ctrl(ctx, EVP_PKEY_CTRL_TLS_SECRET, value);
    }
    else if (XSTRNCMP(type, "seed", 5) == 0) {
        ret = EVP_PKEY_CTX_str2ctrl(ctx, EVP_PKEY_CTRL_TLS_SEED, value);
    }
    else if (XSTRNCMP(type, "hexseed", 8) == 0) {
        ret = EVP_PKEY_CTX_hex2ctrl(ctx, EVP_PKEY_CTRL_TLS_SEED, value);
    }
    else {
        ret = 0;
    }

    WOLFENGINE_LEAVE(WE_LOG_PK, "we_tls1_prf_ctrl_str", ret);

    return ret;
}

/** TLS v1 PRF method using wolfSSL.  */
EVP_PKEY_METHOD *we_tls1_prf_method;

/**
 * Initialize the TLS1 PRF method for use with the EVP_PKEY API.
 *
 * @return  1 on success and 0 on failure.
 */
int we_init_tls1_prf_meth(void)
{
    int ret = 1;

    WOLFENGINE_ENTER(WE_LOG_PK, "we_init_tls1_prf_meth");

    we_tls1_prf_method = EVP_PKEY_meth_new(EVP_PKEY_TLS1_PRF, 0);
    if (we_tls1_prf_method == NULL) {
        WOLFENGINE_ERROR_FUNC_NULL(WE_LOG_PK,
                                   "EVP_PKEY_meth_new", we_tls1_prf_method);
        ret = 0;
    }

    if (ret == 1) {
        EVP_PKEY_meth_set_init(we_tls1_prf_method, we_tls1_prf_init);
        EVP_PKEY_meth_set_cleanup(we_tls1_prf_method, we_tls1_prf_cleanup);
        EVP_PKEY_meth_set_ctrl(we_tls1_prf_method, we_tls1_prf_ctrl,
                               we_tls1_prf_ctrl_str);
        EVP_PKEY_meth_set_derive(we_tls1_prf_method, NULL, we_tls1_prf_derive);
    }

    if (ret == 0 && we_tls1_prf_method != NULL) {
        EVP_PKEY_meth_free(we_tls1_prf_method);
        we_tls1_prf_method = NULL;
    }

    WOLFENGINE_LEAVE(WE_LOG_PK, "we_init_tls1_prf_meth", ret);

    return ret;
}

#endif /* WE_HAVE_TLS1_PRF */

