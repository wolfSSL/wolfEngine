/* test_dsa.c
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

#ifdef WE_HAVE_DSA

int test_dsa_keygen(ENGINE *e, void *data)
{
    int err;
    DSA *dsa = NULL;

    (void)data;

    err = (dsa = DSA_new_method(e)) == NULL;
    if (err == 0) {
        PRINT_MSG("Generating parameters");
        err = DSA_generate_parameters_ex(dsa, 3072, NULL, 0, NULL, NULL, NULL) != 1;
    }
    if (err == 0) {
        PRINT_MSG("Generating key");
        err = DSA_generate_key(dsa) != 1;
    }
    if (err == 0)
        PRINT_MSG("DSA method keygen successful");
    DSA_free(dsa);

    return err;
}


#ifdef WE_HAVE_EVP_PKEY

int test_dsa_pkey_keygen(ENGINE *e, void *data)
{
    int err;
    EVP_PKEY_CTX *paramCtx = NULL;
    EVP_PKEY_CTX *keyCtx = NULL;
    EVP_PKEY *pkeyParams = NULL;
    EVP_PKEY *pkeyKey = NULL;
    DSA *dsaKey = NULL;
    BIGNUM *pub = NULL;
    BIGNUM *priv = NULL;
    const int newKeySize = 3072;
    const int newQSize = 256;

    (void)data;

    err = (paramCtx = EVP_PKEY_CTX_new_id(EVP_PKEY_DSA, e)) == NULL;
    if (err == 0) {
        err = EVP_PKEY_paramgen_init(paramCtx) != 1;
    }
    if (err == 0) {
        PRINT_MSG("Change the key size w/ ctrl command");
        err = EVP_PKEY_CTX_ctrl(paramCtx, EVP_PKEY_DSA, EVP_PKEY_OP_PARAMGEN,
                EVP_PKEY_CTRL_DSA_PARAMGEN_BITS, newKeySize, NULL) <= 0;
    }
    if (err == 0) {
        PRINT_MSG("Change the Q size w/ ctrl command");
        err = EVP_PKEY_CTX_ctrl(paramCtx, EVP_PKEY_DSA, EVP_PKEY_OP_PARAMGEN,
                EVP_PKEY_CTRL_DSA_PARAMGEN_Q_BITS, newQSize, NULL) <= 0;
    }
    if (err == 0) {
        PRINT_MSG("Change the sign digest w/ ctrl command");
        err = EVP_PKEY_CTX_ctrl(paramCtx, EVP_PKEY_DSA, EVP_PKEY_OP_PARAMGEN,
                EVP_PKEY_CTRL_MD, 0, (void*)EVP_sha3_512()) <= 0;
    }
    if (err == 0) {
        PRINT_MSG("Generate DSA new parameters");
        err = EVP_PKEY_paramgen(paramCtx, &pkeyParams) != 1;
    }
    if (err == 0) {
        err = (keyCtx = EVP_PKEY_CTX_new(pkeyParams, e)) == NULL;
    }
    if (err == 0) {
        err = EVP_PKEY_keygen_init(keyCtx) != 1;
    }
    if (err == 0) {
        PRINT_MSG("Generate DSA key w/ new parameters");
        err = EVP_PKEY_keygen(keyCtx, &pkeyKey) != 1;
    }
    if (err == 0) {
        dsaKey = EVP_PKEY_get0_DSA(pkeyKey);
        err = dsaKey == NULL;
    }
    if (err == 0) {
        PRINT_MSG("New keys present");
        DSA_get0_key(dsaKey, (const BIGNUM **)&pub, (const BIGNUM **)&priv);
        err = pub == NULL || priv == NULL;
    }
    if (err == 0)
        PRINT_MSG("Generation successful");

    EVP_PKEY_free(pkeyParams);
    EVP_PKEY_free(pkeyKey);
    EVP_PKEY_CTX_free(paramCtx);
    EVP_PKEY_CTX_free(keyCtx);

    return err;
}

#endif /* WE_HAVE_EVP_PKEY */

#endif /* WE_HAVE_DSA */
