/* test_cmac.c
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
#undef AES_BLOCK_SIZE
#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/cmac.h>

#ifdef WE_HAVE_CMAC

static int test_cmac_generation(ENGINE *e, const EVP_CIPHER *c,
    unsigned char *key, int keySz, unsigned char *msg, int len,
    unsigned char *out, int *outLen)
{
    int err;
    EVP_MD_CTX   *ctx;
    EVP_PKEY_CTX *pctx = NULL;
    EVP_PKEY     *pkey = NULL;

    err = (ctx = EVP_MD_CTX_new()) == NULL;
    if (err == 0) {
        pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_CMAC, e);
        if (pctx == NULL)
            err = -1;
    }
    if (err == 0) {
        EVP_PKEY_keygen_init(pctx);
        err = EVP_PKEY_CTX_ctrl(pctx, -1, EVP_PKEY_OP_KEYGEN,
                EVP_PKEY_CTRL_CIPHER, 0, (void*)c) != 1;
    }
    if (err == 0) {
        err = EVP_PKEY_CTX_ctrl(pctx, -1, EVP_PKEY_OP_KEYGEN,
                EVP_PKEY_CTRL_SET_MAC_KEY, keySz, key) != 1;
    }
    if (err == 0) {
        err = EVP_PKEY_keygen(pctx, &pkey) != 1;
    }
    if (err == 0) {
        err = EVP_DigestSignInit(ctx, NULL, NULL, e, pkey) != 1;
    }
    if (err == 0) {
        err = EVP_DigestSignUpdate(ctx, msg, len/2) != 1;
    }
    if (err == 0) {
        err = EVP_DigestSignUpdate(ctx, msg + len/2, len - len/2) != 1;
    }
    if (err == 0) {
        size_t mlen = (size_t)*outLen;

        err = EVP_DigestSignFinal(ctx, out, &mlen) != 1;
        *outLen = (int)mlen;
    }
    if (err == 0) {
        PRINT_BUFFER("CMAC", out, *outLen);
    }

    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(pctx);

    return err;
}


static int test_cmac_create_helper(ENGINE *e, unsigned char *in,
        int inSz, unsigned char *key, int keySz, const EVP_CIPHER *c)
{
    int ret;

    unsigned char exp[16];
    int expLen;

    unsigned char mac[16];
    int macLen;

    macLen = sizeof(mac);
    expLen = sizeof(exp);

    /* generate mac using OpenSSL */
    ret = test_cmac_generation(NULL, c, key, keySz, in, inSz, exp, &expLen);
    if (ret != 0) {
        PRINT_MSG("Generate MAC using OpenSSL failed");
    }

    if (ret == 0) {
        memset(mac, 0, sizeof(mac));
        ret = test_cmac_generation(e, c, key, keySz, in, inSz, mac, &macLen);
        if (ret != 0) {
            PRINT_MSG("Generate MAC using wolfSSL failed");
        }
    }

    if (ret == 0) {
        if (macLen != expLen) {
            PRINT_MSG("generated length and expected length differ");
            ret = -1;
        }
        else {
            if (memcmp(mac, exp, expLen) != 0) {
                PRINT_MSG("generated mac and expected mac differ");
                ret = -1;
            }
        }
    }

    return ret;
}

int test_cmac_create(ENGINE *e, void *data)
{
    int ret = 0;
    unsigned char in[] = "I'm gonna break my rusty cage and run";
    int inSz;

    unsigned char key[] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07
    };
    int keySz;

    (void)data;
    inSz  = sizeof(in);

    PRINT_MSG("Testing with 256 bit KEY");
    keySz = 32;
    ret = test_cmac_create_helper(e, in, inSz, key, keySz,
            EVP_aes_256_cbc());

    if (ret == 0) {
        PRINT_MSG("Testing with 128 bit KEY");
        keySz = 16;
        ret = test_cmac_create_helper(e, in, inSz, key, keySz,
                EVP_aes_128_cbc());
    }

    if (ret == 0) {
        PRINT_MSG("Testing with a 192 bit KEY");
        keySz = 24;
        ret = test_cmac_create_helper(e, in, inSz, key, keySz,
                EVP_aes_192_cbc());
    }

    return ret;
}

#endif /* WE_HAVE_CMAC */


