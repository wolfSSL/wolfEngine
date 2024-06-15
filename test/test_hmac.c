/* test_hmac.c
 *
 * Copyright (C) 2019-2023 wolfSSL Inc.
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

#ifdef WE_HAVE_HMAC

static int test_mac_generation(ENGINE *e, const EVP_MD *md, int pkeyType,
                           unsigned char *pswd, int pswdSz, unsigned char *msg,
                           int len, unsigned char *mac, int *macLen)
{
    int err;
    EVP_MD_CTX *ctx;
    EVP_PKEY   *pkey = NULL;

    err = (ctx = EVP_MD_CTX_new()) == NULL;
    if (err == 0) {
        err = (pkey = EVP_PKEY_new_mac_key(pkeyType, e, pswd, pswdSz))
            == NULL;
    }
    if (err == 0) {
        err = EVP_DigestSignInit(ctx, NULL, md, e, pkey) != 1;
    }
    if (err == 0) {
        err = EVP_DigestSignUpdate(ctx, msg, len/2) != 1;
    }
    if (err == 0) {
        err = EVP_DigestSignUpdate(ctx, msg + len/2, len - len/2) != 1;
    }
    if (err == 0) {
        size_t mlen = (size_t)*macLen;

        err = EVP_DigestSignFinal(ctx, mac, &mlen) != 1;
        *macLen = (int)mlen;
    }
    if (err == 0) {
        PRINT_BUFFER("MAC", mac, *macLen);
    }

    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(pkey);

    return err;
}


static int test_hmac_create_helper(ENGINE *e, void *data, const EVP_MD *md,
    unsigned char* pswd, int pswdSz)
{
    int ret;

    unsigned char exp[128];
    int expLen;

    unsigned char mac[128];
    int macLen;

    unsigned char msg[] = "Test message";
    int len;

    (void)data;
    len    = sizeof(msg);
    macLen = sizeof(mac);
    expLen = sizeof(exp);

    /* generate mac using OpenSSL */
    ret = test_mac_generation(NULL, md, EVP_PKEY_HMAC, pswd, pswdSz, msg,
            len, exp, &expLen);
    if (ret != 0) {
        PRINT_MSG("Generate MAC using OpenSSL failed");
    }

    if (ret == 0) {
        memset(mac, 0, sizeof(mac));
        ret = test_mac_generation(e, md, EVP_PKEY_HMAC, pswd, pswdSz, msg,
            len, mac, &macLen);
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

int test_hmac_create(ENGINE *e, void *data)
{
    int ret = 0;
    unsigned char pswd[] = "My empire of dirt";
    unsigned char bigPswd[100];

    XMEMSET(bigPswd, 0, sizeof(bigPswd));

    PRINT_MSG("Testing with SHA1");
    ret = test_hmac_create_helper(e, data, EVP_sha1(), pswd, sizeof(pswd));
    if (ret == 0) {
        PRINT_MSG("Testing with SHA1, 0 length key");
        ret = test_hmac_create_helper(e, data, EVP_sha1(), pswd, 0);
    }
    if (ret == 0) {
        PRINT_MSG("Testing with SHA1, key length larger than block size");
        RAND_bytes(bigPswd, sizeof(bigPswd));
        ret = test_hmac_create_helper(e, data, EVP_sha1(), bigPswd,
                  sizeof(bigPswd));
    }

    if (ret == 0) {
        PRINT_MSG("Testing with SHA224");
        ret = test_hmac_create_helper(e, data, EVP_sha224(), pswd, sizeof(pswd));
        if (ret == 0) {
            /* EVP_PKEY_new_mac_key() can be called with -1, OpenSSL expects
             * engine implementations to use strlen() to find string length */
            ret = test_hmac_create_helper(e, data, EVP_sha224(), pswd, -1);
        }
    }

    if (ret == 0) {
        PRINT_MSG("Testing with SHA256");
        ret = test_hmac_create_helper(e, data, EVP_sha256(), pswd, sizeof(pswd));
        if (ret == 0) {
            ret = test_hmac_create_helper(e, data, EVP_sha256(), pswd, -1);
        }
    }

    if (ret == 0) {
        PRINT_MSG("Testing with SHA384");
        ret = test_hmac_create_helper(e, data, EVP_sha384(), pswd, sizeof(pswd));
        if (ret == 0) {
            ret = test_hmac_create_helper(e, data, EVP_sha384(), pswd, -1);
        }
    }

    if (ret == 0) {
        PRINT_MSG("Testing with SHA512");
        ret = test_hmac_create_helper(e, data, EVP_sha512(), pswd, sizeof(pswd));
        if (ret == 0) {
            ret = test_hmac_create_helper(e, data, EVP_sha512(), pswd, -1);
        }
    }

#ifdef WE_HAVE_SHA3_224
    if (ret == 0) {
        PRINT_MSG("Testing with SHA3-224");
        ret = test_hmac_create_helper(e, data, EVP_sha3_224(), pswd, sizeof(pswd));
        if (ret == 0) {
            ret = test_hmac_create_helper(e, data, EVP_sha3_224(), pswd, -1);
        }
    }
#endif
#ifdef WE_HAVE_SHA3_256
    if (ret == 0) {
        PRINT_MSG("Testing with SHA3-256");
        ret = test_hmac_create_helper(e, data, EVP_sha3_256(), pswd, sizeof(pswd));
        if (ret == 0) {
            ret = test_hmac_create_helper(e, data, EVP_sha3_256(), pswd, -1);
        }
    }
#endif
#ifdef WE_HAVE_SHA3_384
    if (ret == 0) {
        PRINT_MSG("Testing with SHA3-384");
        ret = test_hmac_create_helper(e, data, EVP_sha3_384(), pswd, sizeof(pswd));
        if (ret == 0) {
            ret = test_hmac_create_helper(e, data, EVP_sha3_384(), pswd, -1);
        }
    }
#endif
#ifdef WE_HAVE_SHA3_512
    if (ret == 0) {
        PRINT_MSG("Testing with SHA3-512");
        ret = test_hmac_create_helper(e, data, EVP_sha3_512(), pswd, sizeof(pswd));
        if (ret == 0) {
            ret = test_hmac_create_helper(e, data, EVP_sha3_512(), pswd, -1);
        }
    }
#endif
    return ret;
}

#endif /* WE_HAVE_HMAC */


