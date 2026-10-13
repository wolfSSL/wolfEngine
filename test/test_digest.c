/* test_digest.c
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

#include <openssl/hmac.h>

#ifdef WE_HAVE_DIGEST

#ifdef WE_USE_HASH
static int test_digest_copy(const EVP_MD *md, ENGINE *e)
{
    int err = 0;
    EVP_MD_CTX *src = NULL;
    EVP_MD_CTX *dst = NULL;
    const EVP_MD *engineMd;
    const unsigned char prefix[] = "shared prefix";
    const unsigned char srcSuffix[] = " source";
    const unsigned char dstSuffix[] = " destination";
    const unsigned char srcMsg[] = "shared prefix source";
    const unsigned char dstMsg[] = "shared prefix destination";
    unsigned char srcDigest[EVP_MAX_MD_SIZE];
    unsigned char dstDigest[EVP_MAX_MD_SIZE];
    unsigned char expected[EVP_MAX_MD_SIZE];
    unsigned int srcLen = 0;
    unsigned int dstLen = 0;
    unsigned int expectedLen = 0;

    engineMd = ENGINE_get_digest(e, EVP_MD_type(md));
    err = (engineMd == NULL) || (EVP_MD_meth_get_copy(engineMd) == NULL);
    if (err == 0) {
        err = ((src = EVP_MD_CTX_new()) == NULL) ||
              ((dst = EVP_MD_CTX_new()) == NULL);
    }
    if (err == 0) {
        err = EVP_DigestInit_ex(src, md, e) != 1;
    }
    if (err == 0) {
        err = EVP_DigestUpdate(src, prefix, sizeof(prefix) - 1) != 1;
    }
    if (err == 0) {
        err = EVP_MD_meth_get_copy(engineMd)(src, src) != 1;
    }
    if (err == 0) {
        err = EVP_MD_CTX_copy_ex(dst, src) != 1;
    }
    if (err == 0) {
        err = EVP_DigestUpdate(src, srcSuffix, sizeof(srcSuffix) - 1) != 1;
    }
    if (err == 0) {
        err = EVP_DigestUpdate(dst, dstSuffix, sizeof(dstSuffix) - 1) != 1;
    }
    if (err == 0) {
        err = EVP_DigestFinal_ex(src, srcDigest, &srcLen) != 1;
    }
    if (err == 0) {
        err = EVP_DigestFinal_ex(dst, dstDigest, &dstLen) != 1;
    }
    if (err == 0) {
        err = EVP_Digest(srcMsg, sizeof(srcMsg) - 1, expected, &expectedLen,
            md, NULL) != 1;
    }
    if (err == 0) {
        err = (srcLen != expectedLen) ||
              (XMEMCMP(srcDigest, expected, srcLen) != 0);
    }
    if (err == 0) {
        err = EVP_Digest(dstMsg, sizeof(dstMsg) - 1, expected, &expectedLen,
            md, NULL) != 1;
    }
    if (err == 0) {
        err = (dstLen != expectedLen) ||
              (XMEMCMP(dstDigest, expected, dstLen) != 0);
    }

    EVP_MD_CTX_free(dst);
    EVP_MD_CTX_free(src);

    return err;
}

#if defined(WE_HAVE_HMAC) && defined(WE_HAVE_EVP_PKEY) && \
    defined(WE_HAVE_SHA384)
static int test_digest_hmac_reuse(ENGINE *e)
{
    int err;
    EVP_MD_CTX *ctx = NULL;
    EVP_PKEY *key = NULL;
    const EVP_MD *md = EVP_sha384();
    const unsigned char secret[] = "context reuse key";
    const unsigned char message[] = "context reuse message";
    unsigned char mac[EVP_MAX_MD_SIZE];
    unsigned char expected[EVP_MAX_MD_SIZE];
    unsigned int expectedLen = 0;
    size_t macLen = sizeof(mac);

    PRINT_MSG("Reuse a finalized digest context for HMAC");
    err = HMAC(md, secret, sizeof(secret) - 1, message, sizeof(message) - 1,
        expected, &expectedLen) == NULL;
    if (err == 0) {
        ctx = EVP_MD_CTX_new();
        key = EVP_PKEY_new_mac_key(EVP_PKEY_HMAC, e, secret,
            sizeof(secret) - 1);
        err = (ctx == NULL) || (key == NULL);
    }
    if (err == 0) {
        err = EVP_DigestInit_ex(ctx, md, e) != 1;
    }
    if (err == 0) {
        err = EVP_DigestUpdate(ctx, message, sizeof(message) - 1) != 1;
    }
    if (err == 0) {
        err = EVP_DigestFinal_ex(ctx, mac, NULL) != 1;
    }
    if (err == 0) {
        err = EVP_DigestSignInit(ctx, NULL, md, e, key) != 1;
    }
    if (err == 0) {
        err = EVP_DigestSignUpdate(ctx, message, sizeof(message) - 1) != 1;
    }
    if (err == 0) {
        err = EVP_DigestSignFinal(ctx, mac, &macLen) != 1;
    }
    if (err == 0) {
        err = (macLen != expectedLen) ||
              (XMEMCMP(mac, expected, expectedLen) != 0);
    }

    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(key);

    return err;
}
#endif
#endif

int test_digest_op(const EVP_MD *md, ENGINE *e, unsigned char *msg,
                          size_t len, unsigned char *prev,
                          unsigned int *prevLen)
{
    int err;
    EVP_MD_CTX *ctx;
    unsigned char digest[64] = {0,};
    unsigned int dLen = sizeof(digest);

    err = (ctx = EVP_MD_CTX_new()) == NULL;
    if (err == 0) {
        err = EVP_DigestInit_ex(ctx, md, e) != 1;
    }
    if (err == 0) {
        err = EVP_MD_CTX_type(ctx) != EVP_MD_type(md);
    }
    if (err == 0) {
        err = EVP_DigestUpdate(ctx, msg, len/2) != 1;
    }
    if (err == 0) {
        err = EVP_DigestUpdate(ctx, msg + len/2, len - len/2) != 1;
    }
    if (err == 0) {
        err = EVP_DigestFinal_ex(ctx, digest, &dLen) != 1;
    }
    if (err == 0) {
        PRINT_BUFFER("Digest", digest, dLen);

        if (*prevLen == 0) {
            memcpy(prev, digest, dLen);
            *prevLen = dLen;
        }
        else {
            if (memcmp(digest, prev, *prevLen) != 0) {
                PRINT_ERR_MSG("Digests don't match");
                err = 1;
            }
            else {
                PRINT_MSG("Digests match");
            }
        }
    }

    EVP_MD_CTX_free(ctx);

    return err;
}

/******************************************************************************/
static int test_create_digest(const EVP_MD *md, ENGINE *e, void *data)
{
    int err = 0;
    unsigned char *msg = (unsigned char *)"Test pattern";
    const size_t longMsgLen = (2U * 1024U * 1024U) + 2U;
    unsigned char *longMsg = NULL;
    unsigned char digest[64];
    unsigned int dLen;

    (void)data;

    XMEMSET(digest, 0, sizeof(digest));
    err = (longMsg = OPENSSL_malloc(longMsgLen)) == NULL;
    if (err == 0) {
        err = RAND_bytes(longMsg, (int)longMsgLen) != 1;
    }

    dLen = 0;
    if (err == 0) {
        PRINT_MSG("Digest with OpenSSL");
        err = test_digest_op(md, NULL, msg, strlen((char*)msg), digest,
            &dLen);
    }
    if (err == 0) {
        PRINT_MSG("Digest With wolfengine");
        err = test_digest_op(md, e, msg, strlen((char*)msg), digest, &dLen);
    }
    if (err == 0) {
        dLen = 0;
        PRINT_MSG("Digest with OpenSSL");
        err = test_digest_op(md, NULL, longMsg, longMsgLen, digest, &dLen);
    }
    if (err == 0) {
        PRINT_MSG("Digest With wolfengine");
        err = test_digest_op(md, e, longMsg, longMsgLen, digest, &dLen);
    }
#ifdef WE_USE_HASH
    if (err == 0) {
        err = test_digest_copy(md, e);
    }
#endif

    OPENSSL_free(longMsg);

    return err;
}

#ifdef WE_HAVE_SHA1

int test_sha(ENGINE *e, void *data)
{
    int err = 0;

#ifdef WE_HAVE_ECDSA
    const EVP_MD *md = ENGINE_get_digest(e, NID_ecdsa_with_SHA1);

    err = md == NULL;
    if (err == 0) {
        err = EVP_MD_block_size(md) != WC_SHA_BLOCK_SIZE;
    }
#endif
    if (err == 0) {
        err = test_create_digest(EVP_sha1(), e, data);
    }

    return err;
}
#endif /* WE_HAVE_SHA1 */

#ifdef WE_HAVE_SHA224
int test_sha224(ENGINE *e, void *data)
{
    return test_create_digest(EVP_sha224(), e, data);
}
#endif

#ifdef WE_HAVE_SHA256
int test_sha256(ENGINE *e, void *data)
{
    return test_create_digest(EVP_sha256(), e, data);
}
#endif

/******************************************************************************/

#ifdef WE_HAVE_SHA384
int test_sha384(ENGINE *e, void *data)
{
    int err = test_create_digest(EVP_sha384(), e, data);

#if defined(WE_USE_HASH) && defined(WE_HAVE_HMAC) && defined(WE_HAVE_EVP_PKEY)
    if (err == 0) {
        err = test_digest_hmac_reuse(e);
    }
#endif

    return err;
}
#endif

/******************************************************************************/

#ifdef WE_HAVE_SHA512
int test_sha512(ENGINE *e, void *data)
{
    return test_create_digest(EVP_sha512(), e, data);
}
#endif

/******************************************************************************/

#ifdef WE_HAVE_SHA3_224
int test_sha3_224(ENGINE *e, void *data)
{
    return test_create_digest(EVP_sha3_224(), e, data);
}
#endif

/******************************************************************************/

#ifdef WE_HAVE_SHA3_256
int test_sha3_256(ENGINE *e, void *data)
{
    return test_create_digest(EVP_sha3_256(), e, data);
}
#endif

/******************************************************************************/

#ifdef WE_HAVE_SHA3_384
int test_sha3_384(ENGINE *e, void *data)
{
    return test_create_digest(EVP_sha3_384(), e, data);
}
#endif

/******************************************************************************/

#ifdef WE_HAVE_SHA3_512
int test_sha3_512(ENGINE *e, void *data)
{
    return test_create_digest(EVP_sha3_512(), e, data);
}
#endif

/******************************************************************************/

#endif /* WE_HAVE_DIGEST */
