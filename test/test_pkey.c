/* test_pkey.c
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

#ifdef WE_HAVE_EVP_PKEY

int test_digest_sign(EVP_PKEY *pkey, ENGINE *e, unsigned char *data,
                     size_t len, const EVP_MD *md,
                     unsigned char *sig, size_t *sigLen)
{
    int err;
    EVP_MD_CTX *mdCtx = NULL;
    EVP_PKEY_CTX *pkeyCtx = NULL;

    err = (mdCtx = EVP_MD_CTX_new()) == NULL;
    if (err == 0) {
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
        err = EVP_PKEY_set1_engine(pkey, e) != 1;
    }
    if (err == 0) {
        err = EVP_DigestSignInit(mdCtx, &pkeyCtx, md, NULL, pkey) != 1;
#else
        err = EVP_DigestSignInit(mdCtx, &pkeyCtx, md, e, pkey) != 1;
#endif
    }
#if OPENSSL_VERSION_NUMBER >= 0x1010100fL
    if (err == 0) {
        err = EVP_DigestSign(mdCtx, sig, sigLen, data, len) != 1;
    }
#else
    if (err == 0) {
        err = EVP_DigestSignUpdate(mdCtx, data, len) != 1;
    }
    if (err == 0) {
        err = EVP_DigestSignFinal(mdCtx, sig, sigLen) != 1;
    }
#endif
    if (err == 0) {
        PRINT_BUFFER("Signture", sig, *sigLen);
    }

    EVP_MD_CTX_free(mdCtx);

    return err;
}

int test_digest_verify(EVP_PKEY *pkey, ENGINE *e, unsigned char *data,
                       size_t len, const EVP_MD *md,
                       unsigned char *sig, size_t sigLen)
{
    int err;
    EVP_MD_CTX *mdCtx = NULL;
    EVP_PKEY_CTX *pkeyCtx = NULL;

    err = (mdCtx = EVP_MD_CTX_new()) == NULL;
    if (err == 0) {
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
        err = EVP_PKEY_set1_engine(pkey, e) != 1;
    }
    if (err == 0) {
        err = EVP_DigestVerifyInit(mdCtx, &pkeyCtx, md, NULL, pkey) != 1;
#else
        err = EVP_DigestVerifyInit(mdCtx, &pkeyCtx, md, e, pkey) != 1;
#endif
    }
#if OPENSSL_VERSION_NUMBER >= 0x1010100fL
    if (err == 0) {
        err = EVP_DigestVerify(mdCtx, sig, sigLen, data, len) != 1;
    }
#else
    if (err == 0) {
        err = EVP_DigestVerifyUpdate(mdCtx, data, len) != 1;
    }
    if (err == 0) {
        err = EVP_DigestVerifyFinal(mdCtx, sig, sigLen) != 1;
    }
#endif
    if (err == 0) {
        PRINT_MSG("Signature verified");
    }
    else {
        PRINT_MSG("Signature not verified");
    }

    EVP_MD_CTX_free(mdCtx);

    return err;
}

int test_pkey_sign(EVP_PKEY *pkey, ENGINE *e, unsigned char *hash,
                   size_t hashLen, unsigned char *sig,
                   size_t *sigLen)
{
    int err;
    EVP_PKEY_CTX *ctx = NULL;
    size_t sigBufLen = *sigLen;

#if OPENSSL_VERSION_NUMBER >= 0x30000000L
    err = EVP_PKEY_set1_engine(pkey, e) != 1;
    if (err == 0) {
        err = (ctx = EVP_PKEY_CTX_new(pkey, NULL)) == NULL;
    }
#else
    err = (ctx = EVP_PKEY_CTX_new(pkey, e)) == NULL;
#endif
    if (err == 0) {
        err = EVP_PKEY_sign_init(ctx) != 1;
    }
    if (err == 0) {
        err = EVP_PKEY_sign(ctx, sig, sigLen, hash, hashLen) != 1;
    }
    if (err == 0) {
        PRINT_BUFFER("Signture", sig, *sigLen);
    }
    if (err == 0) {
        err = EVP_PKEY_sign_init(ctx) != 1;
    }
    if (err == 0) {
        *sigLen = sigBufLen;
        err = EVP_PKEY_sign(ctx, sig, sigLen, hash, hashLen) != 1;
    }
    if (err == 0) {
        PRINT_BUFFER("Signture", sig, *sigLen);
    }

    EVP_PKEY_CTX_free(ctx);

    return err;
}

int test_pkey_verify(EVP_PKEY *pkey, ENGINE *e,
                     unsigned char *hash, size_t hashLen,
                     unsigned char *sig, size_t sigLen)
{
    int err;
    EVP_PKEY_CTX *ctx = NULL;

#if OPENSSL_VERSION_NUMBER >= 0x30000000L
    err = EVP_PKEY_set1_engine(pkey, e) != 1;
    if (err == 0) {
        err = (ctx = EVP_PKEY_CTX_new(pkey, NULL)) == NULL;
    }
#else
    err = (ctx = EVP_PKEY_CTX_new(pkey, e)) == NULL;
#endif
    if (err == 0) {
        err = EVP_PKEY_verify_init(ctx) != 1;
    }
    if (err == 0) {
        err = EVP_PKEY_verify(ctx, sig, sigLen, hash, hashLen) != 1;
    }
    if (err == 0) {
        PRINT_MSG("Signature verified");
    }
    else {
        PRINT_MSG("Signature not verified");
    }
    if (err == 0) {
        err = EVP_PKEY_verify_init(ctx) != 1;
    }
    if (err == 0) {
        err = EVP_PKEY_verify(ctx, sig, sigLen, hash, hashLen) != 1;
    }
    if (err == 0) {
        PRINT_MSG("Signature verified");
    }
    else {
        PRINT_MSG("Signature not verified");
    }

    EVP_PKEY_CTX_free(ctx);

    return err;
}

#endif /* WE_HAVE_EVP_PKEY */
