/* unit.h
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

#ifndef UNIT_H
#define UNIT_H

/* OpenSSL 3.0.0 has deprecated the ENGINE API. */
#define OPENSSL_API_COMPAT      10101

#include <string.h>

#include <openssl/engine.h>
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/ssl.h>
#include <openssl/aes.h>

#include "openssl_bc.h"

#define PRINT_MSG(str)         printf("MSG: %s\n", str)
#define PRINT_ERR_MSG(str)     printf("ERR: %s\n", str)
#ifdef WOLFENGINE_DEBUG
void print_buffer(const char *desc, const unsigned char *buffer, size_t len);
#define PRINT_BUFFER(d, b, l)  print_buffer(d, b, l)
#else
#define PRINT_BUFFER(d, b, l)
#endif
#define TEST_DECL(func, data)        { #func, func, data, 0, 0, 0 }

typedef int (*TEST_FUNC)(ENGINE *e, void *data);
typedef struct TEST_CASE {
    const char *name;
    TEST_FUNC   func;
    void       *data;
    int         err;
    int         run:1;
    int         done:1;
} TEST_CASE;

int test_logging(ENGINE *e, void *data);

#ifdef WE_HAVE_DIGEST

int test_digest_op(const EVP_MD *md, ENGINE *e, unsigned char *msg,
                   size_t len, unsigned char *prev,
                   unsigned int *prevLen);
int test_sha(ENGINE *e, void *data);
int test_sha224(ENGINE *e, void *data);
int test_sha256(ENGINE *e, void *data);
int test_sha384(ENGINE *e, void *data);
int test_sha512(ENGINE *e, void *data);
int test_sha3_224(ENGINE *e, void *data);
int test_sha3_256(ENGINE *e, void *data);
int test_sha3_384(ENGINE *e, void *data);
int test_sha3_512(ENGINE *e, void *data);

#endif /* WE_HAVE_DIGEST */

#ifdef WE_HAVE_DES3CBC
int test_des3_cbc(ENGINE *e, void *data);
int test_des3_cbc_stream(ENGINE *e, void *data);
#endif

#ifdef WE_HAVE_AESECB

int test_aes128_ecb(ENGINE *e, void *data);
int test_aes192_ecb(ENGINE *e, void *data);
int test_aes256_ecb(ENGINE *e, void *data);
int test_aes128_ecb_stream(ENGINE *e, void *data);
int test_aes192_ecb_stream(ENGINE *e, void *data);
int test_aes256_ecb_stream(ENGINE *e, void *data);

#endif

#ifdef WE_HAVE_AESCBC

int test_aes128_cbc(ENGINE *e, void *data);
int test_aes192_cbc(ENGINE *e, void *data);
int test_aes256_cbc(ENGINE *e, void *data);
int test_aes128_cbc_stream(ENGINE *e, void *data);
int test_aes192_cbc_stream(ENGINE *e, void *data);
int test_aes256_cbc_stream(ENGINE *e, void *data);

#endif

#ifdef WE_HAVE_AESCTR

int test_aes128_ctr_stream(ENGINE *e, void *data);
int test_aes192_ctr_stream(ENGINE *e, void *data);
int test_aes256_ctr_stream(ENGINE *e, void *data);

#endif

#ifdef WE_HAVE_AESGCM

int test_aes128_gcm(ENGINE *e, void *data);
int test_aes192_gcm(ENGINE *e, void *data);
int test_aes256_gcm(ENGINE *e, void *data);
int test_aes128_gcm_fixed(ENGINE *e, void *data);
int test_aes128_gcm_tls(ENGINE *e, void *data);

#endif /* WE_HAVE_AESGCM */

#ifdef WE_HAVE_AESCCM

int test_aes128_ccm(ENGINE *e, void *data);
int test_aes192_ccm(ENGINE *e, void *data);
int test_aes256_ccm(ENGINE *e, void *data);
int test_aes128_ccm_tls(ENGINE *e, void *data);

#endif /* WE_HAVE_AESCCM */

#ifdef WE_HAVE_RANDOM

int test_random(ENGINE *e, void *data);

#endif

#ifdef WE_HAVE_EVP_PKEY

int test_digest_sign(EVP_PKEY *pkey, ENGINE *e, unsigned char *data,
                     size_t len, const EVP_MD *md,
                     unsigned char *sig, size_t *sigLen);

int test_digest_verify(EVP_PKEY *pkey, ENGINE *e, unsigned char *data,
                       size_t len, const EVP_MD *md,
                       unsigned char *sig, size_t sigLen);

int test_pkey_sign(EVP_PKEY *pkey, ENGINE *e, unsigned char *hash,
                   size_t hashLen, unsigned char *sig,
                   size_t *sigLen);
int test_pkey_verify(EVP_PKEY *pkey, ENGINE *e,
                     unsigned char *hash, size_t hashLen,
                     unsigned char *sig, size_t sigLen);

#endif /* WE_HAVE_EVP_PKEY */

#ifdef WE_HAVE_RSA
int test_rsa_direct(ENGINE *e, void *data);
#ifdef WE_HAVE_EVP_PKEY
int test_rsa_sign_verify(ENGINE *e, void *data);
int test_rsa_keygen(ENGINE *e, void *data);
#endif /* WE_HAVE_EVP_PKEY */

#endif /* WE_HAVE_RSA */

#ifdef WE_HAVE_DH
int test_dh(ENGINE *e, void *data);
#endif /* WE_HAVE_DH */

#ifdef WE_HAVE_ECC

#ifdef WE_HAVE_EVP_PKEY

#ifdef WE_HAVE_ECKEYGEN

#ifdef WE_HAVE_EC_P256
int test_eckeygen_p256_by_nid(ENGINE *e, void *data);
int test_eckeygen_p256(ENGINE *e, void *data);
#endif /* WE_HAVE_EC_P256 */

#ifdef WE_HAVE_EC_P384
int test_eckeygen_p384_by_nid(ENGINE *e, void *data);
int test_eckeygen_p384(ENGINE *e, void *data);
#endif /* WE_HAVE_EC_P384 */

#endif /* WE_HAVE_ECKEYGEN */

#ifdef WE_HAVE_ECDH

int test_ecdh_derive(ENGINE *e, EVP_PKEY *key, EVP_PKEY *peerKey,
                     unsigned char **pSecret, size_t expLen);

#ifdef WE_HAVE_ECKEYGEN

int test_ecdh_keygen(ENGINE *e, int nid, int len);
#ifdef WE_HAVE_EC_P256
int test_ecdh_p256_keygen(ENGINE *e, void *data);
#endif /* WE_HAVE_EC_P256 */
#ifdef WE_HAVE_EC_P384
int test_ecdh_p384_keygen(ENGINE *e, void *data);
#endif /* WE_HAVE_EC_P384 */

#endif /* WE_HAVE_ECKEYGEN */

int test_ecdh(ENGINE *e, const unsigned char *privKey, size_t len,
              const unsigned char *peerPrivKey, size_t peerLen,
              const unsigned char *derived, size_t dLen);
#ifdef WE_HAVE_EC_P256
int test_ecdh_p256(ENGINE *e, void *data);
#endif /* WE_HAVE_EC_P256 */
#ifdef WE_HAVE_EC_P384
int test_ecdh_p384(ENGINE *e, void *data);
#endif /* WE_HAVE_EC_P384 */

#endif /* WE_HAVE_ECDH */

#ifdef WE_HAVE_ECDSA

#ifdef WE_HAVE_EC_P256
int test_ecdsa_p256_pkey(ENGINE *e, void *data);
#endif /* WE_HAVE_EC_P256 */

#ifdef WE_HAVE_EC_P384
int test_ecdsa_p384_pkey(ENGINE *e, void *data);
#endif /* WE_HAVE_EC_P384 */

#ifdef WE_HAVE_EC_P256
int test_ecdsa_p256(ENGINE *e, void *data);
#endif /* WE_HAVE_EC_P256 */

#ifdef WE_HAVE_EC_P384
int test_ecdsa_p384(ENGINE *e, void *data);
#endif /* WE_HAVE_EC_P384 */

#endif /* WE_HAVE_ECDSA */

#endif /* WE_HAVE_EVP_PKEY */

#ifdef WE_HAVE_EC_KEY

#ifdef WE_HAVE_ECKEYGEN

int test_ec_key_keygen_by_nid(ENGINE *e, int nid);

#ifdef WE_HAVE_EC_P256
int test_ec_key_keygen_p256_by_nid(ENGINE *e, void *data);
#endif /* WE_HAVE_EC_P256 */

#ifdef WE_HAVE_EC_P384
int test_ec_key_keygen_p384_by_nid(ENGINE *e, void *data);
#endif /* WE_HAVE_EC_P384 */

#endif /* WE_HAVE_ECKEYGEN */

#ifdef WE_HAVE_ECDH

#ifdef WE_HAVE_ECKEYGEN

int test_ec_key_ecdh_keygen(ENGINE *e, int nid, int len);
#ifdef WE_HAVE_EC_P256
int test_ec_key_ecdh_p256_keygen(ENGINE *e, void *data);
#endif /* WE_HAVE_EC_P256 */
#ifdef WE_HAVE_EC_P384
int test_ec_key_ecdh_p384_keygen(ENGINE *e, void *data);
#endif /* WE_HAVE_EC_P384 */

#endif /* WE_HAVE_ECKEYGEN */

int test_ec_key_ecdh(ENGINE *e, const unsigned char *privKey, size_t len,
                     const unsigned char *peerPrivKey, size_t peerLen,
                     const unsigned char *derived, size_t dLen);
#ifdef WE_HAVE_EC_P256
int test_ec_key_ecdh_p256(ENGINE *e, void *data);
#endif /* WE_HAVE_EC_P256 */
#ifdef WE_HAVE_EC_P384
int test_ec_key_ecdh_p384(ENGINE *e, void *data);
#endif /* WE_HAVE_EC_P384 */

#endif /* WE_HAVE_ECDH */

#ifdef WE_HAVE_ECDSA

int test_ec_key_ecdsa_sign(EC_KEY *key, unsigned char *hash,
                           size_t hashLen, unsigned char *ecdsaSig,
                           size_t *ecdsaSigLen);
int test_ec_key_ecdsa_verify(EC_KEY *key, unsigned char *hash,
                             size_t hashLen, unsigned char *ecdsaSig,
                             size_t ecdsaSigLen);
int test_ec_key_ecdsa(ENGINE *e, const unsigned char *privKey,
                      size_t privKeyLen);
#ifdef WE_HAVE_EC_P256
int test_ec_key_ecdsa_p256(ENGINE *e, void *data);
#endif /* WE_HAVE_EC_P256 */
#ifdef WE_HAVE_EC_P384
int test_ec_key_ecdsa_p384(ENGINE *e, void *data);
#endif /* WE_HAVE_EC_P384 */

#endif /* WE_HAVE_ECDSA */

#endif /* WE_HAVE_EC_KEY */

#endif /* WE_HAVE_ECC */

#endif /* UNIT_H */
