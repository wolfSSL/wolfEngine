/* internal.h
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

#ifndef INTERNAL_H
#define INTERNAL_H

/* OpenSSL 3.0.0 has deprecated the ENGINE API. */
#define OPENSSL_API_COMPAT      10101

#include <openssl/engine.h>
#include <openssl/evp.h>
#include <openssl/ec.h>

#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/hash.h>
#include <wolfssl/wolfcrypt/sha256.h>
#include <wolfssl/wolfcrypt/aes.h>
#include <wolfssl/wolfcrypt/rsa.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/signature.h>
#include <wolfssl/wolfcrypt/asn_public.h>
#include <wolfssl/wolfcrypt/ecc.h>

#include "openssl_bc.h"
#include "we_logging.h"

/*
 * Global random
 */

extern WC_RNG* we_rng;

/* For digest method in OpenSSL 1.0.2 */
int we_pkey_get_nids(const int** nids);

/*
 * Digest methods.
 */

extern EVP_MD *we_sha256_md;
int we_init_sha256_meth(void);

extern EVP_MD *we_sha384_md;
int we_init_sha384_meth(void);

extern EVP_MD *we_sha512_md;
int we_init_sha512_meth(void);

extern EVP_MD *we_sha3_224_md;
int we_init_sha3_224_meth(void);

extern EVP_MD *we_sha3_256_md;
int we_init_sha3_256_meth(void);

extern EVP_MD *we_sha3_384_md;
int we_init_sha3_384_meth(void);

extern EVP_MD *we_sha3_512_md;
int we_init_sha3_512_meth(void);

int we_nid_to_wc_hash_oid(int nid);

/*
 * Cipher methods.
 */

extern EVP_CIPHER* we_aes128_cbc_ciph;
extern EVP_CIPHER* we_aes192_cbc_ciph;
extern EVP_CIPHER* we_aes256_cbc_ciph;
int we_init_aescbc_meths(void);

extern EVP_CIPHER* we_aes128_gcm_ciph;
extern EVP_CIPHER* we_aes192_gcm_ciph;
extern EVP_CIPHER* we_aes256_gcm_ciph;
int we_init_aesgcm_meths(void);

/*
 * RSA methods.
 */

#ifdef WE_HAVE_RSA

extern EVP_PKEY_METHOD *we_rsa_pkey_method;

int we_init_rsa_pkey_meth(void);

#endif /* WE_HAVE_RSA */

/*
 * ECC methods.
 */

#ifdef WE_HAVE_EC_KEY
extern EC_KEY_METHOD *we_ec_key_method;
#endif
extern EVP_PKEY_METHOD *we_ec_method;
extern EVP_PKEY_METHOD *we_ec_p256_method;
extern EVP_PKEY_METHOD *we_ec_p384_method;
int we_init_ecc_meths(void);
int we_init_ec_key_meths(void);

int wolfengine_bind(ENGINE *e, const char *id);

#endif /* INTERNAL_H */
