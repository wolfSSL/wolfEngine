/* we_internal.h
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

#ifdef WOLFENGINE_USER_SETTINGS
    #include "user_settings.h"
#endif

/* This define controls the index used for the wolfEngine RSA external data
 * in wolfEngine's RSA_METHOD implementation. This allows the user to put the
 * wolfEngine external data at a specific index at compile time to avoid
 * collisions with other, non-wolfEngine external data. For instance, you may
 * have an application that is already using indexes 0 and 1, so you would
 * define WE_RSA_EX_DATA_IDX to 2 to avoid colliding with the data at index 0
 * (the default index). */
#ifndef WE_RSA_EX_DATA_IDX
#define WE_RSA_EX_DATA_IDX 0
#endif

#include <openssl/engine.h>
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/tls1.h>

#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/hash.h>
#include <wolfssl/wolfcrypt/hmac.h>
#include <wolfssl/wolfcrypt/cmac.h>
#include <wolfssl/wolfcrypt/sha.h>
#include <wolfssl/wolfcrypt/sha256.h>
#include <wolfssl/wolfcrypt/aes.h>
#include <wolfssl/wolfcrypt/des3.h>
#include <wolfssl/wolfcrypt/rsa.h>
#include <wolfssl/wolfcrypt/dh.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/signature.h>
#include <wolfssl/wolfcrypt/asn_public.h>
#include <wolfssl/wolfcrypt/ecc.h>
#include <wolfssl/wolfcrypt/random.h>

#include <wolfengine/we_openssl_bc.h>

#include <wolfengine/we_logging.h>

/*
 * Global random
 */

extern WC_RNG* we_rng;
#ifndef WE_SINGLE_THREADED
extern wolfSSL_Mutex* we_rng_mutex;
#endif

/* For digest method in OpenSSL 1.0.2 */
int we_pkey_get_nids(const int** nids);

/*
 * Digest methods.
 */

extern EVP_MD *we_sha1_md;
int we_init_sha_meth(void);

extern EVP_MD *we_sha224_md;
int we_init_sha224_meth(void);

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

int we_nid_to_wc_hash_type(int nid);
int we_nid_to_wc_hash_oid(int nid);

/*
 * Cipher methods.
 */

extern EVP_CIPHER* we_des3_cbc_ciph;
int we_init_des3cbc_meths(void);

extern EVP_CIPHER* we_aes128_ecb_ciph;
extern EVP_CIPHER* we_aes192_ecb_ciph;
extern EVP_CIPHER* we_aes256_ecb_ciph;
int we_init_aesecb_meths(void);

extern EVP_CIPHER* we_aes128_cbc_ciph;
extern EVP_CIPHER* we_aes192_cbc_ciph;
extern EVP_CIPHER* we_aes256_cbc_ciph;
int we_init_aescbc_meths(void);

extern EVP_CIPHER* we_aes128_cbc_hmac_ciph;
extern EVP_CIPHER* we_aes256_cbc_hmac_ciph;
int we_init_aescbc_hmac_meths(void);

extern EVP_CIPHER* we_aes128_ctr_ciph;
extern EVP_CIPHER* we_aes192_ctr_ciph;
extern EVP_CIPHER* we_aes256_ctr_ciph;
int we_init_aesctr_meths(void);

extern EVP_CIPHER* we_aes128_gcm_ciph;
extern EVP_CIPHER* we_aes192_gcm_ciph;
extern EVP_CIPHER* we_aes256_gcm_ciph;
int we_init_aesgcm_meths(void);

extern EVP_CIPHER* we_aes128_ccm_ciph;
extern EVP_CIPHER* we_aes192_ccm_ciph;
extern EVP_CIPHER* we_aes256_ccm_ciph;
int we_init_aesccm_meths(void);


/*
 * Random method.
 */

extern RAND_METHOD* we_random_method;

/*
 * HMAC methods.
 */

#ifdef WE_HAVE_HMAC

extern EVP_PKEY_METHOD *we_hmac_pkey_method;

int we_init_hmac_pkey_meth(void);

#endif /* WE_HAVE_HMAC */

/*
 * CMAC methods.
 */

#ifdef WE_HAVE_HMAC

extern EVP_PKEY_METHOD *we_cmac_pkey_method;
extern EVP_PKEY_ASN1_METHOD *we_cmac_pkey_asn1_method;

int we_init_cmac_pkey_meth(void);
int we_init_cmac_pkey_asn1_meth(void);

#endif /* WE_HAVE_CMAC */

/*
 * DH method.
 */

#ifdef WE_HAVE_DH

extern DH_METHOD *we_dh_method;
int we_init_dh_meth(void);

extern EVP_PKEY_METHOD *we_dh_pkey_method;
int we_init_dh_pkey_meth(void);

#endif /* WE_HAVE_DH */

/*
 * RSA methods.
 */

#ifdef WE_HAVE_RSA

extern EVP_PKEY_METHOD *we_rsa_pkey_method;
int we_init_rsa_pkey_meth(void);
extern RSA_METHOD *we_rsa_method;
int we_init_rsa_meth(void);

#endif /* WE_HAVE_RSA */

/*
 * ECDH methods.
 */
#if OPENSSL_VERSION_NUMBER < 0x10100000L
#ifdef WE_HAVE_ECDH

extern ECDH_METHOD *we_ecdh_method;
int we_init_ecdh_meth(void);

#endif /* WE_HAVE_ECDH */
#endif /* OPENSSL_VERSION_NUMBER < 0x10100000L */

/*
 * ECDSA methods.
 */

#ifdef WE_HAVE_ECDSA
#if OPENSSL_VERSION_NUMBER <= 0x100020ffL

extern ECDSA_METHOD *we_ecdsa_method;
int we_init_ecdsa_meth(void);

#endif
#endif /* WE_HAVE_ECDSA */

/*
 * ECC methods.
 */

#ifdef WE_HAVE_EC_KEY
extern EC_KEY_METHOD *we_ec_key_method;
#endif
extern EVP_PKEY_METHOD *we_ec_method;
extern EVP_PKEY_METHOD *we_ec_p192_method;
extern EVP_PKEY_METHOD *we_ec_p224_method;
extern EVP_PKEY_METHOD *we_ec_p256_method;
extern EVP_PKEY_METHOD *we_ec_p384_method;
extern EVP_PKEY_METHOD *we_ec_p521_method;
int we_init_ecc_meths(void);
int we_init_ec_key_meths(void);

int wolfengine_bind(ENGINE *e, const char *id);

#endif /* INTERNAL_H */
