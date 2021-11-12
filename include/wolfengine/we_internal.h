/* we_internal.h
 *
 * Copyright (C) 2019-2021 wolfSSL Inc.
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

#ifndef INTERNAL_H
#define INTERNAL_H

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

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

/* Index into extra data of DH object to use for wolfEngine DH object.
 * Customer can define this to avoid clashes with application usages.
 */
#ifndef WE_DH_EX_DATA_IDX
#define WE_DH_EX_DATA_IDX 0
#endif

#include <openssl/engine.h>
#include <openssl/evp.h>
#include <openssl/ec.h>
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
#include <openssl/kdf.h>
#endif
#include <openssl/tls1.h>
#if OPENSSL_VERSION_NUMBER >= 0x10101000L
#include <openssl/cmac.h>
#endif
#include <openssl/pkcs12.h>

#ifndef WOLFENGINE_USER_SETTINGS
#include <wolfssl/options.h>
#endif
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
#include <wolfssl/wolfcrypt/pwdbased.h>
#ifdef HAVE_WOLFSSL_WOLFCRYPT_KDF_H
    #include <wolfssl/wolfcrypt/kdf.h>
#endif

/* The DES3-CBC code won't compile unless wolfCrypt has support for it. */
#if defined(NO_DES3) && defined(WE_HAVE_DES3CBC)
#undef WE_HAVE_DES3CBC
#endif

#include <wolfengine/we_openssl_bc.h>
#include <wolfengine/we_logging.h>
#include <wolfengine/we_fips.h>
#include <wolfengine/we_visibility.h>

/* Defining WE_NO_OPENSSL_MALLOC will cause wolfEngine to not use the OpenSSL
 * memory management functions (e.g. OPENSSL_malloc, OPENSSL_free, etc.).
 * Instead, the corresponding wolfSSL functions will be used (e.g. XMALLOC,
 * XFREE, etc.). */
#ifdef WE_NO_OPENSSL_MALLOC
#undef  OPENSSL_malloc
#define OPENSSL_malloc(num)       XMALLOC((num), NULL, DYNAMIC_TYPE_TMP_BUFFER)
#undef  OPENSSL_free
#define OPENSSL_free(ptr)         XFREE((ptr), NULL, DYNAMIC_TYPE_TMP_BUFFER)
#undef  OPENSSL_realloc
#define OPENSSL_realloc(ptr, num) XREALLOC((ptr), (num), NULL, DYNAMIC_TYPE_TMP_BUFFER)

#if OPENSSL_VERSION_NUMBER >= 0x10100000L
WOLFENGINE_LOCAL void *we_zalloc(size_t num);
WOLFENGINE_LOCAL void we_clear_free(void *str, size_t num);
WOLFENGINE_LOCAL void *we_memdup(const void *data, size_t siz);

#undef  OPENSSL_zalloc
#define OPENSSL_zalloc     we_zalloc
#undef  OPENSSL_clear_free
#define OPENSSL_clear_free we_clear_free
#undef  OPENSSL_memdup
#define OPENSSL_memdup     we_memdup
#endif /* OPENSSL_VERSION_NUMBER >= 0x10100000L */
#endif /* WE_NO_OPENSSL_MALLOC */

#if defined(__IAR_SYSTEMS_ICC__) || defined(__GNUC__)
    /* Function is a printf style function. Pretend parameter is string literal.
     *
     * @param s  [in]  Index of string literal. Index from 1.
     * @param v  [in]  Index of first argument to check. 0 means don't.
     */
    #define WE_PRINTF_FUNC(s, v)  __attribute__((__format__ (__printf__, s, v)))
#else
    #define WE_PRINTF_FUNC(s, v)
#endif

/*
 * Global random
 */

extern WC_RNG* we_rng;
#ifndef WE_SINGLE_THREADED
extern wolfSSL_Mutex* we_rng_mutex;
#endif

WOLFENGINE_LOCAL int we_pkey_get_nids(const int** nids);
WOLFENGINE_LOCAL int we_pkey_asn1_get_nids(const int** nids);

/*
 * Digest methods.
 */

extern EVP_MD *we_sha1_md;
WOLFENGINE_LOCAL int we_init_sha_meth(void);

extern EVP_MD *we_ecdsa_sha1_md;
WOLFENGINE_LOCAL int we_init_ecdsa_sha1_meth(void);

extern EVP_MD *we_sha224_md;
WOLFENGINE_LOCAL int we_init_sha224_meth(void);

extern EVP_MD *we_sha256_md;
WOLFENGINE_LOCAL int we_init_sha256_meth(void);

extern EVP_MD *we_sha384_md;
WOLFENGINE_LOCAL int we_init_sha384_meth(void);

extern EVP_MD *we_sha512_md;
WOLFENGINE_LOCAL int we_init_sha512_meth(void);

extern EVP_MD *we_sha3_224_md;
WOLFENGINE_LOCAL int we_init_sha3_224_meth(void);

extern EVP_MD *we_sha3_256_md;
WOLFENGINE_LOCAL int we_init_sha3_256_meth(void);

extern EVP_MD *we_sha3_384_md;
WOLFENGINE_LOCAL int we_init_sha3_384_meth(void);

extern EVP_MD *we_sha3_512_md;
WOLFENGINE_LOCAL int we_init_sha3_512_meth(void);

WOLFENGINE_LOCAL enum wc_HashType we_nid_to_wc_hash_type(int nid);
WOLFENGINE_LOCAL int we_nid_to_wc_hash_oid(int nid);

/*
 * Cipher methods.
 */

extern EVP_CIPHER* we_des3_cbc_ciph;
WOLFENGINE_LOCAL int we_init_des3cbc_meths(void);

extern EVP_CIPHER* we_aes128_ecb_ciph;
extern EVP_CIPHER* we_aes192_ecb_ciph;
extern EVP_CIPHER* we_aes256_ecb_ciph;
WOLFENGINE_LOCAL int we_init_aesecb_meths(void);

extern EVP_CIPHER* we_aes128_cbc_ciph;
extern EVP_CIPHER* we_aes192_cbc_ciph;
extern EVP_CIPHER* we_aes256_cbc_ciph;
WOLFENGINE_LOCAL int we_init_aescbc_meths(void);

extern EVP_CIPHER* we_aes128_cbc_hmac_ciph;
extern EVP_CIPHER* we_aes256_cbc_hmac_ciph;
WOLFENGINE_LOCAL int we_init_aescbc_hmac_meths(void);

extern EVP_CIPHER* we_aes128_ctr_ciph;
extern EVP_CIPHER* we_aes192_ctr_ciph;
extern EVP_CIPHER* we_aes256_ctr_ciph;
WOLFENGINE_LOCAL int we_init_aesctr_meths(void);

extern EVP_CIPHER* we_aes128_gcm_ciph;
extern EVP_CIPHER* we_aes192_gcm_ciph;
extern EVP_CIPHER* we_aes256_gcm_ciph;
WOLFENGINE_LOCAL int we_init_aesgcm_meths(void);

extern EVP_CIPHER* we_aes128_ccm_ciph;
extern EVP_CIPHER* we_aes192_ccm_ciph;
extern EVP_CIPHER* we_aes256_ccm_ciph;
WOLFENGINE_LOCAL int we_init_aesccm_meths(void);


/*
 * Random method.
 */

extern RAND_METHOD* we_random_method;

/*
 * HMAC methods.
 */

#ifdef WE_HAVE_HMAC

extern EVP_PKEY_METHOD *we_hmac_pkey_method;
extern EVP_PKEY_ASN1_METHOD *we_hmac_pkey_asn1_method;

WOLFENGINE_LOCAL int we_init_hmac_pkey_meth(void);
WOLFENGINE_LOCAL int we_init_hmac_pkey_asn1_meth(void);
WOLFENGINE_LOCAL int we_hmac_update(Hmac*, const void*, size_t);

#endif /* WE_HAVE_HMAC */

/*
 * CMAC methods.
 */

#ifdef WE_HAVE_CMAC

#define NID_wolfengine_cmac 101
extern EVP_PKEY_METHOD *we_cmac_pkey_method;
extern EVP_PKEY_METHOD *we_cmac_we_pkey_method;
extern EVP_PKEY_ASN1_METHOD *we_cmac_pkey_asn1_method;
extern EVP_PKEY_ASN1_METHOD *we_cmac_we_pkey_asn1_method;

WOLFENGINE_LOCAL int we_init_cmac_pkey_meth(void);
WOLFENGINE_LOCAL int we_init_cmac_pkey_asn1_meth(void);

#endif /* WE_HAVE_CMAC */

/*
 * TLS1 PRF method.
 */

extern EVP_PKEY_METHOD *we_tls1_prf_method;
WOLFENGINE_LOCAL int we_init_tls1_prf_meth(void);

/*
 * HKDF method.
 */

extern EVP_PKEY_METHOD *we_hkdf_method;
WOLFENGINE_LOCAL int we_init_hkdf_meth(void);

/*
 * DH method.
 */

#ifdef WE_HAVE_DH

extern DH_METHOD *we_dh_method;
WOLFENGINE_LOCAL int we_init_dh_meth(void);

extern EVP_PKEY_METHOD *we_dh_pkey_method;
WOLFENGINE_LOCAL int we_init_dh_pkey_meth(void);

#endif /* WE_HAVE_DH */

/*
 * RSA methods.
 */

#ifdef WE_HAVE_RSA

extern EVP_PKEY_METHOD *we_rsa_pkey_method;
WOLFENGINE_LOCAL int we_init_rsa_pkey_meth(void);
extern RSA_METHOD *we_rsa_method;
WOLFENGINE_LOCAL int we_init_rsa_meth(void);

#endif /* WE_HAVE_RSA */

/*
 * ECDH methods.
 */
#if OPENSSL_VERSION_NUMBER < 0x10100000L
#ifdef WE_HAVE_ECDH

extern ECDH_METHOD *we_ecdh_method;
WOLFENGINE_LOCAL int we_init_ecdh_meth(void);

#endif /* WE_HAVE_ECDH */
#endif /* OPENSSL_VERSION_NUMBER < 0x10100000L */

/*
 * ECDSA methods.
 */

#ifdef WE_HAVE_ECDSA
#if OPENSSL_VERSION_NUMBER <= 0x100020ffL

extern ECDSA_METHOD *we_ecdsa_method;
WOLFENGINE_LOCAL int we_init_ecdsa_meth(void);

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
WOLFENGINE_LOCAL int we_init_ecc_meths(void);
WOLFENGINE_LOCAL int we_init_ec_key_meths(void);

/*
 * PBE method
 */

#ifdef WE_HAVE_PBE
WOLFENGINE_LOCAL int we_init_pbe_keygen(void);
#endif

WOLFENGINE_LOCAL int wolfengine_bind(ENGINE *e, const char *id);

#endif /* INTERNAL_H */
