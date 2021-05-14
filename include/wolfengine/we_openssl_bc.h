/* we_openssl_bc.h
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

#ifndef OPENSSL_BC_H
#define OPENSSL_BC_H

#include <openssl/opensslv.h>

#if OPENSSL_VERSION_NUMBER < 0x1010104fL
/* Get IV len is not defined and used in versions below 1.1.1d and below. */
#define EVP_CTRL_GET_IVLEN    0x25
/* Custom IV length not defined and used in versions 1.1.1d and below. */
#define EVP_CIPH_CUSTOM_IV_LENGTH    0
#endif

#include <openssl/evp.h>
#include <openssl/crypto.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/dh.h>
#include <openssl/rsa.h>

/* These were all added in OpenSSL 1.1.0 */
#if OPENSSL_VERSION_NUMBER < 0x10100000L

#define EVP_CTRL_AEAD_GET_TAG   EVP_CTRL_GCM_GET_TAG
#define EVP_CTRL_AEAD_SET_TAG   EVP_CTRL_GCM_SET_TAG
#define EVP_CTRL_AEAD_SET_IVLEN EVP_CTRL_GCM_SET_IVLEN

/* EVP_MD_CTX_create / EVP_MD_CTX_destroy were renamed to
   EVP_MD_CTX_new / EVP_MD_CTX_free */
#define EVP_MD_CTX_new          EVP_MD_CTX_create
#define EVP_MD_CTX_free         EVP_MD_CTX_destroy

/* getter function was added for PKEY ctx */
#define EVP_MD_CTX_pkey_ctx(ctx) (ctx)->pctx

/* setter function was added for MD CTX digest update */
#define EVP_MD_CTX_set_update_fn(ctx, fn) (ctx)->update = (fn)

/* ASN1_STRING_data was renamed to ASN1_STRING_get0_data */
#define ASN1_STRING_get0_data ASN1_STRING_data

void *OPENSSL_zalloc(size_t num);
void OPENSSL_clear_free(void *str, size_t num);

void *EVP_MD_CTX_md_data(const EVP_MD_CTX *ctx);

int EVP_MD_meth_set_update(EVP_MD *md, int (*update)(EVP_MD_CTX *ctx,
                           const void *data,
                           size_t count));
int EVP_MD_meth_set_final(EVP_MD *md, int (*final)(EVP_MD_CTX *ctx,
                          unsigned char *md));
int EVP_MD_meth_set_cleanup(EVP_MD *md, int (*cleanup)(EVP_MD_CTX *ctx));
int EVP_MD_meth_set_app_datasize(EVP_MD *md, int datasize);
EVP_MD *EVP_MD_meth_new(int md_type, int pkey_type);
int EVP_MD_meth_set_init(EVP_MD *md, int (*init)(EVP_MD_CTX *ctx));
int EVP_MD_meth_set_result_size(EVP_MD *md, int resultsize);
int EVP_MD_meth_set_input_blocksize(EVP_MD *md, int blocksize);
void EVP_MD_meth_free(EVP_MD *md);

const unsigned char *EVP_CIPHER_CTX_iv(const EVP_CIPHER_CTX *ctx);
void *EVP_CIPHER_CTX_get_cipher_data(const EVP_CIPHER_CTX *ctx);
unsigned char *EVP_CIPHER_CTX_iv_noconst(EVP_CIPHER_CTX *ctx);
int EVP_CIPHER_CTX_num(const EVP_CIPHER_CTX *ctx);
void EVP_CIPHER_CTX_set_num(EVP_CIPHER_CTX *ctx, int num);

int EVP_CIPHER_meth_set_iv_length(EVP_CIPHER *cipher, int iv_len);
int EVP_CIPHER_meth_set_flags(EVP_CIPHER *cipher, unsigned long flags);
int EVP_CIPHER_meth_set_init(EVP_CIPHER *cipher,
                             int (*init) (EVP_CIPHER_CTX *ctx,
                             const unsigned char *key,
                             const unsigned char *iv,
                             int enc));
int EVP_CIPHER_meth_set_do_cipher(EVP_CIPHER *cipher,
                                  int (*do_cipher) (EVP_CIPHER_CTX *ctx,
                                  unsigned char *out,
                                  const unsigned char *in,
                                  size_t inl));
int EVP_CIPHER_meth_set_ctrl(EVP_CIPHER *cipher,
                             int (*ctrl) (EVP_CIPHER_CTX *, int type,
                             int arg, void *ptr));
int EVP_CIPHER_meth_set_impl_ctx_size(EVP_CIPHER *cipher, int ctx_size);
EVP_CIPHER *EVP_CIPHER_meth_new(int cipher_type, int block_size, int key_len);
void EVP_CIPHER_meth_free(EVP_CIPHER *cipher);

RSA *EVP_PKEY_get0_RSA(EVP_PKEY *pkey);
EC_KEY *EVP_PKEY_get0_EC_KEY(EVP_PKEY *pkey);

size_t EC_KEY_priv2buf(const EC_KEY *eckey, unsigned char **pbuf);
size_t EC_KEY_key2buf(const EC_KEY *key, point_conversion_form_t form,
                      unsigned char **pbuf, BN_CTX *ctx);
int EC_KEY_oct2key(EC_KEY *key, const unsigned char *buf, size_t len,
                   BN_CTX *ctx);
int EC_KEY_oct2priv(EC_KEY *eckey, const unsigned char *buf, size_t len);

RSA_METHOD *RSA_meth_new(const char *name, int flags);
void RSA_meth_free(RSA_METHOD *meth);
int RSA_meth_set_init(RSA_METHOD *meth, int (*init) (RSA *rsa));
int RSA_meth_set_pub_enc(RSA_METHOD *meth,
                         int (*pub_enc) (int flen, const unsigned char *from,
                                         unsigned char *to, RSA *rsa,
                                         int padding));
int RSA_meth_set_pub_dec(RSA_METHOD *meth,
                         int (*pub_dec) (int flen, const unsigned char *from,
                                         unsigned char *to, RSA *rsa,
                                         int padding));
int RSA_meth_set_priv_enc(RSA_METHOD *meth,
                          int (*priv_enc) (int flen, const unsigned char *from,
                                           unsigned char *to, RSA *rsa,
                                           int padding));
int RSA_meth_set_priv_dec(RSA_METHOD *meth,
                          int (*priv_dec) (int flen, const unsigned char *from,
                                           unsigned char *to, RSA *rsa,
                                           int padding));
int RSA_meth_set_finish(RSA_METHOD *meth, int (*finish) (RSA *rsa));
int RSA_meth_set_keygen(RSA_METHOD *meth,
                        int (*keygen) (RSA *rsa, int bits, BIGNUM *e,
                                       BN_GENCB *cb));
void RSA_get0_key(const RSA *r,
                  const BIGNUM **n, const BIGNUM **e, const BIGNUM **d);
void RSA_get0_factors(const RSA *r, const BIGNUM **p, const BIGNUM **q);
void RSA_get0_crt_params(const RSA *r,
                         const BIGNUM **dmp1, const BIGNUM **dmq1,
                         const BIGNUM **iqmp);
int RSA_set0_key(RSA *r, BIGNUM *n, BIGNUM *e, BIGNUM *d);
int RSA_set0_factors(RSA *r, BIGNUM *p, BIGNUM *q);
int RSA_set0_crt_params(RSA *r, BIGNUM *dmp1, BIGNUM *dmq1, BIGNUM *iqmp);

DH_METHOD *DH_meth_new(const char *name, int flags);
void DH_meth_free(DH_METHOD *dhm);
int DH_meth_set_generate_key(DH_METHOD *dhm, int (*generate_key) (DH *));
int DH_meth_set_compute_key(DH_METHOD *dhm,
        int (*compute_key) (unsigned char *key, const BIGNUM *pub_key, DH *dh));
int DH_meth_set_generate_params(DH_METHOD *dhm,
        int (*generate_params) (DH *, int, int, BN_GENCB *));
int DH_meth_set_init(DH_METHOD *dhm, int (*init)(DH *));
int DH_meth_set_finish(DH_METHOD *dhm, int (*finish) (DH *));
long DH_get_length(const DH *dh);
void DH_get0_pqg(DH *dh, const BIGNUM **p, const BIGNUM **q, const BIGNUM **g);
int DH_set0_pqg(DH *dh, BIGNUM *p, BIGNUM *q, BIGNUM *g);
int DH_set0_key(DH *dh, BIGNUM *pub_key, BIGNUM *priv_key);
DH *EVP_PKEY_get0_DH(EVP_PKEY *pkey);
int ECDSA_SIG_set0(ECDSA_SIG *sig, BIGNUM *r, BIGNUM *s);

size_t EC_POINT_point2buf(const EC_GROUP *group, const EC_POINT *point,
                                 point_conversion_form_t form,
                                 unsigned char **pbuf, BN_CTX *ctx);
#endif /* OPENSSL_VERSION_NUMBER < 0x10100000L */

#if OPENSSL_VERSION_NUMBER < 0x10101000L

#ifndef EVP_PKEY_HKDEF_MODE_EXTRACT_AND_EXPAND
#define EVP_PKEY_HKDEF_MODE_EXTRACT_AND_EXPAND      0
#endif
#ifndef EVP_PKEY_HKDEF_MODE_EXTRACT_ONLY
#define EVP_PKEY_HKDEF_MODE_EXTRACT_ONLY            1
#endif
#ifndef EVP_PKEY_HKDEF_MODE_EXPAND_ONLY
#define EVP_PKEY_HKDEF_MODE_EXPAND_ONLY             2
#endif
#ifndef EVP_PKEY_ECDH_KDF_X9_63
#define EVP_PKEY_ECDH_KDF_X9_63     EVP_PKEY_ECDH_KDF_X9_62
#endif

const BIGNUM *DH_get0_p(const DH *dh);
const BIGNUM *DH_get0_g(const DH *dh);
const BIGNUM *DH_get0_q(const DH *dh);
const BIGNUM *DH_get0_priv_key(const DH *dh);
const BIGNUM *DH_get0_pub_key(const DH *dh);

#endif /* OPENSSL_VERSION_NUMBER < 0x10101000L */

#endif /* OPENSSL_BC_H */
