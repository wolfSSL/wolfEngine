/* openssl_bc.h
 *
 * Copyright (C) 2006-2019 wolfSSL Inc.
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

/* These were all added in OpenSSL 1.1.0 */
#if OPENSSL_VERSION_NUMBER < 0x10100000L

#include <openssl/evp.h>
#include <openssl/crypto.h>
#include <openssl/ec.h>

#define EVP_CTRL_AEAD_GET_TAG   EVP_CTRL_GCM_GET_TAG
#define EVP_CTRL_AEAD_SET_TAG   EVP_CTRL_GCM_SET_TAG
#define EVP_CTRL_AEAD_SET_IVLEN EVP_CTRL_GCM_SET_IVLEN

/* EVP_MD_CTX_create / EVP_MD_CTX_destroy were renamed to
   EVP_MD_CTX_new / EVP_MD_CTX_free */
#define EVP_MD_CTX_new          EVP_MD_CTX_create
#define EVP_MD_CTX_free         EVP_MD_CTX_destroy

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
void EVP_MD_meth_free(EVP_MD *md);

const unsigned char *EVP_CIPHER_CTX_iv(const EVP_CIPHER_CTX *ctx);
void *EVP_CIPHER_CTX_get_cipher_data(const EVP_CIPHER_CTX *ctx);
unsigned char *EVP_CIPHER_CTX_iv_noconst(EVP_CIPHER_CTX *ctx);

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

EC_KEY *EVP_PKEY_get0_EC_KEY(EVP_PKEY *pkey);

size_t EC_KEY_priv2buf(const EC_KEY *eckey, unsigned char **pbuf);
size_t EC_KEY_key2buf(const EC_KEY *key, point_conversion_form_t form,
                      unsigned char **pbuf, BN_CTX *ctx);
int EC_KEY_oct2key(EC_KEY *key, const unsigned char *buf, size_t len,
                   BN_CTX *ctx);
int EC_KEY_oct2priv(EC_KEY *eckey, const unsigned char *buf, size_t len);

#endif /* OPENSSL_VERSION_NUMBER < 0x10100000L */

#endif /* OPENSSL_BC_H*/
