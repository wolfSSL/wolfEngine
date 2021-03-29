/* openssl_bc.c
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

#include "openssl_bc.h"

/* These were all added in OpenSSL 1.1.0 */
#if OPENSSL_VERSION_NUMBER < 0x10100000L

#include <string.h>

void *OPENSSL_zalloc(size_t num)
{
    void *ret = OPENSSL_malloc(num);

    if (ret != NULL)
        memset(ret, 0, num);
    return ret;
}

const unsigned char *EVP_CIPHER_CTX_iv(const EVP_CIPHER_CTX *ctx)
{
    return ctx->iv;
}

void *EVP_MD_CTX_md_data(const EVP_MD_CTX *ctx)
{
    return ctx->md_data;
}

int EVP_MD_meth_set_update(EVP_MD *md, int (*update)(EVP_MD_CTX *ctx,
                                                     const void *data,
                                                     size_t count))
{
    md->update = update;
    return 1;
}

int EVP_MD_meth_set_final(EVP_MD *md, int (*final)(EVP_MD_CTX *ctx,
                                                   unsigned char *md))
{
    md->final = final;
    return 1;
}

int EVP_MD_meth_set_cleanup(EVP_MD *md, int (*cleanup)(EVP_MD_CTX *ctx))
{
    md->cleanup = cleanup;
    return 1;
}

int EVP_MD_meth_set_app_datasize(EVP_MD *md, int datasize)
{
    md->ctx_size = datasize;
    return 1;
}

EVP_MD *EVP_MD_meth_new(int md_type, int pkey_type)
{
    EVP_MD *md = OPENSSL_zalloc(sizeof(*md));

    if (md != NULL) {
        md->type = md_type;
        md->pkey_type = pkey_type;
    }
    return md;
}

int EVP_MD_meth_set_init(EVP_MD *md, int (*init)(EVP_MD_CTX *ctx))
{
    md->init = init;
    return 1;
}

int EVP_MD_meth_set_result_size(EVP_MD *md, int resultsize)
{
    md->md_size = resultsize;
    return 1;
}

void EVP_MD_meth_free(EVP_MD *md)
{
    OPENSSL_free(md);
}

void *EVP_CIPHER_CTX_get_cipher_data(const EVP_CIPHER_CTX *ctx)
{
    return ctx->cipher_data;
}

unsigned char *EVP_CIPHER_CTX_iv_noconst(EVP_CIPHER_CTX *ctx)
{
    return ctx->iv;
}

int EVP_CIPHER_meth_set_iv_length(EVP_CIPHER *cipher, int iv_len)
{
    cipher->iv_len = iv_len;
    return 1;
}

int EVP_CIPHER_meth_set_flags(EVP_CIPHER *cipher, unsigned long flags)
{
    cipher->flags = flags;
    return 1;
}

int EVP_CIPHER_meth_set_init(EVP_CIPHER *cipher,
                             int (*init) (EVP_CIPHER_CTX *ctx,
                             const unsigned char *key,
                             const unsigned char *iv,
                             int enc))
{
    cipher->init = init;
    return 1;
}

int EVP_CIPHER_meth_set_do_cipher(EVP_CIPHER *cipher,
                                  int (*do_cipher) (EVP_CIPHER_CTX *ctx,
                                  unsigned char *out,
                                  const unsigned char *in,
                                  size_t inl))
{
    cipher->do_cipher = do_cipher;
    return 1;
}

int EVP_CIPHER_meth_set_ctrl(EVP_CIPHER *cipher,
                             int (*ctrl) (EVP_CIPHER_CTX *, int type,
                             int arg, void *ptr))
{
    cipher->ctrl = ctrl;
    return 1;
}

int EVP_CIPHER_meth_set_impl_ctx_size(EVP_CIPHER *cipher, int ctx_size)
{
    cipher->ctx_size = ctx_size;
    return 1;
}

EVP_CIPHER *EVP_CIPHER_meth_new(int cipher_type, int block_size, int key_len)
{
    EVP_CIPHER *cipher = OPENSSL_zalloc(sizeof(EVP_CIPHER));

    if (cipher != NULL) {
        cipher->nid = cipher_type;
        cipher->block_size = block_size;
        cipher->key_len = key_len;
    }
    return cipher;
}

void EVP_CIPHER_meth_free(EVP_CIPHER *cipher)
{
    OPENSSL_free(cipher);
}

size_t EC_KEY_priv2buf(const EC_KEY *eckey, unsigned char **pbuf)
{
    const BIGNUM *priv_key_bn = NULL;
    size_t priv_len = 0;
    unsigned char *priv_key_buf = NULL;

    priv_key_bn = EC_KEY_get0_private_key(eckey);
    priv_len = BN_num_bytes(priv_key_bn);

    if (priv_len == 0)
        return 0;

    priv_key_buf = OPENSSL_malloc(priv_len);
    if (priv_key_buf == NULL)
        return 0;
    
    BN_bn2bin(priv_key_bn, priv_key_buf);
    *pbuf = priv_key_buf;

    return priv_len;
}

void OPENSSL_clear_free(void *str, size_t num)
{
    if (str == NULL)
        return;
    if (num)
        OPENSSL_cleanse(str, num);
    OPENSSL_free(str);
}

static size_t EC_POINT_point2buf(const EC_GROUP *group, const EC_POINT *point,
                                 point_conversion_form_t form,
                                 unsigned char **pbuf, BN_CTX *ctx)
{
    size_t len;
    unsigned char *buf;

    len = EC_POINT_point2oct(group, point, form, NULL, 0, NULL);
    if (len == 0)
        return 0;
    if ((buf = OPENSSL_malloc(len)) == NULL) {
        return 0;
    }
    len = EC_POINT_point2oct(group, point, form, buf, len, ctx);
    if (len == 0) {
        OPENSSL_free(buf);
        return 0;
    }
    *pbuf = buf;
    return len;
}

size_t EC_KEY_key2buf(const EC_KEY *key, point_conversion_form_t form,
                      unsigned char **pbuf, BN_CTX *ctx)
{
    const EC_GROUP *group;
    const EC_POINT *pub_key;

    if (key == NULL)
        return 0;

    group = EC_KEY_get0_group(key);
    pub_key = EC_KEY_get0_public_key(key);

    if (pub_key == NULL || group == NULL)
        return 0;

    return EC_POINT_point2buf(group, pub_key, form, pbuf, ctx);
}

RSA *EVP_PKEY_get0_RSA(EVP_PKEY *pkey)
{
    if (pkey->type != EVP_PKEY_RSA)
        return NULL;

    return pkey->pkey.rsa;
}

EC_KEY *EVP_PKEY_get0_EC_KEY(EVP_PKEY *pkey)
{
    if (pkey->type != EVP_PKEY_EC)
        return NULL;

    return pkey->pkey.ec;
}

int EC_KEY_oct2key(EC_KEY *key, const unsigned char *buf, size_t len,
                   BN_CTX *ctx)
{
    const EC_GROUP *group = NULL;
    EC_POINT *tmp = NULL;

    if (key == NULL)
        return 0;

    group = EC_KEY_get0_group(key);
    if (group == NULL)
        return 0;

    tmp = EC_POINT_new(group);
    if (tmp == NULL)
        return 0;

    if (EC_POINT_oct2point(group, tmp, buf, len, ctx) == 0) {
        EC_POINT_free(tmp);
        return 0;
    }

    if (EC_KEY_set_public_key(key, tmp) == 0) {
        EC_POINT_free(tmp);
        return 0;
    }
    /*
     * Save the point conversion form.
     * For non-custom curves the first octet of the buffer (excluding
     * the last significant bit) contains the point conversion form.
     * EC_POINT_oct2point() has already performed sanity checking of
     * the buffer so we know it is valid.
     */
    EC_KEY_set_conv_form(key, (point_conversion_form_t)(buf[0] & ~0x01));

    EC_POINT_free(tmp);

    return 1;
}

int EC_KEY_oct2priv(EC_KEY *eckey, const unsigned char *buf, size_t len)
{
    BIGNUM *priv_key = NULL;

    priv_key = BN_bin2bn(buf, (int)len, priv_key);
    if (priv_key == NULL)
        return 0;

    if (EC_KEY_set_private_key(eckey, priv_key) == 0) {
        BN_free(priv_key);
        return 0;
    }

    BN_free(priv_key);
    return 1;
}

void RSA_get0_key(const RSA *r,
                  const BIGNUM **n, const BIGNUM **e, const BIGNUM **d)
{
    if (n != NULL)
        *n = r->n;
    if (e != NULL)
        *e = r->e;
    if (d != NULL)
        *d = r->d;
}

#endif /* OPENSSL_VERSION_NUMBER < 0x10100000L */
