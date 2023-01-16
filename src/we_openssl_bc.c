/* we_openssl_bc.c
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

#include <wolfengine/we_internal.h>
#include <wolfengine/we_openssl_bc.h>

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

int EVP_MD_meth_set_input_blocksize(EVP_MD *md, int blocksize)
{
    md->block_size = blocksize;
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

int EVP_CIPHER_CTX_num(const EVP_CIPHER_CTX *ctx)
{
    return ctx->num;
}

void EVP_CIPHER_CTX_set_num(EVP_CIPHER_CTX *ctx, int num)
{
    ctx->num = num;
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

size_t EC_POINT_point2buf(const EC_GROUP *group, const EC_POINT *point,
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

int RSA_meth_set_init(RSA_METHOD *meth, int (*init) (RSA *rsa))
{
    meth->init = init;
    return 1;
}

int RSA_meth_set_pub_enc(RSA_METHOD *meth,
                         int (*pub_enc) (int flen, const unsigned char *from,
                                         unsigned char *to, RSA *rsa,
                                         int padding))
{
    meth->rsa_pub_enc = pub_enc;
    return 1;
}

int RSA_meth_set_pub_dec(RSA_METHOD *meth,
                         int (*pub_dec) (int flen, const unsigned char *from,
                                         unsigned char *to, RSA *rsa,
                                         int padding))
{
    meth->rsa_pub_dec = pub_dec;
    return 1;
}

int RSA_meth_set_priv_enc(RSA_METHOD *meth,
                          int (*priv_enc) (int flen, const unsigned char *from,
                                           unsigned char *to, RSA *rsa,
                                           int padding))
{
    meth->rsa_priv_enc = priv_enc;
    return 1;
}

int RSA_meth_set_priv_dec(RSA_METHOD *meth,
                          int (*priv_dec) (int flen, const unsigned char *from,
                                           unsigned char *to, RSA *rsa,
                                           int padding))
{
    meth->rsa_priv_dec = priv_dec;
    return 1;
}

int RSA_meth_set_finish(RSA_METHOD *meth, int (*finish) (RSA *rsa))
{
    meth->finish = finish;
    return 1;
}

int RSA_meth_set_keygen(RSA_METHOD *meth,
                        int (*keygen) (RSA *rsa, int bits, BIGNUM *e,
                                       BN_GENCB *cb))
{
    meth->rsa_keygen = keygen;
    return 1;
}

RSA_METHOD *RSA_meth_new(const char *name, int flags)
{
    RSA_METHOD *meth = OPENSSL_zalloc(sizeof(*meth));

    if (meth != NULL) {
        meth->flags = flags;
        if (name != NULL) {
            meth->name = name;
            return meth;
        }
    }

    return NULL;
}

void RSA_meth_free(RSA_METHOD *meth)
{
    if (meth != NULL) {
        OPENSSL_free(meth);
    }
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

void RSA_get0_factors(const RSA *r, const BIGNUM **p, const BIGNUM **q)
{
    if (p != NULL)
        *p = r->p;
    if (q != NULL)
        *q = r->q;
}

void RSA_get0_crt_params(const RSA *r,
                         const BIGNUM **dmp1, const BIGNUM **dmq1,
                         const BIGNUM **iqmp)
{
    if (dmp1 != NULL)
        *dmp1 = r->dmp1;
    if (dmq1 != NULL)
        *dmq1 = r->dmq1;
    if (iqmp != NULL)
        *iqmp = r->iqmp;
}

int RSA_set0_key(RSA *r, BIGNUM *n, BIGNUM *e, BIGNUM *d)
{
    /* If the fields n and e in r are NULL, the corresponding input
     * parameters MUST be non-NULL for n and e.  d may be
     * left NULL (in case only the public key is used).
     */
    if ((r->n == NULL && n == NULL)
        || (r->e == NULL && e == NULL))
        return 0;

    if (n != NULL) {
        BN_free(r->n);
        r->n = n;
    }
    if (e != NULL) {
        BN_free(r->e);
        r->e = e;
    }
    if (d != NULL) {
        BN_clear_free(r->d);
        r->d = d;
    }

    return 1;
}

int RSA_set0_factors(RSA *r, BIGNUM *p, BIGNUM *q)
{
    /* If the fields p and q in r are NULL, the corresponding input
     * parameters MUST be non-NULL.
     */
    if ((r->p == NULL && p == NULL)
        || (r->q == NULL && q == NULL))
        return 0;

    if (p != NULL) {
        BN_clear_free(r->p);
        r->p = p;
    }
    if (q != NULL) {
        BN_clear_free(r->q);
        r->q = q;
    }

    return 1;
}

int RSA_set0_crt_params(RSA *r, BIGNUM *dmp1, BIGNUM *dmq1, BIGNUM *iqmp)
{
    /* If the fields dmp1, dmq1 and iqmp in r are NULL, the corresponding input
     * parameters MUST be non-NULL.
     */
    if ((r->dmp1 == NULL && dmp1 == NULL)
        || (r->dmq1 == NULL && dmq1 == NULL)
        || (r->iqmp == NULL && iqmp == NULL))
        return 0;

    if (dmp1 != NULL) {
        BN_clear_free(r->dmp1);
        r->dmp1 = dmp1;
    }
    if (dmq1 != NULL) {
        BN_clear_free(r->dmq1);
        r->dmq1 = dmq1;
    }
    if (iqmp != NULL) {
        BN_clear_free(r->iqmp);
        r->iqmp = iqmp;
    }

    return 1;
}

DH_METHOD *DH_meth_new(const char *name, int flags)
{
    DH_METHOD *dhm = OPENSSL_zalloc(sizeof(*dhm));

    if (dhm != NULL) {
        dhm->flags = flags;
        if (name != NULL) {
            dhm->name = name;
            return dhm;
        }
    }

    return NULL;
}

void DH_meth_free(DH_METHOD *dhm)
{
    if (dhm != NULL) {
        OPENSSL_free(dhm);
    }
}

int DH_meth_set_init(DH_METHOD *dhm, int (*init)(DH *))
{
    dhm->init = init;
    return 1;

}

int DH_meth_set_finish(DH_METHOD *dhm, int (*finish) (DH *))
{
    dhm->finish = finish;
    return 1;
}

int DH_meth_set_generate_key(DH_METHOD *dhm, int (*generate_key) (DH *))
{
    dhm->generate_key = generate_key;
    return 1;

}

int DH_meth_set_compute_key(DH_METHOD *dhm,
        int (*compute_key) (unsigned char *key, const BIGNUM *pub_key, DH *dh))
{
    dhm->compute_key = compute_key;
    return 1;
}

int DH_meth_set_generate_params(DH_METHOD *dhm,
        int (*generate_params) (DH *, int, int, BN_GENCB *))
{
    dhm->generate_params = generate_params;
    return 1;
}

long DH_get_length(const DH *dh)
{
    return dh->length;
}

void DH_get0_pqg(DH *dh, const BIGNUM **p, const BIGNUM **q, const BIGNUM **g)
{
    if (p != NULL) {
        *p = dh->p;
    }
    if (q != NULL) {
        *q = dh->q;
    }
    if (g != NULL) {
        *g = dh->g;
    }
}

int DH_set0_pqg(DH *dh, BIGNUM *p, BIGNUM *q, BIGNUM *g)
{
    /* If the fields p and g in d are NULL, the corresponding input
     * parameters MUST be non-NULL.  q may remain NULL.
     */
    if ((dh->p == NULL && p == NULL)
        || (dh->g == NULL && g == NULL))
        return 0;

    if (p != NULL) {
        BN_free(dh->p);
        dh->p = p;
    }
    if (q != NULL) {
        BN_free(dh->q);
        dh->q = q;
    }
    if (g != NULL) {
        BN_free(dh->g);
        dh->g = g;
    }

    if (q != NULL) {
        dh->length = BN_num_bits(q);
    }

    return 1;
}

int DH_set0_key(DH *dh, BIGNUM *pub_key, BIGNUM *priv_key)
{
    if (pub_key != NULL) {
        BN_free(dh->pub_key);
        dh->pub_key = pub_key;
    }
    if (priv_key != NULL) {
        BN_free(dh->priv_key);
        dh->priv_key = priv_key;
    }

    return 1;
}

int ECDSA_SIG_set0(ECDSA_SIG *sig, BIGNUM *r, BIGNUM *s)
{
    if (r == NULL || s == NULL) {
        return 0;
    }

    /* clear BIGNUM structs first */
    BN_clear_free(sig->r);
    BN_clear_free(sig->s);

    sig->r = r;
    sig->s = s;

    return 1;
}

#endif /* OPENSSL_VERSION_NUMBER < 0x10100000L */

#if OPENSSL_VERSION_NUMBER < 0x10101000L

const BIGNUM *DH_get0_p(const DH *dh)
{
#if OPENSSL_VERSION_NUMBER < 0x10100000L
    return dh->p;
#else
    const BIGNUM *p;
    DH_get0_pqg(dh, &p, NULL, NULL);
    return p;
#endif
}

const BIGNUM *DH_get0_g(const DH *dh)
{
#if OPENSSL_VERSION_NUMBER < 0x10100000L
    return dh->g;
#else
    const BIGNUM *g;
    DH_get0_pqg(dh, NULL, NULL, &g);
    return g;
#endif
}

const BIGNUM *DH_get0_q(const DH *dh)
{
#if OPENSSL_VERSION_NUMBER < 0x10100000L
    return dh->q;
#else
    const BIGNUM *q;
    DH_get0_pqg(dh, NULL, &q, NULL);
    return q;
#endif
}

const BIGNUM *DH_get0_priv_key(const DH *dh)
{
#if OPENSSL_VERSION_NUMBER < 0x10100000L
    return dh->priv_key;
#else
    const BIGNUM *priv_key;
    DH_get0_key(dh, NULL, &priv_key);
    return priv_key;
#endif
}

const BIGNUM *DH_get0_pub_key(const DH *dh)
{
#if OPENSSL_VERSION_NUMBER < 0x10100000L
    return dh->pub_key;
#else
    const BIGNUM *pub_key;
    DH_get0_key(dh, &pub_key, NULL);
    return pub_key;
#endif
}

#endif /* OPENSSL_VERSION_NUMBER < 0x10101000L */

#if OPENSSL_VERSION_NUMBER < 0x10100000L

DH *EVP_PKEY_get0_DH(EVP_PKEY *pkey)
{
    if (pkey->type != EVP_PKEY_DH && pkey->type != EVP_PKEY_DHX) {
        return NULL;
    }
    return pkey->pkey.dh;
}

#endif /* OPENSSL_VERSION_NUMBER < 0x10100000L */

