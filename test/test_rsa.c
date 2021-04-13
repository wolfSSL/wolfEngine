/* test_rsa.c
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

#ifdef WE_HAVE_RSA

static const unsigned char rsa_key_der_2048[] =
{
    0x30, 0x82, 0x04, 0xA3, 0x02, 0x01, 0x00, 0x02, 0x82, 0x01,
    0x01, 0x00, 0xE9, 0x8A, 0x5D, 0x15, 0xA4, 0xD4, 0x34, 0xB9,
    0x59, 0xA2, 0xDA, 0xAF, 0x74, 0xC8, 0xC9, 0x03, 0x26, 0x38,
    0xFA, 0x48, 0xFC, 0x4D, 0x30, 0x6E, 0xEA, 0x76, 0x89, 0xCE,
    0x4F, 0xF6, 0x87, 0xDE, 0x32, 0x3A, 0x46, 0x6E, 0x38, 0x12,
    0x58, 0x37, 0x22, 0x0D, 0x80, 0xAC, 0x2D, 0xAF, 0x2F, 0x12,
    0x3E, 0x62, 0x73, 0x60, 0x66, 0x68, 0x90, 0xB2, 0x6F, 0x47,
    0x17, 0x04, 0x2B, 0xCA, 0xB7, 0x26, 0xB7, 0x10, 0xC2, 0x13,
    0xF9, 0x7A, 0x62, 0x0A, 0x93, 0x32, 0x90, 0x42, 0x0D, 0x16,
    0x2E, 0xFA, 0xD7, 0x29, 0xD7, 0x9F, 0x54, 0xE4, 0xFC, 0x65,
    0x74, 0xF8, 0xF6, 0x43, 0x6B, 0x4E, 0x9E, 0x34, 0x7F, 0xCB,
    0x6B, 0x1C, 0x1A, 0xDE, 0x82, 0x81, 0xBF, 0x08, 0x5D, 0x3F,
    0xC0, 0xB6, 0xB1, 0xA8, 0xA5, 0x9C, 0x81, 0x70, 0xA7, 0x4E,
    0x32, 0x87, 0x15, 0x1C, 0x78, 0x0E, 0xF0, 0x18, 0xFE, 0xEB,
    0x4B, 0x37, 0x2B, 0xE9, 0xE1, 0xF7, 0xFA, 0x51, 0xC6, 0x58,
    0xB9, 0xD8, 0x06, 0x03, 0xED, 0xC0, 0x03, 0x18, 0x55, 0x8B,
    0x98, 0xFE, 0xB1, 0xF6, 0xD0, 0x3D, 0xFA, 0x63, 0xC0, 0x38,
    0x19, 0xC7, 0x00, 0xEF, 0x4D, 0x99, 0x60, 0xB4, 0xBA, 0xCE,
    0xE3, 0xCE, 0xD9, 0x6B, 0x2D, 0x76, 0x94, 0xFF, 0xFB, 0x77,
    0x18, 0x4A, 0xFE, 0x65, 0xF0, 0x0A, 0x91, 0x5C, 0x3B, 0x22,
    0x94, 0x85, 0xD0, 0x20, 0x18, 0x59, 0x2E, 0xA5, 0x33, 0x03,
    0xAC, 0x1B, 0x5F, 0x78, 0x32, 0x11, 0x25, 0xEE, 0x7F, 0x96,
    0x21, 0xA9, 0xD6, 0x76, 0x97, 0x8D, 0x66, 0x7E, 0xB2, 0x91,
    0xD0, 0x36, 0x2E, 0xA3, 0x1D, 0xBF, 0xF1, 0x85, 0xED, 0xC0,
    0x3E, 0x60, 0xB8, 0x5A, 0x9F, 0xAB, 0x80, 0xE0, 0xEA, 0x5D,
    0x5F, 0x75, 0x56, 0xC7, 0x4D, 0x51, 0x8E, 0xD4, 0x1F, 0x34,
    0xA6, 0x36, 0xF1, 0x30, 0x1F, 0x51, 0x99, 0x2F, 0x02, 0x03,
    0x01, 0x00, 0x01, 0x02, 0x82, 0x01, 0x00, 0x52, 0x11, 0x33,
    0x40, 0xC5, 0xD9, 0x64, 0x65, 0xB5, 0xE0, 0x0A, 0xA5, 0x19,
    0x8E, 0xED, 0x44, 0x54, 0x0C, 0x35, 0xB7, 0xAC, 0x21, 0x9B,
    0xE1, 0x7E, 0x37, 0x05, 0x9A, 0x20, 0x73, 0x6B, 0xAF, 0x63,
    0x4B, 0x23, 0x30, 0xDC, 0x37, 0x66, 0x14, 0x89, 0xBC, 0xE0,
    0xF8, 0xA0, 0x5D, 0x2D, 0x57, 0x65, 0xE0, 0xC6, 0xD6, 0x9B,
    0x66, 0x27, 0x62, 0xEC, 0xC3, 0xB8, 0x8C, 0xD8, 0xAE, 0xB5,
    0xC9, 0xBF, 0x0E, 0xFE, 0x84, 0x72, 0x68, 0xD5, 0x47, 0x0E,
    0x0E, 0xF8, 0xAE, 0x9D, 0x56, 0xAC, 0x4F, 0xAD, 0x88, 0xA0,
    0xA2, 0xF6, 0xFC, 0x38, 0xCD, 0x96, 0x5B, 0x5E, 0x7E, 0xB6,
    0x98, 0xBB, 0xF3, 0x8A, 0xEC, 0xFA, 0xC8, 0xB7, 0x90, 0x75,
    0xA0, 0x0E, 0x77, 0x6B, 0xFD, 0x59, 0x45, 0x5A, 0x0C, 0xFF,
    0x95, 0x8D, 0xCE, 0xFE, 0x9B, 0xF6, 0x19, 0x8E, 0x0B, 0xA1,
    0x0C, 0xEE, 0xC6, 0x79, 0xDD, 0x9D, 0x61, 0x85, 0x5C, 0x19,
    0x6C, 0x47, 0xCC, 0x08, 0xFF, 0xA5, 0x62, 0xDB, 0xE4, 0x2D,
    0x2D, 0xDD, 0x14, 0x67, 0xD6, 0x4A, 0x64, 0x2A, 0x66, 0x49,
    0x54, 0x9C, 0xE3, 0x85, 0x18, 0xE7, 0x31, 0x42, 0xE2, 0xD0,
    0x2C, 0x20, 0xA0, 0x74, 0x0F, 0x1F, 0x20, 0x89, 0xBA, 0xAB,
    0x80, 0xD8, 0x38, 0xD9, 0x46, 0x69, 0xBB, 0xEF, 0xCC, 0x8B,
    0xA1, 0x73, 0xA7, 0xF2, 0xE4, 0x38, 0x5D, 0xD6, 0x75, 0x9F,
    0x88, 0x0E, 0x56, 0xCD, 0xD8, 0x84, 0x59, 0x29, 0x73, 0xF5,
    0xA1, 0x79, 0xDA, 0x7A, 0x1F, 0xBF, 0x73, 0x83, 0xC0, 0x6D,
    0x9F, 0x8B, 0x34, 0x15, 0xC0, 0x6D, 0x69, 0x6A, 0x20, 0xE6,
    0x51, 0xCF, 0x45, 0x6E, 0xCC, 0x05, 0xC4, 0x3A, 0xC0, 0x9E,
    0xAA, 0xC1, 0x06, 0x2F, 0xAB, 0x99, 0x30, 0xE1, 0x6E, 0x9D,
    0x45, 0x7A, 0xFF, 0xA9, 0xCE, 0x70, 0xB8, 0x16, 0x1A, 0x0E,
    0x20, 0xFA, 0xC1, 0x02, 0x81, 0x81, 0x00, 0xFF, 0x30, 0x11,
    0xC2, 0x3C, 0x6B, 0xB4, 0xD6, 0x9E, 0x6B, 0xC1, 0x93, 0xD1,
    0x48, 0xCE, 0x80, 0x2D, 0xBE, 0xAF, 0xF7, 0xBA, 0xB2, 0xD7,
    0xC3, 0xC4, 0x53, 0x6E, 0x15, 0x02, 0xAA, 0x61, 0xB9, 0xEA,
    0x05, 0x9B, 0x79, 0x67, 0x0B, 0xCE, 0xD9, 0xFB, 0x98, 0x8C,
    0x1D, 0x6B, 0xF4, 0x5A, 0xA7, 0xA0, 0x5E, 0x54, 0x18, 0xE9,
    0x31, 0x44, 0x7C, 0xC7, 0x52, 0xD8, 0x6D, 0xA0, 0x3E, 0xD6,
    0x14, 0x2D, 0x7B, 0x15, 0x9D, 0x1E, 0x39, 0x87, 0x96, 0xDD,
    0xA8, 0x33, 0x55, 0x2A, 0x8E, 0x32, 0xC0, 0xC4, 0xE5, 0xB8,
    0xCB, 0xCD, 0x32, 0x8D, 0xAD, 0x7B, 0xE5, 0xC6, 0x7E, 0x4D,
    0x6F, 0xF3, 0xA4, 0xC5, 0xA6, 0x40, 0xBE, 0x90, 0x3A, 0x33,
    0x6A, 0x24, 0xB2, 0x80, 0x81, 0x12, 0xAC, 0xE3, 0x7B, 0x26,
    0x63, 0xCF, 0x88, 0xB9, 0xFF, 0x74, 0x23, 0x37, 0x52, 0xF0,
    0xC4, 0x27, 0x5D, 0x45, 0x1F, 0x02, 0x81, 0x81, 0x00, 0xEA,
    0x48, 0xA7, 0xDD, 0x73, 0x41, 0x56, 0x21, 0x15, 0xF7, 0x42,
    0x45, 0x4D, 0xA9, 0xE1, 0x66, 0x5B, 0xBD, 0x25, 0x7D, 0xF7,
    0xA8, 0x65, 0x13, 0xAE, 0x2D, 0x38, 0x11, 0xCD, 0x93, 0xFC,
    0x30, 0xA3, 0x2C, 0x44, 0xBB, 0xCF, 0xD0, 0x21, 0x8F, 0xFB,
    0xC1, 0xF9, 0xAD, 0x1D, 0xEE, 0x96, 0xCF, 0x97, 0x49, 0x60,
    0x53, 0x80, 0xA5, 0xA2, 0xF8, 0xEE, 0xB9, 0xD5, 0x77, 0x44,
    0xDD, 0xFD, 0x19, 0x2A, 0xF1, 0x81, 0xF4, 0xD9, 0x3C, 0xEC,
    0x73, 0xD0, 0x2A, 0xD8, 0x3C, 0x27, 0x87, 0x79, 0x12, 0x86,
    0xE7, 0x57, 0x0C, 0x59, 0xD1, 0x44, 0x55, 0xAE, 0xC3, 0x4D,
    0x42, 0xAD, 0xA9, 0xB3, 0x28, 0x61, 0xB4, 0x9C, 0xA6, 0x63,
    0xD3, 0x96, 0xB1, 0x75, 0x9F, 0x2A, 0x78, 0x99, 0xE3, 0x1E,
    0x71, 0x47, 0x39, 0xF4, 0x52, 0xE3, 0x66, 0xF1, 0xEB, 0x7F,
    0xEF, 0xC6, 0x81, 0x93, 0x4C, 0x99, 0xF1, 0x02, 0x81, 0x81,
    0x00, 0xC5, 0xB6, 0x20, 0x8C, 0x34, 0xF3, 0xDD, 0xF0, 0x4A,
    0x5D, 0x82, 0x65, 0x5C, 0x48, 0xE4, 0x75, 0x3A, 0xFB, 0xFA,
    0xAA, 0x1C, 0xE4, 0x63, 0x77, 0x31, 0xAC, 0xD2, 0x25, 0x45,
    0x23, 0x6D, 0x03, 0xF5, 0xE4, 0xD2, 0x48, 0x85, 0x26, 0x08,
    0xE5, 0xAA, 0xA0, 0xCE, 0x2E, 0x1D, 0x6D, 0xFC, 0xAE, 0xD2,
    0xF9, 0x42, 0x7E, 0xEA, 0x6D, 0x59, 0x7A, 0xB3, 0x93, 0xE4,
    0x4B, 0x4B, 0x54, 0x63, 0xD8, 0xCE, 0x44, 0x06, 0xC2, 0xEC,
    0x9F, 0xF6, 0x05, 0x55, 0x46, 0xF4, 0x3E, 0x8F, 0xF2, 0x0C,
    0x30, 0x7E, 0x5C, 0xDD, 0x88, 0x49, 0x3B, 0x59, 0xB9, 0x87,
    0xBC, 0xC6, 0xC5, 0x24, 0x8A, 0x10, 0x63, 0x21, 0x1F, 0x66,
    0x1A, 0x3E, 0xF4, 0x58, 0xD1, 0x6C, 0x0D, 0x40, 0xB2, 0xC0,
    0x1D, 0x63, 0x42, 0x0E, 0xC4, 0x56, 0x0E, 0xC0, 0xCC, 0xC2,
    0xD6, 0x66, 0x0E, 0xC4, 0xAB, 0xB5, 0x33, 0xF6, 0x51, 0x02,
    0x81, 0x80, 0x19, 0x7E, 0xE6, 0xA5, 0xB6, 0xD1, 0x39, 0x6A,
    0x48, 0x55, 0xAC, 0x24, 0x96, 0x9B, 0x12, 0x28, 0x6D, 0x7B,
    0x5C, 0x05, 0x25, 0x5A, 0x72, 0x05, 0x7E, 0x42, 0xF5, 0x83,
    0x1A, 0x78, 0x2C, 0x4D, 0xAE, 0xB4, 0x36, 0x96, 0xA9, 0xBA,
    0xE0, 0xAC, 0x26, 0x9D, 0xA9, 0x6A, 0x29, 0x83, 0xB9, 0x6D,
    0xC5, 0xEC, 0xFA, 0x4A, 0x9C, 0x09, 0x6A, 0x7E, 0xE4, 0x9B,
    0xDC, 0x9B, 0x2A, 0x27, 0x6E, 0x4F, 0xBA, 0xD8, 0xA5, 0x67,
    0xDB, 0xEC, 0x41, 0x5F, 0x29, 0x1C, 0x40, 0x83, 0xEB, 0x59,
    0x56, 0xD7, 0xA9, 0x4E, 0xAB, 0xAE, 0x70, 0x67, 0xD1, 0xA3,
    0xF1, 0x6C, 0xD7, 0x8F, 0x96, 0x0E, 0x8D, 0xAC, 0xAB, 0x55,
    0x58, 0x66, 0xD3, 0x1E, 0x47, 0x9B, 0xF0, 0x4C, 0xED, 0xF6,
    0x49, 0xE8, 0xE9, 0x7B, 0x32, 0x61, 0x20, 0x31, 0x95, 0x05,
    0xB2, 0xF6, 0x09, 0xEA, 0x32, 0x14, 0x0F, 0xCF, 0x9A, 0x41,
    0x02, 0x81, 0x80, 0x77, 0x3F, 0xB6, 0x14, 0x8D, 0xC5, 0x13,
    0x08, 0x7E, 0xC9, 0xC4, 0xEA, 0xD4, 0xBA, 0x0D, 0xA4, 0x9E,
    0xB3, 0x6E, 0xDE, 0x1A, 0x7A, 0xF8, 0x89, 0x88, 0xEF, 0x36,
    0x3C, 0x11, 0xBC, 0x83, 0xE8, 0x30, 0x6C, 0x81, 0x7C, 0x47,
    0xF3, 0x4D, 0xCA, 0xEA, 0x56, 0x01, 0x62, 0x55, 0x2E, 0x4B,
    0x89, 0xA9, 0xBD, 0x6F, 0x01, 0xF6, 0x74, 0x02, 0xAA, 0xE3,
    0x84, 0x66, 0x06, 0x95, 0x34, 0xA1, 0xE2, 0xCA, 0x65, 0xFE,
    0xA3, 0x2D, 0x43, 0x97, 0x95, 0x6C, 0x6F, 0xD5, 0xB4, 0x38,
    0xF6, 0xF9, 0x95, 0x30, 0xFA, 0xF8, 0x9C, 0x25, 0x2B, 0xB6,
    0x14, 0x51, 0xCC, 0x2E, 0xB3, 0x5B, 0xD6, 0xDC, 0x1A, 0xEC,
    0x2D, 0x09, 0x5B, 0x3F, 0x3A, 0xD0, 0xB8, 0x4E, 0x27, 0x1F,
    0xDC, 0x2A, 0xEE, 0xAC, 0xA9, 0x59, 0x5D, 0x07, 0x63, 0x11,
    0x83, 0x0B, 0xD4, 0x74, 0x80, 0xB6, 0x7D, 0x62, 0x45, 0xBF,
    0x56
};

/* Copy RSA params from a to b. Surprisingly, there's no function I can find to
   do this with OpenSSL. There are functions to duplicate private/public keys
   and return a corresponding RSA object, but no function duplicates BOTH
   private and public parameters. Returns 1 on success and 0 on failure. */
static int copy_rsa(RSA *a, RSA *b)
{
    const BIGNUM *aN = NULL, *aE = NULL, *aD = NULL, *aP = NULL, *aQ = NULL,
                 *aDmp1 = NULL, *aDmq1 = NULL, *aIqmp = NULL;
    BIGNUM *bN = NULL, *bE = NULL, *bD = NULL, *bP = NULL, *bQ = NULL,
           *bDmp1 = NULL, *bDmq1 = NULL, *bIqmp = NULL;

    if (a == NULL || b == NULL)
        return 0;

    RSA_get0_key(a, &aN, &aE, &aD);
    RSA_get0_factors(a, &aP, &aQ);
    RSA_get0_crt_params(a, &aDmp1, &aDmq1, &aIqmp);

    if (aN == NULL || aE == NULL || aD == NULL || aP == NULL || aQ == NULL ||
        aDmp1 == NULL || aDmq1 == NULL || aIqmp == NULL)
        return 0;

    bN = BN_dup(aN);
    bE = BN_dup(aE);
    bD = BN_dup(aD);
    bP = BN_dup(aP);
    bQ = BN_dup(aQ);
    bDmp1 = BN_dup(aDmp1);
    bDmq1 = BN_dup(aDmq1);
    bIqmp = BN_dup(aIqmp);

    if (bN == NULL || bE == NULL || bD == NULL || bP == NULL || bQ == NULL ||
        bDmp1 == NULL || bDmq1 == NULL || bIqmp == NULL)
        return 0;

    if (RSA_set0_key(b, bN, bE, bD) != 1)
        return 0;

    if (RSA_set0_factors(b, bP, bQ) != 1)
        return 0;

    if (RSA_set0_crt_params(b, bDmp1, bDmq1, bIqmp) != 1)
        return 0;

    return 1;
}

/* Load the RSA key held in buffer rsa_key_der_2048 into wolfEngine and OpenSSL
   RSA keys for use in RSA direct tests. Returns 1 on success, 0 on failure. */
static int load_static_rsa_key(ENGINE *e, RSA **weRsaKey, RSA **osslRsaKey)
{
    int ret = 1;
    int rc = 0;
    const unsigned char *p = rsa_key_der_2048;
    EVP_PKEY *pkey = NULL;
    RSA *rsa = NULL;

    if (e == NULL) {
        PRINT_MSG("load_static_rsa_key: e was NULL.");
        ret = 0;
    }
    if (weRsaKey == NULL) {
        PRINT_MSG("load_static_rsa_key: weRsaKey was NULL.");
        ret = 0;
    }
    if (osslRsaKey == NULL) {
        PRINT_MSG("load_static_rsa_key: osslRsaKey was NULL.");
        ret = 0;
    }

    if (ret == 1) {
        pkey = d2i_PrivateKey(EVP_PKEY_RSA, NULL, &p, sizeof(rsa_key_der_2048));
        if (pkey == NULL) {
            PRINT_MSG("load_static_rsa_key: d2i_PrivateKey failed.");
            ret = 0;
        }
    }
    if (ret == 1) {
        rsa = (RSA *)EVP_PKEY_get0_RSA(pkey);
        if (rsa == NULL) {
            PRINT_MSG("load_static_rsa_key: EVP_PKEY_get0_RSA failed.");
            ret = 0;
        }
    }

    if (ret == 1 && *weRsaKey == NULL) {
        *weRsaKey = RSA_new_method(e);
        if (*weRsaKey == NULL) {
            PRINT_MSG("load_static_rsa_key: RSA_new_method failed.");
            ret = 0;
        }
    }
    if (ret == 1) {
        rc = copy_rsa(rsa, *weRsaKey);
        if (rc != 1) {
            PRINT_MSG("load_static_rsa_key: copy_rsa w/ weRsaKey failed.");
            ret = 0;
        }
    }

    if (ret == 1 && *osslRsaKey == NULL) {
        *osslRsaKey = RSA_new();
        if (*osslRsaKey == NULL) {
            PRINT_MSG("load_static_rsa_key: RSA_new failed.");
            ret = 0;
        }
    }
    if (ret == 1) {
        rc = copy_rsa(rsa, *osslRsaKey);
        if (rc != 1) {
            PRINT_MSG("load_static_rsa_key: copy_rsa w/ osslRsaKey failed.");
            ret = 0;
        }
    }

    EVP_PKEY_free(pkey);

    return ret;
}

enum RsaTestType {
    PRIVATE_ENCRYPT,
    PRIVATE_DECRYPT,
    PUBLIC_ENCRYPT,
    PUBLIC_DECRYPT
};
typedef enum RsaTestType RsaTestType;

/* Test the RSA_METHOD API (AKA RSA direct) for a particular half of the key
   pair (public/private) and direction (encrypt/decrypt). */
static int test_rsa_direct(ENGINE *e, RsaTestType testType)
{
    int err = 0;
    RSA *weRsaKey = NULL;
    RSA *osslRsaKey = NULL;
    unsigned char buf[20];
    unsigned char *noPaddingBuf = NULL;
    unsigned char *encryptedBuf = NULL;
    int encryptedLen = 0;
    unsigned char *decryptedBuf = NULL;
    int decryptedLen = 0;
    typedef struct {
        int padding;
        const char *padName;
        unsigned char *inBuf;
        int inBufLen;
    } TestVector;
    const int numTestVectors = 3;
    TestVector testVectors[numTestVectors];
    int i = 0;
    int rsaSize = 0;

    PRINT_MSG("Load RSA key");    
    err = load_static_rsa_key(e, &weRsaKey, &osslRsaKey) != 1;
    if (err == 0) {
        rsaSize = RSA_size(weRsaKey);
        err = RAND_bytes(buf, sizeof(buf)) == 0;
    }
    if (err == 0) {
        encryptedBuf = OPENSSL_malloc(rsaSize);
        err = encryptedBuf == NULL;
    }
    if (err == 0) {
        decryptedBuf = OPENSSL_malloc(rsaSize);
        err = decryptedBuf == NULL;
    }
    if (err == 0) {
        noPaddingBuf = OPENSSL_malloc(rsaSize);
        err = noPaddingBuf == NULL;
    }
    if (err == 0) {
        err = RAND_bytes(noPaddingBuf, rsaSize) == 0;
    }
    if (err == 0) {
        /* Set the MSB to 0 so there's no chance the number is too large for the
           RSA modulus. */
        noPaddingBuf[0] = 0;
    }

    if (err == 0) {
        testVectors[0] = (TestVector){RSA_PKCS1_PADDING, "RSA_PKCS1_PADDING",
                                      buf, sizeof(buf)};
        testVectors[1] = (TestVector){RSA_PKCS1_OAEP_PADDING,
                                      "RSA_PKCS1_OAEP_PADDING", buf,
                                      sizeof(buf)};
        /* OpenSSL requires the to/from buffers to be the same size when doing
           RSA encrypt/decrypt with no padding. */
        testVectors[2] = (TestVector){RSA_NO_PADDING, "RSA_NO_PADDING",
                                      noPaddingBuf, rsaSize};
    }

    for (; err == 0 && i < numTestVectors; ++i) {
        PRINT_MSG(testVectors[i].padName);
        switch (testType) {
            case PRIVATE_ENCRYPT:
                if (testVectors[i].padding == RSA_PKCS1_OAEP_PADDING) {
                    /* OpenSSL doesn't support OAEP padding for private
                       encrypt. */
                    continue;
                }
                if (err == 0) {
                    PRINT_MSG("Private encrypt with wolfengine");
                    PRINT_MSG(testVectors[i].padName);
                    encryptedLen = RSA_private_encrypt(testVectors[i].inBufLen,
                                                       testVectors[i].inBuf,
                                                       encryptedBuf, weRsaKey,
                                                       testVectors[i].padding);
                    err = encryptedLen <= 0;
                }
                if (err == 0) {
                    PRINT_MSG("Public decrypt with OpenSSL");
                    decryptedLen = RSA_public_decrypt(encryptedLen,
                                                      encryptedBuf,
                                                      decryptedBuf, osslRsaKey,
                                                      testVectors[i].padding);
                    err = decryptedLen <= 0;
                }
                break;
            case PRIVATE_DECRYPT:
                if (err == 0) {
                    PRINT_MSG("Public encrypt with OpenSSL");
                    encryptedLen = RSA_public_encrypt(testVectors[i].inBufLen,
                                                      testVectors[i].inBuf,
                                                      encryptedBuf, osslRsaKey,
                                                      testVectors[i].padding);
                    err = encryptedLen <= 0;
                }
                if (err == 0) {
                    PRINT_MSG("Private decrypt with wolfengine");
                    decryptedLen = RSA_private_decrypt(encryptedLen,
                                                       encryptedBuf,
                                                       decryptedBuf, weRsaKey,
                                                       testVectors[i].padding);
                    err = decryptedLen <= 0;
                }
                break;
            case PUBLIC_ENCRYPT:
                if (err == 0) {
                    PRINT_MSG("Public encrypt with wolfengine");
                    PRINT_MSG(testVectors[i].padName);
                    encryptedLen = RSA_public_encrypt(testVectors[i].inBufLen,
                                                      testVectors[i].inBuf,
                                                      encryptedBuf, weRsaKey,
                                                      testVectors[i].padding);
                    err = encryptedLen <= 0;
                }
                if (err == 0) {
                    PRINT_MSG("Private decrypt with OpenSSL");
                    decryptedLen = RSA_private_decrypt(encryptedLen,
                                                       encryptedBuf,
                                                       decryptedBuf, osslRsaKey,
                                                       testVectors[i].padding);
                    err = decryptedLen <= 0;
                }
                break;
            case PUBLIC_DECRYPT:
                if (testVectors[i].padding == RSA_PKCS1_OAEP_PADDING) {
                    /* OpenSSL doesn't support OAEP padding for private
                       encrypt. */
                    continue;
                }
                if (err == 0) {
                    PRINT_MSG("Private encrypt with OpenSSL");
                    PRINT_MSG(testVectors[i].padName);
                    encryptedLen = RSA_private_encrypt(testVectors[i].inBufLen,
                                                       testVectors[i].inBuf,
                                                       encryptedBuf, osslRsaKey,
                                                       testVectors[i].padding);
                    err = encryptedLen <= 0;
                }
                if (err == 0) {
                    PRINT_MSG("Public decrypt with wolfengine");
                    decryptedLen = RSA_public_decrypt(encryptedLen,
                                                      encryptedBuf,
                                                      decryptedBuf, weRsaKey,
                                                      testVectors[i].padding);
                    err = decryptedLen <= 0;
                }
                break;
            default:
                PRINT_MSG("test_rsa_direct: unsupported test type.");
                err = 1;
                break;
        }
        if (err == 0) {
            err = decryptedLen != testVectors[i].inBufLen;
        }
        if (err == 0) {
            err = memcmp(decryptedBuf, testVectors[i].inBuf,
                         decryptedLen) != 0;
        }
    }

    RSA_free(weRsaKey);
    RSA_free(osslRsaKey);

    if (encryptedBuf)
        OPENSSL_free(encryptedBuf);
    if (decryptedBuf)
        OPENSSL_free(decryptedBuf);
    if (noPaddingBuf)
        OPENSSL_free(noPaddingBuf);

    return err;
}

int test_rsa_direct_key_gen(ENGINE *e, void *data)
{
    int err = 0;
    RSA *rsaKey = NULL;
    BIGNUM *pubExp = NULL;
    const int bits = 2048;
    BIGNUM *n = NULL;
    BIGNUM *pubExpFromKey = NULL;

    (void)data;

    rsaKey = RSA_new_method(e);
    err = rsaKey == NULL;
    if (err == 0) {
        pubExp = BN_new();
        err = pubExp == NULL;
    }
    if (err == 0) {
        err = BN_set_word(pubExp, 65537) != 1;
    }
    if (err == 0) {
        PRINT_MSG("Generate RSA key with wolfEngine");
        err = RSA_generate_key_ex(rsaKey, bits, pubExp, NULL) == 0;
    }
    if (err == 0) {
        PRINT_MSG("Verify parameters were used");
        RSA_get0_key(rsaKey, (const BIGNUM **)&n,
                     (const BIGNUM **)&pubExpFromKey, NULL);
        err = BN_num_bits(n) != bits;
    }
    if (err == 0) {
        err = BN_cmp(pubExp, pubExpFromKey) != 0;
    }

    return err;
}

int test_rsa_direct_priv_enc(ENGINE *e, void *data)
{
    (void)data;

    return test_rsa_direct(e, PRIVATE_ENCRYPT);
}

int test_rsa_direct_priv_dec(ENGINE *e, void *data)
{
    (void)data;

    return test_rsa_direct(e, PRIVATE_DECRYPT);
}

int test_rsa_direct_pub_enc(ENGINE *e, void *data)
{
    (void)data;

    return test_rsa_direct(e, PUBLIC_ENCRYPT);
}

int test_rsa_direct_pub_dec(ENGINE *e, void *data)
{
    (void)data;

    return test_rsa_direct(e, PUBLIC_DECRYPT);
}

#ifdef WE_HAVE_EVP_PKEY

static int test_rsa_sign_verify_pad(ENGINE *e, int padMode)
{
    int err;
    int res;
    EVP_PKEY *pkey = NULL;
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
    const RSA *rsaKey = NULL;
#else
    RSA *rsaKey = NULL;
#endif
    unsigned char *rsaSig = NULL;
    size_t rsaSigLen = 0;
    size_t bufLen = 20;
    unsigned char *buf = NULL;
    const unsigned char *p = rsa_key_der_2048;

    PRINT_MSG("Load RSA key");    
    pkey = d2i_PrivateKey(EVP_PKEY_RSA, NULL, &p, sizeof(rsa_key_der_2048));
    err = pkey == NULL;
    if (err == 0) {
        rsaKey = EVP_PKEY_get0_RSA(pkey);
        err = rsaKey == NULL;
    }
    if (err == 0) {
        rsaSigLen = RSA_size(rsaKey);
        rsaSig = OPENSSL_malloc(rsaSigLen);
        err = rsaSig == NULL;
    }
    if (err == 0) {
        if (padMode == RSA_NO_PADDING) {
            bufLen = rsaSigLen;
        }
        buf = (unsigned char *)OPENSSL_malloc(bufLen);
        err = buf == NULL;
    }
    if (err == 0) {
        err = RAND_bytes(buf, (int)bufLen) == 0;
    }
     if (err == 0 && padMode == RSA_NO_PADDING) {
        /* Set the MSB to 0 so there's no chance the number is too large for the
           RSA modulus. */
        buf[0] = 0;
    }

    /* Don't run these first tests in the case of PSS, which is strictly for
       signatures and not arbitrary data. */
    if ((err == 0) && (padMode != RSA_PKCS1_PSS_PADDING)) {
        PRINT_MSG("Test signing/verifying arbitrary data");
        PRINT_MSG("Sign with OpenSSL");
        err = test_pkey_sign(pkey, NULL, buf, bufLen, rsaSig, &rsaSigLen,
                             padMode);
    }
    if ((err == 0) && (padMode != RSA_PKCS1_PSS_PADDING)) {
        PRINT_MSG("Verify with wolfengine");
        err = test_pkey_verify(pkey, e, buf, bufLen, rsaSig, rsaSigLen,
                               padMode);
    }
    if ((err == 0) && (padMode != RSA_PKCS1_PSS_PADDING)) {
        PRINT_MSG("Verify bad signature with wolfengine");
        rsaSig[1] ^= 0x80;
        res = test_pkey_verify(pkey, e, buf, bufLen, rsaSig, rsaSigLen,
                               padMode);
        if (res != 1)
            err = 1;
    }
    if ((err == 0) && (padMode != RSA_PKCS1_PSS_PADDING)) {
        PRINT_MSG("Sign with wolfengine");
        rsaSigLen = RSA_size(rsaKey);
        err = test_pkey_sign(pkey, e, buf, bufLen, rsaSig, &rsaSigLen,
                             padMode);
    }
    if ((err == 0) && (padMode != RSA_PKCS1_PSS_PADDING)) {
        PRINT_MSG("Verify with OpenSSL");
        err = test_pkey_verify(pkey, NULL, buf, bufLen, rsaSig, rsaSigLen,
                               padMode);
    }

    /* OpenSSL doesn't allow RSA signatures with no padding. */
    if ((err == 0) && (padMode != RSA_NO_PADDING)) {
        PRINT_MSG("Test creating/verifying a signature");
        PRINT_MSG("Sign with OpenSSL");
        err = test_digest_sign(pkey, NULL, buf, bufLen, EVP_sha256(),
                               rsaSig, &rsaSigLen, padMode);
    }
    if ((err == 0) && (padMode != RSA_NO_PADDING)) {
        PRINT_MSG("Verify with wolfengine");
        err = test_digest_verify(pkey, e, buf, bufLen, EVP_sha256(),
                                 rsaSig, rsaSigLen, padMode);
    }
    if ((err == 0) && (padMode != RSA_NO_PADDING)) {
        PRINT_MSG("Verify bad signature with wolfengine");
        rsaSig[1] ^= 0x80;
        res = test_digest_verify(pkey, e, buf, bufLen, EVP_sha256(),
                                 rsaSig, rsaSigLen, padMode);
        if (res != 1)
            err = 1;
    }
    if ((err == 0) && (padMode != RSA_NO_PADDING)) {
        PRINT_MSG("Sign with wolfengine");
        rsaSigLen = RSA_size(rsaKey);
        err = test_digest_sign(pkey, e, buf, bufLen, EVP_sha256(),
                              rsaSig, &rsaSigLen, padMode);
    }
    if ((err == 0) && (padMode != RSA_NO_PADDING)) {
        PRINT_MSG("Verify with OpenSSL");
        err = test_digest_verify(pkey, NULL, buf, bufLen, EVP_sha256(),
                                 rsaSig, rsaSigLen, padMode);
    }

    EVP_PKEY_free(pkey);

    if (rsaSig)
        OPENSSL_free(rsaSig);
    if (buf)
        OPENSSL_free(buf);

    return err;
}

int test_rsa_sign_verify_pkcs1(ENGINE *e, void *data)
{
    (void)data;

    return test_rsa_sign_verify_pad(e, RSA_PKCS1_PADDING);
}

int test_rsa_sign_verify_no_pad(ENGINE *e, void *data)
{
    (void)data;

#if OPENSSL_VERSION_NUMBER < 0x30000000L
    return test_rsa_sign_verify_pad(e, RSA_NO_PADDING);
#else
    (void)e;
    return 0;
#endif
}

int test_rsa_sign_verify_pss(ENGINE *e, void *data)
{
    (void)data;

    return test_rsa_sign_verify_pad(e, RSA_PKCS1_PSS_PADDING);
}

static int test_rsa_enc_dec(ENGINE *e, int padMode)
{
    int err;
    int res;
    EVP_PKEY *pkey = NULL;
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
    const RSA *rsaKey = NULL;
#else
    RSA *rsaKey = NULL;
#endif
    unsigned char *rsaEnc = NULL;
    size_t rsaEncLen = 0;
    size_t bufLen = 20;
    unsigned char *buf = NULL;
    const unsigned char *p = rsa_key_der_2048;

    PRINT_MSG("Load RSA key");    
    pkey = d2i_PrivateKey(EVP_PKEY_RSA, NULL, &p, sizeof(rsa_key_der_2048));
    err = pkey == NULL;
    if (err == 0) {
        rsaKey = EVP_PKEY_get0_RSA(pkey);
        err = rsaKey == NULL;
    }
    if (err == 0) {
        rsaEncLen = RSA_size(rsaKey);
        rsaEnc = OPENSSL_malloc(rsaEncLen);
        err = rsaEnc == NULL;
    }
    if (err == 0) {
        if (padMode == RSA_NO_PADDING) {
            bufLen = rsaEncLen;
        }
        buf = (unsigned char *)OPENSSL_malloc(bufLen);
        err = buf == NULL;
    }
    if (err == 0) {
        err = RAND_bytes(buf, (int)bufLen) == 0;
    }
     if (err == 0 && padMode == RSA_NO_PADDING) {
        /* Set the MSB to 0 so there's no chance the number is too large for the
           RSA modulus. */
        buf[0] = 0;
    }

    if (err == 0) {
        PRINT_MSG("Test encrypt/decrypt arbitrary data");
        PRINT_MSG("Encrypt with OpenSSL");
        err = test_pkey_enc(pkey, NULL, buf, bufLen, rsaEnc, rsaEncLen,
                            padMode);
    }
    if (err == 0) {
        PRINT_MSG("Decrypt with wolfengine");
        err = test_pkey_dec(pkey, e, buf, bufLen, rsaEnc, rsaEncLen,
                            padMode);
    }
    if (err == 0) {
        PRINT_MSG("Decrypt bad cipher text with wolfengine");
        rsaEnc[1] ^= 0x80;
        res = test_pkey_dec(pkey, e, buf, bufLen, rsaEnc, rsaEncLen,
                            padMode);
        if (res != 1)
            err = 1;
    }
    if (err == 0) {
        PRINT_MSG("Encrypt with wolfengine");
        rsaEncLen = RSA_size(rsaKey);
        err = test_pkey_enc(pkey, e, buf, bufLen, rsaEnc, rsaEncLen,
                            padMode);
    }
    if (err == 0) {
        PRINT_MSG("Decrypt with OpenSSL");
        err = test_pkey_dec(pkey, NULL, buf, bufLen, rsaEnc, rsaEncLen,
                            padMode);
    }

    EVP_PKEY_free(pkey);

    if (rsaEnc)
        OPENSSL_free(rsaEnc);
    if (buf)
        OPENSSL_free(buf);

    return err;
}

int test_rsa_enc_dec_pkcs1(ENGINE *e, void *data)
{
    (void)data;

    return test_rsa_enc_dec(e, RSA_PKCS1_PADDING);
}

int test_rsa_enc_dec_no_pad(ENGINE *e, void *data)
{
    (void)data;

    return test_rsa_enc_dec(e, RSA_NO_PADDING);
}

int test_rsa_enc_dec_oaep(ENGINE *e, void *data)
{
    (void)data;

    return test_rsa_enc_dec(e, RSA_PKCS1_OAEP_PADDING);
}

int test_rsa_pkey_keygen(ENGINE *e, void *data)
{
    int err;
    EVP_PKEY_CTX *ctx = NULL;
    EVP_PKEY *pkey = NULL;
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
    const RSA *rsaKey = NULL;
#else
    RSA *rsaKey = NULL;
#endif
    BIGNUM *eCmd = NULL;
    BIGNUM *n = NULL;
    BIGNUM *eKey = NULL;
    const int newKeySize = 1024;

    (void)data;

    err = (ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, e)) == NULL;
    if (err == 0) {
        err = EVP_PKEY_keygen_init(ctx) != 1;
    }
    if (err == 0) {
        PRINT_MSG("Change the key size w/ ctrl command");
        err = EVP_PKEY_CTX_ctrl(ctx, EVP_PKEY_RSA, EVP_PKEY_OP_KEYGEN,
                                EVP_PKEY_CTRL_RSA_KEYGEN_BITS, newKeySize,
                                NULL) <= 0;
    }
    if (err == 0) {
        err = (eCmd = BN_new()) == NULL;
    }
    if (err == 0) {
        err = BN_set_word(eCmd, 3) != 1;
    }
    if (err == 0) {
         PRINT_MSG("Change the public exponent w/ ctrl command");
        err = EVP_PKEY_CTX_ctrl(ctx, EVP_PKEY_RSA, EVP_PKEY_OP_KEYGEN,
                                EVP_PKEY_CTRL_RSA_KEYGEN_PUBEXP, 0, eCmd) <= 0;
    }
    if (err == 0) {
        PRINT_MSG("Generate RSA key w/ new parameters");
        err = EVP_PKEY_keygen(ctx, &pkey) != 1;
    }
    if (err == 0) {
        rsaKey = EVP_PKEY_get0_RSA(pkey);
        err = rsaKey == NULL;
    }
    if (err == 0) {
        PRINT_MSG("Verify new parameters were used");
        RSA_get0_key(rsaKey, (const BIGNUM **)&n, (const BIGNUM **)&eKey, NULL);
        err = BN_num_bits(n) != newKeySize;
    }
    if (err == 0) {
        err = BN_cmp(eCmd, eKey) != 0;
    }

    BN_free(eCmd);
    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(ctx);

    return err;
}

#endif /* WE_HAVE_EVP_PKEY */

#endif /* WE_HAVE_RSA */
