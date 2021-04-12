/* test_ecc.c
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

#ifdef WE_HAVE_ECC

#if defined(WE_HAVE_ECDSA) || defined(WE_HAVE_ECDH)

#ifdef WE_HAVE_EC_P192
static const unsigned char ecc_key_der_192[] = {
    0x30, 0x5F, 0x02, 0x01, 0x01, 0x04, 0x18, 0xA8, 0x57, 0x41,
    0x64, 0xE3, 0xD3, 0xD4, 0xFB, 0xB4, 0x5F, 0x78, 0xF4, 0x81,
    0x04, 0xDE, 0x03, 0x64, 0x56, 0xDA, 0x0D, 0x9C, 0x14, 0xB2,
    0x35, 0xA0, 0x0A, 0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D,
    0x03, 0x01, 0x01, 0xA1, 0x34, 0x03, 0x32, 0x00, 0x04, 0x99,
    0x33, 0x7F, 0x79, 0xAC, 0x23, 0xC6, 0x75, 0x27, 0x67, 0x50,
    0xAE, 0xCC, 0xC2, 0x79, 0x06, 0x1D, 0x9C, 0xB2, 0x4E, 0x81,
    0xF4, 0xA4, 0xB7, 0xB7, 0xF9, 0xF6, 0xB8, 0xC8, 0x36, 0xF9,
    0x37, 0xB2, 0x1C, 0x79, 0x55, 0xE5, 0x60, 0x3C, 0x28, 0xE7,
    0x39, 0x39, 0x31, 0xD3, 0x16, 0xB8, 0x91
};
#endif /* WE_HAVE_EC_P192 */

#ifdef WE_HAVE_EC_P224
static const unsigned char ecc_key_der_224[] = {
    0x30, 0x68, 0x02, 0x01, 0x01, 0x04, 0x1C, 0x98, 0x0A, 0x89,
    0x49, 0x7C, 0x53, 0xED, 0x13, 0xFB, 0x29, 0x58, 0x17, 0xAE,
    0x7D, 0xFB, 0xCC, 0x60, 0x96, 0xC2, 0x22, 0x1B, 0xD4, 0x0A,
    0xE6, 0x9D, 0x88, 0x1F, 0x15, 0xA0, 0x07, 0x06, 0x05, 0x2B,
    0x81, 0x04, 0x00, 0x21, 0xA1, 0x3C, 0x03, 0x3A, 0x00, 0x04,
    0x77, 0x9A, 0xAF, 0x71, 0xA6, 0x5F, 0xC1, 0x26, 0x85, 0x9B,
    0x87, 0x6C, 0x5B, 0x89, 0x67, 0x35, 0xB4, 0x61, 0xBD, 0xA2,
    0x4E, 0xA2, 0x58, 0x8E, 0x9D, 0xE2, 0x7A, 0xFE, 0xFE, 0xF1,
    0x2F, 0x6A, 0xFB, 0x8C, 0x85, 0x4F, 0x99, 0xAE, 0x07, 0x67,
    0x97, 0x24, 0x12, 0xAF, 0x7E, 0x9D, 0x3F, 0x5C, 0x84, 0x54,
    0x78, 0x82, 0x7A, 0xD4, 0x83, 0x8C
};
#endif /* WE_HAVE_EC_P224 */

#ifdef WE_HAVE_EC_P256
static const unsigned char ecc_key_der_256[] = {
    0x30, 0x77, 0x02, 0x01, 0x01, 0x04, 0x20, 0x45, 0xB6, 0x69,
    0x02, 0x73, 0x9C, 0x6C, 0x85, 0xA1, 0x38, 0x5B, 0x72, 0xE8,
    0xE8, 0xC7, 0xAC, 0xC4, 0x03, 0x8D, 0x53, 0x35, 0x04, 0xFA,
    0x6C, 0x28, 0xDC, 0x34, 0x8D, 0xE1, 0xA8, 0x09, 0x8C, 0xA0,
    0x0A, 0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01,
    0x07, 0xA1, 0x44, 0x03, 0x42, 0x00, 0x04, 0xBB, 0x33, 0xAC,
    0x4C, 0x27, 0x50, 0x4A, 0xC6, 0x4A, 0xA5, 0x04, 0xC3, 0x3C,
    0xDE, 0x9F, 0x36, 0xDB, 0x72, 0x2D, 0xCE, 0x94, 0xEA, 0x2B,
    0xFA, 0xCB, 0x20, 0x09, 0x39, 0x2C, 0x16, 0xE8, 0x61, 0x02,
    0xE9, 0xAF, 0x4D, 0xD3, 0x02, 0x93, 0x9A, 0x31, 0x5B, 0x97,
    0x92, 0x21, 0x7F, 0xF0, 0xCF, 0x18, 0xDA, 0x91, 0x11, 0x02,
    0x34, 0x86, 0xE8, 0x20, 0x58, 0x33, 0x0B, 0x80, 0x34, 0x89,
    0xD8
};
#endif /* WE_HAVE_EC_P256 */

#ifdef WE_HAVE_EC_P384
static const unsigned char ecc_key_der_384[] = {
    0x30, 0x81, 0xA4, 0x02, 0x01, 0x01, 0x04, 0x30, 0x7B, 0x16,
    0xE3, 0xD6, 0xD2, 0x81, 0x94, 0x6C, 0x8A, 0xDD, 0xA8, 0x78,
    0xEE, 0xC7, 0x7E, 0xB3, 0xC5, 0xD1, 0xDB, 0x2E, 0xF3, 0xED,
    0x0E, 0x48, 0x85, 0xB1, 0xF2, 0xE1, 0x7A, 0x39, 0x56, 0xC0,
    0xF1, 0x62, 0x12, 0x0F, 0x35, 0xB7, 0x39, 0xBC, 0x9C, 0x25,
    0xC0, 0x76, 0xEB, 0xFE, 0x55, 0x70, 0xA0, 0x07, 0x06, 0x05,
    0x2B, 0x81, 0x04, 0x00, 0x22, 0xA1, 0x64, 0x03, 0x62, 0x00,
    0x04, 0xEE, 0x82, 0xD4, 0x39, 0x9A, 0xB1, 0x27, 0x82, 0xF4,
    0xD7, 0xEA, 0xC6, 0xBC, 0x03, 0x1D, 0x4D, 0x83, 0x61, 0xF4,
    0x03, 0xAE, 0x7E, 0xBD, 0xD8, 0x5A, 0xA5, 0xB9, 0xF0, 0x8E,
    0xA2, 0xA5, 0xDA, 0xCE, 0x87, 0x3B, 0x5A, 0xAB, 0x44, 0x16,
    0x9C, 0xF5, 0x9F, 0x62, 0xDD, 0xF6, 0x20, 0xCD, 0x9C, 0x76,
    0x3C, 0x40, 0xB1, 0x3F, 0x97, 0x17, 0xDF, 0x59, 0xF6, 0xCD,
    0xDE, 0xCD, 0x46, 0x35, 0xC0, 0xED, 0x5E, 0x2E, 0x48, 0xB6,
    0x66, 0x91, 0x71, 0x74, 0xB7, 0x0C, 0x3F, 0xB9, 0x9A, 0xB7,
    0x83, 0xBD, 0x93, 0x3F, 0x5F, 0x50, 0x2D, 0x70, 0x3F, 0xDE,
    0x35, 0x25, 0xE1, 0x90, 0x3B, 0x86, 0xE0
};
#endif /* WE_HAVE_EC_P384 */

#ifdef WE_HAVE_EC_P521
static const unsigned char ecc_key_der_521[] = {
    0x30, 0x81, 0xDC, 0x02, 0x01, 0x01, 0x04, 0x42, 0x01, 0x20,
    0x39, 0x65, 0x17, 0x39, 0xC7, 0xD5, 0x51, 0x2C, 0x38, 0x28,
    0x71, 0x44, 0xBC, 0x74, 0x65, 0x1F, 0x0F, 0x22, 0xEA, 0xF4,
    0xF4, 0xC0, 0xC0, 0xB6, 0x42, 0x6B, 0xF1, 0x8B, 0x59, 0xCF,
    0x9A, 0x0F, 0x99, 0x57, 0x9F, 0x64, 0x2F, 0x2C, 0x7A, 0x55,
    0xDA, 0x11, 0x7F, 0x07, 0xC9, 0x2A, 0x6B, 0xD4, 0x50, 0x67,
    0x17, 0x1E, 0x4A, 0x48, 0x5D, 0xD6, 0xEA, 0x94, 0x3A, 0x3C,
    0x17, 0x95, 0x22, 0x07, 0xA0, 0x07, 0x06, 0x05, 0x2B, 0x81,
    0x04, 0x00, 0x23, 0xA1, 0x81, 0x89, 0x03, 0x81, 0x86, 0x00,
    0x04, 0x01, 0x87, 0x6D, 0xF1, 0x43, 0x50, 0xB8, 0xA8, 0xD9,
    0x6F, 0x70, 0xBB, 0x0A, 0xEB, 0x42, 0x2B, 0xCE, 0x31, 0x33,
    0xF6, 0x15, 0xD0, 0xD5, 0x95, 0x42, 0x44, 0x87, 0xF1, 0x3D,
    0xB7, 0x5F, 0x17, 0x69, 0xBE, 0xEF, 0xDF, 0x8D, 0xB7, 0xCF,
    0x73, 0xAA, 0xF3, 0x34, 0xD1, 0xEA, 0xEA, 0x1B, 0x74, 0xCC,
    0x64, 0x12, 0x17, 0xEF, 0x56, 0x77, 0xED, 0xC0, 0x83, 0xF9,
    0xA8, 0x1F, 0x4C, 0x01, 0xC5, 0x05, 0x7A, 0x01, 0x31, 0xF6,
    0x84, 0xAB, 0x6A, 0xB8, 0x9B, 0x94, 0xFB, 0xFE, 0x42, 0xAF,
    0x50, 0x46, 0x8B, 0x00, 0x8F, 0xE2, 0xB1, 0x94, 0xB8, 0xC2,
    0xFF, 0x57, 0x2D, 0x90, 0x77, 0xB5, 0x09, 0x9A, 0x36, 0xEB,
    0x14, 0xB8, 0x5B, 0x89, 0x73, 0xA9, 0x8C, 0x0B, 0x04, 0xB4,
    0xDC, 0xDF, 0xA7, 0x3B, 0x60, 0xD6, 0x8E, 0x89, 0x0C, 0xCB,
    0x48, 0x4B, 0xB0, 0xDC, 0x0B, 0x9E, 0x31, 0x44, 0x58, 0x54,
    0x2D, 0xF4, 0x15
};
#endif /* WE_HAVE_EC_P521 */
#endif /* WE_HAVE_ECDSA || WE_HAVE_ECDH */
#ifdef WE_HAVE_ECDH

#ifdef WE_HAVE_EC_P192
static const unsigned char ecc_peerkey_der_192[] = {
    0x30, 0x5F, 0x02, 0x01, 0x01, 0x04, 0x18, 0x7D, 0x26, 0xEB,
    0x62, 0x0A, 0xE8, 0x75, 0x13, 0xE0, 0xBC, 0x3F, 0x35, 0xEB,
    0x07, 0x59, 0x1E, 0x48, 0xF1, 0x09, 0xAE, 0xEC, 0x1B, 0x1C,
    0x1F, 0xA0, 0x0A, 0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D,
    0x03, 0x01, 0x01, 0xA1, 0x34, 0x03, 0x32, 0x00, 0x04, 0x4B,
    0x14, 0xE6, 0x8B, 0x18, 0xEC, 0x44, 0x63, 0xB6, 0x79, 0xB8,
    0x67, 0x32, 0xD3, 0x21, 0x96, 0x06, 0x27, 0x78, 0x5B, 0x24,
    0xC0, 0xCA, 0x52, 0xAF, 0xE5, 0x55, 0x59, 0x5E, 0xC1, 0x22,
    0xD2, 0x0B, 0xBB, 0xBE, 0xA7, 0x1C, 0x99, 0x92, 0x95, 0xA2,
    0x56, 0x5B, 0x34, 0x7B, 0xD9, 0x6D, 0xC3
};

static const unsigned char ecc_derived_192[] = {
    0xE2, 0x5D, 0x04, 0x8E, 0x6D, 0x0C, 0xBD, 0x4E, 0x38, 0xBB,
    0x23, 0x1C, 0x0B, 0xF3, 0x22, 0x8D, 0x5E, 0x7C, 0x21, 0x71,
    0x39, 0xEB, 0x8E, 0x37
};
#endif /* WE_HAVE_EC_P192 */

#ifdef WE_HAVE_EC_P224
static const unsigned char ecc_peerkey_der_224[] = {
    0x30, 0x68, 0x02, 0x01, 0x01, 0x04, 0x1C, 0xC4, 0xAB, 0x52,
    0x75, 0xAA, 0x54, 0xA8, 0x7D, 0x1C, 0x0C, 0x25, 0xE9, 0xE9,
    0x4B, 0x3D, 0x75, 0xEB, 0xB2, 0xEF, 0x65, 0x17, 0x11, 0x05,
    0x17, 0x74, 0xDF, 0xCF, 0xDA, 0xA0, 0x07, 0x06, 0x05, 0x2B,
    0x81, 0x04, 0x00, 0x21, 0xA1, 0x3C, 0x03, 0x3A, 0x00, 0x04,
    0xBA, 0x62, 0x06, 0x6E, 0xC3, 0x8F, 0x30, 0x48, 0xBF, 0x13,
    0x14, 0xE9, 0x3E, 0xD7, 0x68, 0x67, 0xBB, 0x22, 0x97, 0x97,
    0x8E, 0xB1, 0x7B, 0xF5, 0x12, 0xE7, 0x9A, 0x27, 0x61, 0x92,
    0x9B, 0x1C, 0x70, 0xF2, 0x9D, 0x7E, 0x20, 0x5B, 0x3F, 0xCB,
    0x69, 0xE3, 0xF5, 0x3B, 0xBB, 0x97, 0xA3, 0x25, 0x31, 0xA7,
    0xBB, 0xB0, 0x8A, 0xBE, 0xF2, 0x35
};

static const unsigned char ecc_derived_224[] = {
    0xF5, 0x68, 0x43, 0x92, 0xC6, 0x0E, 0x16, 0x5A, 0x5D, 0xDF,
    0x89, 0xDA, 0xB1, 0x7E, 0x01, 0x50, 0xCD, 0x83, 0x59, 0xFD,
    0x3A, 0x7B, 0xA7, 0x82, 0xA4, 0xF5, 0xB0, 0x5F
};
#endif /* WE_HAVE_EC_P224 */

#ifdef WE_HAVE_EC_P256
static const unsigned char ecc_peerkey_der_256[] = {
    0x30, 0x77, 0x02, 0x01, 0x01, 0x04, 0x20, 0xF8, 0xCF, 0x92,
    0x6B, 0xBD, 0x1E, 0x28, 0xF1, 0xA8, 0xAB, 0xA1, 0x23, 0x4F,
    0x32, 0x74, 0x18, 0x88, 0x50, 0xAD, 0x7E, 0xC7, 0xEC, 0x92,
    0xF8, 0x8F, 0x97, 0x4D, 0xAF, 0x56, 0x89, 0x65, 0xC7, 0xA0,
    0x0A, 0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01,
    0x07, 0xA1, 0x44, 0x03, 0x42, 0x00, 0x04, 0x55, 0xBF, 0xF4,
    0x0F, 0x44, 0x50, 0x9A, 0x3D, 0xCE, 0x9B, 0xB7, 0xF0, 0xC5,
    0x4D, 0xF5, 0x70, 0x7B, 0xD4, 0xEC, 0x24, 0x8E, 0x19, 0x80,
    0xEC, 0x5A, 0x4C, 0xA2, 0x24, 0x03, 0x62, 0x2C, 0x9B, 0xDA,
    0xEF, 0xA2, 0x35, 0x12, 0x43, 0x84, 0x76, 0x16, 0xC6, 0x56,
    0x95, 0x06, 0xCC, 0x01, 0xA9, 0xBD, 0xF6, 0x75, 0x1A, 0x42,
    0xF7, 0xBD, 0xA9, 0xB2, 0x36, 0x22, 0x5F, 0xC7, 0x5D, 0x7F,
    0xB4
};

static const unsigned char ecc_derived_256[] = {
    0x18, 0x5b, 0x4d, 0x35, 0x8b, 0x70, 0x0e, 0x3c, 0xfa, 0xd1,
    0xd8, 0x8c, 0x9e, 0xcc, 0xf6, 0xb3, 0xf6, 0xf5, 0x46, 0x56,
    0xdc, 0x53, 0xea, 0x06, 0x59, 0x8e, 0xfa, 0x44, 0xd8, 0xba,
    0x2d, 0x7b
};
#endif /* WE_HAVE_EC_P256 */

#ifdef WE_HAVE_EC_P384
static const unsigned char ecc_peerkey_der_384[] = {
    0x30, 0x81, 0xA4, 0x02, 0x01, 0x01, 0x04, 0x30, 0x29, 0xf9,
    0x59, 0x0c, 0xa7, 0x03, 0x3b, 0xb8, 0x22, 0x56, 0x93, 0xe7,
    0xe8, 0x6d, 0x2c, 0x4b, 0xb6, 0x21, 0x76, 0x9d, 0xdf, 0xf8,
    0x60, 0x32, 0x72, 0xd8, 0x88, 0xce, 0xf8, 0x88, 0xf3, 0xa0,
    0x40, 0xc6, 0x24, 0x1e, 0x04, 0x92, 0xbd, 0x40, 0x1b, 0x16,
    0x26, 0x89, 0x2e, 0x7b, 0x21, 0x55, 0xA0, 0x07, 0x06, 0x05,
    0x2B, 0x81, 0x04, 0x00, 0x22, 0xA1, 0x64, 0x03, 0x62, 0x00,
    0x04, 0xbf, 0xe2, 0xf7, 0xd8, 0xe5, 0x80, 0x5d, 0x76, 0xf7,
    0x09, 0xb3, 0xcd, 0x55, 0x5e, 0xf9, 0xb7, 0x82, 0xac, 0x08,
    0xbf, 0x3c, 0x9c, 0x36, 0xd4, 0xf8, 0xf1, 0x94, 0x3d, 0x6e,
    0xa1, 0x89, 0x04, 0x44, 0x4c, 0x01, 0x79, 0x26, 0x3a, 0x0c,
    0xcf, 0x57, 0x3e, 0x1c, 0x48, 0x8a, 0xf7, 0xdc, 0xa7, 0xc8,
    0x28, 0x68, 0x5f, 0x82, 0x35, 0x4a, 0xc5, 0x20, 0x28, 0xad,
    0x42, 0x9f, 0x73, 0x47, 0x16, 0x7f, 0x47, 0x59, 0x66, 0x1d,
    0xd4, 0xc6, 0x95, 0xde, 0x37, 0x5c, 0x77, 0x77, 0x1b, 0x4a,
    0xde, 0x11, 0x03, 0xd7, 0x2f, 0x29, 0x7a, 0x6c, 0x2e, 0xcf,
    0x7b, 0x58, 0xba, 0xe3, 0x81, 0x6e, 0xdc
};

static const unsigned char ecc_derived_384[] = {
    0xf4, 0x7e, 0xe7, 0xdb, 0x13, 0x98, 0xb8, 0xce, 0xd0, 0x41,
    0xfa, 0xd8, 0x7a, 0xfd, 0x07, 0x77, 0x6d, 0x2c, 0x76, 0x0b,
    0x42, 0xed, 0x89, 0xdf, 0x7e, 0x24, 0xfd, 0xaf, 0x47, 0x94,
    0x6c, 0xab, 0x0f, 0x7f, 0x60, 0x3e, 0xc4, 0xc8, 0xf3, 0x0e,
    0xd1, 0x73, 0x7d, 0x3a, 0x11, 0x91, 0x6e, 0x3c
};
#endif /* WE_HAVE_EC_P384 */

#ifdef WE_HAVE_EC_P521
static const unsigned char ecc_peerkey_der_521[] = {
    0x30, 0x81, 0xDC, 0x02, 0x01, 0x01, 0x04, 0x42, 0x00, 0x17,
    0xD2, 0x97, 0xF9, 0xBE, 0x0E, 0x1A, 0xF3, 0x1A, 0x36, 0xC0,
    0xAE, 0x24, 0xFD, 0x96, 0x35, 0x31, 0x21, 0xD4, 0xB1, 0x95,
    0x1B, 0xA8, 0x9E, 0x1D, 0xB0, 0xA6, 0x54, 0x4B, 0x3D, 0x33,
    0x76, 0x88, 0x9A, 0x4C, 0x1A, 0x8B, 0xEC, 0x96, 0x7E, 0xEC,
    0x4E, 0xC8, 0xC9, 0xDE, 0x7B, 0xCA, 0x0D, 0x87, 0x92, 0xD2,
    0xA9, 0x3F, 0x19, 0xA5, 0x31, 0x34, 0x6E, 0xD1, 0x6F, 0x1B,
    0x46, 0x9A, 0x6F, 0x00, 0xA0, 0x07, 0x06, 0x05, 0x2B, 0x81,
    0x04, 0x00, 0x23, 0xA1, 0x81, 0x89, 0x03, 0x81, 0x86, 0x00,
    0x04, 0x00, 0x71, 0x53, 0x4C, 0x65, 0x53, 0xEA, 0xD4, 0x4A,
    0x5F, 0x47, 0xD6, 0x48, 0xBA, 0xED, 0x1C, 0xC6, 0xF6, 0xC3,
    0xF0, 0x3E, 0x22, 0xB6, 0x3C, 0x84, 0x6A, 0xF6, 0xE4, 0x22,
    0x64, 0xF0, 0xFB, 0xF2, 0xB3, 0xAD, 0x99, 0x31, 0x45, 0x2C,
    0xC4, 0x1A, 0x18, 0xF6, 0x97, 0xCD, 0x22, 0xDA, 0xD3, 0xAA,
    0x3F, 0x64, 0x8C, 0x2C, 0xAE, 0x87, 0xE3, 0xE0, 0xD7, 0xE8,
    0x41, 0x05, 0x84, 0xA0, 0xDE, 0x0C, 0xD8, 0x00, 0x3B, 0x6F,
    0x2B, 0x94, 0x8F, 0x75, 0xC1, 0x39, 0x93, 0xDE, 0xD9, 0xB7,
    0x6D, 0x45, 0x6C, 0xDE, 0xCA, 0xCB, 0x65, 0x6E, 0xBA, 0x60,
    0x3F, 0x36, 0x70, 0xD1, 0x08, 0x28, 0x86, 0x49, 0x7F, 0x79,
    0x17, 0x57, 0x7B, 0x71, 0x2F, 0xCB, 0xB2, 0x3C, 0xBA, 0xE1,
    0xFF, 0xAA, 0x27, 0x29, 0xB7, 0x70, 0x2F, 0x4E, 0x32, 0x4B,
    0x86, 0xE7, 0x38, 0x66, 0x7B, 0xA5, 0x48, 0xB1, 0xA0, 0x08,
    0xD4, 0x20, 0x9A
};

static const unsigned char ecc_derived_521[] = {
    0x00, 0xD6, 0x7C, 0x04, 0xAC, 0xF7, 0x70, 0x65, 0x82, 0xA5,
    0x34, 0x87, 0x67, 0x23, 0x5F, 0xD5, 0xD0, 0x1F, 0x7F, 0x28,
    0x3B, 0xF3, 0x01, 0xBE, 0x77, 0x0F, 0x50, 0x73, 0xF3, 0x6E,
    0x70, 0x4D, 0xC6, 0x35, 0x0D, 0x8D, 0xBA, 0xC2, 0x8C, 0x37,
    0xA0, 0x79, 0x49, 0x54, 0xBF, 0x52, 0xCA, 0xF4, 0x60, 0x2B,
    0xC2, 0xCD, 0x3E, 0xED, 0xDA, 0x5F, 0xB5, 0xFE, 0x53, 0xDD,
    0x1A, 0xA5, 0xDB, 0x71, 0x4A, 0xCD
};
#endif /* WE_HAVE_EC_P384 */
#endif /* WE_HAVE_ECDH */

#ifdef WE_HAVE_EVP_PKEY

#ifdef WE_HAVE_ECKEYGEN

#ifdef WE_HAVE_EC_P192
int test_eckeygen_p192_by_nid(ENGINE *e, void *data)
{
    int err;
    EVP_PKEY_CTX *ctx = NULL;
    EVP_PKEY *key = NULL;

    (void)data;

    PRINT_MSG("Create P-192 public key context");
    err = (ctx = EVP_PKEY_CTX_new_id(NID_X9_62_prime192v1, e)) == NULL;
    if (err == 0) {
        PRINT_MSG("Initialize key generation");
        err = EVP_PKEY_keygen_init(ctx) != 1;
    }
    if (err == 0) {
        PRINT_MSG("Generate key");
        err = EVP_PKEY_keygen(ctx, &key) != 1;
    }

    EVP_PKEY_free(key);
    EVP_PKEY_CTX_free(ctx);

    return err;
}

int test_eckeygen_p192(ENGINE *e, void *data)
{
    int err;
    EVP_PKEY_CTX *ctx = NULL;
    EVP_PKEY *key = NULL;

    (void)data;

    PRINT_MSG("Create public key context");
    err = (ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, e)) == NULL;
    if (err == 0) {
        PRINT_MSG("Initialize key generation");
        err = EVP_PKEY_keygen_init(ctx) != 1;
    }
    if (err == 0) {
        PRINT_MSG("Set named curve NID");
        err = EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx,
                                                     NID_X9_62_prime192v1) != 1;
    }
    if (err == 0) {
        PRINT_MSG("Generate key");
        err = EVP_PKEY_keygen(ctx, &key) != 1;
    }

    EVP_PKEY_free(key);
    EVP_PKEY_CTX_free(ctx);

    return err;
}
#endif /* WE_HAVE_EC_P192 */

#ifdef WE_HAVE_EC_P224
int test_eckeygen_p224_by_nid(ENGINE *e, void *data)
{
    int err;
    EVP_PKEY_CTX *ctx = NULL;
    EVP_PKEY *key = NULL;

    (void)data;

    PRINT_MSG("Create P-224 public key context");
    err = (ctx = EVP_PKEY_CTX_new_id(NID_secp224r1, e)) == NULL;
    if (err == 0) {
        PRINT_MSG("Initialize key generation");
        err = EVP_PKEY_keygen_init(ctx) != 1;
    }
    if (err == 0) {
        PRINT_MSG("Generate key");
        err = EVP_PKEY_keygen(ctx, &key) != 1;
    }

    EVP_PKEY_free(key);
    EVP_PKEY_CTX_free(ctx);

    return err;
}

int test_eckeygen_p224(ENGINE *e, void *data)
{
    int err;
    EVP_PKEY_CTX *ctx = NULL;
    EVP_PKEY *key = NULL;

    (void)data;

    PRINT_MSG("Create public key context");
    err = (ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, e)) == NULL;
    if (err == 0) {
        PRINT_MSG("Initialize key generation");
        err = EVP_PKEY_keygen_init(ctx) != 1;
    }
    if (err == 0) {
        PRINT_MSG("Set named curve NID");
        err = EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx,
                                                     NID_secp224r1) != 1;
    }
    if (err == 0) {
        PRINT_MSG("Generate key");
        err = EVP_PKEY_keygen(ctx, &key) != 1;
    }

    EVP_PKEY_free(key);
    EVP_PKEY_CTX_free(ctx);

    return err;
}
#endif /* WE_HAVE_EC_P224 */

#ifdef WE_HAVE_EC_P256
int test_eckeygen_p256_by_nid(ENGINE *e, void *data)
{
    int err;
    EVP_PKEY_CTX *ctx = NULL;
    EVP_PKEY *key = NULL;

    (void)data;

    PRINT_MSG("Create P-256 public key context");
    err = (ctx = EVP_PKEY_CTX_new_id(NID_X9_62_prime256v1, e)) == NULL;
    if (err == 0) {
        PRINT_MSG("Initialize key generation");
        err = EVP_PKEY_keygen_init(ctx) != 1;
    }
    if (err == 0) {
        PRINT_MSG("Generate key");
        err = EVP_PKEY_keygen(ctx, &key) != 1;
    }

    EVP_PKEY_free(key);
    EVP_PKEY_CTX_free(ctx);

    return err;
}

int test_eckeygen_p256(ENGINE *e, void *data)
{
    int err;
    EVP_PKEY_CTX *ctx = NULL;
    EVP_PKEY *key = NULL;

    (void)data;

    PRINT_MSG("Create public key context");
    err = (ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, e)) == NULL;
    if (err == 0) {
        PRINT_MSG("Initialize key generation");
        err = EVP_PKEY_keygen_init(ctx) != 1;
    }
    if (err == 0) {
        PRINT_MSG("Set named curve NID");
        err = EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx,
                                                     NID_X9_62_prime256v1) != 1;
    }
    if (err == 0) {
        PRINT_MSG("Generate key");
        err = EVP_PKEY_keygen(ctx, &key) != 1;
    }

    EVP_PKEY_free(key);
    EVP_PKEY_CTX_free(ctx);

    return err;
}
#endif /* WE_HAVE_EC_P256 */

#ifdef WE_HAVE_EC_P384
int test_eckeygen_p384_by_nid(ENGINE *e, void *data)
{
    int err;
    EVP_PKEY_CTX *ctx = NULL;
    EVP_PKEY *key = NULL;

    (void)data;

    PRINT_MSG("Create P-384 public key context");
    err = (ctx = EVP_PKEY_CTX_new_id(NID_secp384r1, e)) == NULL;
    if (err == 0) {
        PRINT_MSG("Initialize key generation");
        err = EVP_PKEY_keygen_init(ctx) != 1;
    }
    if (err == 0) {
        PRINT_MSG("Generate key");
        err = EVP_PKEY_keygen(ctx, &key) != 1;
    }

    EVP_PKEY_free(key);
    EVP_PKEY_CTX_free(ctx);

    return err;
}

int test_eckeygen_p384(ENGINE *e, void *data)
{
    int err;
    EVP_PKEY_CTX *ctx = NULL;
    EVP_PKEY *key = NULL;

    (void)data;

    PRINT_MSG("Create public key context");
    err = (ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, e)) == NULL;
    if (err == 0) {
        PRINT_MSG("Initialize key generation");
        err = EVP_PKEY_keygen_init(ctx) != 1;
    }
    if (err == 0) {
        PRINT_MSG("Set named curve NID");
        err = EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx, NID_secp384r1) != 1;
    }
    if (err == 0) {
        PRINT_MSG("Generate key");
        err = EVP_PKEY_keygen(ctx, &key) != 1;
    }

    EVP_PKEY_free(key);
    EVP_PKEY_CTX_free(ctx);

    return err;
}
#endif /* WE_HAVE_EC_P384 */

#ifdef WE_HAVE_EC_P521
int test_eckeygen_p521_by_nid(ENGINE *e, void *data)
{
    int err;
    EVP_PKEY_CTX *ctx = NULL;
    EVP_PKEY *key = NULL;

    (void)data;

    PRINT_MSG("Create P-521 public key context");
    err = (ctx = EVP_PKEY_CTX_new_id(NID_secp521r1, e)) == NULL;
    if (err == 0) {
        PRINT_MSG("Initialize key generation");
        err = EVP_PKEY_keygen_init(ctx) != 1;
    }
    if (err == 0) {
        PRINT_MSG("Generate key");
        err = EVP_PKEY_keygen(ctx, &key) != 1;
    }

    EVP_PKEY_free(key);
    EVP_PKEY_CTX_free(ctx);

    return err;
}

int test_eckeygen_p521(ENGINE *e, void *data)
{
    int err;
    EVP_PKEY_CTX *ctx = NULL;
    EVP_PKEY *key = NULL;

    (void)data;

    PRINT_MSG("Create public key context");
    err = (ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, e)) == NULL;
    if (err == 0) {
        PRINT_MSG("Initialize key generation");
        err = EVP_PKEY_keygen_init(ctx) != 1;
    }
    if (err == 0) {
        PRINT_MSG("Set named curve NID");
        err = EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx, NID_secp521r1) != 1;
    }
    if (err == 0) {
        PRINT_MSG("Generate key");
        err = EVP_PKEY_keygen(ctx, &key) != 1;
    }

    EVP_PKEY_free(key);
    EVP_PKEY_CTX_free(ctx);

    return err;
}
#endif /* WE_HAVE_EC_P521 */

#endif /* WE_HAVE_ECKEYGEN */

#ifdef WE_HAVE_ECDH

int test_ecdh_derive(ENGINE *e, EVP_PKEY *key, EVP_PKEY *peerKey,
                     unsigned char **pSecret, size_t expLen)
{
    int err;
    EVP_PKEY_CTX *ctx = NULL;
    unsigned char *secret = NULL;
    size_t outLen;

#if OPENSSL_VERSION_NUMBER >= 0x30000000L
    err = EVP_PKEY_set1_engine(key, e) != 1;
    if (err == 0) {
        err = (ctx = EVP_PKEY_CTX_new(key, NULL)) == NULL;
    }
#else
    err = (ctx = EVP_PKEY_CTX_new(key, e)) == NULL;
#endif
    if (err == 0) {
        err = EVP_PKEY_derive_init(ctx) != 1;
    }
    if (err == 0) {
        err = EVP_PKEY_derive_set_peer(ctx, peerKey) != 1;
    }
    if (err == 0) {
        err = EVP_PKEY_derive(ctx, NULL, &outLen) != 1;
    }
    if (err == 0) {
        err = (expLen == outLen) == 0;
    }
    if (err == 0) {
        err = (secret = (unsigned char*)OPENSSL_malloc(outLen)) == NULL;
    }
    if (err == 0) {
        err = EVP_PKEY_derive(ctx, secret, &outLen) != 1;
    }
    if (err == 0) {
        *pSecret = secret;
        secret = NULL;
    }

    OPENSSL_free(secret);
    EVP_PKEY_CTX_free(ctx);

    return err;
}

#ifdef WE_HAVE_ECKEYGEN
int test_ecdh_keygen(ENGINE *e, int nid, int len)
{
    int err;
    EVP_PKEY_CTX *kgCtx = NULL;
    EVP_PKEY *keyA = NULL;
    EVP_PKEY *keyB = NULL;
    unsigned char *secretA = NULL;
    unsigned char *secretB = NULL;

    err = (kgCtx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, e)) == NULL;
    if (err == 0) {
        err = EVP_PKEY_keygen_init(kgCtx) != 1;
    }
    if (err == 0) {
        err = EVP_PKEY_CTX_set_ec_paramgen_curve_nid(kgCtx, nid) != 1;
    }
    if (err == 0) {
        err = EVP_PKEY_keygen(kgCtx, &keyA) != 1;
    }
    if (err == 0) {
        err = EVP_PKEY_keygen(kgCtx, &keyB) != 1;
    }
    if (err == 0) {
        PRINT_MSG("Derive secret A");
        err = test_ecdh_derive(e, keyA, keyB, &secretA, len);
    }
    if (err == 0) {
        PRINT_MSG("Derive secret B");
        err = test_ecdh_derive(e, keyB, keyA, &secretB, len);
    }
    if (err == 0) {
        PRINT_BUFFER("Secret A", secretA, len);
        PRINT_BUFFER("Secret B", secretB, len);
        err = memcmp(secretA, secretB, len) != 0;
        if (err != 0) {
            PRINT_ERR_MSG("Secrets do not match!");
        }
    }

    OPENSSL_free(secretA);
    OPENSSL_free(secretB);
    EVP_PKEY_free(keyB);
    EVP_PKEY_free(keyA);
    EVP_PKEY_CTX_free(kgCtx);

    return err;
}

#ifdef WE_HAVE_EC_P192
int test_ecdh_p192_keygen(ENGINE *e, void *data)
{
    (void)data;

    return test_ecdh_keygen(e, NID_X9_62_prime192v1, 24);
}
#endif /* WE_HAVE_EC_P192 */

#ifdef WE_HAVE_EC_P224
int test_ecdh_p224_keygen(ENGINE *e, void *data)
{
    (void)data;

    return test_ecdh_keygen(e, NID_secp224r1, 28);
}
#endif /* WE_HAVE_EC_P224 */

#ifdef WE_HAVE_EC_P256
int test_ecdh_p256_keygen(ENGINE *e, void *data)
{
    (void)data;

    return test_ecdh_keygen(e, NID_X9_62_prime256v1, 32);
}
#endif /* WE_HAVE_EC_P256 */

#ifdef WE_HAVE_EC_P384
int test_ecdh_p384_keygen(ENGINE *e, void *data)
{
    (void)data;

    return test_ecdh_keygen(e, NID_secp384r1, 48);
}
#endif /* WE_HAVE_EC_P384 */

#ifdef WE_HAVE_EC_P521
int test_ecdh_p521_keygen(ENGINE *e, void *data)
{
    (void)data;

    return test_ecdh_keygen(e, NID_secp521r1, 66);
}
#endif /* WE_HAVE_EC_P521 */
#endif /* WE_HAVE_ECKEYGEN */

int test_ecdh(ENGINE *e, const unsigned char *privKey, size_t len,
              const unsigned char *peerPrivKey, size_t peerLen,
              const unsigned char *derived, size_t dLen)
{
    int err = 0;
    EVP_PKEY_CTX *kgCtx = NULL;
    EVP_PKEY *keyA = NULL;
    EVP_PKEY *keyB = NULL;
    unsigned char *secretA = NULL;
    unsigned char *secretB = NULL;
    const unsigned char *p;

    p = privKey;
    keyA = d2i_PrivateKey(EVP_PKEY_EC, NULL, &p, len);
    if (keyA == NULL) {
        err = 1;
    }
    if (err == 0) {
        p = peerPrivKey;
        err = (keyB = d2i_PrivateKey(EVP_PKEY_EC, NULL, &p, peerLen)) == NULL;
    }
    if (err == 0) {
        PRINT_MSG("Derive secret A");
        err = test_ecdh_derive(e, keyA, keyB, &secretA, dLen);
    }
    if (err == 0) {
        PRINT_MSG("Derive secret B");
        err = test_ecdh_derive(e, keyB, keyA, &secretB, dLen);
    }
    if (err == 0) {
        PRINT_BUFFER("Secret A", secretA, dLen);
        PRINT_BUFFER("Secret B", secretB, dLen);
        err = memcmp(secretA, secretB, dLen) != 0;
        if (err != 0) {
            PRINT_ERR_MSG("Secrets do not match!");
        }
    }
    if (err == 0) {
        err = memcmp(secretA, derived, dLen) != 0;
        if (err != 0) {
            PRINT_ERR_MSG("Secret does not match, expected!");
        }
    }

    OPENSSL_free(secretA);
    OPENSSL_free(secretB);
    EVP_PKEY_free(keyB);
    EVP_PKEY_free(keyA);
    EVP_PKEY_CTX_free(kgCtx);

    return err;
}

#ifdef WE_HAVE_EC_P192
int test_ecdh_p192(ENGINE *e, void *data)
{
    (void)data;
    return test_ecdh(e, ecc_key_der_192, sizeof(ecc_key_der_192),
                     ecc_peerkey_der_192, sizeof(ecc_peerkey_der_192),
                     ecc_derived_192, sizeof(ecc_derived_192));
}
#endif /* WE_HAVE_EC_P192 */

#ifdef WE_HAVE_EC_P224
int test_ecdh_p224(ENGINE *e, void *data)
{
    (void)data;
    return test_ecdh(e, ecc_key_der_224, sizeof(ecc_key_der_224),
                     ecc_peerkey_der_224, sizeof(ecc_peerkey_der_224),
                     ecc_derived_224, sizeof(ecc_derived_224));
}
#endif /* WE_HAVE_EC_P224 */

#ifdef WE_HAVE_EC_P256
int test_ecdh_p256(ENGINE *e, void *data)
{
    (void)data;
    return test_ecdh(e, ecc_key_der_256, sizeof(ecc_key_der_256),
                     ecc_peerkey_der_256, sizeof(ecc_peerkey_der_256),
                     ecc_derived_256, sizeof(ecc_derived_256));
}
#endif /* WE_HAVE_EC_P256 */

#ifdef WE_HAVE_EC_P384
int test_ecdh_p384(ENGINE *e, void *data)
{
    (void)data;
    return test_ecdh(e, ecc_key_der_384, sizeof(ecc_key_der_384),
                     ecc_peerkey_der_384, sizeof(ecc_peerkey_der_384),
                     ecc_derived_384, sizeof(ecc_derived_384));
}
#endif /* WE_HAVE_EC_P384 */

#ifdef WE_HAVE_EC_P521
int test_ecdh_p521(ENGINE *e, void *data)
{
    (void)data;
    return test_ecdh(e, ecc_key_der_521, sizeof(ecc_key_der_521),
                     ecc_peerkey_der_521, sizeof(ecc_peerkey_der_521),
                     ecc_derived_521, sizeof(ecc_derived_521));
}
#endif /* WE_HAVE_EC_P521 */

#endif /* WE_HAVE_ECDH */

#ifdef WE_HAVE_ECDSA

/* Convenience function for calling test_pkey_sign without RSA-specific
   parameters. */
static int test_pkey_sign_ecc(EVP_PKEY *pkey, ENGINE *e, unsigned char *hash,
                              size_t hashLen, unsigned char *sig,
                              size_t *sigLen)
{
    return test_pkey_sign(pkey, e, hash, hashLen, sig, sigLen, 0, NULL, NULL);
}

/* Convenience function for calling test_pkey_verify without RSA-specific
   parameters. */
static int test_pkey_verify_ecc(EVP_PKEY *pkey, ENGINE *e, unsigned char *hash,
                                size_t hashLen, unsigned char *sig,
                                size_t sigLen)
{
    return test_pkey_verify(pkey, e, hash, hashLen, sig, sigLen, 0, NULL, NULL);
}

#ifdef WE_HAVE_EC_P192
int test_ecdsa_p192_pkey(ENGINE *e, void *data)
{
    int err;
    int res;
    EVP_PKEY *pkey = NULL;
    unsigned char ecdsaSig[64];
    size_t ecdsaSigLen;
    unsigned char buf[20];
    const unsigned char *p = ecc_key_der_192;

    (void)data;

    err = RAND_bytes(buf, sizeof(buf)) == 0;
    if (err == 0) {
        pkey = d2i_PrivateKey(EVP_PKEY_EC, NULL, &p, sizeof(ecc_key_der_192));
        err = pkey == NULL;
    }
    if (err == 0) {
        PRINT_MSG("Sign with OpenSSL");
        ecdsaSigLen = sizeof(ecdsaSig);
        err = test_pkey_sign_ecc(pkey, NULL, buf, sizeof(buf), ecdsaSig,
                                 &ecdsaSigLen);
    }
    if (err == 0) {
        PRINT_MSG("Verify with wolfengine");
        err = test_pkey_verify_ecc(pkey, e, buf, sizeof(buf), ecdsaSig,
                                   ecdsaSigLen);
    }
    if (err == 0) {
        PRINT_MSG("Verify bad signature with wolfengine");
        ecdsaSig[1] ^= 0x80;
        res = test_pkey_verify_ecc(pkey, e, buf, sizeof(buf), ecdsaSig,
                                   ecdsaSigLen);
        if (res != 1)
            err = 1;
    }
    if (err == 0) {
        PRINT_MSG("Sign with wolfengine");
        ecdsaSigLen = sizeof(ecdsaSig);
        err = test_pkey_sign_ecc(pkey, e, buf, sizeof(buf), ecdsaSig,
                                 &ecdsaSigLen);
    }
    if (err == 0) {
        PRINT_MSG("Verify with OpenSSL");
        err = test_pkey_verify_ecc(pkey, NULL, buf, sizeof(buf), ecdsaSig,
                                   ecdsaSigLen);
    }

    EVP_PKEY_free(pkey);

    return err;
}
#endif /* WE_HAVE_EC_P192 */

#ifdef WE_HAVE_EC_P224
int test_ecdsa_p224_pkey(ENGINE *e, void *data)
{
    int err;
    int res;
    EVP_PKEY *pkey = NULL;
    unsigned char ecdsaSig[64];
    size_t ecdsaSigLen;
    unsigned char buf[20];
    const unsigned char *p = ecc_key_der_224;

    (void)data;

    err = RAND_bytes(buf, sizeof(buf)) == 0;
    if (err == 0) {
        pkey = d2i_PrivateKey(EVP_PKEY_EC, NULL, &p, sizeof(ecc_key_der_224));
        err = pkey == NULL;
    }
    if (err == 0) {
        PRINT_MSG("Sign with OpenSSL");
        ecdsaSigLen = sizeof(ecdsaSig);
        err = test_pkey_sign_ecc(pkey, NULL, buf, sizeof(buf), ecdsaSig,
                                 &ecdsaSigLen);
    }
    if (err == 0) {
        PRINT_MSG("Verify with wolfengine");
        err = test_pkey_verify_ecc(pkey, e, buf, sizeof(buf), ecdsaSig,
                                   ecdsaSigLen);
    }
    if (err == 0) {
        PRINT_MSG("Verify bad signature with wolfengine");
        ecdsaSig[1] ^= 0x80;
        res = test_pkey_verify_ecc(pkey, e, buf, sizeof(buf), ecdsaSig,
                                   ecdsaSigLen);
        if (res != 1)
            err = 1;
    }
    if (err == 0) {
        PRINT_MSG("Sign with wolfengine");
        ecdsaSigLen = sizeof(ecdsaSig);
        err = test_pkey_sign_ecc(pkey, e, buf, sizeof(buf), ecdsaSig,
                                 &ecdsaSigLen);
    }
    if (err == 0) {
        PRINT_MSG("Verify with OpenSSL");
        err = test_pkey_verify_ecc(pkey, NULL, buf, sizeof(buf),
                                   ecdsaSig, ecdsaSigLen);
    }

    EVP_PKEY_free(pkey);

    return err;
}
#endif /* WE_HAVE_EC_P224 */

#ifdef WE_HAVE_EC_P256
int test_ecdsa_p256_pkey(ENGINE *e, void *data)
{
    int err;
    int res;
    EVP_PKEY *pkey = NULL;
    unsigned char ecdsaSig[80];
    size_t ecdsaSigLen;
    unsigned char buf[20];
    const unsigned char *p = ecc_key_der_256;

    (void)data;

    err = RAND_bytes(buf, sizeof(buf)) == 0;
    if (err == 0) {
        pkey = d2i_PrivateKey(EVP_PKEY_EC, NULL, &p, sizeof(ecc_key_der_256));
        err = pkey == NULL;
    }
    if (err == 0) {
        PRINT_MSG("Sign with OpenSSL");
        ecdsaSigLen = sizeof(ecdsaSig);
        err = test_pkey_sign_ecc(pkey, NULL, buf, sizeof(buf), ecdsaSig,
                                 &ecdsaSigLen);
    }
    if (err == 0) {
        PRINT_MSG("Verify with wolfengine");
        err = test_pkey_verify_ecc(pkey, e, buf, sizeof(buf), ecdsaSig,
                                   ecdsaSigLen);
    }
    if (err == 0) {
        PRINT_MSG("Verify bad signature with wolfengine");
        ecdsaSig[1] ^= 0x80;
        res = test_pkey_verify_ecc(pkey, e, buf, sizeof(buf), ecdsaSig,
                                   ecdsaSigLen);
        if (res != 1)
            err = 1;
    }
    if (err == 0) {
        PRINT_MSG("Sign with wolfengine");
        ecdsaSigLen = sizeof(ecdsaSig);
        err = test_pkey_sign_ecc(pkey, e, buf, sizeof(buf), ecdsaSig,
                                 &ecdsaSigLen);
    }
    if (err == 0) {
        PRINT_MSG("Verify with OpenSSL");
        err = test_pkey_verify_ecc(pkey, NULL, buf, sizeof(buf),
                                   ecdsaSig, ecdsaSigLen);
    }

    EVP_PKEY_free(pkey);

    return err;
}
#endif /* WE_HAVE_EC_P256 */

#ifdef WE_HAVE_EC_P384
int test_ecdsa_p384_pkey(ENGINE *e, void *data)
{
    int err;
    int res;
    EVP_PKEY *pkey = NULL;
    unsigned char ecdsaSig[120];
    size_t ecdsaSigLen;
    unsigned char buf[20];
    const unsigned char *p = ecc_key_der_384;

    (void)data;

    err = RAND_bytes(buf, sizeof(buf)) == 0;
    if (err == 0) {
        pkey = d2i_PrivateKey(EVP_PKEY_EC, NULL, &p, sizeof(ecc_key_der_384));
        err = pkey == NULL;
    }
    if (err == 0) {
        PRINT_MSG("Sign with OpenSSL");
        ecdsaSigLen = sizeof(ecdsaSig);
        err = test_pkey_sign_ecc(pkey, NULL, buf, sizeof(buf), ecdsaSig,
                                 &ecdsaSigLen);
    }
    if (err == 0) {
        PRINT_MSG("Verify with wolfengine");
        err = test_pkey_verify_ecc(pkey, e, buf, sizeof(buf), ecdsaSig,
                                   ecdsaSigLen);
    }
    if (err == 0) {
        PRINT_MSG("Verify bad signature with wolfengine");
        ecdsaSig[1] ^= 0x80;
        res = test_pkey_verify_ecc(pkey, e, buf, sizeof(buf), ecdsaSig,
                                   ecdsaSigLen);
        if (res != 1)
            err = 1;
    }
    if (err == 0) {
        PRINT_MSG("Sign with wolfengine");
        ecdsaSigLen = sizeof(ecdsaSig);
        err = test_pkey_sign_ecc(pkey, e, buf, sizeof(buf), ecdsaSig,
                                 &ecdsaSigLen);
    }
    if (err == 0) {
        PRINT_MSG("Verify with OpenSSL");
        err = test_pkey_verify_ecc(pkey, NULL, buf, sizeof(buf),
                                   ecdsaSig, ecdsaSigLen);
    }

    EVP_PKEY_free(pkey);

    return err;
}
#endif /* WE_HAVE_EC_P384 */

#ifdef WE_HAVE_EC_P521
int test_ecdsa_p521_pkey(ENGINE *e, void *data)
{
    int err;
    int res;
    EVP_PKEY *pkey = NULL;
    unsigned char ecdsaSig[163];
    size_t ecdsaSigLen;
    unsigned char buf[20];
    const unsigned char *p = ecc_key_der_521;

    (void)data;

    err = RAND_bytes(buf, sizeof(buf)) == 0;
    if (err == 0) {
        pkey = d2i_PrivateKey(EVP_PKEY_EC, NULL, &p, sizeof(ecc_key_der_521));
        err = pkey == NULL;
    }
    if (err == 0) {
        PRINT_MSG("Sign with OpenSSL");
        ecdsaSigLen = sizeof(ecdsaSig);
        err = test_pkey_sign_ecc(pkey, NULL, buf, sizeof(buf), ecdsaSig,
                                 &ecdsaSigLen);
    }
    if (err == 0) {
        PRINT_MSG("Verify with wolfengine");
        err = test_pkey_verify_ecc(pkey, e, buf, sizeof(buf), ecdsaSig,
                                   ecdsaSigLen);
    }
    if (err == 0) {
        PRINT_MSG("Verify bad signature with wolfengine");
        ecdsaSig[1] ^= 0x80;
        res = test_pkey_verify_ecc(pkey, e, buf, sizeof(buf), ecdsaSig,
                                   ecdsaSigLen);
        if (res != 1)
            err = 1;
    }
    if (err == 0) {
        PRINT_MSG("Sign with wolfengine");
        ecdsaSigLen = sizeof(ecdsaSig);
        err = test_pkey_sign_ecc(pkey, e, buf, sizeof(buf), ecdsaSig,
                                 &ecdsaSigLen);
    }
    if (err == 0) {
        PRINT_MSG("Verify with OpenSSL");
        err = test_pkey_verify_ecc(pkey, NULL, buf, sizeof(buf),
                                   ecdsaSig, ecdsaSigLen);
    }

    EVP_PKEY_free(pkey);

    return err;
}
#endif /* WE_HAVE_EC_P521 */

#ifdef WE_HAVE_EC_P192
int test_ecdsa_p192(ENGINE *e, void *data)
{
    int err;
    int res;
    EVP_PKEY *pkey = NULL;
    unsigned char ecdsaSig[64];
    size_t ecdsaSigLen;
    unsigned char buf[128];
    const unsigned char *p = ecc_key_der_192;

    (void)data;

    err = RAND_bytes(buf, sizeof(buf)) == 0;
    if (err == 0) {
        pkey = d2i_PrivateKey(EVP_PKEY_EC, NULL, &p, sizeof(ecc_key_der_192));
        err = pkey == NULL;
    }
    if (err == 0) {
        PRINT_MSG("Sign with OpenSSL");
        ecdsaSigLen = sizeof(ecdsaSig);
        err = test_digest_sign(pkey, NULL, buf, sizeof(buf), EVP_sha224(),
                              ecdsaSig, &ecdsaSigLen, 0);
    }
    if (err == 0) {
        PRINT_MSG("Verify with wolfengine");
        err = test_digest_verify(pkey, e, buf, sizeof(buf), EVP_sha224(),
                                ecdsaSig, ecdsaSigLen, 0);
    }
    if (err == 0) {
        PRINT_MSG("Verify bad signature with wolfengine");
        ecdsaSig[1] ^= 0x80;
        res = test_digest_verify(pkey, e, buf, sizeof(buf), EVP_sha224(),
                                ecdsaSig, ecdsaSigLen, 0);
        if (res != 1)
            err = 1;
    }
    if (err == 0) {
        PRINT_MSG("Sign with wolfengine");
        ecdsaSigLen = sizeof(ecdsaSig);
        err = test_digest_sign(pkey, e, buf, sizeof(buf), EVP_sha224(),
                              ecdsaSig, &ecdsaSigLen, 0);
    }
    if (err == 0) {
        PRINT_MSG("Verify with OpenSSL");
        err = test_digest_verify(pkey, NULL, buf, sizeof(buf), EVP_sha224(),
                                ecdsaSig, ecdsaSigLen, 0);
    }

    EVP_PKEY_free(pkey);

    return err;
}
#endif /* WE_HAVE_EC_P192 */

#ifdef WE_HAVE_EC_P224
int test_ecdsa_p224(ENGINE *e, void *data)
{
    int err;
    int res;
    EVP_PKEY *pkey = NULL;
    unsigned char ecdsaSig[64];
    size_t ecdsaSigLen;
    unsigned char buf[128];
    const unsigned char *p = ecc_key_der_224;

    (void)data;

    err = RAND_bytes(buf, sizeof(buf)) == 0;
    if (err == 0) {
        pkey = d2i_PrivateKey(EVP_PKEY_EC, NULL, &p, sizeof(ecc_key_der_224));
        err = pkey == NULL;
    }
    if (err == 0) {
        PRINT_MSG("Sign with OpenSSL");
        ecdsaSigLen = sizeof(ecdsaSig);
        err = test_digest_sign(pkey, NULL, buf, sizeof(buf), EVP_sha224(),
                              ecdsaSig, &ecdsaSigLen, 0);
    }
    if (err == 0) {
        PRINT_MSG("Verify with wolfengine");
        err = test_digest_verify(pkey, e, buf, sizeof(buf), EVP_sha224(),
                                ecdsaSig, ecdsaSigLen, 0);
    }
    if (err == 0) {
        PRINT_MSG("Verify bad signature with wolfengine");
        ecdsaSig[1] ^= 0x80;
        res = test_digest_verify(pkey, e, buf, sizeof(buf), EVP_sha224(),
                                ecdsaSig, ecdsaSigLen, 0);
        if (res != 1)
            err = 1;
    }
    if (err == 0) {
        PRINT_MSG("Sign with wolfengine");
        ecdsaSigLen = sizeof(ecdsaSig);
        err = test_digest_sign(pkey, e, buf, sizeof(buf), EVP_sha224(),
                              ecdsaSig, &ecdsaSigLen, 0);
    }
    if (err == 0) {
        PRINT_MSG("Verify with OpenSSL");
        err = test_digest_verify(pkey, NULL, buf, sizeof(buf), EVP_sha224(),
                                ecdsaSig, ecdsaSigLen, 0);
    }

    EVP_PKEY_free(pkey);

    return err;
}
#endif /* WE_HAVE_EC_P224 */

#ifdef WE_HAVE_EC_P256
int test_ecdsa_p256(ENGINE *e, void *data)
{
    int err;
    int res;
    EVP_PKEY *pkey = NULL;
    unsigned char ecdsaSig[80];
    size_t ecdsaSigLen;
    unsigned char buf[128];
    const unsigned char *p = ecc_key_der_256;

    (void)data;

    err = RAND_bytes(buf, sizeof(buf)) == 0;
    if (err == 0) {
        pkey = d2i_PrivateKey(EVP_PKEY_EC, NULL, &p, sizeof(ecc_key_der_256));
        err = pkey == NULL;
    }
    if (err == 0) {
        PRINT_MSG("Sign with OpenSSL");
        ecdsaSigLen = sizeof(ecdsaSig);
        err = test_digest_sign(pkey, NULL, buf, sizeof(buf), EVP_sha256(),
                              ecdsaSig, &ecdsaSigLen, 0);
    }
    if (err == 0) {
        PRINT_MSG("Verify with wolfengine");
        err = test_digest_verify(pkey, e, buf, sizeof(buf), EVP_sha256(),
                                ecdsaSig, ecdsaSigLen, 0);
    }
    if (err == 0) {
        PRINT_MSG("Verify bad signature with wolfengine");
        ecdsaSig[1] ^= 0x80;
        res = test_digest_verify(pkey, e, buf, sizeof(buf), EVP_sha256(),
                                ecdsaSig, ecdsaSigLen, 0);
        if (res != 1)
            err = 1;
    }
    if (err == 0) {
        PRINT_MSG("Sign with wolfengine");
        ecdsaSigLen = sizeof(ecdsaSig);
        err = test_digest_sign(pkey, e, buf, sizeof(buf), EVP_sha256(),
                              ecdsaSig, &ecdsaSigLen, 0);
    }
    if (err == 0) {
        PRINT_MSG("Verify with OpenSSL");
        err = test_digest_verify(pkey, NULL, buf, sizeof(buf), EVP_sha256(),
                                ecdsaSig, ecdsaSigLen, 0);
    }

    EVP_PKEY_free(pkey);

    return err;
}
#endif /* WE_HAVE_EC_P256 */

#ifdef WE_HAVE_EC_P384
int test_ecdsa_p384(ENGINE *e, void *data)
{
    int err;
    int res;
    EVP_PKEY *pkey = NULL;
    unsigned char ecdsaSig[120];
    size_t ecdsaSigLen;
    unsigned char buf[128];
    const unsigned char *p = ecc_key_der_384;

    (void)data;

    err = RAND_bytes(buf, sizeof(buf)) == 0;
    if (err == 0) {
        pkey = d2i_PrivateKey(EVP_PKEY_EC, NULL, &p, sizeof(ecc_key_der_384));
        err = pkey == NULL;
    }
    if (err == 0) {
        PRINT_MSG("Sign with OpenSSL");
        ecdsaSigLen = sizeof(ecdsaSig);
        err = test_digest_sign(pkey, NULL, buf, sizeof(buf), EVP_sha384(),
                              ecdsaSig, &ecdsaSigLen, 0);
    }
    if (err == 0) {
        PRINT_MSG("Verify with wolfengine");
        err = test_digest_verify(pkey, e, buf, sizeof(buf), EVP_sha384(),
                                ecdsaSig, ecdsaSigLen, 0);
    }
    if (err == 0) {
        PRINT_MSG("Verify bad signature with wolfengine");
        ecdsaSig[1] ^= 0x80;
        res = test_digest_verify(pkey, e, buf, sizeof(buf), EVP_sha384(),
                                ecdsaSig, ecdsaSigLen, 0);
        if (res != 1)
            err = 1;
    }
    if (err == 0) {
        PRINT_MSG("Sign with wolfengine");
        ecdsaSigLen = sizeof(ecdsaSig);
        err = test_digest_sign(pkey, e, buf, sizeof(buf), EVP_sha384(),
                              ecdsaSig, &ecdsaSigLen, 0);
    }
    if (err == 0) {
        PRINT_MSG("Verify with OpenSSL");
        err = test_digest_verify(pkey, NULL, buf, sizeof(buf), EVP_sha384(),
                                ecdsaSig, ecdsaSigLen, 0);
    }

    EVP_PKEY_free(pkey);

    return err;
}
#endif /* WE_HAVE_EC_P384 */

#ifdef WE_HAVE_EC_P521
int test_ecdsa_p521(ENGINE *e, void *data)
{
    int err;
    int res;
    EVP_PKEY *pkey = NULL;
    unsigned char ecdsaSig[163];
    size_t ecdsaSigLen;
    unsigned char buf[128];
    const unsigned char *p = ecc_key_der_521;

    (void)data;

    err = RAND_bytes(buf, sizeof(buf)) == 0;
    if (err == 0) {
        pkey = d2i_PrivateKey(EVP_PKEY_EC, NULL, &p, sizeof(ecc_key_der_521));
        err = pkey == NULL;
    }
    if (err == 0) {
        PRINT_MSG("Sign with OpenSSL");
        ecdsaSigLen = sizeof(ecdsaSig);
        err = test_digest_sign(pkey, NULL, buf, sizeof(buf), EVP_sha512(),
                              ecdsaSig, &ecdsaSigLen, 0);
    }
    if (err == 0) {
        PRINT_MSG("Verify with wolfengine");
        err = test_digest_verify(pkey, e, buf, sizeof(buf), EVP_sha512(),
                                ecdsaSig, ecdsaSigLen, 0);
    }
    if (err == 0) {
        PRINT_MSG("Verify bad signature with wolfengine");
        ecdsaSig[1] ^= 0x80;
        res = test_digest_verify(pkey, e, buf, sizeof(buf), EVP_sha512(),
                                ecdsaSig, ecdsaSigLen, 0);
        if (res != 1)
            err = 1;
    }
    if (err == 0) {
        PRINT_MSG("Sign with wolfengine");
        ecdsaSigLen = sizeof(ecdsaSig);
        err = test_digest_sign(pkey, e, buf, sizeof(buf), EVP_sha512(),
                              ecdsaSig, &ecdsaSigLen, 0);
    }
    if (err == 0) {
        PRINT_MSG("Verify with OpenSSL");
        err = test_digest_verify(pkey, NULL, buf, sizeof(buf), EVP_sha512(),
                                ecdsaSig, ecdsaSigLen, 0);
    }

    EVP_PKEY_free(pkey);

    return err;
}
#endif /* WE_HAVE_EC_P521 */

#endif /* WE_HAVE_ECDSA */

#endif /* WE_HAVE_EVP_PKEY */

#ifdef WE_HAVE_EC_KEY

#ifdef WE_HAVE_ECKEYGEN

int test_ec_key_keygen_by_nid(ENGINE *e, int nid)
{
    int err;
    EC_KEY *key = NULL;
    EC_GROUP *group = NULL;

    PRINT_MSG("Create group");
    err = (group = EC_GROUP_new_by_curve_name(nid)) == NULL;
    if (err == 0) {
        PRINT_MSG("Create key with engine");
        err = (key = EC_KEY_new_method(e)) == NULL;
    }
    if (err == 0) {
        PRINT_MSG("Set group");
        err = EC_KEY_set_group(key, group) != 1;
    }
    if (err == 0) {
        PRINT_MSG("Generate key");
        err = EC_KEY_generate_key(key) != 1;
    }

    EC_KEY_free(key);
    EC_GROUP_free(group);

    return err;
}

#ifdef WE_HAVE_EC_P192
int test_ec_key_keygen_p192_by_nid(ENGINE *e, void *data)
{
    (void)data;
    return test_ec_key_keygen_by_nid(e, NID_X9_62_prime192v1);
}
#endif /* WE_HAVE_EC_P192 */

#ifdef WE_HAVE_EC_P224
int test_ec_key_keygen_p224_by_nid(ENGINE *e, void *data)
{
    (void)data;
    return test_ec_key_keygen_by_nid(e, NID_secp224r1);
}
#endif /* WE_HAVE_EC_P224 */

#ifdef WE_HAVE_EC_P256
int test_ec_key_keygen_p256_by_nid(ENGINE *e, void *data)
{
    (void)data;
    return test_ec_key_keygen_by_nid(e, NID_X9_62_prime256v1);
}
#endif /* WE_HAVE_EC_P256 */

#ifdef WE_HAVE_EC_P384
int test_ec_key_keygen_p384_by_nid(ENGINE *e, void *data)
{
    (void)data;
    return test_ec_key_keygen_by_nid(e, NID_secp384r1);
}
#endif /* WE_HAVE_EC_P384 */

#ifdef WE_HAVE_EC_P521
int test_ec_key_keygen_p521_by_nid(ENGINE *e, void *data)
{
    (void)data;
    return test_ec_key_keygen_by_nid(e, NID_secp521r1);
}
#endif /* WE_HAVE_EC_P521 */

#endif /* WE_HAVE_ECKEYGEN */

#ifdef WE_HAVE_ECDH

#ifdef WE_HAVE_ECKEYGEN
int test_ec_key_ecdh_keygen(ENGINE *e, int nid, int len)
{
    int err;
    EC_GROUP *group = NULL;
    EC_KEY *keyA = NULL;
    EC_KEY *keyB = NULL;
    const EC_POINT *pubKeyA;
    const EC_POINT *pubKeyB;
    unsigned char secretA[66];
    unsigned char secretB[66];

    err = (group = EC_GROUP_new_by_curve_name(nid)) == NULL;
    if (err == 0) {
        err = (keyA = EC_KEY_new_method(e)) == NULL;
    }
    if (err == 0) {
        err = EC_KEY_set_group(keyA, group) != 1;
    }
    if (err == 0) {
        err = EC_KEY_generate_key(keyA) != 1;
    }
    if (err == 0) {
        err = (keyB = EC_KEY_new_method(e)) == NULL;
    }
    if (err == 0) {
        err = EC_KEY_set_group(keyB, group) != 1;
    }
    if (err == 0) {
        err = EC_KEY_generate_key(keyB) != 1;
    }
    if (err == 0) {
        err = (pubKeyA = EC_KEY_get0_public_key(keyA)) == NULL;
    }
    if (err == 0) {
        err = (pubKeyB = EC_KEY_get0_public_key(keyB)) == NULL;
    }
    if (err == 0) {
        PRINT_MSG("Derive secret A");
        err = ECDH_compute_key(secretA, len, pubKeyB, keyA, NULL) != len;
    }
    if (err == 0) {
        PRINT_MSG("Derive secret B");
        err = ECDH_compute_key(secretB, len, pubKeyA, keyB, NULL) != len;
    }
    if (err == 0) {
        PRINT_BUFFER("Secret A", secretA, len);
        PRINT_BUFFER("Secret B", secretB, len);
        err = memcmp(secretA, secretB, len) != 0;
        if (err != 0) {
            PRINT_ERR_MSG("Secrets do not match!");
        }
    }

    EC_KEY_free(keyB);
    EC_KEY_free(keyA);
    EC_GROUP_free(group);

    return err;
}

#ifdef WE_HAVE_EC_P192
int test_ec_key_ecdh_p192_keygen(ENGINE *e, void *data)
{
    (void)data;

    return test_ec_key_ecdh_keygen(e, NID_X9_62_prime192v1, 24);
}
#endif /* WE_HAVE_EC_P192 */

#ifdef WE_HAVE_EC_P224
int test_ec_key_ecdh_p224_keygen(ENGINE *e, void *data)
{
    (void)data;

    return test_ec_key_ecdh_keygen(e, NID_secp224r1, 28);
}
#endif /* WE_HAVE_EC_P224 */

#ifdef WE_HAVE_EC_P256
int test_ec_key_ecdh_p256_keygen(ENGINE *e, void *data)
{
    (void)data;

    return test_ec_key_ecdh_keygen(e, NID_X9_62_prime256v1, 32);
}
#endif /* WE_HAVE_EC_P256 */

#ifdef WE_HAVE_EC_P384
int test_ec_key_ecdh_p384_keygen(ENGINE *e, void *data)
{
    (void)data;

    return test_ec_key_ecdh_keygen(e, NID_secp384r1, 48);
}
#endif /* WE_HAVE_EC_P384 */

#ifdef WE_HAVE_EC_P521
int test_ec_key_ecdh_p521_keygen(ENGINE *e, void *data)
{
    (void)data;

    return test_ec_key_ecdh_keygen(e, NID_secp521r1, 66);
}
#endif /* WE_HAVE_EC_P521 */
#endif /* WE_HAVE_ECKEYGEN */

int test_ec_key_ecdh(ENGINE *e, const unsigned char *privKey, size_t len,
                     const unsigned char *peerPrivKey, size_t peerLen,
                     const unsigned char *derived, size_t dLen)
{
    int err;
    EC_KEY *keyA = NULL;
    EC_KEY *keyB = NULL;
    const EC_POINT *pubKeyA;
    const EC_POINT *pubKeyB;
    unsigned char secretA[66];
    unsigned char secretB[66];
    const unsigned char *p;

    err = (keyA = EC_KEY_new_method(e)) == NULL;
    if (err == 0) {
        p = privKey;
        err = (keyA = d2i_ECPrivateKey(&keyA, &p, len)) == NULL;
    }
    if (err == 0) {
        err = (keyB = EC_KEY_new_method(e)) == NULL;
    }
    if (err == 0) {
        p = peerPrivKey;
        err = (keyB = d2i_ECPrivateKey(&keyB, &p, peerLen)) == NULL;
    }
    if (err == 0) {
        err = (pubKeyA = EC_KEY_get0_public_key(keyA)) == NULL;
    }
    if (err == 0) {
        err = (pubKeyB = EC_KEY_get0_public_key(keyB)) == NULL;
    }
    if (err == 0) {
        PRINT_MSG("Derive secret A");
        err = ECDH_compute_key(secretA, dLen, pubKeyB, keyA, NULL) != (int)dLen;
    }
    if (err == 0) {
        PRINT_MSG("Derive secret B");
        err = ECDH_compute_key(secretB, dLen, pubKeyA, keyB, NULL) != (int)dLen;
    }
    if (err == 0) {
        PRINT_BUFFER("Secret A", secretA, dLen);
        PRINT_BUFFER("Secret B", secretB, dLen);
        err = memcmp(secretA, secretB, dLen) != 0;
        if (err != 0) {
            PRINT_ERR_MSG("Secrets do not match!");
        }
    }
    if (err == 0) {
        err = memcmp(secretA, derived, dLen) != 0;
        if (err != 0) {
            PRINT_ERR_MSG("Secret does not match, expected!");
        }
    }

    EC_KEY_free(keyB);
    EC_KEY_free(keyA);

    return err;
}

#ifdef WE_HAVE_EC_P192
int test_ec_key_ecdh_p192(ENGINE *e, void *data)
{
    (void)data;
    return test_ec_key_ecdh(e, ecc_key_der_192, sizeof(ecc_key_der_192),
                            ecc_peerkey_der_192, sizeof(ecc_peerkey_der_192),
                            ecc_derived_192, sizeof(ecc_derived_192));
}
#endif /* WE_HAVE_EC_P192 */

#ifdef WE_HAVE_EC_P224
int test_ec_key_ecdh_p224(ENGINE *e, void *data)
{
    (void)data;
    return test_ec_key_ecdh(e, ecc_key_der_224, sizeof(ecc_key_der_224),
                            ecc_peerkey_der_224, sizeof(ecc_peerkey_der_224),
                            ecc_derived_224, sizeof(ecc_derived_224));
}
#endif /* WE_HAVE_EC_P224 */

#ifdef WE_HAVE_EC_P256
int test_ec_key_ecdh_p256(ENGINE *e, void *data)
{
    (void)data;
    return test_ec_key_ecdh(e, ecc_key_der_256, sizeof(ecc_key_der_256),
                            ecc_peerkey_der_256, sizeof(ecc_peerkey_der_256),
                            ecc_derived_256, sizeof(ecc_derived_256));
}
#endif /* WE_HAVE_EC_P256 */

#ifdef WE_HAVE_EC_P384
int test_ec_key_ecdh_p384(ENGINE *e, void *data)
{
    (void)data;
    return test_ec_key_ecdh(e, ecc_key_der_384, sizeof(ecc_key_der_384),
                            ecc_peerkey_der_384, sizeof(ecc_peerkey_der_384),
                            ecc_derived_384, sizeof(ecc_derived_384));
}
#endif /* WE_HAVE_EC_P384 */

#ifdef WE_HAVE_EC_P521
int test_ec_key_ecdh_p521(ENGINE *e, void *data)
{
    (void)data;
    return test_ec_key_ecdh(e, ecc_key_der_521, sizeof(ecc_key_der_521),
                            ecc_peerkey_der_521, sizeof(ecc_peerkey_der_521),
                            ecc_derived_521, sizeof(ecc_derived_521));
}
#endif /* WE_HAVE_EC_P521 */

#endif /* WE_HAVE_ECDH */

#ifdef WE_HAVE_ECDSA

int test_ec_key_ecdsa_sign(EC_KEY *key, unsigned char *hash,
                           size_t hashLen, unsigned char *ecdsaSig,
                           size_t *ecdsaSigLen)
{
    int err;
    unsigned int sigLen;
    PRINT_MSG("test_ec_key_ecdsa_sign");
    sigLen = (unsigned int)*ecdsaSigLen;
    err = ECDSA_sign(0, hash, (int)hashLen, ecdsaSig, &sigLen, key) != 1;
    if (err == 0) {
        PRINT_BUFFER("Signature", ecdsaSig, sigLen);
    }
    if (err == 0) {
        sigLen = (unsigned int)*ecdsaSigLen;
        err = ECDSA_sign(0, hash, (int)hashLen, ecdsaSig, &sigLen, key) != 1;
    }
    if (err == 0) {
        PRINT_BUFFER("Signature", ecdsaSig, sigLen);
        *ecdsaSigLen = sigLen;
    }

    return err;
}

int test_ec_key_ecdsa_verify(EC_KEY *key, unsigned char *hash,
                             size_t hashLen, unsigned char *ecdsaSig,
                             size_t ecdsaSigLen)
{
    int err;

    err = ECDSA_verify(0, hash, (int)hashLen, ecdsaSig, (int)ecdsaSigLen,
                       key) != 1;
    if (err == 0) {
        PRINT_MSG("Signature verified");
    }
    else {
        PRINT_MSG("Signature not verified");
    }
    if (err == 0) {
        err = ECDSA_verify(0, hash, (int)hashLen, ecdsaSig, (int)ecdsaSigLen,
                           key) != 1;
    }
    if (err == 0) {
        PRINT_MSG("Signature verified");
    }
    else {
        PRINT_MSG("Signature not verified");
    }

    return err;
}

int test_ec_key_ecdsa(ENGINE *e, const unsigned char *privKey,
                      size_t privKeyLen)
{
    int err;
    int res;
    EC_KEY *key = NULL;
    EC_KEY *keyOSSL = NULL;
    unsigned char ecdsaSig[140];
    size_t ecdsaSigLen;
    unsigned char buf[20];
    const unsigned char *p;

    err = RAND_bytes(buf, sizeof(buf)) == 0;
    if (err == 0) {
        err = (key = EC_KEY_new_method(e)) == NULL;
    }
    if (err == 0) {
        p = privKey;
        key = d2i_ECPrivateKey(&key, &p, privKeyLen);
        err = (key == NULL);
    }
    if (err == 0) {
        p = privKey;
        keyOSSL = d2i_ECPrivateKey(NULL, &p, privKeyLen);
        err = (key == NULL);
    }
    if (err == 0) {
        PRINT_MSG("Sign with OpenSSL");
        ecdsaSigLen = sizeof(ecdsaSig);
        err = test_ec_key_ecdsa_sign(keyOSSL, buf, sizeof(buf), ecdsaSig,
                                     &ecdsaSigLen);
    }
    if (err == 0) {
        PRINT_MSG("Verify with wolfengine");
        err = test_ec_key_ecdsa_verify(key, buf, sizeof(buf), ecdsaSig,
                                       ecdsaSigLen);
    }
    if (err == 0) {
        PRINT_MSG("Verify bad signature with wolfengine");
        ecdsaSig[1] ^= 0x80;
        res = test_ec_key_ecdsa_verify(key, buf, sizeof(buf), ecdsaSig,
                                       ecdsaSigLen);
        if (res != 1)
            err = 1;
    }
    if (err == 0) {
        PRINT_MSG("Sign with wolfengine");
        ecdsaSigLen = sizeof(ecdsaSig);
        err = test_ec_key_ecdsa_sign(key, buf, sizeof(buf), ecdsaSig,
                                     &ecdsaSigLen);
    }
    if (err == 0) {
        PRINT_MSG("Verify with OpenSSL");
        err = test_ec_key_ecdsa_verify(keyOSSL, buf, sizeof(buf),
                                       ecdsaSig, ecdsaSigLen);
    }

    EC_KEY_free(keyOSSL);
    EC_KEY_free(key);

    return err;
}

#ifdef WE_HAVE_EC_P192
int test_ec_key_ecdsa_p192(ENGINE *e, void *data)
{
    (void)data;
    return test_ec_key_ecdsa(e, ecc_key_der_192, sizeof(ecc_key_der_192));
}
#endif /* WE_HAVE_EC_P192 */

#ifdef WE_HAVE_EC_P224
int test_ec_key_ecdsa_p224(ENGINE *e, void *data)
{
    (void)data;
    return test_ec_key_ecdsa(e, ecc_key_der_224, sizeof(ecc_key_der_224));
}
#endif /* WE_HAVE_EC_P224 */

#ifdef WE_HAVE_EC_P256
int test_ec_key_ecdsa_p256(ENGINE *e, void *data)
{
    (void)data;
    return test_ec_key_ecdsa(e, ecc_key_der_256, sizeof(ecc_key_der_256));
}
#endif /* WE_HAVE_EC_P256 */

#ifdef WE_HAVE_EC_P384
int test_ec_key_ecdsa_p384(ENGINE *e, void *data)
{
    (void)data;
    return test_ec_key_ecdsa(e, ecc_key_der_384, sizeof(ecc_key_der_384));
}
#endif /* WE_HAVE_EC_P384 */

#ifdef WE_HAVE_EC_P521
int test_ec_key_ecdsa_p521(ENGINE *e, void *data)
{
    (void)data;
    return test_ec_key_ecdsa(e, ecc_key_der_521, sizeof(ecc_key_der_521));
}
#endif /* WE_HAVE_EC_P521 */

#endif /* WE_HAVE_ECDSA */

#endif /* WE_HAVE_EC_KEY */
#if OPENSSL_VERSION_NUMBER < 0x10100000L
#ifdef WE_HAVE_ECDH

static int test_ecdh_direct(ENGINE* e, const unsigned char* keyDer,
                            size_t keyDerLen, const unsigned char* keyPeerDer,
                            size_t keyPeerDerLen,
                            const unsigned char* knownSecret,
                            size_t knownSecretLen)
{
    int err = 0, rc;
    EVP_PKEY *keyA = NULL;
    EVP_PKEY *keyB = NULL;
    unsigned char secret[66];
    const unsigned char *p;
    const unsigned char *peerPrivKey;
    const ECDH_METHOD* method;
    EC_KEY *eckeyA = NULL,*eckeyB = NULL;
    const EC_POINT* pub;

    PRINT_MSG("Get ECDH_METHOD from engine");
    method = ENGINE_get_ECDH(e);
    if (method == NULL) {
        err = 1;
    }

    p = keyDer;
    peerPrivKey = keyPeerDer;

    /* sanity check on secret buffer size */
    if (sizeof(secret) < knownSecretLen) {
        PRINT_MSG("Shared secret buffer too small for secret operation");
        err = 1;
    }

    if (err == 0) {
        keyA = d2i_PrivateKey(EVP_PKEY_EC, NULL, &p, keyDerLen);
        if (keyA == NULL) {
            err = 1;
        }
    }
    if (err == 0) {
        keyB = d2i_PrivateKey(EVP_PKEY_EC, NULL, &peerPrivKey, keyPeerDerLen);
        if (keyB == NULL) {
            err = 1;
        }
    }
    if (err == 0) {
        eckeyA = EVP_PKEY_get1_EC_KEY(keyA);
        if (eckeyA == NULL) {
            err = 1;
        }
    }
    if (err == 0) {
        pub = EC_KEY_get0_public_key(eckeyA);
        if (pub == NULL) {
            err = 1;
        }
    }
    if (err == 0) {
        eckeyB = EVP_PKEY_get1_EC_KEY(keyB);
        if (eckeyB == NULL) {
            err = 1;
        }
    }
    if (err == 0) {
        PRINT_MSG("Compute ECDH shared secret with OpenSSL default method");
        rc = ECDH_compute_key(secret, sizeof(secret), pub, eckeyB, NULL);
        if (rc == -1 || ((size_t)rc != knownSecretLen)) {
            err = 1;
        }
    }
    if (err == 0) {
        PRINT_MSG("Compare shared secret with known-answer");
        if (memcmp(knownSecret, secret, knownSecretLen) != 0) {
            err = 1;
        } else {
            PRINT_MSG("OpenSSL ECDH shared secret matched expected value");
        }
        memset(secret, 0, sizeof(secret));
    }
    /* test again with ECDH_METHOD of wolfEngine */
    if (err == 0) {
        PRINT_MSG("Setting wolfEngine with ECDH_set_method");
        rc = ECDH_set_method(eckeyB, method);
        if (rc != 1) {
            err = 1;
        }
    }
    if (err == 0) {
        PRINT_MSG("Compute ECDH shared secret with wolfEngine");
        rc = ECDH_compute_key(secret, sizeof(secret), pub, eckeyB, NULL);
        if (rc == -1 || ((size_t)rc != knownSecretLen)) {
            err = 1;
        }
    }
    if (err == 0) {
        PRINT_MSG("Compare wolfEngine ECDH shared secret with known-answer");
        if (memcmp(knownSecret, secret, knownSecretLen) != 0) {
            PRINT_MSG("wolfEngine ECDH shared secret did not match expected");
            err = 1;
        } else {
            PRINT_MSG("wolfEngine ECDH shared secret matched expected value");
        }
    }

    EVP_PKEY_free(keyA);
    EVP_PKEY_free(keyB);
    EC_KEY_free(eckeyA);
    EC_KEY_free(eckeyB);

    keyA = NULL;
    keyB = NULL;
    eckeyA = NULL;
    eckeyB = NULL;

    return err;
}


#if defined(WE_HAVE_EC_P192)
int test_ecdh_direct_p192(ENGINE* e, void* data)
{
    (void)data;
    PRINT_MSG("test_ecdh_direct_p192");
    return test_ecdh_direct(e, ecc_key_der_192, sizeof(ecc_key_der_192),
                            ecc_peerkey_der_192, sizeof(ecc_peerkey_der_192),
                            ecc_derived_192, sizeof(ecc_derived_192));
}
#endif /* WE_HAVE_EC_P256 */

#if defined(WE_HAVE_EC_P256)
int test_ecdh_direct_p256(ENGINE* e, void* data)
{
    (void)data;
    PRINT_MSG("test_ecdh_direct_p256");
    return test_ecdh_direct(e, ecc_key_der_256, sizeof(ecc_key_der_256),
                            ecc_peerkey_der_256, sizeof(ecc_peerkey_der_256),
                            ecc_derived_256, sizeof(ecc_derived_256));
}
#endif /* WE_HAVE_EC_P256 */

#if defined(WE_HAVE_EC_P384)
int test_ecdh_direct_p384(ENGINE* e, void* data)
{
    (void)data;
    PRINT_MSG("test_ecdh_direct_p384");
    return test_ecdh_direct(e, ecc_key_der_384, sizeof(ecc_key_der_384),
                            ecc_peerkey_der_384, sizeof(ecc_peerkey_der_384),
                            ecc_derived_384, sizeof(ecc_derived_384));
}
#endif /* WE_HAVE_EC_P384 */

#if defined(WE_HAVE_EC_P521)
int test_ecdh_direct_p521(ENGINE* e, void* data)
{
    (void)data;
    PRINT_MSG("test_ecdh_direct_p521");
    return test_ecdh_direct(e, ecc_key_der_521, sizeof(ecc_key_der_521),
                            ecc_peerkey_der_521, sizeof(ecc_peerkey_der_521),
                            ecc_derived_521, sizeof(ecc_derived_521));
}
#endif /* WE_HAVE_EC_P521 */

#endif /* WE_HAVE_ECDH */
#endif /* OPENSSL_VERSION_NUMBER < 0x10100000L */



#if defined(WE_HAVE_ECDSA)
#if OPENSSL_VERSION_NUMBER <= 0x100020ffL

static int test_ecdsa_sign(EC_KEY *key, unsigned char *hash,
                           size_t hashLen, unsigned char *ecdsaSig,
                           size_t *ecdsaSigLen)
{
    int err;
    unsigned int sigLen;

    PRINT_MSG("ENTER: test_ecdsa_sign");
    sigLen = (unsigned int)*ecdsaSigLen;
    err = ECDSA_sign(0, hash, (int)hashLen, ecdsaSig, &sigLen, key) != 1;
    if (err == 0) {
        PRINT_BUFFER("Signature", ecdsaSig, sigLen);
        *ecdsaSigLen = sigLen;
    }

    return err;
}

static int test_ecdsa_verify(EC_KEY *key, unsigned char *hash,
                             size_t hashLen, unsigned char *ecdsaSig,
                             size_t ecdsaSigLen)
{
    int err;

    PRINT_MSG("ENTER: test_ecdsa_verify");
    err = ECDSA_verify(0, hash, (int)hashLen, ecdsaSig, (int)ecdsaSigLen,
                       key) != 1;
    if (err == 0) {
        PRINT_MSG("Signature verified");
    }
    else {
        PRINT_MSG("Signature NOT verified");
    }

    return err;
}
static int test_ecdsa_key(const unsigned char *privKey, size_t privKeyLen);

int test_ecdsa(ENGINE *e, void *data)
{
    int err = 0;
    EC_KEY *ecdsaWE;
    ECDSA_METHOD *ecdsaMeth;
    (void)data;

    ecdsaWE = EC_KEY_new();
    if (ecdsaWE == NULL) {
        err = 1;
    }
    if (err == 0) {
        ecdsaMeth = (ECDSA_METHOD *)ENGINE_get_ECDSA(e);
        if (ecdsaMeth == NULL) {
            err = 1;
        }
    }
    if (err == 0) {
        ENGINE_set_default_ECDSA(e);
        ECDSA_set_method(ecdsaWE, ecdsaMeth);
    }

    if (err == 0) {
        PRINT_MSG("ECDSA: Verify with wolfengine (DER 256)");
        err = test_ecdsa_key(ecc_key_der_256, sizeof(ecc_key_der_256));
        if (err != 0) {
            PRINT_MSG("ERROR: Verify with wolfengine");
        }
    }

    if (err == 0) {
        PRINT_MSG("ECDSA: Verify with wolfengine (DER 384)");
        err = test_ecdsa_key(ecc_key_der_384, sizeof(ecc_key_der_384));
        if (err != 0) {
            PRINT_MSG("ERROR: Verify with wolfengine");
        }
    }

    EC_KEY_free(ecdsaWE);
    return err;
}

static int test_ecdsa_key(const unsigned char *privKey,
                      size_t privKeyLen)
{
    int err;
    int res;
    EC_KEY *key = NULL;
    EC_KEY *keyOSSL = NULL;
    unsigned char ecdsaSig[140];
    size_t ecdsaSigLen;
    unsigned char buf[20];
    const unsigned char *p;

    PRINT_MSG("ENTER: test_ecdsa");
    err = RAND_bytes(buf, sizeof(buf)) == 0;
    if (err == 0) {
        p = privKey;
        key = d2i_ECPrivateKey(&key, &p, privKeyLen);
        err = (key == NULL);
    }
    if (err == 0) {
        p = privKey;
        keyOSSL = d2i_ECPrivateKey(NULL, &p, privKeyLen);
        err = (keyOSSL == NULL);
    }
    if (err == 0) {
        PRINT_MSG("ECDSA: Sign with OpenSSL");
        ecdsaSigLen = sizeof(ecdsaSig);
        err = test_ecdsa_sign(keyOSSL, buf, sizeof(buf), ecdsaSig,
                                     &ecdsaSigLen);
    }
    if (err == 0) {
        PRINT_MSG("ECDSA: Verify with wolfengine");
        err = test_ecdsa_verify(keyOSSL, buf, sizeof(buf), ecdsaSig,
                                       ecdsaSigLen);
    }
    if (err == 0) {
        PRINT_MSG("ECDSA: Verify bad signature with wolfengine");
        ecdsaSig[1] ^= 0x80;
        res = test_ecdsa_verify(key, buf, sizeof(buf), ecdsaSig,
                                       ecdsaSigLen);
        if (res != 1)
            err = 1;
    }
    if (err == 0) {
        PRINT_MSG("ECDSA:Sign with wolfengine");
        ecdsaSigLen = sizeof(ecdsaSig);
        err = test_ecdsa_sign(key, buf, sizeof(buf), ecdsaSig,
                                     &ecdsaSigLen);
    }
    if (err == 0) {
        PRINT_MSG("ECDSA:Verify with OpenSSL");
        err = test_ecdsa_verify(keyOSSL, buf, sizeof(buf),
                                       ecdsaSig, ecdsaSigLen);
    }
    EC_KEY_free(key);
    EC_KEY_free(keyOSSL);
    PRINT_MSG("LEAVE: test_ecdsa");

    return err;
}

#endif /* OPENSSL_VERSION_NUMBER <= 0x100020ffL */
#endif /* WE_HAVE_ECDSA */

#endif /* WE_HAVE_ECC */
