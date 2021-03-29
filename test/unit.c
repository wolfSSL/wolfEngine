/* unit.c
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

#include "wolfengine.h"
#include "we_logging.h"
#include "unit.h"

#ifdef WOLFENGINE_DEBUG
void print_buffer(const char *desc, const unsigned char *buffer, size_t len)
{
    size_t i;

    printf("%s:\n", desc);
    for (i = 0; i < len; i++) {
        printf("%02x ", buffer[i]);
        if ((i % 16) == 15) {
            printf("\n");
        }
    }
    if ((i % 16) != 0) {
        printf("\n");
    }
}

static int debug = 1;
#else
static int debug = 0;
#endif /* WOLFENGINE_DEBUG */

TEST_CASE test_case[] = {
    TEST_DECL(test_logging, &debug),
#ifdef WE_HAVE_SHA1
    TEST_DECL(test_sha, NULL),
#endif
#ifdef WE_HAVE_SHA256
    TEST_DECL(test_sha256, NULL),
#endif
#ifdef WE_HAVE_SHA384
    TEST_DECL(test_sha384, NULL),
#endif
#ifdef WE_HAVE_SHA512
    TEST_DECL(test_sha512, NULL),
#endif
#ifdef WE_HAVE_SHA3_224
    TEST_DECL(test_sha3_224, NULL),
#endif
#ifdef WE_HAVE_SHA3_256
    TEST_DECL(test_sha3_256, NULL),
#endif
#ifdef WE_HAVE_SHA3_384
    TEST_DECL(test_sha3_384, NULL),
#endif
#ifdef WE_HAVE_SHA3_512
    TEST_DECL(test_sha3_512, NULL),
#endif
#ifdef WE_HAVE_AESCBC
    TEST_DECL(test_aes128_cbc, NULL),
    TEST_DECL(test_aes192_cbc, NULL),
    TEST_DECL(test_aes256_cbc, NULL),
    TEST_DECL(test_aes128_cbc_stream, NULL),
    TEST_DECL(test_aes192_cbc_stream, NULL),
    TEST_DECL(test_aes256_cbc_stream, NULL),
#endif
#ifdef WE_HAVE_AESGCM
    TEST_DECL(test_aes128_gcm, NULL),
    TEST_DECL(test_aes192_gcm, NULL),
    TEST_DECL(test_aes256_gcm, NULL),
    TEST_DECL(test_aes128_gcm_fixed, NULL),
    TEST_DECL(test_aes128_gcm_tls, NULL),
#endif
#ifdef WE_HAVE_EVP_PKEY
#ifdef WE_HAVE_RSA
    TEST_DECL(test_rsa_sign_verify, NULL),
    TEST_DECL(test_rsa_keygen, NULL),
#endif /* WE_HAVE_RSA */
#ifdef WE_HAVE_EC_P256
    #ifdef WE_HAVE_ECKEYGEN
        TEST_DECL(test_eckeygen_p256_by_nid, NULL),
        TEST_DECL(test_eckeygen_p256, NULL),
    #endif
    #ifdef WE_HAVE_ECDH
    #ifdef WE_HAVE_ECKEYGEN
        TEST_DECL(test_ecdh_p256_keygen, NULL),
    #endif
        TEST_DECL(test_ecdh_p256, NULL),
    #endif
    #ifdef WE_HAVE_ECDSA
        TEST_DECL(test_ecdsa_p256_pkey, NULL),
        TEST_DECL(test_ecdsa_p256, NULL),
    #endif
#endif
#ifdef WE_HAVE_EC_P384
    #ifdef WE_HAVE_ECKEYGEN
        TEST_DECL(test_eckeygen_p384_by_nid, NULL),
        TEST_DECL(test_eckeygen_p384, NULL),
    #endif
    #ifdef WE_HAVE_ECDH
    #ifdef WE_HAVE_ECKEYGEN
        TEST_DECL(test_ecdh_p384_keygen, NULL),
    #endif
        TEST_DECL(test_ecdh_p384, NULL),
    #endif
    #ifdef WE_HAVE_ECDSA
        TEST_DECL(test_ecdsa_p384_pkey, NULL),
        TEST_DECL(test_ecdsa_p384, NULL),
    #endif
#endif
#endif /* WE_HAVE_EVP_PKEY */
#ifdef WE_HAVE_EC_KEY
#ifdef WE_HAVE_EC_P256
    #ifdef WE_HAVE_ECKEYGEN
        TEST_DECL(test_ec_key_keygen_p256_by_nid, NULL),
    #endif
    #ifdef WE_HAVE_ECDH
    #ifdef WE_HAVE_ECKEYGEN
        TEST_DECL(test_ec_key_ecdh_p256_keygen, NULL),
    #endif
        TEST_DECL(test_ec_key_ecdh_p256, NULL),
    #endif
    #ifdef WE_HAVE_ECDSA
        TEST_DECL(test_ec_key_ecdsa_p256, NULL),
    #endif
#endif
#ifdef WE_HAVE_EC_P384
    #ifdef WE_HAVE_ECKEYGEN
        TEST_DECL(test_ec_key_keygen_p384_by_nid, NULL),
    #endif
    #ifdef WE_HAVE_ECDH
    #ifdef WE_HAVE_ECKEYGEN
        TEST_DECL(test_ec_key_ecdh_p384_keygen, NULL),
    #endif
        TEST_DECL(test_ec_key_ecdh_p384, NULL),
    #endif
    #ifdef WE_HAVE_ECDSA
        TEST_DECL(test_ec_key_ecdsa_p384, NULL),
    #endif
#endif
#endif /* WE_HAVE_EC_KEY */
};
#define TEST_CASE_CNT   (int)(sizeof(test_case) / sizeof(*test_case))

static void usage()
{
    printf("\n");
    printf("Usage: unit.test [options]\n");
    printf("  --help          Show this usage information.\n");
    printf("  --static        Run the tests using the static engine.\n");
    printf("  --dir <path>    Location of wolfengine shared library.\n");
    printf("                  Default: .libs\n");
    printf("  --engine <str>  Name of wolfsslengine. Default: libwolfengine\n");
    printf("  --no-debug      Disable debug logging\n");
    printf("  --list          Display all test cases\n");
    printf("  <num>           Run this test case, but not all\n");
}

int main(int argc, char* argv[])
{
    int err = 0;
    ENGINE *e = NULL;
#ifdef WE_NO_DYNAMIC_ENGINE
    int staticTest = 1;
    const char *name = wolfengine_id;
#else
    int staticTest = 0;
    const char *name = wolfengine_lib;
#endif /* WE_NO_DYNAMIC_ENGINE */
    const char *dir = ".libs";
    int i;
    int runAll = 1;
    int runTests = 1;

    for (--argc, ++argv; argc > 0; argc--, argv++) {
        if (strncmp(*argv, "--help", 6) == 0) {
            usage();
            runAll = 0;
            break;
        }
        else if (strncmp(*argv, "--static", 9) == 0) {
            staticTest = 1;
        }
        else if (strncmp(*argv, "--dir", 6) == 0) {
            argc--;
            argv++;
            if (argc == 0) {
                printf("\n");
                printf("Missing directory argument\n");
                usage();
                err = 1;
                break;
            }
            dir = *argv;
            printf("Engine directory: %s\n", dir);
        }
        else if (strncmp(*argv, "--engine", 9) == 0) {
            argc--;
            argv++;
            if (argc == 0) {
                printf("\n");
                printf("Missing engine argument\n");
                usage();
                err = 1;
                break;
            }
            name = *argv;
            printf("Engine: %s\n", name);
        }
        else if (strncmp(*argv, "--no-debug", 11) == 0) {
            debug = 0;
        }
        else if (strncmp(*argv, "--list", 7) == 0) {
            for (i = 0; i < TEST_CASE_CNT; i++) {
                printf("%2d: %s\n", i + 1, test_case[i].name);
            }
            runTests = 0;
        }
        else if ((i = atoi(*argv)) > 0) {
            if (i > TEST_CASE_CNT) {
                printf("Test case %d not found\n", i);
                err = 1;
                break;
            }
            
            printf("Run test case: %d\n", i);
            test_case[i-1].run = 1;
            runAll = 0;
        }
        else {
            printf("\n");
            printf("Unrecognized option: %s\n", *argv);
            usage();
            err = 1;
            break;
        }
    }

    if (err == 0 && runTests) {
        printf("\n");

        /* Set directory where wolfsslengine library is stored */
        setenv("OPENSSL_ENGINES", dir, 1);

        if (staticTest == 1) {
            printf("Running tests using static engine.\n");
            ENGINE_load_wolfengine();
            name = wolfengine_id;
        }
    #ifndef WE_NO_DYNAMIC_ENGINE
        else {
            printf("Running tests using dynamic engine.\n");
        #if OPENSSL_VERSION_NUMBER >= 0x10100000L
            OPENSSL_init_ssl(OPENSSL_INIT_ENGINE_DYNAMIC |
                             OPENSSL_INIT_LOAD_CONFIG,
                             NULL);
        #else
            ENGINE_load_dynamic();
        #endif
        }
    #endif /* WE_NO_DYNAMIC_ENGINE */

        e = ENGINE_by_id(name);
        if (e == NULL) {
            PRINT_ERR_MSG("Failed to find engine!\n");
            err = 1;
        }
    }

    if ((err == 0) && debug) {
        if (ENGINE_ctrl_cmd(e, "enable_debug", 1, NULL, NULL, 0) != 1) {
            PRINT_ERR_MSG("Failed to enable debug logging");
            err = 1;
        }
    }

    if (err == 0 && runTests) {
        printf("###### TESTSUITE START\n");
        printf("\n");

        if (err == 0) {
            for (i = 0; i < TEST_CASE_CNT; i++) {
                if (!runAll && !test_case[i].run) {
                    continue;
                }

                printf("#### Start: %d - %s\n", i + 1, test_case[i].name);

                test_case[i].err = test_case[i].func(e, test_case[i].data);
                test_case[i].done = 1;

                if (!test_case[i].err)
                    printf("#### SUCCESS: %d - %s\n", i + 1, test_case[i].name);
                else
                    printf("#### FAILED: %d - %s\n", i + 1, test_case[i].name);
                printf("\n");
            }

            for (i = 0; i < TEST_CASE_CNT; i++) {
                if (test_case[i].done && test_case[i].err != 0) {
                    err = test_case[i].err;
                    break;
                }
            }
        }

        if (err == 0) {
            printf("###### TESTSUITE SUCCESS\n");
        }
        else {
            for (i = 0; i < TEST_CASE_CNT; i++) {
                if (test_case[i].err) {
                    printf("## FAIL: %d: %s\n", i + 1, test_case[i].name);
                }
            }
            printf("###### TESTSUITE FAILED\n");
        }

        ENGINE_free(e);
    #if OPENSSL_VERSION_NUMBER >= 0x10100000L
        OPENSSL_cleanup();
    #endif
    }

    return err;
}

