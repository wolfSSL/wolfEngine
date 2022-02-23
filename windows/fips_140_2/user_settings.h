#ifndef USER_SETTINGS_H
#define USER_SETTINGS_H

#define WOLFENGINE_DEBUG
#define WE_USE_HASH
#define WE_HAVE_SHA384
#define WE_HAVE_SHA512
#define WE_HAVE_SHA1
#define WE_HAVE_SHA224
#define WE_HAVE_SHA256
#define WE_HAVE_CMAC
#define WE_HAVE_MAC
#define WE_HAVE_HMAC
#define WE_HAVE_MAC
#define WE_HAVE_DES3CBC
#define WE_HAVE_AESECB
#define WE_HAVE_AESCBC
#define WE_HAVE_AESCTR
#define WE_HAVE_RANDOM
#define WE_HAVE_RSA
#define WE_HAVE_DH
#define WE_HAVE_ECC
#define WE_HAVE_EVP_PKEY
#define WE_HAVE_ECDSA
#define WE_HAVE_ECDH
#define WE_HAVE_ECKEYGEN
#define WE_HAVE_EC_P192
#define WE_HAVE_EC_P224
#define WE_HAVE_EC_P256
#define WE_HAVE_EC_P384
#define WE_HAVE_EC_P521
#define WE_HAVE_DIGEST

#ifdef _WIN32

/* The wolfSSL Visual Studio project may define these FIPS macros. We want to
 * override them if that's the case. */
#undef  HAVE_FIPS
#define HAVE_FIPS
#undef  HAVE_FIPS_VERSION
#define HAVE_FIPS_VERSION 2
#undef  HAVE_FIPS_VERSION_MINOR
#define HAVE_FIPS_VERSION_MINOR 0

#define HAVE_AES_ECB
#define WC_RSA_NO_PADDING
#define WOLFSSL_PUBLIC_MP
#define ECC_MIN_KEY_SZ 192
#define WOLFSSL_TLS13
#define HAVE_TLS_EXTENSIONS
#define HAVE_SUPPORTED_CURVES
#define HAVE_THREAD_LS
#define ECC_TIMING_RESISTANT
#define WC_RSA_BLINDING
#define HAVE_AESCCM
#define WOLFSSL_AES_COUNTER
#define WOLFSSL_AES_DIRECT
#define WOLFSSL_SHA224
#define WOLFSSL_SHA512
#define WOLFSSL_SHA384
#define WOLFSSL_KEY_GEN
#define HAVE_HKDF
#define HAVE_X963_KDF
#define NO_DSA
#define HAVE_ECC
#define ECC_SHAMIR
#define HAVE_ECC_CDH
#define WC_RSA_PSS
#define WOLFSSL_BASE64_ENCODE
#define NO_RC4
#define WOLFSSL_CMAC
#define NO_HC128
#define NO_RABBIT
#define WOLFSSL_SHA3
#define HAVE_ONE_TIME_AUTH
#define HAVE_HASHDRBG
#define HAVE_EXTENDED_MASTER
#define HAVE_ENCRYPT_THEN_MAC
#define NO_PSK
#define NO_MD4
#define NO_PWDBASED
#define WC_NO_ASYNC_THREADING
#define HAVE_DH_DEFAULT_PARAMS
#define GCM_TABLE_4BIT
#define HAVE_AESGCM
#define HAVE_WC_INTROSPECTION
#define OPENSSL_COEXIST
#define NO_OLD_RNGNAME
#define NO_OLD_WC_NAMES
#define NO_OLD_SSL_NAMES
#define NO_OLD_SHA_NAMES
#define NO_OLD_MD5_NAME
#define NO_OLD_SHA256_NAMES
#define HAVE_PUBLIC_FFDHE
#define HAVE_FFDHE_2048
#define HAVE_FFDHE_3072
#define HAVE_FFDHE_4096
#define Sha3 wc_Sha3
#define WOLFSSL_VALIDATE_ECC_IMPORT
#define WOLFSSL_VALIDATE_FFC_IMPORT
#define HAVE_FFDHE_Q
#define WOLFSSL_NO_SHAKE256
#define WOLFSSL_NOSHA512_224
#define WOLFSSL_NOSHA512_256

#ifdef _WIN64
#define WOLFSSL_AESNI
#endif

/* Needed to export symbols in the final DLL */
#define OPENSSL_SYS_WINDOWS
#define OPENSSL_OPT_WINDLL

#endif /* _WIN32 */

#endif
