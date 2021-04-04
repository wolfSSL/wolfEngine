# configure.ac
#
# Copyright (C) 2019-2021 wolfSSL Inc.
#

AC_COPYRIGHT([Copyright (C) 2019-2021 wolfSSL Inc.])
AC_PREREQ([2.69])
AC_INIT([wolfengine], [1.0.0])
AC_CONFIG_AUX_DIR([build-aux])

AC_CONFIG_HEADERS([include/config.h])
AC_CONFIG_MACRO_DIR([m4])

dnl m4_include([m4/ax_check_openssl.m4])

AM_INIT_AUTOMAKE([1.11  -Wall -Werror -Wno-portability foreign tar-ustar subdir-objects no-define color-tests])
LT_INIT([disable-static pic-only])

# capture user C_EXTRA_FLAGS from ./configure line, CFLAGS may hold -g -O2 even
# if user doesn't override, no way to tell
USER_C_EXTRA_FLAGS="$C_EXTRA_FLAGS"
USER_CFLAGS="$CFLAGS"

AC_PROG_CC
AC_LANG(C)

LIBS="$LIBS -ldl"

AC_CHECK_HEADERS([openssl/engine.h])

AX_CHECK_OPENSSL(
    [have_openssl=yes],
    AC_MSG_FAILURE([could not locate OpenSSL])
)

if test "x$have_openssl" = "xyes"; then
    LIBS="$LIBS $OPENSSL_LIBS"
    CFLAGS="$CFLAGS $OPENSSL_INCLUDES"
    LDFLAGS="$LDFLAGS $OPENSSL_LDFLAGS"
fi

AC_RUN_IFELSE([AC_LANG_PROGRAM([
    #include <openssl/opensslv.h>
    ],[
    #if OPENSSL_VERSION_NUMBER < 0x10101000L
    exit(1);
    #endif
])], [OPENSSL_111_PLUS=yes], [OPENSSL_111_PLUS=no])

# DEBUG
DEBUG_CFLAGS="-g -O0 -DWOLFENGINE_DEBUG"

# DEBUG
AX_DEBUG
AS_IF([test "$ax_enable_debug" = "yes"],
      [AM_CFLAGS="$DEBUG_CFLAGS $AM_CFLAGS"],
      [])

# COVERAGE
COVERAGE_CFLAGS="--coverage"
AX_COVERAGE
AS_IF([test "$ax_enable_coverage" = "yes"],
      [AM_CFLAGS="$COVERAGE_CFLAGS $AM_CFLAGS"])

# user_settings.h
AC_ARG_ENABLE([usersettings],
    [AS_HELP_STRING([--enable-usersettings],[Use your own user_settings.h and do not add Makefile CFLAGS (default: disabled)])],
    [ ENABLED_USERSETTINGS=$enableval ],
    [ ENABLED_USERSETTINGS=no ]
    )

# Dynamic engine support
AC_ARG_ENABLE([dynamic-engine],
    [AS_HELP_STRING([--enable-dynamic-engine],[Enable loading wolfEngine as a dynamic engine (default: enabled).])],
    [ ENABLED_DYNAMIC_ENGINE=$enableval ],
    [ ENABLED_DYNAMIC_ENGINE=yes ]
    )

if test "$ENABLED_DYNAMIC_ENGINE" != "yes"
then
    AM_CFLAGS="$AM_CFLAGS -DWE_NO_DYNAMIC_ENGINE"
fi

# Single threaded
AC_ARG_ENABLE([singlethreaded],
    [AS_HELP_STRING([--enable-singlethreaded],[Enable wolfEngine single threaded (default: disabled).])],
    [ ENABLED_SINGLETHREADED=$enableval ],
    [ ENABLED_SINGLETHREADED=no ]
    )

if test "$ENABLED_SINGLETHREADED" = "yes"
then
    AM_CFLAGS="$AM_CFLAGS -DWE_SINGLE_THREADED"
fi

# Digest options
AC_ARG_ENABLE([hash],
    [AS_HELP_STRING([--enable-digest],[Enable use of wc_Hash API for digesting (default: enabled)])],
    [ ENABLED_HASH=$enableval ],
    [ ENABLED_HASH=yes ]
    )

if test "$ENABLED_HASH" = "yes"
then
    AM_CFLAGS="$AM_CFLAGS -DWE_USE_HASH"
fi

AC_ARG_ENABLE([sha384],
    [AS_HELP_STRING([--enable-sha384],[Enable SHA384 (default: enabled)])],
    [ ENABLED_SHA384=$enableval ],
    [ ENABLED_SHA384=$ENABLED_HASH ]
    )

if test "$ENABLED_SHA384" = "yes"
then
    ENABLED_DIGEST="yes"
    AM_CFLAGS="$AM_CFLAGS -DWE_HAVE_SHA384"
fi

AC_ARG_ENABLE([sha512],
    [AS_HELP_STRING([--enable-sha512],[Enable SHA512 (default: enabled)])],
    [ ENABLED_SHA512=$enableval ],
    [ ENABLED_SHA512=$ENABLED_HASH ]
    )

if test "$ENABLED_SHA512" = "yes"
then
    ENABLED_DIGEST="yes"
    AM_CFLAGS="$AM_CFLAGS -DWE_HAVE_SHA512"
fi

AC_ARG_ENABLE([sha],
    [AS_HELP_STRING([--enable-sha],[Enable SHA1 (default: enabled)])],
    [ ENABLED_SHA1=$enableval ],
    [ ENABLED_SHA1=yes ]
    )

if test "$ENABLED_SHA1" = "yes"
then
    ENABLED_DIGEST="yes"
    AM_CFLAGS="$AM_CFLAGS -DWE_HAVE_SHA1"
    if test "$ENABLED_HASH" = "no"
    then
        AM_CFLAGS="$AM_CFLAGS -DWE_SHA1_DIRECT"
    fi
fi

AC_ARG_ENABLE([sha224],
    [AS_HELP_STRING([--enable-sha224],[Enable SHA224 (default: enabled)])],
    [ ENABLED_SHA224=$enableval ],
    [ ENABLED_SHA224=yes ]
    )

if test "$ENABLED_SHA224" = "yes"
then
    ENABLED_DIGEST="yes"
    AM_CFLAGS="$AM_CFLAGS -DWE_HAVE_SHA224"
    if test "$ENABLED_HASH" = "no"
    then
        AM_CFLAGS="$AM_CFLAGS -DWE_SHA224_DIRECT"
    fi
fi

AC_ARG_ENABLE([sha256],
    [AS_HELP_STRING([--enable-sha256],[Enable SHA256 (default: enabled)])],
    [ ENABLED_SHA256=$enableval ],
    [ ENABLED_SHA256=yes ]
    )

if test "$ENABLED_SHA256" = "yes"
then
    ENABLED_DIGEST="yes"
    AM_CFLAGS="$AM_CFLAGS -DWE_HAVE_SHA256"
    if test "$ENABLED_HASH" = "no"
    then
        AM_CFLAGS="$AM_CFLAGS -DWE_SHA256_DIRECT"
    fi
fi

AC_ARG_ENABLE([sha3],
    [AS_HELP_STRING([--enable-sha3],[Enable SHA3 (default: enabled)])],
    [ ENABLED_SHA3=$enableval ],
    [ ENABLED_SHA3=no ]
    )

AC_ARG_ENABLE([sha3-224],
    [AS_HELP_STRING([--enable-sha3-224],[Enable SHA3-224 (default: enabled)])],
    [ ENABLED_SHA3_224=$enableval ],
    [ ENABLED_SHA3_224=yes ]
    )

if test "$ENABLED_SHA3_224" = "yes" || test "$ENABLED_SHA3" = "yes"
then
    if test "$OPENSSL_111_PLUS" = "no"
    then
        ENABLED_SHA3_224="no"
        AC_MSG_WARN([--enable-sha3-224 ignored because OpenSSL doesn't have support for SHA-3.])
    else
        ENABLED_DIGEST="yes"
        AM_CFLAGS="$AM_CFLAGS -DWE_HAVE_SHA3_224"
    fi
fi

AC_ARG_ENABLE([sha3-256],
    [AS_HELP_STRING([--enable-sha3-256],[Enable SHA3-256 (default: enabled)])],
    [ ENABLED_SHA3_256=$enableval ],
    [ ENABLED_SHA3_256=yes ]
    )

if test "$ENABLED_SHA3_256" = "yes" || test "$ENABLED_SHA3" = "yes"
then
    if test "$OPENSSL_111_PLUS" = "no"
    then
        ENABLED_SHA3_256="no"
        AC_MSG_WARN([--enable-sha3-256 ignored because OpenSSL doesn't have support for SHA-3.])
    else
        ENABLED_DIGEST="yes"
        AM_CFLAGS="$AM_CFLAGS -DWE_HAVE_SHA3_256"
    fi
fi

AC_ARG_ENABLE([sha3-384],
    [AS_HELP_STRING([--enable-sha3-384],[Enable SHA3-384 (default: enabled)])],
    [ ENABLED_SHA3_384=$enableval ],
    [ ENABLED_SHA3_384=yes ]
    )

if test "$ENABLED_SHA3_384" = "yes" || test "$ENABLED_SHA3" = "yes"
then
    if test "$OPENSSL_111_PLUS" = "no"
    then
        ENABLED_SHA3_384="no"
        AC_MSG_WARN([--enable-sha3-384 ignored because OpenSSL doesn't have support for SHA-3.])
    else
        ENABLED_DIGEST="yes"
        AM_CFLAGS="$AM_CFLAGS -DWE_HAVE_SHA3_384"
    fi
fi

AC_ARG_ENABLE([sha3-512],
    [AS_HELP_STRING([--enable-sha3-512],[Enable SHA3-512 (default: enabled)])],
    [ ENABLED_SHA3_512=$enableval ],
    [ ENABLED_SHA3_512=yes ]
    )

if test "$ENABLED_SHA3_512" = "yes" || test "$ENABLED_SHA3" = "yes"
then
    if test "$OPENSSL_111_PLUS" = "no"
    then
        ENABLED_SHA3_512="no"
        AC_MSG_WARN([--enable-sha3-512 ignored because OpenSSL doesn't have support for SHA-3.])
    else
        ENABLED_DIGEST="yes"
        AM_CFLAGS="$AM_CFLAGS -DWE_HAVE_SHA3_512"
    fi
fi

AC_ARG_ENABLE([cmac],
    [AS_HELP_STRING([--enable-cmac],[Enable CMAC (default: enabled)])],
    [ ENABLED_CMAC=$enableval ],
    [ ENABLED_CMAC=yes ]
    )

if test "$ENABLED_CMAC" = "yes"
then
    ENABLED_DIGEST="yes"
    AM_CFLAGS="$AM_CFLAGS -DWE_HAVE_CMAC -DWE_HAVE_MAC"
fi

AC_ARG_ENABLE([hmac],
    [AS_HELP_STRING([--enable-hmac],[Enable HMAC (default: enabled)])],
    [ ENABLED_HMAC=$enableval ],
    [ ENABLED_HMAC=yes ]
    )

if test "$ENABLED_HMAC" = "yes"
then
    ENABLED_DIGEST="yes"
    AM_CFLAGS="$AM_CFLAGS -DWE_HAVE_HMAC -DWE_HAVE_MAC"
fi

# DES3-CBC
AC_ARG_ENABLE([des3cbc],
    [AS_HELP_STRING([--enable-des3cbc],[Enable DES3-CBC (default: enabled)])],
    [ ENABLED_DES3CBC=$enableval ],
    [ ENABLED_DES3CBC=yes ]
    )

if test "$ENABLED_DES3CBC" = "yes"
then
    AM_CFLAGS="$AM_CFLAGS -DWE_HAVE_DES3CBC"
fi

# AES-ECB
AC_ARG_ENABLE([aesecb],
    [AS_HELP_STRING([--enable-aesecb],[Enable AES-ECB (default: enabled)])],
    [ ENABLED_AESECB=$enableval ],
    [ ENABLED_AESECB=yes ]
    )

if test "$ENABLED_AESECB" = "yes"
then
    AM_CFLAGS="$AM_CFLAGS -DWE_HAVE_AESECB"
fi

# AES-CBC
AC_ARG_ENABLE([aescbc],
    [AS_HELP_STRING([--enable-aescbc],[Enable AES-CBC (default: enabled)])],
    [ ENABLED_AESCBC=$enableval ],
    [ ENABLED_AESCBC=yes ]
    )

if test "$ENABLED_AESCBC" = "yes"
then
    AM_CFLAGS="$AM_CFLAGS -DWE_HAVE_AESCBC"
fi

# AES-CTR
AC_ARG_ENABLE([aesctr],
    [AS_HELP_STRING([--enable-aesctr],[Enable AES-CTR (default: enabled)])],
    [ ENABLED_AESCTR=$enableval ],
    [ ENABLED_AESCTR=yes ]
    )

if test "$ENABLED_AESCTR" = "yes"
then
    AM_CFLAGS="$AM_CFLAGS -DWE_HAVE_AESCTR"
fi

# AES-GCM
AC_ARG_ENABLE([aesgcm],
    [AS_HELP_STRING([--enable-aesgcm],[Enable AES-GCM (default: disabled)])],
    [ ENABLED_AESGCM=$enableval ],
    [ ENABLED_AESGCM=no ]
    )

if test "$ENABLED_AESGCM" = "yes"
then
    AM_CFLAGS="$AM_CFLAGS -DWE_HAVE_AESGCM"
fi

# AES-CCM
AC_ARG_ENABLE([aesccm],
    [AS_HELP_STRING([--enable-aesccm],[Enable AES-CCM (default: disabled)])],
    [ ENABLED_AESCCM=$enableval ],
    [ ENABLED_AESCCM=no ]
    )

if test "$ENABLED_AESCCM" = "yes"
then
    AM_CFLAGS="$AM_CFLAGS -DWE_HAVE_AESCCM"
fi

# RANDOM
AC_ARG_ENABLE([rand],
    [AS_HELP_STRING([--enable-rand],[Enable RAND (default: enabled)])],
    [ ENABLED_RAND=$enableval ],
    [ ENABLED_RAND=yes ]
    )

if test "$ENABLED_RAND" = "yes"
then
    AM_CFLAGS="$AM_CFLAGS -DWE_HAVE_RANDOM"
fi

# RSA
AC_ARG_ENABLE([rsa],
    [AS_HELP_STRING([--enable-rsa],[Enable RSA (default: enabled)])],
    [ ENABLED_RSA=$enableval ],
    [ ENABLED_RSA=yes ]
    )

if test "$ENABLED_RSA" = "yes"
then
    AM_CFLAGS="$AM_CFLAGS -DWE_HAVE_RSA"
fi

# DH
AC_ARG_ENABLE([dh],
    [AS_HELP_STRING([--enable-dh],[Enable Diffie-Hellman (DH) (default: enabled)])],
    [ ENABLED_DH=$enableval ],
    [ ENABLED_DH=yes ]
    )

if test "$ENABLED_DH" = "yes"
then
    AM_CFLAGS="$AM_CFLAGS -DWE_HAVE_DH"
fi

# ECC
AC_ARG_ENABLE([ecc],
    [AS_HELP_STRING([--enable-ecc],[Enable ECC (default: enabled)])],
    [ ENABLED_ECC=$enableval ],
    [ ENABLED_ECC=yes ]
    )

if test "$ENABLED_ECC" = "yes"
then
    AM_CFLAGS="$AM_CFLAGS -DWE_HAVE_ECC"
fi

AC_ARG_ENABLE([evp-pkey],
    [AS_HELP_STRING([--enable-evp-pkey],[Enable ECC using EVP_PKEY (default: enabled)])],
    [ ENABLED_EVP_PKEY=$enableval ],
    [ ENABLED_EVP_PKEY=$ENABLED_ECC ]
    )

if test "$ENABLED_EVP_PKEY" = "yes"
then
    AM_CFLAGS="$AM_CFLAGS -DWE_HAVE_EVP_PKEY"
fi

AC_ARG_ENABLE([ec-key],
    [AS_HELP_STRING([--enable-ec-key],[Enable ECC using EC_KEY (default: enabled)])],
    [ ENABLED_EC_KEY=$enableval ],
    [ ENABLED_EC_KEY=$ENABLED_ECC ]
    )

if test "$ENABLED_EC_KEY" = "yes"
then
    AC_CHECK_FUNC([ENGINE_set_EC], [], [])

    if test "x$ac_cv_func_ENGINE_set_EC" = "xyes"
    then
        AM_CFLAGS="$AM_CFLAGS -DWE_HAVE_EC_KEY"
    else
        ENABLED_EC_KEY="no"
        AC_MSG_WARN([--enable-ec-key ignored because OpenSSL doesn't have ENGINE_set_EC.])
    fi
fi

AC_ARG_ENABLE([ecdsa],
    [AS_HELP_STRING([--enable-ecdsa],[Enable EDSA (default: enabled)])],
    [ ENABLED_ECDSA=$enableval ],
    [ ENABLED_ECDSA=$ENABLED_ECC ]
    )

if test "$ENABLED_ECDSA" = "yes"
then
    if test ENABLED_ECC = "no"
    then
        AM_CFLAGS="$AM_CFLAGS -DWE_HAVE_ECC"
    fi
    AM_CFLAGS="$AM_CFLAGS -DWE_HAVE_ECDSA"
fi

AC_ARG_ENABLE([ecdh],
    [AS_HELP_STRING([--enable-ecdh],[Enable ECDH (default: enabled)])],
    [ ENABLED_ECDH=$enableval ],
    [ ENABLED_ECDH=$ENABLED_ECC ]
    )

if test "$ENABLED_ECDH" = "yes"
then
    ENABLED_ECKG="yes"
    if test ENABLED_ECC = "no"
    then
        AM_CFLAGS="$AM_CFLAGS -DWE_HAVE_ECC"
    fi
    AM_CFLAGS="$AM_CFLAGS -DWE_HAVE_ECDH"
fi

AC_ARG_ENABLE([eckg],
    [AS_HELP_STRING([--enable-eckg],[Enable EC Key Generation (default: enabled)])],
    [ ENABLED_ECKG=$enableval ],
    [ ENABLED_ECKG=$ENABLED_ECC ]
    )

if test "$ENABLED_ECKG" = "yes"
then
    if test ENABLED_ECC = "no"
    then
        AM_CFLAGS="$AM_CFLAGS -DWE_HAVE_ECC"
    fi
    AM_CFLAGS="$AM_CFLAGS -DWE_HAVE_ECKEYGEN"
fi

AC_ARG_ENABLE([p192],
    [AS_HELP_STRING([--enable-p192],[Enable EC Curve P-192 (default: enabled)])],
    [ ENABLED_EC_P192=$enableval ],
    [ ENABLED_EC_P192=$ENABLED_ECC ]
    )

if test "$ENABLED_EC_P192" = "yes"
then
    AM_CFLAGS="$AM_CFLAGS -DWE_HAVE_EC_P192"
fi

AC_ARG_ENABLE([p224],
    [AS_HELP_STRING([--enable-p224],[Enable EC Curve P-224 (default: enabled)])],
    [ ENABLED_EC_P224=$enableval ],
    [ ENABLED_EC_P224=$ENABLED_ECC ]
    )

if test "$ENABLED_EC_P224" = "yes"
then
    AM_CFLAGS="$AM_CFLAGS -DWE_HAVE_EC_P224"
fi

AC_ARG_ENABLE([p256],
    [AS_HELP_STRING([--enable-p256],[Enable EC Curve P-256 (default: enabled)])],
    [ ENABLED_EC_P256=$enableval ],
    [ ENABLED_EC_P256=$ENABLED_ECC ]
    )

if test "$ENABLED_EC_P256" = "yes"
then
    AM_CFLAGS="$AM_CFLAGS -DWE_HAVE_EC_P256"
fi

AC_ARG_ENABLE([p384],
    [AS_HELP_STRING([--enable-p384],[Enable EC Curve P-384 (default: enabled)])],
    [ ENABLED_EC_P384=$enableval ],
    [ ENABLED_EC_P384=$ENABLED_ECC ]
    )

if test "$ENABLED_EC_P384" = "yes"
then
    AM_CFLAGS="$AM_CFLAGS -DWE_HAVE_EC_P384"
fi

AC_ARG_ENABLE([p521],
    [AS_HELP_STRING([--enable-p521],[Enable EC Curve P-521 (default: enabled)])],
    [ ENABLED_EC_P521=$enableval ],
    [ ENABLED_EC_P521=$ENABLED_ECC ]
    )

if test "$ENABLED_EC_P521" = "yes"
then
    AM_CFLAGS="$AM_CFLAGS -DWE_HAVE_EC_P521"
fi


# Check enable options
if test "$ENABLED_DIGEST" = "yes"
then
    AM_CFLAGS="$AM_CFLAGS -DWE_HAVE_DIGEST"
fi
if test "$ENABLED_HASH" = "no"
then
    if test "$ENABLED_SHA384" = "yes"
    then
        AC_MSG_ERROR([cannot enable SHA-384 without enabling hash.])
    fi
    if test "$ENABLED_SHA512" = "yes"
    then
        AC_MSG_ERROR([cannot enable SHA-512 without enabling hash.])
    fi
fi
if test "$ENABLED_DH" = "yes"
then
    if test "$ENABLED_ECKG" = "no"
    then
        AC_MSG_ERROR([cannot disable EC Key Gen with ECDH enabled.])
    fi
fi

if test "x$ENABLED_USERSETTINGS" = "xyes"
then
    # Replace all options and just use -DWOLFENGINE_USER_SETTINGS
    AM_CFLAGS="-DWOLFENGINE_USER_SETTINGS"
fi


AX_HARDEN_CC_COMPILER_FLAGS

OPTION_FLAGS="$CFLAGS $CPPFLAGS $AM_CFLAGS"

LIBS="$LIBS -lwolfssl -ldl -lm"

if test "$GCC" = "yes"
then
    AM_CFLAGS="$AM_CFLAGS -Wall -Wno-unused -Wno-error=deprecated-declarations"
fi

CFLAGS="$CFLAGS $USER_C_EXTRA_FLAGS"

AC_SUBST([AM_CPPFLAGS])
AC_SUBST([AM_CFLAGS])
AC_SUBST([AM_LDFLAGS])

AC_CONFIG_FILES([Makefile])
AC_OUTPUT

# force make clean
echo "---"
echo "Running make clean..."
make clean >/dev/null 2>&1


# output config summary
echo "---"
echo "Configuration summary for $PACKAGE_NAME version $VERSION"
echo ""
echo "   * Installation prefix:        $prefix"
echo "   * System type:                $host_vendor-$host_os"
echo "   * Host CPU:                   $host_cpu"
echo "   * C Compiler:                 $CC"
echo "   * C Flags:                    $CFLAGS"
echo "   * Debug enabled:              $ax_enable_debug"
echo
echo "   Features "
echo "   * User settings:              $ENABLED_USERSETTINGS"
echo "   * Dynamic engine:             $ENABLED_DYNAMIC_ENGINE"
echo "   * Digest:"
echo "   *  - SHA-1:                   $ENABLED_SHA1"
echo "   *  - SHA-224:                 $ENABLED_SHA224"
echo "   *  - SHA-256:                 $ENABLED_SHA256"
echo "   *  - SHA-384:                 $ENABLED_SHA384"
echo "   *  - SHA-512:                 $ENABLED_SHA512"
echo "   *  - SHA3-224:                $ENABLED_SHA3_224"
echo "   *  - SHA3-256:                $ENABLED_SHA3_256"
echo "   *  - SHA3-384:                $ENABLED_SHA3_384"
echo "   *  - SHA3-512:                $ENABLED_SHA3_512"
echo "   * HMAC:                       $ENABLED_HMAC"
echo "   * CMAC:                       $ENABLED_CMAC"
echo "   * Random:                     $ENABLED_RAND"
echo "   * RSA:                        $ENABLED_RSA"
echo "   * DH:                         $ENABLED_DH"
echo "   * AES-GCM:                    $ENABLED_AESGCM"
echo "   * AES-CBC:                    $ENABLED_AESCBC"
echo "   * AES-CCM:                    $ENABLED_AESCCM"
echo "   * AES-CTR:                    $ENABLED_AESCTR"
echo "   * AES-ECB:                    $ENABLED_AESECB"
echo "   * 3DES-CBC:                   $ENABLED_DES3CBC"
echo "   * ECC:                        $ENABLED_ECC"
echo "   *  - EVP_PKEY:                $ENABLED_EVP_PKEY"
echo "   *  - EC_KEY:                  $ENABLED_EC_KEY"
echo "   *  - ECDSA:                   $ENABLED_ECDSA"
echo "   *  - EC Key Gen:              $ENABLED_ECKG"
echo "   *  - ECDH:                    $ENABLED_ECDH"
echo "   *  - P-192:                   $ENABLED_EC_P192"
echo "   *  - P-224:                   $ENABLED_EC_P224"
echo "   *  - P-256:                   $ENABLED_EC_P256"
echo "   *  - P-384:                   $ENABLED_EC_P384"
echo "   *  - P-521:                   $ENABLED_EC_P521"
echo ""
echo "---"

