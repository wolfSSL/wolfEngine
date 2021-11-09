# SYNOPSIS
#
#   AX_CHECK_WOLFSSL([action-if-found[, action-if-not-found]])
#
# DESCRIPTION
#
#   Look for wolfSSL in a number of default spots, or in a user-selected
#   spot (via --with-wolfssl).  Sets
#
#     WOLFSSL_INCLUDES to the include directives required
#     WOLFSSL_LIBS to the -l directives required
#     WOLFSSL_LDFLAGS to the -L or -R flags required
#
#   and calls ACTION-IF-FOUND or ACTION-IF-NOT-FOUND appropriately
#
#   This macro sets WOLFSSL_INCLUDES such that source files should use the
#   wolfssl/ directory in include directives:
#
#     #include <wolfssl/wolfcrypt/hmac.h>
#
# LICENSE
#
#   Copyright (c) 2021 wolfSSL <http://www.wolfssl.com/>
#
#   Copying and distribution of this file, with or without modification, are
#   permitted in any medium without royalty provided the copyright notice
#   and this notice are preserved. This file is offered as-is, without any
#   warranty.

#serial 1

AU_ALIAS([CHECK_SSL], [AX_CHECK_WOLFSSL])
AC_DEFUN([AX_CHECK_WOLFSSL], [
    found=false
    AC_ARG_WITH([wolfssl],
        [AS_HELP_STRING([--with-wolfssl=DIR],
            [root of the wolfSSL directory])],
        [
            case "$withval" in
            "" | y | ye | yes | n | no)
            AC_MSG_ERROR([Invalid --with-wolfssl value])
              ;;
            *) wolfssldirs="$withval"
              ;;
            esac
        ], [
            # if pkg-config is installed and wolfssl has installed a .pc file,
            # then use that information and don't search wolfssldirs
            AC_CHECK_TOOL([PKG_CONFIG], [pkg-config])
            if test x"$PKG_CONFIG" != x""; then
                WOLFSSL_LDFLAGS=`$PKG_CONFIG wolfssl --libs-only-L 2>/dev/null`
                if test $? = 0; then
                    WOLFSSL_LIBS=`$PKG_CONFIG wolfssl --libs-only-l 2>/dev/null`
                    WOLFSSL_INCLUDES=`$PKG_CONFIG wolfssl --cflags-only-I 2>/dev/null`
                    found=true
                fi
            fi

            # no such luck; use some default wolfssldirs
            if ! $found; then
                wolfssldirs="/usr/local /usr/lib /usr"
            fi
        ]
        )


    # note that we #include <wolfssl/foo.h>, so the wolfSSL headers have to be
    # in an 'wolfssl' subdirectory

    if ! $found; then
        WOLFSSL_INCLUDES=
        for wolfssldir in $wolfssldirs; do
            AC_MSG_CHECKING([for include/wolfssl/ssl.h in $wolfssldir])
            if test -f "$wolfssldir/include/wolfssl/ssl.h"; then
                WOLFSSL_INCLUDES="-I$wolfssldir/include"
                WOLFSSL_LDFLAGS="-L$wolfssldir/lib"
                WOLFSSL_LIBS="-lwolfssl"

                WOLFSSL_VERSION=$(grep -oP "(?<=define LIBWOLFSSL_VERSION_HEX)\s+0x[[0-9a-fA-F]]+" $wolfssldir/include/wolfssl/version.h)
                WOLFSSL_VERSION_DEC=$(printf "%d" $WOLFSSL_VERSION)

                found=true
                AC_MSG_RESULT([yes])
                break
            else
                AC_MSG_RESULT([no])
            fi
        done
    fi

    if $found; then
        AC_MSG_RESULT([yes])
        $1
    else
        AC_MSG_RESULT([no])
        $2
    fi

    AC_SUBST([WOLFSSL_INCLUDES])
    AC_SUBST([WOLFSSL_LIBS])
    AC_SUBST([WOLFSSL_LDFLAGS])
])
