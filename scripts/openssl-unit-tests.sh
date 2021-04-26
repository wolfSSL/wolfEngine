#!/bin/bash

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
WOLFENGINE_ROOT=`dirname "$SCRIPT_DIR"`
WOLFENGINE_LIBS="$WOLFENGINE_ROOT/.libs"
CERT_DIR="$WOLFENGINE_ROOT/certs"
TMP_CONF="$SCRIPT_DIR/tmp.conf"
TMP_OUT="$SCRIPT_DIR/out"

TEST_PATCH_DIR_102="$WOLFENGINE_ROOT/openssl_patches/1.0.2h/tests/"
TEST_PATCH_DIR_111="$WOLFENGINE_ROOT/openssl_patches/1.1.1b/tests/"

OPENSSL_EXTRA_CFLAGS="-g3 -O0 -fno-omit-frame-pointer -fno-inline-functions"

if [ "$MAKE_JOBS" = "" ]; then
  MAKE_JOBS=4
fi

if [ -z ${LOGFILE} ]; then
    LOGFILE=${SCRIPT_DIR}/openssl-unit-tests.log
fi

# Clear log file.
>$LOGFILE

do_cleanup() {
    # Remove the temporary config file used for testenc.
    rm -f $TMP_CONF
    rm -f $TMP_OUT
}

do_trap() {
    printf "got trap\n"
    do_cleanup
    exit 1
}

trap do_trap INT TERM

run_testssl() {
    KEY=$CERT_DIR/server-key.pem
    CERT=$CERT_DIR/server-cert.pem
    CA=$CERT_DIR/ca-cert.pem
    printf "\ttestssl RSA..." | tee -a $LOGFILE
    sh ./testssl $KEY $CERT $CA &>> $LOGFILE
    if [ $? != 0 ]; then
        printf "failed\n"
        FAILED=$((FAILED+1))
    else
        printf "passed\n"
    fi

    # Using ECC keys doesn't work as SSLv3 doesn't have any ciphers
}

# assuming is running from OpenSSL-1.1.1/test directory
run_111testssl() {
    printf "\t$1..." | tee -a $LOGFILE
    eval "CTLOG_FILE=ct/log_list.conf TEST_CERTS_DIR=certs ./$* &>> $LOGFILE"
    if [ $? != 0 ]; then
        printf "failed\n"
        FAILED=$((FAILED+1))
    else
        printf "passed\n"
    fi
}

run_openssl() {
    printf "\t$1 $2..." | tee -a $LOGFILE
    (LD_LIBRARY_PATH="$WOLFENGINE_LIBS:$LD_LIBRARY_PATH" \
    eval "../apps/openssl $1 -engine wolfengine $2" &>> $LOGFILE)
    if [ $? != 0 ]; then
        printf "failed\n"
        FAILED=$((FAILED+1))
    else
        printf "passed\n"
    fi
}

run_test() {
    printf "\t$1..." | tee -a $LOGFILE
    ./$* &>> $LOGFILE
    if [ $? != 0 ]; then
        printf "failed\n"
        FAILED=$((FAILED+1))
    else
        printf "passed\n"
    fi
}

create_tmp_conf() {
    cat > $TMP_CONF << EOF
openssl_conf = openssl_init

[openssl_init]
engines = engine_section

[engine_section]
wolfengine = wolfengine_section

[wolfengine_section]
dynamic_path = $WOLFENGINE_ROOT/.libs/libwolfengine.so
default_algorithms = ALL
init = 1
enable_debug = 1
EOF
    export OPENSSL_CONF=$TMP_CONF
}

patch_openssl() {
    printf "\tPatching unit tests to use wolfEngine.\n"
    PATCHES=`find $TEST_PATCH_DIR -name "*.patch"`
    for PATCH in $PATCHES
    do
        # Try to patch. If doesn't work, check whether it has already been
        # applied.
        git apply $PATCH &>$LOGFILE || git apply $PATCH -R --check &>> $LOGFILE
        if [ $? != 0 ]; then
            printf "$PATCH failed to apply\n"
            do_cleanup
            exit 1
        fi
    done
}

setup_openssl_102h() {
    printf "Setting up OpenSSL 1.0.2h.\n"
    if [ -z "${OPENSSL_1_0_2_SOURCE}" ]; then
        if [ ! -d "openssl-1_0_2h" ]; then
            printf "\tCloning OpenSSL and checking out version 1.0.2h.\n"
            git clone --depth=1 -b OpenSSL_1_0_2h https://github.com/openssl/openssl.git openssl-1_0_2h 2>&1 | tee -a $LOGFILE
            if [ "${PIPESTATUS[0]}" != 0 ]; then
                printf "clone failed\n"
                do_cleanup
                exit 1
            fi
        fi

        cd openssl-1_0_2h

        patch_openssl

        if [ -z "${OPENSSL_NO_CONFIG}" ]; then
            printf "\tConfiguring.\n"
            # Configure for debug.
            ./config shared no-asm $OPENSSL_EXTRA_CFLAGS 2>&1 | tee -a $LOGFILE
            if [ "${PIPESTATUS[0]}" != 0 ]; then
                printf "config failed\n"
                do_cleanup
                exit 1
            fi
        fi

        if [ -z "${OPENSSL_NO_BUILD}" ]; then
            printf "\tBuilding.\n"
            make -j$MAKE_JOBS 2>&1 | tee -a $LOGFILE
            if [ "${PIPESTATUS[0]}" != 0 ]; then
                printf "make failed\n"
                do_cleanup
                exit 1
            fi
        fi

        OPENSSL_1_0_2_SOURCE=`pwd`
        cd ..
    else
        printf "\tUsing OpenSSL 1.0.2h source code at $OPENSSL_1_0_2_SOURCE\n"
    fi
}

setup_openssl_111b() {
    printf "Setting up OpenSSL 1.1.1b.\n"
    if [ -z "${OPENSSL_1_1_1_SOURCE}" ]; then
        if [ ! -d "openssl-1_1_1b" ]; then
            printf "\tCloning OpenSSL and checking out version 1.1.1b.\n"
            git clone --depth=1 -b OpenSSL_1_1_1b https://github.com/openssl/openssl.git openssl-1_1_1b 2>&1 | tee -a $LOGFILE
            if [ "${PIPESTATUS[0]}" != 0 ]; then
                printf "clone failed\n"
                do_cleanup
                exit 1
            fi
        fi

        cd openssl-1_1_1b

        patch_openssl

        if [ -z "${OPENSSL_NO_CONFIG}" ]; then
            printf "\tConfiguring.\n"
            # Configure for debug.
            ./config shared no-asm $OPENSSL_EXTRA_CFLAGS 2>&1 | tee -a $LOGFILE
            if [ "${PIPESTATUS[0]}" != 0 ]; then
                printf "config failed\n"
                do_cleanup
                exit 1
            fi
        fi

        if [ -z "${OPENSSL_NO_BUILD}" ]; then
            printf "\tBuilding.\n"
            make -j$MAKE_JOBS 2>&1 | tee -a $LOGFILE
            if [ "${PIPESTATUS[0]}" != 0 ]; then
                printf "make failed\n"
                do_cleanup
                exit 1
            fi
        fi

        OPENSSL_1_1_1_SOURCE=`pwd`
        cd ..
    else
        printf "\tUsing OpenSSL 1.1.1b source code at $OPENSSL_1_1_1_SOURCE\n"
    fi
}

build_wolfssl() {
    if [ -z "${WOLFENGINE_NO_BUILD}" ]; then
        printf "Setting up wolfEngine to use $OPENSSL_VERS_STR.\n"
        if [ ! -f "./configure" ]; then
            printf "\tAutogen.\n"
            ./autogen.sh
        fi
        printf "\tConfiguring.\n"
        # Tests have been patched to use debug logging - must enable debug.
        # User can set WOLFENGINE_EXTRA_LDFLAGS to provide extra LDFLAGS and
        # WOLFENGINE_EXTRA_CPPFLAGS to provide extra CPPFLAGS.
echo "./configure LDFLAGS="-L$OPENSSL_SOURCE $WOLFENGINE_EXTRA_LDFLAGS" \
                    CPPFLAGS="$WOLFENGINE_EXTRA_CPPFLAGS" \
                    --with-openssl=$OPENSSL_SOURCE \
                    --enable-debug"
        ./configure LDFLAGS="-L$OPENSSL_SOURCE $WOLFENGINE_EXTRA_LDFLAGS" \
                    CPPFLAGS="$WOLFENGINE_EXTRA_CPPFLAGS" \
                    --with-openssl=$OPENSSL_SOURCE \
                    --enable-debug 2>&1 | tee -a $LOGFILE
        if [ "${PIPESTATUS[0]}" != 0 ]; then
            printf "config failed\n"
            do_cleanup
            exit 1
        fi

        printf "\tBuilding.\n"
        make -j$MAKE_JOBS 2>&1 | tee $LOGFILE
        if [ "${PIPESTATUS[0]}" != 0 ]; then
            printf "make failed\n"
            do_cleanup
            exit 1
        fi
    fi
}

run_patched_tests() {
    printf "Running unit tests.\n"
    for p in $TEST_PATCH_DIR/*.patch
    do
        # Construct the test executable name by stripping the _102.patch suffix
        # off the patch file name.
        TEST="$(basename $p $PATCH_EXT)"

        # evp_test takes the file evptests.txt as input.
        if [ "$TEST" == "evp_test" ]; then
            TEST="$TEST evptests.txt"
        fi
        # main is the common file for 1.1.1b tests
        if [ "$TEST" == "main" -o "$TEST" == "apps" ]; then
            continue
        fi
        if [[ "$TEST" == *".txt"* ]]; then
            continue
        fi

        run_test $TEST
    done
}

test_openssl_102h() {
    OPENSSL_VERS_STR="OpenSSL 1.0.2h"
    TEST_PATCH_DIR=$TEST_PATCH_DIR_102
    PATCH_EXT="_102h.patch"

    setup_openssl_102h

    OPENSSL_SOURCE=$OPENSSL_1_0_2_SOURCE
    export LD_LIBRARY_PATH="$OPENSSL_SOURCE:$OLD_LIB_PATH"


    printf "Running OpenSSL unit tests using wolfEngine.\n\n"

    build_wolfssl

    cd $OPENSSL_SOURCE/test

    run_patched_tests

    # testenc doesn't need to be patched, but it does need to have the
    # configuration file set so that wolfEngine is used.
    create_tmp_conf
    if [ ! -x testenc ]; then
        chmod 755 testenc
    fi
    run_test testenc
    run_testssl

    cd $WOLFENGINE_ROOT
}

test_openssl_111b() {
    OPENSSL_VERS_STR="OpenSSL 1.1.1b"
    TEST_PATCH_DIR=$TEST_PATCH_DIR_111
    PATCH_EXT="_111b.patch"

    setup_openssl_111b

    OPENSSL_SOURCE=$OPENSSL_1_1_1_SOURCE
    export LD_LIBRARY_PATH="$OPENSSL_SOURCE:$OLD_LIB_PATH"

    printf "Running OpenSSL unit tests using wolfEngine.\n\n"

    build_wolfssl

    cd $OPENSSL_SOURCE/test

    run_patched_tests

    run_test "clienthellotest session.pem"

    # test/recipes/15-test_genrsa.t
    for BITS in 2048 3072 4096
    do
        run_openssl "genrsa" "$BITS"
    done

    # "evppkey.txt" - only one left
    for EVP_KATS in "evpciph.txt" "evpdigest.txt" "evpencod.txt" "evpkdf.txt" "evpmac.txt" "evppbe.txt" "evppkey_ecc.txt" "evpcase.txt" 
    do
        run_test "evp_test recipes/30-test_evp_data/$EVP_KATS"
    done

    # verify_extra_test - test/recipes/70-test_verify_extra.t
    run_test "verify_extra_test ./certs/roots.pem ./certs/untrusted.pem ./certs/bad.pem"

#failing "14-curves.conf"
#failing "15-certstatus.conf"
#failing "16-certstatus.conf"
#failing "20-cert-select.conf"
#failing "22-compression.conf"
#failing "26-tls13_client_auth.conf"
#failing "29-dtls-sctp-label-bug.conf"
    for SSL_TEST in "01-simple.conf" "02-protocol-version.conf" \
        "03-custom_verify.conf" "04-client_auth.conf" "05-sni.conf" \
        "06-sni-ticket.conf" "07-dtls-protocol-version.conf" \
        "08-npn.conf" "09-alpn.conf" "10-resumption.conf" \
        "11-dtls_resumption.conf" "12-ct.conf" "13-fragmentation.conf" \
        "16-dtls-certstatus.conf" "17-renegotiate.conf" \
        "18-dtls-renegotiate.conf" "19-mac-then-encrypt.conf" \
        "21-key-update.conf" \
        "23-srp.conf" "24-padding.conf" "25-cipher.conf" \
        "27-ticket-appdata.conf" \
        "28-seclevel.conf"
    do
        run_111testssl "ssl_test ssl-tests/$SSL_TEST"
    done

    cd $WOLFENGINE_ROOT
}

# Start
OLD_LIB_PATH=$LD_LIBRARY_PATH
export OPENSSL_ENGINES="$WOLFENGINE_LIBS"
FAILED=0

VERSIONS="1.0.2 1.1.1"
if [ "$OPENSSL_VERSIONS" != "" ]; then
    VERSIONS=$OPENSSL_VERSIONS
fi

for VERSION in $VERSIONS
do
    if [ $VERSION = "1.0.2" ]; then
        test_openssl_102h
    elif [ $VERSION = "1.1.1" ]; then
        test_openssl_111b
    fi
done

do_cleanup

if [ $FAILED == 0 ]; then
    printf "All tests passed.\n\n"
    exit 0
else
    printf "$FAILED tests failed.\n\n"
    exit 1
fi

