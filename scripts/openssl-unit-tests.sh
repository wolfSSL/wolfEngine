#!/bin/bash

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
WOLFENGINE_ROOT=`dirname "$SCRIPT_DIR"`
WOLFENGINE_LIBS="$WOLFENGINE_ROOT/.libs"
LIBWOLFENGINE_PATH="$WOLFENGINE_LIBS/libwolfengine.so"
CERT_DIR="$WOLFENGINE_ROOT/certs"
TMP_CONF="$SCRIPT_DIR/tmp.conf"
TMP_OUT="$SCRIPT_DIR/out"

TEST_PATCH_DIR_102="$WOLFENGINE_ROOT/openssl_patches/1.0.2h/tests/"
TEST_PATCH_DIR_111="$WOLFENGINE_ROOT/openssl_patches/1.1.1b/tests/"

OPENSSL_EXTRA_CFLAGS="-g3 -O0 -fno-omit-frame-pointer -fno-inline-functions"
OPENSSL_CONFIG_CMD="./config"
ARCH="$(arch)"
OS="$(uname -s)"
if [ "$OS" == "Darwin" ]; then
    LIBWOLFENGINE_PATH="$WOLFENGINE_LIBS/libwolfengine.dylib"

    # See https://wiki.openssl.org/index.php/Compilation_and_Installation#Configure_.26_Config
    if [ "$ARCH" == "i386" ]; then # Intel
        OPENSSL_CONFIG_CMD="./Configure darwin64-x86_64-cc"
    elif [ "$ARCH" == "arm64" ]; then # M1
        echo "Not able to run tests on Mac with arm64 architecture, yet."
        exit 1
        # OPENSSL_CONFIG_CMD="./Configure darwin64-arm64-cc"
    fi
fi

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
    # Using ECC keys doesn't work as SSLv3 doesn't have any ciphers
    KEY=$CERT_DIR/server-key.pem
    CERT=$CERT_DIR/server-cert.pem
    CA=$CERT_DIR/ca-cert.pem
    printf "\ttestssl RSA..." | tee -a $LOGFILE
    echo "" >> $LOGFILE # add a newline to make failure logs easier to read
    local TMP_LOG=$(mktemp ./log.XXXXX)
    sh ./testssl $KEY $CERT $CA >> $TMP_LOG 2>&1
    if [ $? != 0 ]; then
        printf "failed\n"
        FAILED=$((FAILED+1))
        cat $TMP_LOG >> $LOGFILE
    else
        printf "passed\n"
    fi
    rm $TMP_LOG
}

# Used to run individual ssl-test if wanted, recipes are preferred.
# assuming is running from OpenSSL-1.1.1/test directory
run_individual_111testssl() {
    printf "\t$1..." | tee -a $LOGFILE
    echo "" >> $LOGFILE
    local TMP_LOG=$(mktemp ./log.XXXXX)
    eval "CTLOG_FILE=ct/log_list.conf TEST_CERTS_DIR=certs ./$* >> $TMP_LOG 2>&1"
    if [ $? != 0 ]; then
        printf "failed\n"
        FAILED=$((FAILED+1))
        cat $TMP_LOG >> $LOGFILE
    else
        printf "passed\n"
    fi
    rm $TMP_LOG
}

run_111recipe() {
    printf "\t$1..." | tee -a $LOGFILE
    echo "" >> $LOGFILE
    local TMP_LOG=$(mktemp ./log.XXXXX)
    eval "SRCTOP=../. BLDTOP=../. RESULT_D=test-runs PERL="/usr/bin/perl" EXE_EXT= OPENSSL_ENGINES=`cd ../../.libs 2>/dev/null && pwd` OPENSSL_DEBUG_MEMORY=on perl run_tests.pl $1 >> $TMP_LOG 2>&1"
    if [ $? != 0 ]; then
        printf "failed\n"
        FAILED=$((FAILED+1))
        cat $TMP_LOG >> $LOGFILE
    else
        printf "passed\n"
    fi
    rm $TMP_LOG
}

# used to regenerate ssl-test/ files that have the .in changed
run_111testssl_generate() {
    eval "TOP=.. perl -I ../util/perl generate_ssl_tests.pl ./ssl-tests/$1.in default > ./ssl-tests/$1"
}

run_openssl() {
    printf "\t$1 $2..." | tee -a $LOGFILE
    echo "" >> $LOGFILE
    local TMP_LOG=$(mktemp ./log.XXXXX)
    (LD_LIBRARY_PATH="$WOLFENGINE_LIBS:$LD_LIBRARY_PATH" \
    eval "../apps/openssl $1 -engine wolfengine $2" >> $TMP_LOG 2>&1)
    if [ $? != 0 ]; then
        printf "failed\n"
        FAILED=$((FAILED+1))
        cat $TMP_LOG >> $LOGFILE
    else
        printf "passed\n"
    fi
    rm $TMP_LOG
}

run_test() {
    printf "\t$1..." | tee -a $LOGFILE
    echo "" >> $LOGFILE
    local TMP_LOG=$(mktemp ./log.XXXXX)
    ./$* >> $TMP_LOG 2>&1
    if [ $? != 0 ]; then
        printf "failed\n"
        FAILED=$((FAILED+1))
        cat $TMP_LOG >> $LOGFILE
    else
        printf "passed\n"
    fi
    rm $TMP_LOG
}

create_tmp_conf() {
    cat > $TMP_CONF << EOF
openssl_conf = openssl_init

[openssl_init]
engines = engine_section

[engine_section]
wolfengine = wolfengine_section

[wolfengine_section]
dynamic_path = $LIBWOLFENGINE_PATH
default_algorithms = ALL
init = 1
enable_debug = 1
EOF
    export OPENSSL_CONF=$TMP_CONF
}

apply_patches() {
    for PATCH in $PATCHES
    do
        # Try to patch. If doesn't work, check whether it has already been
        # applied.
        git apply $PATCH &>$LOGFILE || git apply $PATCH -R --check >> $LOGFILE 2>&1
        if [ $? != 0 ]; then
            printf "$PATCH failed to apply\n"
            do_cleanup
            exit 1
        fi
    done
}

patch_openssl_fips() {
    if [ "$WOLFSSL_FIPS" == 1 ]; then
        cd $OPENSSL_SOURCE
        printf "Patching unit tests to support wolfCrypt FIPS.\n"
        if [ -d "$TEST_PATCH_DIR/fips" ]; then
            PATCHES=`find $TEST_PATCH_DIR/fips -name "*.patch"`
            apply_patches
        fi
        printf "\tRebuilding patched tests.\n"
        make -j$MAKE_JOBS 2>&1 | tee -a $LOGFILE
        if [ "${PIPESTATUS[0]}" != 0 ]; then
            printf "make failed\n"
            do_cleanup
            exit 1
        fi
    else
        printf "Skipping unit test FIPS patches.\n"
    fi
}

patch_openssl() {
    printf "\tPatching unit tests to use wolfEngine.\n"
    PATCHES=`find $TEST_PATCH_DIR -maxdepth 1 -name "*.patch"`
    apply_patches
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
            $OPENSSL_CONFIG_CMD shared no-asm $OPENSSL_EXTRA_CFLAGS 2>&1 | tee -a $LOGFILE
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

        #update the certificates so they are not expired.
        cd test
        cd certs
        ./setup.sh
        cd ..
        cd smime-certs
        chmod a+x mksmime-certs.sh
        ./mksmime-certs.sh
        cd ..
        cd ..

        if [ -z "${OPENSSL_NO_CONFIG}" ]; then
            printf "\tConfiguring.\n"
            # Configure for debug.
            $OPENSSL_CONFIG_CMD shared no-asm $OPENSSL_EXTRA_CFLAGS 2>&1 | tee -a $LOGFILE
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

check_fips() {
    printf "Checking if libwolfssl is FIPS.\n"
    if [ ! -f $LIBWOLFENGINE_PATH ]; then
        printf "\tlibwolfengine.so not built yet, can't do FIPS check.\n"
    else
        if [ "$OS" == "Darwin" ]; then
            local LIBWOLFSSL=$(otool -L $LIBWOLFENGINE_PATH | grep -oE "(\/.*libwolfssl.*dylib)")
        else
            local LIBWOLFSSL=$(ldd $LIBWOLFENGINE_PATH | grep -oP "(?<!=>)+\/.*(libwolfssl\.so(\.[0-9]+)*)")
        fi
        if [ -z "$LIBWOLFSSL" ]; then
            printf "\tUnable to find libwolfssl.\n"
        else
            nm $LIBWOLFSSL | grep -q "fipsEntry"
            if [ $? == 0 ]; then
                printf "\tlibwolfssl is FIPS.\n"
                WOLFSSL_FIPS=1
            else
                printf "\tlibwolfssl is not FIPS.\n"
                WOLFSSL_FIPS=0
            fi
        fi
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
        ./configure LDFLAGS="-L$OPENSSL_SOURCE $WOLFENGINE_EXTRA_LDFLAGS" \
                    CPPFLAGS="$WOLFENGINE_EXTRA_CPPFLAGS" \
                    --with-openssl=$OPENSSL_SOURCE \
                    $WOLFENGINE_EXTRA_OPTS \
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

    check_fips
    patch_openssl_fips
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
        if [ "$TEST" == "main" ]; then
            continue
        fi
        # apps and openssl are common files for openssl superapp in 1.1.1b tests
        if [ "$TEST" == "apps" -o "$TEST" == "openssl" ]; then
            continue
        fi
        # ocspapitest is a 1.1.1b tests that needs setup with a recipe
        if [ "$TEST" == "ocspapitest" ]; then
            continue
        fi
        if [[ "$TEST" == *".conf.in"* ]]; then
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
    if [ "$OS" == "Darwin" ]; then
        export DYLD_LIBRARY_PATH="$OPENSSL_SOURCE:$OLD_LIB_PATH"
    else
        export LD_LIBRARY_PATH="$OPENSSL_SOURCE:$OLD_LIB_PATH"
    fi

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
    if [ "$OS" == "Darwin" ]; then
        export DYLD_LIBRARY_PATH="$OPENSSL_SOURCE:$OLD_LIB_PATH"
    else
        export LD_LIBRARY_PATH="$OPENSSL_SOURCE:$OLD_LIB_PATH"
    fi

    printf "Running OpenSSL unit tests using wolfEngine.\n\n"

    build_wolfssl

    cd $OPENSSL_SOURCE/test

    run_patched_tests

    run_test "clienthellotest session.pem"
    run_test "x509_dup_cert_test certs/leaf.pem"

    # test/recipes/15-test_genrsa.t
    for BITS in 2048 3072 4096
    do
        run_openssl "genrsa" "$BITS"
    done

    for EVP_KATS in "evpciph.txt" "evpdigest.txt" "evpencod.txt" "evpkdf.txt" "evpmac.txt" "evppbe.txt" "evppkey.txt" "evppkey_ecc.txt" "evpcase.txt"
    do
        run_test "evp_test recipes/30-test_evp_data/$EVP_KATS"
    done

    # verify_extra_test - test/recipes/70-test_verify_extra.t
    run_test "verify_extra_test ./certs/roots.pem ./certs/untrusted.pem ./certs/bad.pem"

    printf "\n\tTesting Recipes:\n"
    run_111testssl_generate "12-ct.conf"
    run_111testssl_generate "14-curves.conf"
    run_111testssl_generate "20-cert-select.conf"
    run_111recipe "test_ssl_new"
    run_111recipe "test_ssl_old"
    run_111recipe "test_ssl_test_ctx"
    run_111recipe "test_sslcorrupt"
    run_111recipe "test_x509_store"
    run_111recipe "test_pkcs7"
    run_111recipe "test_cms"
    run_111recipe "test_cmsapi"
    run_111recipe "test_crl"
    run_111recipe "test_rsa"
    if [ $WOLFSSL_FIPS = "0" ]; then
        # Uses a 512-bit RSA key to check using SHA512 and full salt length.
        run_111recipe "test_rsapss"
    fi
    run_111recipe "test_x509_check_cert_pkey"
    run_111recipe "test_ocsp"
    run_111recipe "test_sslapi"

# individual test runs (recipe is preferred)
#    for SSL_TEST in "01-simple.conf" "02-protocol-version.conf" \
#        "03-custom_verify.conf" "04-client_auth.conf" "05-sni.conf" \
#        "06-sni-ticket.conf" "07-dtls-protocol-version.conf" \
#        "08-npn.conf" "09-alpn.conf" "10-resumption.conf" \
#        "11-dtls_resumption.conf" "12-ct.conf" "13-fragmentation.conf" \
#        "14-curves.conf" "15-certstatus.conf" \
#        "16-dtls-certstatus.conf" "17-renegotiate.conf" \
#        "18-dtls-renegotiate.conf" "19-mac-then-encrypt.conf" \
#        "20-cert-select.conf" "21-key-update.conf" \
#        "23-srp.conf" "24-padding.conf" "25-cipher.conf" \
#        "26-tls13_client_auth.conf" "27-ticket-appdata.conf" \
#        "28-seclevel.conf"
#    do
#        run_individual_111testssl "ssl_test ssl-tests/$SSL_TEST"
#    done

    cd $WOLFENGINE_ROOT
}

# Start
export OPENSSL_ENGINES="$WOLFENGINE_LIBS"
FAILED=0

VERSIONS="1.0.2 1.1.1"
if [ "$OS" == "Darwin" ]; then
    OLD_LIB_PATH=$DYLD_LIBRARY_PATH

    if [ "$ARCH" == "arm64" ]; then
        # 1.0.2 isn't set up to work with the M1.
        VERSIONS="1.1.1"
    fi
else
    OLD_LIB_PATH=$LD_LIBRARY_PATH
fi

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

