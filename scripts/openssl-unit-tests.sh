#!/bin/bash

printf "Running OpenSSL 1.0.2h unit tests using wolfEngine.\n\n"

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
WOLFENGINE_ROOT="$SCRIPT_DIR/.."
TEST_PATCH_DIR="$WOLFENGINE_ROOT/openssl_patches/1.0.2h/tests/"
if [ "$MAKE_JOBS" = "" ]; then
  MAKE_JOBS=4
fi

if [ -z ${LOGILE} ]; then
    LOGFILE=${SCRIPT_DIR}/openssl-unit-tests.log
fi

FAILED=0

run_test() {
    printf "\t$1..."
    ./$* 2>&1 | tee $LOGFILE
    if [ $? != 0 ]; then
        printf "failed\n"
        FAILED=$((FAILED+1))
    else
        printf "passed\n"
    fi
}

printf "Setting up OpenSSL 1.0.2h.\n"
if [ -z "${OPENSSL_1_0_2_SOURCE}" ]; then
    printf "\tCloning OpenSSL and checking out version 1.0.2h.\n"
    git clone --depth=1 -b OpenSSL_1_0_2h https://github.com/openssl/openssl.git openssl-1_0_2h 2>&1 | tee $LOGFILE
    if [ $? != 0 ]; then
        printf "clone failed\n"
        exit 1
    fi

    cd openssl-1_0_2h

    printf "\tPatching unit tests to use wolfEngine.\n"
    PATCHES=`find $TEST_PATCH_DIR -name "*.patch"`
    for PATCH in $PATCHES
    do
        # Try to patch. If doesn't work, check whether it has already been
        # applied.
        git apply $PATCH &>$LOGFILE || git apply $PATCH -R --check &>> $LOGFILE
        if [ $? != 0 ]; then
            printf "$PATCH failed to apply\n"
            exit 1
        fi
    done

    if [ -z "${OPENSSL_NO_BUILD}" ]; then
        printf "\tConfiguring.\n"
        # Configure for debug.
        ./config shared no-asm -g3 -O0 -fno-omit-frame-pointer -fno-inline-functions 2>&1 | tee $LOGFILE
        if [ $? != 0 ]; then
            printf "config failed\n"
            exit 1
        fi

        printf "\tBuilding.\n"
        make -j$MAKE_JOBS 2>&1 | tee $LOGFILE
        if [ $? != 0 ]; then
            printf "make failed\n"
            exit 1
        fi
    fi

    OPENSSL_1_0_2_SOURCE=`pwd`
    cd ..
else
    printf "\tUsing OpenSSL 1.0.2h source code at $OPENSSL_1_0_2_SOURCE\n"
fi

export LD_LIBRARY_PATH="$OPENSSL_1_0_2_SOURCE:$LD_LIBRARY_PATH"
export OPENSSL_ENGINES="$WOLFENGINE_ROOT/.libs/"

if [ -z "${WOLFENGINE_NO_BUILD}" ]; then
    printf "Setting up wolfEngine to use OpenSSL 1.0.2h.\n"
    printf "\tConfiguring.\n"
    # Tests have been patched to use debug logging - must enable debug
    ./configure LDFLAGS="-L$OPENSSL_1_0_2_SOURCE" --with-openssl=$OPENSSL_1_0_2_SOURCE --enable-debug 2>&1 | tee $LOGFILE
    if [ $? != 0 ]; then
        printf "config failed\n"
        exit 1
    fi

    printf "\tBuilding.\n"
    make -j$MAKE_JOBS 2>&1 | tee $LOGFILE
    if [ $? != 0 ]; then
        printf "make failed\n"
        exit 1
    fi
fi

printf "Running unit tests.\n"
cd $OPENSSL_1_0_2_SOURCE/test
for p in $TEST_PATCH_DIR/*.patch
do
    # Construct the test executable name by stripping the _102.patch suffix off
    # the patch file name.
    TEST="$(basename $p _102h.patch)"

    # evp_test takes the file evptests.txt as input.
    if [ "$TEST" == "evp_test" ]; then
        TEST="$TEST evptests.txt"
    fi

    run_test $TEST
done

# testenc doesn't need to be patched, but it does need to have the configuration
# file set so that wolfEngine is used.
cat > $SCRIPT_DIR/tmp.conf << EOF
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
export OPENSSL_CONF=$SCRIPT_DIR/tmp.conf

run_test testenc

# Remove the temporary config file used for testenc.
rm $SCRIPT_DIR/tmp.conf

if [ $FAILED == 0 ]; then
    printf "All tests passed.\n\n"
    exit 0
else
    printf "$FAILED tests failed.\n\n"
    exit 1
fi
