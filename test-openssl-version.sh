#!/bin/sh

TMP_FILE=/tmp/test_config.$$
CONFIG_STATUS=config.status
CONFIG_STATUS_TMP=/tmp/config.status.$$

C_EXTRA_FLAGS=
VERBOSE="no"

OPENSSL300_DIR=~/wolfssl/external/openssl
OPENSSL111_DIR=~/wolfssl/external/openssl-1.1.1
OPENSSL110_DIR=~/wolfssl/external/openssl-1.1.0h


do_cleanup() {
    if [ -f $CONFIG_STATUS_TMP ]; then
        mv $CONFIG_STATUS_TMP $CONFIG_STATUS
    fi
    ./config.status >/dev/null 2>&1
    make clean >/dev/null 2>&1
    make -j 8 >/dev/null 2>&1

    rm -f $CONFIG_STATUS_TMP
    rm -f $TMP_FILE
}

do_trap() {
    echo "got trap"
    do_cleanup
    exit 2
}

trap do_trap INT TERM

cp $CONFIG_STATUS $CONFIG_STATUS_TMP


do_config() {
    export OPENSSL=$OPENSSL_DIR/apps/openssl

    echo -n "  Configure ... "
    ./configure CFLAGS="-I$OPENSSL_DIR/include" LDFLAGS="-L$OPENSSL_DIR" \
            $C_EXTRA_FLAGS >$TMP_FILE 2>&1
    if [ $? != 0 ]; then
        cat $TMP_FILE
        echo "Failed to configure wolfSSL engine"
        do_cleanup
        exit 1
    fi
    echo "DONE"
    if [ "$VERBOSE" = "yes" ]; then
        cat $TMP_FILE
    fi

    echo -n "  Make ... "
    make >$TMP_FILE 2>&1
    if [ $? != 0 ]; then
        cat $TMP_FILE
        echo "Failed to make wolfSSL engine"
        do_cleanup
        exit 1
    fi
    echo "DONE"
    if [ "$VERBOSE" = "yes" ]; then
        cat $TMP_FILE
    fi

    echo -n "  unit.test ... "
    LD_LIBRARY_PATH=$OPENSSL_DIR ./unit.test >$TMP_FILE 2>&1
    if [ $? != 0 ]; then
        cat $TMP_FILE
        echo "Unit test failed for wolfSSL engine"
        do_cleanup
        exit 1
    fi
    echo "PASS"
    if [ "$VERBOSE" = "yes" ]; then
        cat $TMP_FILE
    fi
}


CONFIG_300="yes"
CONFIG_111="yes"
CONFIG_110="yes"

while [ $# -gt 0 ]
do
    case $1 in
        300)
            echo "Only testing OpenSSL v3.0.0"
            CONFIG_111="no"
            CONFIG_110="no"
            ;;
        111)
            echo "Only testing OpenSSL v1.1.1"
            CONFIG_300="no"
            CONFIG_110="no"
            ;;
        110)
            echo "Only testing OpenSSL v1.1.0"
            CONFIG_300="no"
            CONFIG_111="no"
            ;;
        --debug)
            echo "Enabling debug in wolfengine"
            C_EXTRA_FLAGS="$C_EXTRA_FLAGS --enable-debug"
            ;;
        --no-hash)
            echo "Disabling hash in wolfengine"
            C_EXTRA_FLAGS="$C_EXTRA_FLAGS --disable-hash"
            ;;
        -v)
            VERBOSE="yes"
            ;;
        --verbose)
            VERBOSE="yes"
            ;;
    esac

    shift 1
done

echo

if [ "$CONFIG_300" = "yes" ]; then
    echo "OpenSSL v3.0.0"
    OPENSSL_DIR=$OPENSSL300_DIR
    do_config
fi
if [ "$CONFIG_111" = "yes" ]; then
    echo "OpenSSL v1.1.1"
    OPENSSL_DIR=$OPENSSL111_DIR
    do_config
fi
if [ "$CONFIG_110" = "yes" ]; then
    echo "OpenSSL v1.1.0"
    OPENSSL_DIR=$OPENSSL110_DIR
    do_config
fi

do_cleanup

