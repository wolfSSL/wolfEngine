#!/bin/sh

# test-openssl-version.sh
#
# Copyright (C) 2019-2021 wolfSSL Inc.
#


TMP_FILE=/tmp/test_config.$$
CONFIG_STATUS=config.status
CONFIG_STATUS_TMP=/tmp/config.status.$$

# See README.md for change to make to OpenSSL to enable this to work.
EXTRA_OPTS=""
VERBOSE="no"

# User can set the directory to find different versions of OpenSSL
if [ "$OPENSSL_VER_DIR" = "" ]
then
    OPENSSL_VER_DIR=~/wolfssl/external
fi

# User can set directory of specific versions
if [ "$OPENSSL300_DIR" = "" ]
then
    OPENSSL300_DIR=$OPENSSL_VER_DIR/openssl-3.0.0
fi
if [ "$OPENSSL111_DIR" = "" ]
then
    OPENSSL111_DIR=$OPENSSL_VER_DIR/openssl-1.1.1
fi
if [ "$OPENSSL110_DIR" = "" ]
then
    OPENSSL110_DIR=$OPENSSL_VER_DIR/openssl-1.1.0
fi
if [ "$OPENSSL102_DIR" = "" ]
then
    OPENSSL102_DIR=$OPENSSL_VER_DIR/openssl-1.0.2
fi

# Check if a directory for an OpenSSL version exists to know to test
if [ -d "$OPENSSL300_DIR" ]
then
    CONFIG_300="yes"
else
    CONFIG_300="no"
fi
if [ -d "$OPENSSL111_DIR" ]
then
    CONFIG_111="yes"
else
    CONFIG_111="no"
fi
if [ -d "$OPENSSL110_DIR" ]
then
    CONFIG_110="yes"
else
    CONFIG_110="no"
fi
if [ -d "$OPENSSL102_DIR" ]
then
    CONFIG_102="yes"
else
    CONFIG_102="no"
fi


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
    # Using development version of OpenSSL not install - set LDFLAGS
    ./configure LDFLAGS="-L$OPENSSL_DIR" $EXTRA_OPTS \
            --with-openssl=$OPENSSL_DIR >$TMP_FILE 2>&1
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
    LD_LIBRARY_PATH=$OPENSSL_DIR ./test/unit.test >$TMP_FILE 2>&1
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

while [ $# -gt 0 ]
do
    case $1 in
        300)
            echo "Only testing OpenSSL v3.0.0"
            CONFIG_111="no"
            CONFIG_110="no"
            CONFIG_102="no"
            ;;
        111)
            echo "Only testing OpenSSL v1.1.1"
            CONFIG_300="no"
            CONFIG_110="no"
            CONFIG_102="no"
            ;;
        110)
            echo "Only testing OpenSSL v1.1.0"
            CONFIG_300="no"
            CONFIG_111="no"
            CONFIG_102="no"
            ;;
        102)
            echo "Only testing OpenSSL v1.0.2"
            CONFIG_300="no"
            CONFIG_111="no"
            CONFIG_110="no"
            ;;
        --debug)
            echo "Enabling debug in wolfengine"
            EXTRA_OPTS="$EXTRA_OPTS --enable-debug"
            ;;
        --no-hash)
            echo "Disabling hash in wolfengine"
            EXTRA_OPTS="$EXTRA_OPTS --disable-hash"
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

# Only tests the OpenSSL versions request and available
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
if [ "$CONFIG_102" = "yes" ]; then
    echo "OpenSSL v1.0.2"
    OPENSSL_DIR=$OPENSSL102_DIR
    do_config
fi

# Cleanup temporary files and restore configuration
do_cleanup

