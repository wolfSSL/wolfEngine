#!/bin/bash

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
CERT_DIR=$SCRIPT_DIR/../certs
LOG_FILE=$SCRIPT_DIR/we-cs-test.log
LOG_SERVER=$SCRIPT_DIR/we-cs-test-server.log
LOG_WE_SERVER=$SCRIPT_DIR/we-cs-test-we-server.log
LOG_CLIENT=$SCRIPT_DIR/we-cs-test-client.log

OPENSSL_CONFIG_OPTS="-g3 -O0 -fno-omit-frame-pointer -fno-inline-functions"

OPENSSL_SERVER_PID=-1
WE_OPENSSL_SERVER_PID=-1

kill_servers() {
    SERVER_PID=$OPENSSL_SERVER_PID
    check_process_running
    if [ "$PS_EXIT" = "0" ]; then
        (kill -INT $SERVER_PID) >/dev/null 2>&1
    fi

    SERVER_PID=$WE_OPENSSL_SERVER_PID
    check_process_running
    if [ "$PS_EXIT" = "0" ]; then
        (kill -INT $SERVER_PID) >/dev/null 2>&1
    fi
}

do_cleanup() {
    kill_servers
}

do_trap() {
    printf "got trap\n"
    do_cleanup
    date
    exit 1
}

trap do_trap INT TERM

TLS13_CIPHERS=(
    TLS_AES_256_GCM_SHA384
    TLS_AES_128_GCM_SHA256
)
TLS12_CIPHERS=(
    ECDHE-ECDSA-AES256-GCM-SHA384
    ECDHE-RSA-AES256-GCM-SHA384
    DHE-RSA-AES256-GCM-SHA384
    ECDHE-ECDSA-AES128-GCM-SHA256
    ECDHE-RSA-AES128-GCM-SHA256
    DHE-RSA-AES128-GCM-SHA256
    ECDHE-ECDSA-AES256-SHA384
    ECDHE-RSA-AES256-SHA384
    DHE-RSA-AES256-SHA256
    ECDHE-ECDSA-AES128-SHA256
    ECDHE-RSA-AES128-SHA256
    DHE-RSA-AES128-SHA256
    ECDHE-ECDSA-AES256-SHA
    ECDHE-RSA-AES256-SHA
    DHE-RSA-AES256-SHA
    ECDHE-ECDSA-AES128-SHA
    ECDHE-RSA-AES128-SHA
    DHE-RSA-AES128-SHA
    AES256-GCM-SHA384
    AES128-GCM-SHA256
    AES256-SHA256
    AES128-SHA256
    AES256-SHA
    AES128-SHA
)
TLS1_CIPHERS=(
    ECDHE-RSA-AES256-SHA
    ECDHE-ECDSA-AES256-SHA
    DHE-RSA-AES256-SHA
    AES256-SHA
    ECDHE-RSA-AES128-SHA
    ECDHE-ECDSA-AES128-SHA
    DHE-RSA-AES128-SHA
    AES128-SHA
)
TLS1_DES_CIPHERS=(
    ECDHE-RSA-DES-CBC3-SHA
    ECDHE-ECDSA-DES-CBC3-SHA
    DES-CBC3-SHA
)
TLS1_STATIC_CIPHERS=(
    DH-RSA-AES256-SHA
    ECDH-RSA-AES256-SHA
    ECDH-ECDSA-AES256-SHA
    DH-RSA-AES128-SHA
    ECDH-RSA-AES128-SHA
    ECDH-ECDSA-AES128-SHA
    EDH-RSA-DES-CBC3-SHA
    DH-RSA-DES-CBC3-SHA
    ECDH-RSA-DES-CBC3-SHA
    ECDH-ECDSA-DES-CBC3-SHA
)
TLS1_DSS_CIPHERS=(
    DHE-DSS-AES256-SHA
    DH-DSS-AES256-SHA
    DHE-DSS-AES128-SHA
    DH-DSS-AES128-SHA
    EDH-DSS-DES-CBC3-SHA
    DH-DSS-DES-CBC3-SHA
)
TLS1_PSK_CIPHERS=(
    PSK-AES256-CBC-SHA
    PSK-AES128-CBC-SHA
    PSK-3DES-EDE-CBC-SHA
)

check_process_running() {
    ps -p $SERVER_PID > /dev/null
    PS_EXIT=$?
}

# need a unique port since may run the same time as testsuite
generate_port() {
    port=$(($(od -An -N2 /dev/random) % (65535-49512) + 49512))
}

start_openssl_server() {
    generate_port
    export OPENSSL_PORT=$port

    ($OPENSSL_DIR/apps/openssl s_server -www \
         -cert $CERT_DIR/server-cert.pem -key $CERT_DIR/server-key.pem \
         -dcert $CERT_DIR/server-ecc.pem -dkey $CERT_DIR/ecc-key.pem \
         -accept $OPENSSL_PORT \
         >$LOG_SERVER 2>&1
    ) &
    OPENSSL_SERVER_PID=$!

    sleep 0.1

    SERVER_PID=$OPENSSL_SERVER_PID
    check_process_running
    if [ "$PS_EXIT" != "0" ]; then
        printf "OpenSSL server failed to start\n"
        exit 1
    fi
}

start_we_openssl_server() {
    generate_port
    export WE_OPENSSL_PORT=$port

    (OPENSSL_CONF=engine.conf \
     $OPENSSL_DIR/apps/openssl s_server -www \
         -engine wolfSSL \
         -cert $CERT_DIR/server-cert.pem -key $CERT_DIR/server-key.pem \
         -dcert $CERT_DIR/server-ecc.pem -dkey $CERT_DIR/ecc-key.pem \
         -accept $WE_OPENSSL_PORT \
         >$LOG_WE_SERVER 2>&1
    ) &
    WE_OPENSSL_SERVER_PID=$!

    sleep 0.1

    SERVER_PID=$WE_OPENSSL_SERVER_PID
    check_process_running
    if [ "$PS_EXIT" != "0" ]; then
        printf "server failed to start\n"
        printf "OpenSSL server using wolfEngine failed to start\n"
        exit 1
    fi
}

do_we_client() {
    printf "\t\t$CIPHER..."
    if [ "$PROTOCOL" != "-tls1_3" ]; then
        (echo -n | \
         OPENSSL_CONF=engine.conf \
         LD_LIBRARY_PATH="./.libs:$LD_LIBRARY_PATH" \
         $OPENSSL_DIR/apps/openssl s_client \
             -engine wolfSSL \
             -cipher $CIPHER $PROTOCOL \
             -connect localhost:$OPENSSL_PORT \
             >>$LOG_CLIENT 2>&1
        )
    else
        (echo -n | \
         OPENSSL_CONF=engine.conf \
         LD_LIBRARY_PATH="./.libs:$LD_LIBRARY_PATH" \
         $OPENSSL_DIR/apps/openssl s_client \
             -engine wolfSSL \
             -ciphersuites $CIPHER $PROTOCOL \
             -connect localhost:$OPENSSL_PORT \
             >>$LOG_CLIENT 2>&1
        )
    fi
    if [ "$?" = "0" ]; then
        printf "pass\n"
    else
        printf "fail\n"
        FAIL=$((FAIL+1))
    fi
}

do_client() {
    printf "\t\t$CIPHER..."
    if [ "$PROTOCOL" != "-tls1_3" ]; then
        (echo -n | \
         $OPENSSL_DIR/apps/openssl s_client -cipher $CIPHER $PROTOCOL \
             -connect localhost:$WE_OPENSSL_PORT \
             >>$LOG_CLIENT 2>&1
        )
    else
        (echo -n | \
         $OPENSSL_DIR/apps/openssl s_client -ciphersuites $CIPHER $PROTOCOL \
             -connect localhost:$WE_OPENSSL_PORT \
             >>$LOG_CLIENT 2>&1
        )
    fi
    if [ "$?" = "0" ]; then
        printf "pass\n"
    else
        printf "fail\n"
        FAIL=$((FAIL+1))
    fi
}

do_we_client_test() {
    printf "\tClient testing\n"

    if [ "$VERSION" = "1.0.2" ]; then
        PROTOCOL=-tls1
        printf "\t$PROTOCOL\n"
        for CIPHER in ${TLS1_DES_CIPHERS[@]}
        do
            do_we_client
        done
    fi

    PROTOCOL=-tls1
    printf "\t$PROTOCOL\n"
    for CIPHER in ${TLS1_CIPHERS[@]}
    do
        do_we_client
    done

    PROTOCOL=-tls1_1
    printf "\t$PROTOCOL\n"
    for CIPHER in ${TLS1_CIPHERS[@]}
    do
        do_we_client
    done

    PROTOCOL=-tls1_2
    printf "\t$PROTOCOL\n"
    for CIPHER in ${TLS12_CIPHERS[@]}
    do
        do_we_client
    done

    if [ "$VERSION" = "1.1.1" ]; then
        PROTOCOL=-tls1_3
        printf "\t$PROTOCOL\n"
        for CIPHER in ${TLS13_CIPHERS[@]}
        do
            do_we_client
        done
    fi
}

do_client_test() {
    printf "\tServer testing\n"

    if [ "$VERSION" = "1.0.2" ]; then
        PROTOCOL=-tls1
        printf "\t$PROTOCOL\n"
        for CIPHER in ${TLS1_DES_CIPHERS[@]}
        do
            do_client
        done
    fi

    PROTOCOL=-tls1
    printf "\t$PROTOCOL\n"
    for CIPHER in ${TLS1_CIPHERS[@]}
    do
        do_client
    done

    PROTOCOL=-tls1_1
    printf "\t$PROTOCOL\n"
    for CIPHER in ${TLS1_CIPHERS[@]}
    do
        do_client
    done

    PROTOCOL=-tls1_2
    printf "\t$PROTOCOL\n"
    for CIPHER in ${TLS12_CIPHERS[@]}
    do
        do_client
    done

    if [ "$VERSION" = "1.1.1" ]; then
        PROTOCOL=-tls1_3
        printf "\t$PROTOCOL\n"
        for CIPHER in ${TLS13_CIPHERS[@]}
        do
            do_client
        done
    fi
}

do_configure() {
    if [ "$WOLFENGINE_NO_BUILD" = "" ]; then
        printf "Setting up wolfEngine\n"
        printf "\tConfigure ... "
        ./configure LDFLAGS="-L$OPENSSL_DIR" --with-openssl=$OPENSSL_DIR \
            --enable-debug &>$LOG_FILE
        if [ "$?" = "0" ]; then
            printf "done\n"
        else
            printf "failed\n"
            exit 1
        fi

        printf "\tMake ... "
        make &> $LOG_FILE
        if [ "$?" = "0" ]; then
            printf "done\n"
        else
            printf "failed\n"
            exit 1
        fi
    fi
}

setup_openssl_102h() {
    printf "Setting up OpenSSL 1.0.2h.\n"
    if [ -z "${OPENSSL_1_0_2_SOURCE}" ]; then
        printf "\tCloning OpenSSL and checking out version 1.0.2h.\n"
        git clone --depth=1 -b OpenSSL_1_0_2h git@github.com:openssl/openssl.git openssl-1_0_2h &> $LOG_FILE

        cd openssl-1_0_2h

        printf "\tPatching unit tests to use wolfEngine.\n"
        PATCHES=`find $TEST_PATCH_DIR -name "*.patch"`
        for PATCH in $PATCHES
        do
            # Try to patch.
            # If doesn't work check wether it has already been applied
            git apply $PATCH &>$LOG_FILE || git apply $PATCH -R --check &>> $LOG_FILE
            if [ $? != 0 ]; then
                printf "$PATCH failed to apply\n"
                exit 1
            fi
        done

        if [ -z "${OPENSSL_NO_BUILD}" ]; then
            printf "\tConfiguring.\n"
            # Configure for debug.
            ./config shared no-asm $OPENSSL_CONFIG_OPTS &> $LOG_FILE
            if [ $? != 0 ]; then
                printf "config failed\n"
                exit 1
            fi

            printf "\tBuilding.\n"
            make -j$MAKE_JOBS &> $LOG_FILE
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
}

setup_openssl_110j() {
    printf "Setting up OpenSSL 1.1.0j.\n"
    if [ -z "${OPENSSL_1_1_0_SOURCE}" ]; then
        printf "\tCloning OpenSSL and checking out version 1.1.0j.\n"
        git clone --depth=1 -b OpenSSL_1_1_0j git@github.com:openssl/openssl.git openssl-1_1_0j &> $LOG_FILE

        cd openssl-1_1_0j

        printf "\tPatching unit tests to use wolfEngine.\n"
        PATCHES=`find $TEST_PATCH_DIR -name "*.patch"`
        for PATCH in $PATCHES
        do
            # Try to patch.
            # If doesn't work check wether it has already been applied
            git apply $PATCH &>$LOG_FILE || \
                git apply $PATCH -R --check &>> $LOG_FILE
            if [ $? != 0 ]; then
                printf "$PATCH failed to apply\n"
                exit 1
            fi
        done

        if [ -z "${OPENSSL_NO_BUILD}" ]; then
            printf "\tConfiguring.\n"
            # Configure for debug.
            ./config shared no-asm $OPENSSL_CONFIG_OPTS &> $LOG_FILE
            if [ $? != 0 ]; then
                printf "config failed\n"
                exit 1
            fi

            printf "\tBuilding.\n"
            make -j$MAKE_JOBS &> $LOG_FILE
            if [ $? != 0 ]; then
                printf "make failed\n"
                exit 1
            fi
        fi

        OPENSSL_1_1_0_SOURCE=`pwd`
        cd ..
    else
        printf "\tUsing OpenSSL 1.1.0j source code at $OPENSSL_1_1_0_SOURCE\n"
    fi
}

setup_openssl_111b() {
    printf "Setting up OpenSSL 1.1.1b.\n"
    if [ -z "${OPENSSL_1_1_1_SOURCE}" ]; then
        printf "\tCloning OpenSSL and checking out version 1.1.1b.\n"
        git clone --depth=1 -b OpenSSL_1_1_1b git@github.com:openssl/openssl.git openssl-1_1_1b &> $LOG_FILE

        cd openssl-1_1_1b

        printf "\tPatching unit tests to use wolfEngine.\n"
        PATCHES=`find $TEST_PATCH_DIR -name "*.patch"`
        for PATCH in $PATCHES
        do
            # Try to patch.
            # If doesn't work check wether it has already been applied
            git apply $PATCH &>$LOG_FILE || \
                git apply $PATCH -R --check &>> $LOG_FILE
            if [ $? != 0 ]; then
                printf "$PATCH failed to apply\n"
                exit 1
            fi
        done

        if [ -z "${OPENSSL_NO_BUILD}" ]; then
            printf "\tConfiguring.\n"
            # Configure for debug.
            ./config shared no-asm $OPENSSL_CONFIG_OPTS &> $LOG_FILE
            if [ $? != 0 ]; then
                printf "config failed\n"
                exit 1
            fi

            printf "\tBuilding.\n"
            make -j$MAKE_JOBS &> $LOG_FILE
            if [ $? != 0 ]; then
                printf "make failed\n"
                exit 1
            fi
        fi

        OPENSSL_1_1_1_SOURCE=`pwd`
        cd ..
    else
        printf "\tUsing OpenSSL 1.1.1b source code at $OPENSSL_1_1_1_SOURCE\n"
    fi
}


# Versions of OpenSSL to test
if [ "$OPENSSL_VERSIONS" != "" ]; then
    VERSIONS=$OPENSSL_VERSIONS
else
    VERSIONS="1.0.2 1.1.1"
fi

for VERSION in $VERSIONS
do
    rm -f $LOG_CLIENT
    FAIL=0

    printf "OpenSSL $VERSION\n"

    if [ "$VERSION" = "1.0.2" ]; then
        setup_openssl_102h
        OPENSSL_DIR="${OPENSSL_1_0_2_SOURCE}"
    fi
    if [ "$VERSION" = "1.1.0" ]; then
        setup_openssl_110j
        OPENSSL_DIR="${OPENSSL_1_1_0_SOURCE}"
    fi
    if [ "$VERSION" = "1.1.1" ]; then
        setup_openssl_111b
        OPENSSL_DIR="${OPENSSL_1_1_1_SOURCE}"
    fi

    export LD_LIBRARY_PATH=$OPENSSL_DIR

    do_configure
    if [ "$NO_TEST_CLIENT" = "" ]; then
        start_openssl_server
        do_we_client_test
    fi
    if [ "$NO_TEST_SERVER" = "" ]; then
        start_we_openssl_server
        do_client_test
    fi
    kill_servers

    if [ "$FAIL" = "0" ]; then
        printf "All tests passed.\n"
    else
        printf "$FAIL tests failed.\n"
        exit 1
    fi
done
do_cleanup

