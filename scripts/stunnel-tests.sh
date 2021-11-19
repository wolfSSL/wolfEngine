#!/bin/bash

#
# Tests that using stunnel with wolfEngine works.
#
# 1. Runs the stunnel unit tests with wolfEngine and ensures they pass.
# 2. Creates a TLS-protected tunnel using stunnel with wolfEngine under the
# hood. Uses example TCP client and server from wolfssl-examples to communicate
# through the tunnel. Once communication is established, the script tries the
# same thing with the next cipher suite, and so on.
#
# Tested cipher suites:
#
#   TLS 1.0/1.1
#        DES-CBC3-SHA
#   TLS 1.2
#       ECDHE-RSA-AES128-GCM-SHA256
#       ECDHE-RSA-AES256-GCM-SHA384
#       DHE-RSA-AES128-SHA256
#       DHE-RSA-AES256-SHA256
#       ECDHE-RSA-AES128-SHA256
#       ECDHE-RSA-AES256-SHA384
#       DHE-RSA-AES128-GCM-SHA256
#       DHE-RSA-AES256-GCM-SHA384
#       ECDHE-ECDSA-AES128-GCM-SHA256
#       ECDHE-ECDSA-AES256-GCM-SHA384
#       ECDHE-ECDSA-AES128-SHA256
#       ECDHE-ECDSA-AES256-SHA384
#   TLS 1.3
#       TLS_AES_128_GCM_SHA256
#       TLS_AES_256_GCM_SHA384
#       TLS_AES_128_CCM_SHA256
#

do_cleanup() {
    printf "Cleaning up.\n"

    if [ -n "$APP_SERVER_PID" ]; then
        check_process_running $APP_SERVER_PID
        if [ "$PS_EXIT" = "0" ]; then
            printf "\tKilling application server..."
            echo "shutdown" | $SCRIPT_DIR/wolfssl-examples/tls/client-tcp 127.0.0.1 >> application-client.log 2>&1
            if [ $? != 0 ]; then
                printf "failed.\n"
            fi
            printf "ok.\n"
        fi
    fi

    if [ -n "$STUNNEL_SERVER_PID" ]; then
        printf "\tKilling stunnel server..."
        kill_process $STUNNEL_SERVER_PID
        if [ $? != 0 ]; then
            printf "failed.\n"
        fi
        printf "ok.\n"
    fi

    if [ -n "$STUNNEL_CLIENT_PID" ]; then
        printf "\tKilling stunnel client..."
        kill_process $STUNNEL_CLIENT_PID
        if [ $? != 0 ]; then
            printf "failed.\n"
        fi
        printf "ok.\n"
    fi

    if [ -d $SCRIPT_DIR/wolfssl-examples ]; then
        printf "\tDeleting wolfssl-examples.\n"
        rm -rf $SCRIPT_DIR/wolfssl-examples
    fi

    if [ -f $SCRIPT_DIR/stunnel-server.conf ]; then
        printf "\tDeleting stunnel-server.conf.\n"
        rm $SCRIPT_DIR/stunnel-server.conf
    fi
    if [ -f $SCRIPT_DIR/stunnel-client.conf ]; then
        printf "\tDeleting stunnel-client.conf.\n"
        rm $SCRIPT_DIR/stunnel-client.conf
    fi

    # Use the environment variable KEEP_LOGS to prevent log deletion at the end
    # of the run.
    if [ -z "${KEEP_LOGS}" ]; then
        printf "\tDeleting log files.\n"
        if [ -f $SCRIPT_DIR/stunnel-server.log ]; then
            rm $SCRIPT_DIR/stunnel-server.log
        fi
        if [ -f $SCRIPT_DIR/stunnel-client.log ]; then
            rm $SCRIPT_DIR/stunnel-client.log
        fi

        if [ -f $SCRIPT_DIR/application-server.log ]; then
            rm $SCRIPT_DIR/application-server.log
        fi
        if [ -f $SCRIPT_DIR/application-client.log ]; then
            rm $SCRIPT_DIR/application-client.log
        fi
    else
        printf "\tKeeping log files.\n"
    fi

    # Use the environment variable KEEP_STUNNEL to prevent stunnel directory
    # deletion at the end of the run.
    if [ -z "${KEEP_STUNNEL}" ]; then
        printf "\tDeleting stunnel-5.59 directory.\n"
        rm -rf $SCRIPT_DIR/stunnel-5.59
    fi

    if [ -f $SCRIPT_DIR/stunnel-5.59.tar.gz ]; then
        printf "\tDeleting stunnel-5.59.tar.gz.\n"
        rm $SCRIPT_DIR/stunnel-5.59.tar.gz
    fi
}

do_failure() {
    # Keep the logs around to help debug the failure.
    KEEP_LOGS=1
    do_cleanup
    exit 1
}

# Configure and build wolfEngine.
build_wolfengine() {
    printf "Setting up wolfEngine.\n"

    if [ ! -f $WOLFENGINE_ROOT/configure ]; then
        printf "\tRunning autogen.sh..." 
        ./autogen.sh >>$LOGFILE 2>&1
        if [ $? != 0 ]; then
            printf "failed.\n"
            do_failure
        fi
        printf "ok.\n"
    fi

    printf "\tConfiguring..."
    ./configure $OPENSSL_CPPFLAGS $OPENSSL_LDFLAGS --with-openssl=$OPENSSL_INSTALL --enable-debug >>$LOGFILE 2>&1
    if [ $? != 0 ]; then
        printf "failed.\n"
        do_failure
    fi
    printf "ok.\n"

    printf "\tBuilding..."
    make -j$MAKE_JOBS >> $LOGFILE 2>&1
    if [ $? != 0 ]; then
        printf "failed.\n"
        do_failure
    fi
    printf "ok.\n"
}

build_stunnel() {
    printf "Setting up stunnel.\n"
    printf "\tDownloading..."
    curl -O https://www.stunnel.org/downloads/stunnel-5.59.tar.gz >> $LOGFILE 2>&1
    if [ $? != 0 ]; then
        printf "failed\n"
        do_failure
    fi
    printf "ok.\n"

    printf "\tExtracting..."
    tar xvf stunnel-5.59.tar.gz >> $LOGFILE 2>&1
    if [ $? != 0 ]; then
        printf "failed.\n"
        do_failure
    fi
    printf "ok.\n"
    
    cd stunnel-5.59
    printf "\tPatching..."
    # wolfEngine logs to stderr by default. When running the stunnel unit tests,
    # logging to stderr is interpreted as a test having failed. This patch hooks
    # wolfEngine into stunnel's logging framework.
    patch -p1 -i $SCRIPT_DIR/patches/stunnel-5.59/5.59.patch >> $LOGFILE 2>&1
    if [ $? != 0 ]; then
        printf "failed.\n"
        do_failure
    fi
    printf "ok.\n"

    printf "\tConfiguring..."
    ./configure $OPENSSL_CPPFLAGS $OPENSSL_LDFLAGS --with-ssl=$OPENSSL_INSTALL >> $LOGFILE 2>&1
    if [ $? != 0 ]; then
        printf "failed.\n"
        do_failure
    fi
    printf "ok.\n"

    printf "\tBuilding..."
    make -j$MAKE_JOBS >> $LOGFILE 2>&1
    if [ $? != 0 ]; then
        printf "failed.\n"
        do_failure
    fi
    printf "ok.\n"

    cd tests/recipes

    printf "\tModifying test recipes to use wolfEngine..."
    # Inject wolfEngine config. TODO: Find a less ugly way to do this.
    find . -type f | xargs -I{} sed -i "s/debug = debug/debug = debug\n  engine = $WOLFENGINE_ID\n  engineDefault = ALL\n  engineCtrl = enable_debug:1\n/" {} >> $LOGFILE 2>&1
    if [ $? != 0 ]; then
        printf "failed.\n"
        do_failure
    fi
    printf "ok.\n"
}

run_stunnel_unit_tests() {
    cd $SCRIPT_DIR/stunnel-5.59/tests
    
    printf "Running stunnel unit tests with wolfEngine..."
    ./make_test >> $LOGFILE 2>&1
    if [ $? != 0 ]; then
        printf "failed.\n"
        do_failure
    fi
    printf "ok.\n"
}

generate_port() {
    PORT=$(($(od -An -N2 /dev/random) % (65535-49512) + 49512))
}

clone_wolfssl_examples () {
    printf "Cloning wolfssl-examples repo..."

    cd $SCRIPT_DIR

    git clone --depth=1 https://github.com/wolfSSL/wolfssl-examples.git >> $LOGFILE 2>&1
    if [ $? != 0 ]; then
        printf "failed\n"
        do_failure
    fi
    printf "ok.\n"
}

build_wolfssl_examples () {
    printf "\tBuilding server-tcp and client-tcp.\n"

    cd $SCRIPT_DIR/wolfssl-examples/tls

    generate_port
    SERVER_PORT=$PORT
    generate_port
    CLIENT_PORT=$PORT

    printf "\tChanging server port to $SERVER_PORT..."
    sed -i "s/#define DEFAULT_PORT [0-9]\+/#define DEFAULT_PORT $SERVER_PORT/g" server-tcp.c
    if [ $? != 0 ]; then
        printf "failed\n"
        do_failure
    fi
    printf "ok.\n"

    printf "\tChanging client port to $CLIENT_PORT..."
    sed -i "s/#define DEFAULT_PORT [0-9]\+/#define DEFAULT_PORT $CLIENT_PORT/g" client-tcp.c
    if [ $? != 0 ]; then
        printf "failed\n"
        do_failure
    fi
    printf "ok.\n"

    printf "\tBuilding server-tcp and client-tcp..."
    make -j$MAKE_JOBS server-tcp client-tcp >> $LOGFILE 2>&1
    if [ $? != 0 ]; then
        printf "failed.\n"
        do_failure
    fi
    printf "ok.\n"

}

write_conf_file () {
    # $1: "client" to generate client configuration, otherwise generates server
    #     configuration.
    # $2: TLS version. One of TLSv1.2, TLSv1.3.
    # $3: Cert type. One of RSA, ECC.
    # $4: Colon-delimited list of the ciphers.

    if [ "$1" == "client" ]; then
        local CLIENT=yes
        local LOG=$(pwd)/stunnel-client.log
        local PID=$(pwd)/stunnel-client.pid
        local CONF_FILE=stunnel-client.conf
        local ACCEPT=127.0.0.1:$CLIENT_PORT
        local CONNECT=127.0.0.1:$STUNNEL_PORT
        STUNNEL_CLIENT_PID_FILE=$PID
    else
        local CLIENT=no
        local LOG=$(pwd)/stunnel-server.log
        local PID=$(pwd)/stunnel-server.pid
        local CONF_FILE=stunnel-server.conf
        local ACCEPT=127.0.0.1:$STUNNEL_PORT
        local CONNECT=127.0.0.1:$SERVER_PORT

        if [ "$3" == "RSA" ]; then
            local CERT="cert = $WOLFENGINE_ROOT/certs/server-cert.pem"
            local KEY="key = $WOLFENGINE_ROOT/certs/server-key.pem"
        else
            local CERT="cert = $WOLFENGINE_ROOT/certs/server-ecc.pem"
            local KEY="key = $WOLFENGINE_ROOT/certs/ecc-key.pem"
        fi
        STUNNEL_SERVER_PID_FILE=$PID
    fi

    local CURVES="curves = prime256v1"

    if [ -n "$4" ]; then
        if [ "$2" == "TLSv1.3" ]; then
            local CIPHERS="ciphersuites = $4"
        else
            local CIPHERS="ciphers = $4"
        fi
    fi


    cat > $CONF_FILE << EOF
debug = debug
output = $LOG
pid = $PID
sslVersion = $2
$CIPHERS
$CURVES
engine = $WOLFENGINE_ID
engineDefault = ALL
engineCtrl = enable_debug:1

[stunnel]
client = $CLIENT
$CERT
$KEY
accept = $ACCEPT
connect = $CONNECT
EOF
}

check_process_running() {
    ps -p $1 > /dev/null
    PS_EXIT=$?
}

kill_process() {
    check_process_running $1
    if [ "$PS_EXIT" = "0" ]; then
        kill -INT $1 >/dev/null 2>&1
    fi
}

wait_file() {
  local FILE="$1"; shift
  local WAIT_SECONDS="${1:-3}"; shift # 3 seconds as default timeout

  until test $((WAIT_SECONDS--)) -eq 0 -o -e "$FILE" ; do sleep 1; done

  ((++WAIT_SECONDS))
}

run_stunnel_custom_tests() {
    # $1: Cert type. One of RSA, ECC.
    # $2: TLS version. One of TLSv1, TLSv1.1, TLSv1.2, TLSv1.3.

    printf "Running stunnel custom tests.\n"
    if [ $# -ne 2 ]; then
        printf "run_stunnel_custom_tests requires 2 arguments: RSA/ECC, TLSv1/TLSv1.1/TLSv1.2/TLSv1.3\n"
        do_failure
    fi

    echo "Building wolfssl-examples" >> $LOGFILE
    build_wolfssl_examples

    cd $SCRIPT_DIR

    if [ "$1" == "RSA" -o "$1" == "ECC" ]; then
        CERT_TYPE=$1
    else
        printf "\tUnrecognized certificate type $1.\n"
        do_failure
    fi
    printf "\tUsing $CERT_TYPE cert.\n"

    if [ "$2" == "TLSv1" -o "$2" == "TLSv1.1" -o "$2" == "TLSv1.2" -o "$2" == "TLSv1.3" ]; then
        TLS_VERSION=$2
    else
        printf "\tUnrecognized TLS version $2.\n"
        do_failure
    fi
    printf "\tUsing $TLS_VERSION.\n"

    if [ "$TLS_VERSION" == "TLSv1" -o "$TLS_VERSION" == "TLSv1.1" ]; then
        local CIPHER_SUITES=("DES-CBC3-SHA")
    elif [ "$TLS_VERSION" == "TLSv1.2" ]; then
        if [ "$CERT_TYPE" == "RSA" ]; then
            local CIPHER_SUITES=(
                "ECDHE-RSA-AES128-GCM-SHA256"
                "ECDHE-RSA-AES256-GCM-SHA384"
                "DHE-RSA-AES128-SHA256"
                "DHE-RSA-AES256-SHA256"
                "ECDHE-RSA-AES128-SHA256"
                "ECDHE-RSA-AES256-SHA384"
                "DHE-RSA-AES128-GCM-SHA256"
                "DHE-RSA-AES256-GCM-SHA384"
            )
        else
            local CIPHER_SUITES=(
                "ECDHE-ECDSA-AES128-GCM-SHA256"
                "ECDHE-ECDSA-AES256-GCM-SHA384"
                "ECDHE-ECDSA-AES128-SHA256"
                "ECDHE-ECDSA-AES256-SHA384"
            )
        fi
    else
        local CIPHER_SUITES=(
            "TLS_AES_128_GCM_SHA256"
            "TLS_AES_256_GCM_SHA384"
            "TLS_AES_128_CCM_SHA256"
        )
    fi

    local SERVER_CIPHER_SUITES=$( IFS=$':'; echo "${CIPHER_SUITES[*]}" )
    generate_port
    STUNNEL_PORT=$PORT

    printf "\tWriting stunnel server configuration file..."
    write_conf_file server $TLS_VERSION $CERT_TYPE $SERVER_CIPHER_SUITES
    if [ $? != 0 ]; then
        printf "failed.\n"
        do_failure
    fi
    printf "ok.\n"

    printf "\tStarting stunnel server..."
    echo "Starting stunnel server" >> $LOGFILE
    $SCRIPT_DIR/stunnel-5.59/src/stunnel ./stunnel-server.conf >> $LOGFILE 2>&1
    
    wait_file $STUNNEL_SERVER_PID_FILE || {
      printf "failed, timed out.\n"
      do_failure
    }
    printf "ok.\n"
    STUNNEL_SERVER_PID=$(cat $STUNNEL_SERVER_PID_FILE)

    printf "\tWriting initial stunnel client configuration file..."
    write_conf_file client $TLS_VERSION $CERT_TYPE
    if [ $? != 0 ]; then
        printf "failed.\n"
        do_failure
    fi
    printf "ok.\n"

    printf "\tStarting stunnel client..."
    echo "Starting stunnel client" >> $LOGFILE
    $SCRIPT_DIR/stunnel-5.59/src/stunnel ./stunnel-client.conf >> $LOGFILE 2>&1

    wait_file $STUNNEL_CLIENT_PID_FILE || {
      printf "failed, timed out.\n"
      do_failure
    }
    printf "ok.\n"
    STUNNEL_CLIENT_PID=$(cat $STUNNEL_CLIENT_PID_FILE)

    printf "\tStarting application server..."
    # Using stdbuf -oL because sometimes log file output doesn't get flushed in
    # the event that the script crashes, making it harder to debug.
    stdbuf -oL $SCRIPT_DIR/wolfssl-examples/tls/server-tcp &> application-server.log &
    APP_SERVER_PID=$!
    check_process_running $APP_SERVER_PID
    if [ "$PS_EXIT" != "0" ]; then
        printf "failed, process not running.\n"
        do_failure
    fi
    printf "ok.\n"

    for C in ${CIPHER_SUITES[*]}
    do
        printf "\tWriting stunnel client configuration file using cipher suite $C..."
        write_conf_file client $TLS_VERSION $CERT_TYPE $C
        if [ $? != 0 ]; then
            printf "failed.\n"
            do_failure
        fi
        printf "ok.\n"

        printf "\tReloading stunnel client config..."
        # Sending SIGHUP to the stunnel client process will trigger a reload
        # of the configuration file.
        kill -HUP $STUNNEL_CLIENT_PID > /dev/null 2>&1
        if [ $? != 0 ]; then
            printf "failed.\n"
            do_failure
        fi
        printf "ok.\n"

        # Wait for 10 ms for stunnel client to reload.
        sleep 0.01

        printf "\tStarting application client and sending data to server..."
        echo "hello wolfEngine" | stdbuf -oL $SCRIPT_DIR/wolfssl-examples/tls/client-tcp 127.0.0.1 &> application-client.log
        if [ $? != 0 ]; then
            printf "failed.\n"
            do_failure
        fi
        printf "ok.\n"

        # Give server max 50 ms to respond.
        local CONNECTED=0
        for i in {0..4}
        do
            if grep -q "I hear ya fa shizzle!" application-client.log; then
                CONNECTED=1
                break
            else
                cat application-client.log
                sleep 0.01
            fi
        done

        printf "\tChecking connectivity..."
        if [ $CONNECTED == 0 ]; then
            printf "failed.\n"
            do_failure
        fi
        printf "ok.\n"
    done

    printf "\tKilling application server..."
    echo "shutdown" | stdbuf -oL $SCRIPT_DIR/wolfssl-examples/tls/client-tcp 127.0.0.1 >> application-client.log 2>&1
    if [ $? != 0 ]; then
        printf "failed.\n"
        do_failure
    fi
    printf "ok.\n"

    printf "\tKilling stunnel client..."
    kill_process $STUNNEL_CLIENT_PID
    if [ $? != 0 ]; then
        printf "failed.\n"
        do_failure
    fi
    printf "ok.\n"
    unset STUNNEL_CLIENT_PID

    printf "\tKilling stunnel server..."
    kill_process $STUNNEL_SERVER_PID
    if [ $? != 0 ]; then
        printf "failed.\n"
        do_failure
    fi
    printf "ok.\n"
}

# Register trap on interrupt (2) and terminate (15)
trap do_failure INT TERM

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
WOLFENGINE_ROOT="$SCRIPT_DIR/.."

if [ -z ${LOGFILE} ]; then
    LOGFILE=${SCRIPT_DIR}/stunnel-tests.log
fi

# Clear log files, if they exist (e.g. if the script was run previously with
# KEEP_LOGS).
>$LOGFILE
rm -f $SCRIPT_DIR/stunnel-server.log
rm -f $SCRIPT_DIR/stunnel-client.log
rm -f $SCRIPT_DIR/application-server.log
rm -f $SCRIPT_DIR/application-client.log

if [ -z "${OPENSSL_INSTALL}" ]; then
    OPENSSL_INSTALL=/usr/local
fi

# If the OPENSSL_INSTALL directory has a "lib" subdirectory, use that.
# Otherwise, we're working with an OpenSSL source directory, and the libraries
# will be in the root, not a subdirectory.
if [ -d "${OPENSSL_INSTALL}/lib" ]; then
    export LD_LIBRARY_PATH=$OPENSSL_INSTALL/lib:$LD_LIBRARY_PATH
else
    export LD_LIBRARY_PATH=$OPENSSL_INSTALL:$LD_LIBRARY_PATH
    OPENSSL_LDFLAGS="LDFLAGS=-L$OPENSSL_INSTALL"

    if [ -d "${OPENSSL_INSTALL}/include" ]; then
        OPENSSL_CPPFLAGS="CPPFLAGS=-I$OPENSSL_INSTALL/include"
    else
        printf "OpenSSL source directory has no include subdirectory.\n"
        do_failure
    fi
fi

OPENSSL_VERSION=$(grep -oP "(?<=define OPENSSL_VERSION_NUMBER)\s+0x[0-9a-fA-F]+" $OPENSSL_INSTALL/include/openssl/opensslv.h)
(( "$OPENSSL_VERSION" < "0x10100000" ))
if [ $? == 1 ]; then
    WOLFENGINE_ID=libwolfengine
    RUN_TLS13_TESTS=1
    RUN_OLD_TLS_TESTS=0
else
    WOLFENGINE_ID=wolfengine
    RUN_TLS13_TESTS=0
    RUN_OLD_TLS_TESTS=1
fi

export OPENSSL_ENGINES="$WOLFENGINE_ROOT/.libs/"

if [ -z "${WOLFENGINE_NO_BUILD}" ]; then
    cd $WOLFENGINE_ROOT
    echo "Building wolfEngine" >> $LOGFILE
    build_wolfengine
fi

if [ -z "${STUNNEL_NO_BUILD}" ]; then
    cd $SCRIPT_DIR
    echo "Building stunnel" >> $LOGFILE
    build_stunnel
fi

if [ -z "${STUNNEL_NO_UNIT}" ]; then
    echo "Running stunnel unit tests with wolfEngine" >> $LOGFILE
    run_stunnel_unit_tests
fi

echo "Cloning wolfssl-examples" >> $LOGFILE
clone_wolfssl_examples

if [ "$RUN_OLD_TLS_TESTS" == 1 ]; then
    echo "Running stunnel custom tests with RSA cert, TLS 1.0" >> $LOGFILE
    run_stunnel_custom_tests RSA TLSv1
    
    echo "Running stunnel custom tests with RSA cert, TLS 1.1" >> $LOGFILE
    run_stunnel_custom_tests RSA TLSv1.1    
else
    printf "DES-CBC3-SHA not supported by OpenSSL version, skipping TLS 1.0/1.1 tests.\n"
fi

echo "Running stunnel custom tests with RSA cert, TLS 1.2" >> $LOGFILE
run_stunnel_custom_tests RSA TLSv1.2

echo "Running stunnel custom tests with ECC cert, TLS 1.2" >> $LOGFILE
run_stunnel_custom_tests ECC TLSv1.2

if [ "$RUN_TLS13_TESTS" == 1 ]; then
    echo "Running stunnel custom tests with RSA cert, TLS 1.3" >> $LOGFILE
    run_stunnel_custom_tests RSA TLSv1.3

    echo "Running stunnel custom tests with ECC cert, TLS 1.3" >> $LOGFILE
    run_stunnel_custom_tests ECC TLSv1.3
else
    printf "TLS 1.3 not supported by OpenSSL version, skipping TLS 1.3 tests.\n"
fi

do_cleanup
