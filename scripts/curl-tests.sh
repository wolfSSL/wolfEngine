#!/bin/bash

# Tests that using curl with wolfEngine works.
# Attempts to connect, with different cipher suites, to an OpenSSL server.

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
WOLFENGINE_ROOT="$SCRIPT_DIR/.."
CERT_DIR="$WOLFENGINE_ROOT/certs"

TMP_CONF=$SCRIPT_DIR/tmp.conf
TMP_LOG=$SCRIPT_DIR/curl-tests-tmp.log
if [ -z ${LOGFILE} ]; then
    LOGFILE=${SCRIPT_DIR}/curl-tests.log
fi
# Clear log file.
>$LOGFILE

export OPENSSL_ENGINES="$WOLFENGINE_ROOT/.libs/"

# Script needs to be run from root of wolfEngine source.
cd $WOLFENGINE_ROOT

# Kill the OpenSSL server
kill_server() {
    SERVER_PID=$OPENSSL_SERVER_PID
    check_process_running
    if [ "$PS_EXIT" = "0" ]; then
        (kill -INT $SERVER_PID) >/dev/null 2>&1
    fi
}

# Cleanup temporary files and OpenSSL servers before exiting script
do_cleanup() {
    kill_server

    rm -f $TMP_CONF
    if [ -f $TMP_LOG ]; then
        cat $TMP_LOG >> $LOGFILE
    fi
    rm -f $TMP_LOG
}

# Got interrupt so cleanup
do_trap() {
    printf "got trap\n"
    do_cleanup
    exit 1
}
# Register trap on interrupt (2) and terminate (15)
trap do_trap INT TERM

# Write out a OpenSSL configuration file that uses wolfEngine
write_conf_file() {
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

# Configure and build wolfEngine with debug and installed OpenSSL
build_wolfengine() {
    printf "Setting up wolfEngine.\n"
    printf "\tConfiguring.\n"
    # Using installed OpenSSL as it will match curl
    ./configure --enable-debug >>$LOGFILE 2>&1
    if [ $? != 0 ]; then
        printf "config failed\n"
        exit 1
    fi

    printf "\tBuilding.\n"
    make -j$MAKE_JOBS >> $LOGFILE 2>&1
    if [ $? != 0 ]; then
        printf "make failed\n"
        exit 1
    fi
}

# Check whether server is running.
check_process_running() {
    ps -p $SERVER_PID > /dev/null
    PS_EXIT=$?
}

# need a unique port since may run the same time as testsuite
generate_port() {
    port=$(($(od -An -N2 /dev/random) % (65535-49512) + 49512))
}

# Start an OpenSSL server capable of handling all cipher suites.
start_openssl_server() {
    generate_port
    export OPENSSL_PORT=$port
    CURVES=prime256v1

    (openssl s_server -www $TLS_VERSION \
         -cert $CERT_DIR/server-cert.pem -key $CERT_DIR/server-key.pem \
         -dcert $CERT_DIR/server-ecc.pem -dkey $CERT_DIR/ecc-key.pem \
         -curves $CURVES \
         -accept $OPENSSL_PORT \
         >/dev/null 2>&1
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

# Check the log file for debug from wolfEngine to detect which cryptographic
# algorithms were performed there.
check_log() {
    WE_ALGS="\t\twolfEngine:"

    # Check wolfEngine's random was used.
    grep we_rand_pseudorand $TMP_LOG >/dev/null 2>&1
    if [ $? != 0 ]; then
        printf "\tRandom not wolfEngine...failed\n"
        FAILED=$((FAILED+1))
    else
        WE_ALGS="$WE_ALGS RAND"
    fi

    # Check wolfEngine's digest was used.
    grep we_digest_update $TMP_LOG >/dev/null 2>&1
    if [ $? != 0 ]; then
        printf "\tDigest not wolfEngine...failed\n"
        FAILED=$((FAILED+1))
    else
        grep we_sha_init $TMP_LOG >/dev/null 2>&1
        if [ $? = 0 ]; then
            WE_ALGS="$WE_ALGS SHA-1"
        fi
        grep we_sha256_init $TMP_LOG >/dev/null 2>&1
        if [ $? = 0 ]; then
            WE_ALGS="$WE_ALGS SHA-256"
        fi
        grep we_sha384_init $TMP_LOG >/dev/null 2>&1
        if [ $? = 0 ]; then
            WE_ALGS="$WE_ALGS SHA-384"
        fi
    fi

    if [ $TLS_VERSION = "-tls1_3" ]; then
        # Check wolfEngine's HMAC was used.
        grep we_hmac_pkey_signctx $TMP_LOG >/dev/null 2>&1
        if [ $? != 0 ]; then
            printf "\tHMAC not wolfEngine...failed\n"
            FAILED=$((FAILED+1))
        else
            WE_ALGS="$WE_ALGS HMAC"
        fi
    fi

    if [ $TLS_VERSION != "-tls1_3" ]; then
        # Check wolfEngine's TLS1 PRF was used.
        grep we_tls1_prf_derive $TMP_LOG >/dev/null 2>&1
        if [ $? != 0 ]; then
            printf "\tTLS1 PRF not wolfEngine...failed\n"
            FAILED=$((FAILED+1))
        else
            WE_ALGS="$WE_ALGS TLS1_PRF"
        fi
    fi

    # Check wolfEngine's public key DH code was used.
    grep we_dh_compute_key $TMP_LOG >/dev/null 2>&1
    DH_CK_GREP=$?
    grep we_dh_pkey_derive $TMP_LOG >/dev/null 2>&1
    DH_DRV_GREP=$?
    grep we_ecdh_compute_key $TMP_LOG >/dev/null 2>&1
    ECDH_CK_GREP=$?
    grep we_ecdh_derive $TMP_LOG >/dev/null 2>&1
    ECDH_DRV_GREP=$?
    if [ $DH_CK_GREP != 0 -a $DH_DRV_GREP != 0 -a $ECDH_CK_GREP != 0  -a $ECDH_DRV_GREP != 0 ]; then
        printf "\t\tPublic key DH not wolfEngine...failed\n"
        FAIL=$((FAIL+1))
    fi
    if [ $DH_CK_GREP = 0 -o $DH_DRV_GREP = 0 ]; then
        WE_ALGS="$WE_ALGS DH"
    fi
    if [ $ECDH_CK_GREP = 0 -o $ECDH_DRV_GREP = 0 ]; then
        WE_ALGS="$WE_ALGS ECDH"
    fi

    # Check wolfEngine's public key verify code was used.
    grep we_rsa_pkey_verify $TMP_LOG >/dev/null 2>&1
    RSA_GREP=$?
    grep we_ecdsa_verify $TMP_LOG >/dev/null 2>&1
    ECDSA_GREP=$?
    if [ $RSA_GREP != 0 -a $ECDSA_GREP != 0 ]; then
        printf "\tPublic key verification not wolfEngine...failed\n"
        FAILED=$((FAILED+1))
    fi
    if [ $RSA_GREP = 0 ]; then
        WE_ALGS="$WE_ALGS RSA"
    fi
    if [ $ECDSA_GREP = 0 ]; then
        WE_ALGS="$WE_ALGS ECDSA"
    fi

    # Check wolfEngine's cipher code was used.
    grep we_aes_gcm_cipher $TMP_LOG >/dev/null 2>&1
    GCM_GREP=$?
    grep we_aes_cbc_cipher $TMP_LOG >/dev/null 2>&1
    CBC_GREP=$?
    if [ $GCM_GREP != 0 -a $CBC_GREP != 0 ]; then
        printf "\tCipher not wolfEngine...failed\n"
        FAILED=$((FAILED+1))
    fi
    if [ $GCM_GREP = 0 ]; then
        WE_ALGS="$WE_ALGS AES-GCM"
    fi
    if [ $CBC_GREP = 0 ]; then
        WE_ALGS="$WE_ALGS AES-CBC"
    fi

    printf "$WE_ALGS\n"
}

# Test curl using wolfEngine and connect to OpenSSL server
test_curl() {
    start_openssl_server

    printf "\t$1..."
    echo -e "\ncurl -s -k $CIPHER https://localhost:$OPENSSL_PORT" >> $LOGFILE
    curl -s -k $CIPHER https://localhost:$OPENSSL_PORT >$TMP_LOG 2>&1
    if [ $? != 0 ]; then
        printf "failed\n"
        FAILED=$((FAILED+1))
    else
        printf "passed\n"
    fi

    kill_server

    check_log

    cat $TMP_LOG >> $LOGFILE
}


# TLS 1.2 cipher suites
CIPHER_SUITES="
    DHE-RSA-AES128-GCM-SHA256
    DHE-RSA-AES256-GCM-SHA384
    ECDHE-RSA-AES128-GCM-SHA256
    ECDHE-RSA-AES256-GCM-SHA384
    ECDHE-ECDSA-AES128-GCM-SHA256
    ECDHE-ECDSA-AES256-GCM-SHA384
    DHE-RSA-AES128-SHA256
    DHE-RSA-AES256-SHA256
    ECDHE-RSA-AES128-SHA256
    ECDHE-RSA-AES256-SHA384
    ECDHE-ECDSA-AES128-SHA256
    ECDHE-ECDSA-AES256-SHA384
"
# TLS 1.3 cipher suites
TLS13_CIPHER_SUITES="
    TLS_AES_128_GCM_SHA256
    TLS_AES_256_GCM_SHA384
"

# Create temporary OpenSSL configuration file.
# Removed in do_cleanup().
write_conf_file
# Build wolfEngine with require configuration unless user asks not to.
if [ -z "${WOLFENGINE_NO_BUILD}" ]; then
    build_wolfengine
fi

FAILED=0
echo "Testing curl against OpenSSL server"
# TLS 1.2 cipher suites
TLS_VERSION=-tls1_2
for C in $CIPHER_SUITES
do
    CIPHER="--ciphers $C"
    test_curl $C
done
# TLS 1.3 cipher suites
TLS_VERSION=-tls1_3
for C in $TLS13_CIPHER_SUITES
do
    CIPHER="--tls13-ciphers $C"
    test_curl $C
done

do_cleanup

# Check number of failures
if [ $FAILED == 0 ]; then
    printf "All tests passed.\n\n"
    exit 0
else
    printf "$FAILED tests failed.\n\n"
    exit 1
fi

