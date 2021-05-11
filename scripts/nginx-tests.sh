#!/bin/bash

#
# Tests that using nginx with wolfEngine works.
#

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
WOLFENGINE_ROOT="$SCRIPT_DIR/.."

source ${SCRIPT_DIR}/build-openssl-wolfengine.sh

do_cleanup() {
    printf "Cleaning up.\n"

    # Use the environment variable KEEP_NGINX to prevent nginx directories
    # from being deleted at the end of the run.
    if [ -z "${KEEP_NGINX}" ]; then
        printf "\tDeleting ${NGINX_NAME} directory.\n"
        rm -rf ${NGINX_DIR}

        printf "\tDeleting ${NGINX_TEST_DIR} directory.\n"
        rm -rf ${NGINX_TEST_DIR}
    fi

    if [ -f ${NGINX_TGZ} ]; then
        printf "\tDeleting ${NGINX_TGZ}.\n"
        rm ${NGINX_TGZ}
    fi
}

do_failure() {
    # Keep the logs around to help debug the failure.
    KEEP_LOGS=1
    do_cleanup
    exit 1
}

# Register trap on interrupt (2) and terminate (15)
trap do_failure INT TERM

download_nginx() {
    cd ${SCRIPT_DIR}

    printf "Setting up nginx.\n"
    printf "\tDownloading..."
    curl -O https://nginx.org/download/${NGINX_TGZ_NAME} >> $LOGFILE 2>&1
    if [ $? != 0 ]; then
        printf "failed\n"
        do_failure
    fi
    printf "ok.\n"

    cd ${WOLFENGINE_ROOT}
}

prepare_nginx() {
    if [ -n "${NGINX_NO_BUILD}" ]; then
        return
    fi

    printf "Preparing nginx.\n"
    printf "\tRemove old nginx dir.\n"
    rm -rf ${NGINX_DIR}

    cd ${SCRIPT_DIR}

    printf "\tExtracting..."
    tar xvf ${NGINX_TGZ} >> $LOGFILE 2>&1
    if [ $? != 0 ]; then
        printf "failed.\n"
        do_failure
    fi
    printf "ok.\n"

    cd ${NGINX_DIR}

    printf "\tPatching..."
    patch -p1 -i ${NGINX_PATCH_FILE} >> $LOGFILE 2>&1
    if [ $? != 0 ]; then
        printf "failed.\n"
        do_failure
    fi
    printf "ok.\n"

    cd ${WOLFENGINE_ROOT}
}

build_nginx() {
    if [ -n "${NGINX_NO_BUILD}" ]; then
        return
    fi

    cd ${NGINX_DIR}

    printf "Building nginx.\n"
    printf "\tConfiguring..."
    ./configure --with-openssl=$OPENSSL_INSTALL --with-openssl-opt="shared no-asm ${OPENSSL_EXTRA_CFLAGS}" --with-http_ssl_module >> $LOGFILE 2>&1
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

    cd ${WOLFENGINE_ROOT}
}

download_nginx_tests() {
    if [ -n "${NGINX_NO_BUILD}" ]; then
        return
    fi

    rm -rf ${NGINX_TEST_DIR}

    cd ${SCRIPT_DIR}

    printf "Setting up nginx tests.\n"
    printf "\tDownloading..."
    git clone https://github.com/nginx/nginx-tests.git >> $LOGFILE 2>&1
    if [ $? != 0 ]; then
        printf "failed\n"
        do_failure
    fi
    printf "ok.\n"

    cd ${WOLFENGINE_ROOT}
}

run_nginx_tests() {
    cd ${SCRIPT_DIR}
    cd nginx-tests

    printf "Running nginx tests with wolfEngine..."
    OPENSSL_ENGINES=${WOLFENGINE_ROOT}/.libs
    export TEST_NGINX_BINARY=${NGINX_DIR}/objs/nginx
    prove . >> $LOGFILE 2>&1
    if [ $? != 0 ]; then
        printf "failed\n"
        do_failure
    fi
    printf "ok.\n"

    cd ${WOLFENGINE_ROOT}
}

if [ -z "${LOGFILE}" ]; then
    LOGFILE=${SCRIPT_DIR}/nginx-tests.log
fi
rm -f $LOGFILE

if [ -z "${NGINX_VERSION}" ]; then
    NGINX_VERSION="1.19.10"
fi
NGINX_NAME=nginx-${NGINX_VERSION}
NGINX_TGZ_NAME=${NGINX_NAME}.tar.gz
NGINX_TGZ=${SCRIPT_DIR}/${NGINX_TGZ_NAME}
NGINX_DIR=${SCRIPT_DIR}/${NGINX_NAME}
NGINX_TEST_DIR=${SCRIPT_DIR}/nginx-tests

export OPENSSL_EXTRA_CFLAGS="-g3 -O0 -fno-omit-frame-pointer -fno-inline-functions"
VERSIONS="1.0.2 1.1.1"
if [ "$OPENSSL_VERSIONS" != "" ]; then
    VERSIONS=$OPENSSL_VERSIONS
fi

download_nginx
download_nginx_tests

for VERSION in $VERSIONS
do
    if [ $VERSION = "1.0.2" ]; then
        OPENSSL_VERS_STR="OpenSSL 1.0.2h"
        echo "TESTING nginx with OpenSSL 1.0.2h"
        get_openssl_102h
        configure_openssl_102h
        build_openssl_102h
        OPENSSL_INSTALL=${OPENSSL_1_0_2_SOURCE}
        NGINX_PATCH_FILE=${SCRIPT_DIR}/patches/nginx/${NGINX_VERSION}_ossl102h.patch
    elif [ $VERSION = "1.1.1" ]; then
        echo "TESTING nginx with OpenSSL 1.1.1b"
        OPENSSL_VERS_STR="OpenSSL 1.1.1b"
        get_openssl_111b
        configure_openssl_111b
        build_openssl_111b
        OPENSSL_INSTALL=${OPENSSL_1_1_1_SOURCE}
        NGINX_PATCH_FILE=${SCRIPT_DIR}/patches/nginx/${NGINX_VERSION}_ossl111b.patch
    fi
    setup_openssl_install

    prepare_nginx
    # Nginx re-configures and builds OpenSSL
    build_nginx

    build_wolfengine

    if [ $VERSION = "1.0.2" ]; then
        cp ${WOLFENGINE_ROOT}/.libs/lib* ${OPENSSL_INSTALL}/.openssl/lib/engines/
    elif [ $VERSION = "1.1.1" ]; then
        cp ${WOLFENGINE_ROOT}/.libs/lib* ${OPENSSL_INSTALL}/.openssl/lib/engines-1.1/
    fi

    run_nginx_tests
done

