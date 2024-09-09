#!/bin/bash
#
# Copyright (C) 2021 wolfSSL Inc.
#
# This file is part of wolfEngine.
#
# wolfProvider is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 3 of the License, or
# (at your option) any later version.
#
# wolfProvider is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1335, USA
#

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
source ${SCRIPT_DIR}/utils-general.sh

OPENSSL_GIT="https://github.com/openssl/openssl.git"
OPENSSL_TAG=${OPENSSL_TAG:-"OpenSSL_1_1_0h"}
OPENSSL_SOURCE_DIR=${SCRIPT_DIR}/../openssl-source
OPENSSL_INSTALL_DIR=${SCRIPT_DIR}/../openssl-install

NUMCPU=${NUMCPU:-8}
WOLFENGINE_DEBUG=${WOLFENGINE_DEBUG:-0}

if [ -z $LD_LIBRARY_PATH ]; then
  export LD_LIBRARY_PATH=$OPENSSL_INSTALL_DIR/lib
else
  export LD_LIBRARY_PATH=$OPENSSL_INSTALL_DIR/lib:$LD_LIBRARY_PATH
fi

clone_openssl() {
    if [ -d ${OPENSSL_SOURCE_DIR} ]; then
        OPENSSL_TAG_CUR=$(cd ${OPENSSL_SOURCE_DIR} && (git describe --tags 2>/dev/null || git branch --show-current))
        if [ "${OPENSSL_TAG_CUR}" != "${OPENSSL_TAG}" ]; then # force a rebuild
            printf "Version inconsistency. Please fix ${OPENSSL_SOURCE_DIR} (expected: ${OPENSSL_TAG}, got: ${OPENSSL_TAG_CUR})\n"
            do_cleanup
            exit 1
        fi
    fi

    if [ ! -d ${OPENSSL_SOURCE_DIR} ]; then
        printf "\tClone OpenSSL ${OPENSSL_TAG} ... "
        if [ "$WOLFENGINE_DEBUG" = "1" ]; then
            git clone -b ${OPENSSL_TAG} ${OPENSSL_GIT} \
                 ${OPENSSL_SOURCE_DIR} >>$LOG_FILE 2>&1
            RET=$?
        else
            git clone --depth=1 -b ${OPENSSL_TAG} ${OPENSSL_GIT} \
                 ${OPENSSL_SOURCE_DIR} >>$LOG_FILE 2>&1
            RET=$?
        fi
        if [ $RET != 0 ]; then
            printf "ERROR.\n"
            do_cleanup
            exit 1
        fi
        printf "Done.\n"
    fi
}

install_openssl() {
    clone_openssl
    cd ${OPENSSL_SOURCE_DIR}

    if [ ! -d ${OPENSSL_INSTALL_DIR} ]; then
        printf "\tConfigure OpenSSL ${OPENSSL_TAG} ... "
        if [ "$WOLFENGINE_DEBUG" = "1" ]; then
            ./config shared --prefix=${OPENSSL_INSTALL_DIR} --debug >>$LOG_FILE 2>&1
            RET=$?
        else
            ./config shared --prefix=${OPENSSL_INSTALL_DIR} >>$LOG_FILE 2>&1
            RET=$?
        fi
        if [ $RET != 0 ]; then
            printf "ERROR.\n"
            rm -rf ${OPENSSL_INSTALL_DIR}
            do_cleanup
            exit 1
        fi
        printf "Done.\n"

        printf "\tBuild OpenSSL ${OPENSSL_TAG} ... "
        make -j$NUMCPU >>$LOG_FILE 2>&1
        if [ $? != 0 ]; then
            printf "ERROR.\n"
            rm -rf ${OPENSSL_INSTALL_DIR}
            do_cleanup
            exit 1
        fi
        printf "Done.\n"

        printf "\tInstalling OpenSSL ${OPENSSL_TAG} ... "
        make -j$NUMCPU install >>$LOG_FILE 2>&1
        if [ $? != 0 ]; then
            printf "ERROR.\n"
            rm -rf ${OPENSSL_INSTALL_DIR}
            do_cleanup
            exit 1
        fi
        printf "Done.\n"
    fi

    cd ..
}

init_openssl() {
    install_openssl
    printf "\tOpenSSL ${OPENSSL_TAG} installed in: ${OPENSSL_INSTALL_DIR}\n"

    OPENSSL_BIN=${OPENSSL_INSTALL_DIR}/bin/openssl
    OPENSSL_TEST=${OPENSSL_SOURCE_DIR}/test

    OSSL_VER=`LD_LIBRARY_PATH=${OPENSSL_INSTALL_DIR}/lib $OPENSSL_BIN version | tail -n1`
    case $OSSL_VER in
        OpenSSL\ 1.*) ;;
        *)
            echo "OpenSSL ($OPENSSL_BIN) has wrong version: $OSSL_VER"
            echo "Set: OPENSSL_DIR"
            exit 1
            ;;
    esac
}

