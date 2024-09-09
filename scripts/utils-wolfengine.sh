#!/bin/bash
#
# Copyright (C) 2021 wolfSSL Inc.
#
# This file is part of wolfProvider.
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
source ${SCRIPT_DIR}/utils-openssl.sh
source ${SCRIPT_DIR}/utils-wolfssl.sh

WOLFENGINE_SOURCE_DIR=${SCRIPT_DIR}/..
WOLFENGINE_INSTALL_DIR=${SCRIPT_DIR}/../wolfengine-install
if [ "$WOLFSSL_ISFIPS" -eq "1" ]; then
    WOLFENGINE_CONFIG=${WOLFENGINE_CONFIG:-"$WOLFENGINE_SOURCE_DIR/engine-fips.conf"}
else
    WOLFENGINE_CONFIG=${WOLFENGINE_CONFIG:-"$WOLFENGINE_SOURCE_DIR/engine.conf"}
fi

WOLFENGINE_NAME="libwolfengine"
WOLFENGINE_PATH=$WOLFENGINE_INSTALL_DIR/lib

WOLFENGINE_DEBUG=${WOLFENGINE_DEBUG:-0}

install_wolfengine() {
    cd ${WOLFENGINE_SOURCE_DIR}

    init_openssl
    init_wolfssl
    printf "LD_LIBRARY_PATH: $LD_LIBRARY_PATH\n"

    if [ ! -d ${WOLFENGINE_INSTALL_DIR} ]; then
        printf "\tConfigure wolfEngine ... "
        if [ ! -e "${WOLFENGINE_SOURCE_DIR}/configure" ]; then
            ./autogen.sh >>$LOG_FILE 2>&1
        fi
        if [ "$WOLFENGINE_DEBUG" = "1" ]; then
            ./configure --with-openssl=${OPENSSL_INSTALL_DIR} --with-wolfssl=${WOLFSSL_INSTALL_DIR} --prefix=${WOLFENGINE_INSTALL_DIR} --enable-debug >>$LOG_FILE 2>&1
            RET=$?
        else
            ./configure --with-openssl=${OPENSSL_INSTALL_DIR} --with-wolfssl=${WOLFSSL_INSTALL_DIR} --prefix=${WOLFENGINE_INSTALL_DIR} >>$LOG_FILE 2>&1
            RET=$?
        fi
        if [ $RET != 0 ]; then
            printf "\n\n...\n"
            tail -n 40 $LOG_FILE
            do_cleanup
            exit 1
        fi
        printf "Done.\n"

        printf "\tBuild wolfEngine ... "
        make -j$NUMCPU >>$LOG_FILE 2>&1
        if [ $? != 0 ]; then
            printf "\n\n...\n"
            tail -n 40 $LOG_FILE
            do_cleanup
            exit 1
        fi
        printf "Done.\n"

        printf "\tTest wolfEngine ... "
        make test >>$LOG_FILE 2>&1
        if [ $? != 0 ]; then
            printf "\n\n...\n"
            tail -n 40 $LOG_FILE
            do_cleanup
            exit 1
        fi
        printf "Done.\n"

        printf "\tInstall wolfEngine ... "
        make install >>$LOG_FILE 2>&1
        if [ $? != 0 ]; then
            printf "\n\n...\n"
            tail -n 40 $LOG_FILE
            do_cleanup
            exit 1
        fi
        printf "Done.\n"
    fi
}

init_wolfengine() {
    install_wolfengine
    printf "\twolfEngine installed in: ${WOLFENGINE_INSTALL_DIR}\n"

    export OPENSSL_MODULES=$WOLFENGINE_PATH
    export OPENSSL_CONF=${WOLFENGINE_CONFIG}
}

