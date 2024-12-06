#!/bin/bash
# This script provides simple sanity checks to make sure the provider is working
# NOTE: Careful running this script, because it will remove folders automatically

SET_PRE=$( set )
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
LOG_FILE=${SCRIPT_DIR}/test-sanity.log
rm -f ${LOG_FILE}
source ${SCRIPT_DIR}/utils-wolfengine.sh

echo "Using openssl: $OPENSSL_TAG, wolfssl: $WOLFSSL_TAG"

function doTestCmd() {
    CMD=$*
    echo ">>>>>> Running $CMD"
    eval $CMD
    RET=$?
    if [ $RET -ne 0 ]; then
        echo "Failed $CMD: $RET"
        exit 1
    fi
    echo "<<<<<<"
}

function runSpotCheck() {
    SPOTCHECK_ARGS=$1
    unset OPENSSL_MODULES
    unset OPENSSL_CONF
    rm -rf ${WOLFSSL_INSTALL_DIR} ${WOLFSSL_SOURCE_DIR} ${WOLFENGINE_INSTALL_DIR}
    doTestCmd init_wolfengine

    SET_POST=$( set )
    echo "New variables set:"
    diff <(echo "$SET_PRE") <(echo "$SET_POST") | grep "="

    doTestCmd "${OPENSSL_INSTALL_DIR}/bin/openssl engine -c"

    if [ $(${OPENSSL_INSTALL_DIR}/bin/openssl engine -c | grep libwolfengine | wc -l) = 0 ]; then
        echo "Not using wolfEngine for some reason"
        exit 2
    fi

    doTestCmd "${OPENSSL_INSTALL_DIR}/bin/openssl s_client -engine libwolfengine -CApath /etc/ssl/certs -connect github.com:443 </dev/null"

    doTestCmd "${OPENSSL_INSTALL_DIR}/bin/openssl s_client -engine libwolfengine -CApath /etc/ssl/certs -connect tcp.support:443 </dev/null"
}

runSpotCheck

exit $?
