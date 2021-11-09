#!/bin/bash

#
# Tests that using OpenSSH with wolfEngine works.
#

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
WOLFENGINE_ROOT="${SCRIPT_DIR}/.."

if [ -z "${OPENSSL_INSTALL_DIR}" ]; then
    OPENSSL_INSTALL_DIR=${SCRIPT_DIR}/openssl
fi
OPENSSH_DIR=${SCRIPT_DIR}/openssh

source ${SCRIPT_DIR}/build-openssl-wolfengine.sh

do_cleanup() {
    printf "Cleaning up.\n"

    # Use the environment variable KEEP_OPENSSH to prevent OpenSSH and OpenSSL
    # directories from being deleted at the end of the run.
    if [ -z "${KEEP_OPENSSH}" ]; then
        printf "\tDeleting OpenSSH directory.\n"
        rm -rf ${OPENSSH_DIR}

        printf "\tDeleting OpenSSL install directory.\n"
        rm -rf ${OPENSSL_INSTALL_DIR}
    fi
}

do_failure() {
    # Keep the OpenSSH and OpenSSL directories around to help debug the failure.
    KEEP_OPENSSH=1
    do_cleanup
    exit 1
}

# Register trap on interrupt (2) and terminate (15)
trap do_failure INT TERM

download_openssh() {
    printf "Downloading OpenSSH..."
    if [ -n "${OPENSSH_NO_DOWNLOAD}" -o -n "${OPENSSH_NO_BUILD}" ]; then
        return
    fi

    rm -rf ${OPENSSH_DIR}

    cd ${SCRIPT_DIR}

    git clone https://github.com/openssh/openssh-portable.git $OPENSSH_DIR >> $LOGFILE 2>&1
    if [ $? != 0 ]; then
        printf "failed\n"
        do_failure
    fi
    printf "ok.\n"

    cd ${WOLFENGINE_ROOT}
}

build_openssh() {
    if [ -n "${OPENSSH_NO_BUILD}" ]; then
        return
    fi

    cd ${OPENSSH_DIR}

    printf "Building OpenSSH.\n"
    printf "\tRunning autoreconf..."
    autoreconf >> $LOGFILE 2>&1
    if [ $? != 0 ]; then
        printf "failed.\n"
        do_failure
    fi
    printf "ok.\n"

    printf "\tConfiguring..."
    ./configure --with-ssl-dir=${OPENSSL_INSTALL} --without-openssl-header-check --with-ssl-engine >> $LOGFILE 2>&1
    if [ $? != 0 ]; then
        printf "failed.\n"
        do_failure
    fi
    printf "ok.\n"
    make clean >> $LOGFILE 2>&1

    printf "\tBuilding..."
    make -j$MAKE_JOBS >> $LOGFILE 2>&1
    if [ $? != 0 ]; then
        printf "failed.\n"
        do_failure
    fi
    printf "ok.\n"

    cd ${WOLFENGINE_ROOT}
}

test_openssh_separate() {
    cd ${OPENSSH_DIR}

    printf "Running OpenSSH tests with wolfEngine\n"
    for T in connect \
             proxy-connect \
             agent \
             connect-privsep \
             connect-uri \
             proto-version \
             proto-mismatch \
             exit-status \
             envpass \
             transfer \
             banner \
             rekey \
             dhgex \
             stderr-data \
             stderr-after-eof \
             broken-pipe \
             try-ciphers \
             yes-head \
             login-timeout \
             agent-getpeereid \
             agent-timeout \
             agent-ptrace \
             agent-subprocess \
             keyscan \
             keygen-change \
             keygen-convert \
             keygen-moduli \
             key-options \
             scp \
             scp-uri \
             sftp \
             sftp-chroot \
             sftp-cmds \
             sftp-badcmds \
             sftp-batch \
             sftp-glob \
             sftp-perm \
             sftp-uri \
             reconfigure \
             dynamic-forward \
             forwarding \
             multiplex \
             reexec \
             brokenkeys \
             sshcfgparse \
             cfgparse \
             cfgmatch \
             cfgmatchlisten \
             percent \
             addrmatch \
             localcommand \
             forcecommand \
             portnum \
             keytype \
             kextype \
             cert-hostkey \
             cert-userkey \
             host-expand \
             keys-command \
             forward-control \
             integrity \
             krl \
             multipubkey \
             limit-keytype \
             hostkey-agent \
             keygen-knownhosts \
             hostkey-rotate \
             principals-command \
             cert-file \
             cfginclude \
             servcfginclude \
             allow-deny-users \
             authinfo \
             sshsig \
             keygen-comment \
             knownhosts-command
    do
        printf "\t$T..."
        make t-exec LTESTS=$T >> $LOGFILE 2>&1
        if [ $? != 0 ]; then
            printf "failed\n"
            do_failure
        fi
        printf "ok.\n"
    done

    cd ${WOLFENGINE_ROOT}
}

test_openssh_one() {
    cd ${OPENSSH_DIR}

    printf "Running OpenSSH tests with wolfEngine\n"
    for T in integrity
    do
        printf "\t$T..."
        make t-exec LTESTS=$T >> $LOGFILE 2>&1
        if [ $? != 0 ]; then
            printf "failed\n"
            do_failure
        fi
        printf "ok.\n"
    done

    cd ${WOLFENGINE_ROOT}
}

test_openssh() {
    cd ${OPENSSH_DIR}

    printf "Running OpenSSH tests with wolfEngine..."
    make tests >> $LOGFILE 2>&1
    if [ $? != 0 ]; then
        printf "failed\n"
        do_failure
    fi
    printf "ok.\n"

    cd ${WOLFENGINE_ROOT}
}

if [ -z "${LOGFILE}" ]; then
    LOGFILE=${SCRIPT_DIR}/openssh-tests.log
fi
rm -f $LOGFILE

export OPENSSL_EXTRA_CFLAGS="-g3 -O0 -fno-omit-frame-pointer -fno-inline-functions"

# Versions of OpenSSL to test
if [ -n "${OPENSSL_VERSIONS}" ]; then
    VERSIONS=${OPENSSL_VERSIONS}
else
    VERSIONS="1.0.2 1.1.1"
fi

export OPENSSL_CONF=$WOLFENGINE_ROOT/engine.conf
export OPENSSL_ENGINES=$WOLFENGINE_ROOT/.libs
export LD_LIBRARY_PATH="$WOLFENGINE_ROOT/.libs:$WOLFENGINE_ROOT:$LD_LIBRARY_PATH"

download_openssh

for VERSION in $VERSIONS
do
    if [ "${VERSION}" = "1.0.2" ]; then
        OPENSSL_VERS_STR="OpenSSL 1.0.2h"
        get_openssl_102h
        configure_openssl_102h
        build_openssl_102h
        install_openssl_102h
    elif [ "${VERSION}" = "1.1.1" ]; then
        OPENSSL_VERS_STR="OpenSSL 1.1.1b"
        get_openssl_111b
        configure_openssl_111b
        build_openssl_111b
        install_openssl_111b
    fi
    OPENSSL_INSTALL=${OPENSSL_INSTALL_DIR}
    setup_openssl_install

    WOLFENGINE_EXTRA_OPTS="--enable-openssh"
    build_wolfengine

    # We don't want to print debug messages as that will trigger false failures
    # in the OpenSSH tests.
    WE_DEBUG=0
    WE_OPENSSL_CONF=${SCRIPT_DIR}/wolfengine.conf
    write_conf_file

    build_openssh
    test_openssh_separate
done


