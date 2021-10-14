
# Enviornment variables
#
# OPENSSL_1_1_1_INSTALL (location of OpenSSL 1.1.1 install)
# OPENSSL_1_0_2_INSTALL (location of OpenSSL 1.0.2 install)
# WOLFSSL_INSTALL       (location of wolfSSL install to use)
# WOLFENGINE_1_1_1_INSTALL    (location of wolfEngine install to use)
# WOLFENGINE_1_0_2_INSTALL    (location of wolfEngine install to use)
# WOLFSSL_DIR           (location for running wolfssl/scripts/openssl.test)
# EXTRA_WOLFSSL_OPTIONS (additional configure options to use building wolfSSL)
# LOGFILE               (defaults to log.txt but can be over ridden)

FAILED=0

if [ -z "${WOLFSSL_DIR}" ] && [ ! -z "${WOLFSSL_INSTALL}" ]; then
    printf "WOLFSSL_DIR environment variable needs to be set to location of\n"
    printf "wolfSSL source code.\n"
    exit 1
fi

printf "Running wolfSSL + OpenSSL (w/ wolfEngine) interoperability tests using\n"
printf "OpenSSL versions 1.1.1 and 1.0.2.\n\n"

PWD=`pwd`
if [ -z ${LOGFILE} ]; then
    LOGFILE=${PWD}/log.txt
    printf "Using default log file: $LOGFILE.\n\n"
fi
OPENSSL_1_0_2_RES=${PWD}/openssl_1_0_2.res
OPENSSL_1_1_1_RES=${PWD}/openssl_1_1_1.res

printf "Setting up...\n"
if [ -z "${OPENSSL_1_1_1_INSTALL}" ]; then
    printf "\tOPENSSL_1_1_1_INSTALL not set, installing OpenSSL 1.1.1b..."
    git clone --depth=1 -b OpenSSL_1_1_1b git@github.com:openssl/openssl.git openssl-1_1_1b &> $LOGFILE
    OPENSSL_1_1_1_INSTALL=$PWD/openssl-1_1_1b-install

    cd openssl-1_1_1b
    ./config shared --prefix=$OPENSSL_1_1_1_INSTALL &> $LOGFILE
    if [ $? != 0 ]; then
        printf "config failed.\n"
        exit 1
    fi

    make install &> $LOGFILE
    if [ $? != 0 ]; then
        printf "make install failed.\n"
        exit 1
    fi
    printf "installed.\n"
    cd ..
else
    printf "\tUsing OpenSSL 1.1.1 installed at $OPENSSL_1_1_1_INSTALL.\n"
fi

if [ -z "${OPENSSL_1_0_2_INSTALL}" ]; then
    printf "\tOPENSSL_1_0_2_INSTALL not set, installing OpenSSSL 1.0.2h..."
    git clone --depth=1 -b OpenSSL_1_0_2h git@github.com:openssl/openssl.git openssl-1_0_2h &> $LOGFILE
    OPENSSL_1_0_2_INSTALL=${PWD}/openssl-1_0_2h-install

    cd openssl-1_0_2h
    ./config shared --prefix=$OPENSSL_1_0_2_INSTALL &> $LOGFILE
    if [ $? != 0 ]; then
        printf "config failed.\n"
        exit 1
    fi

    make install &> $LOGFILE
    if [ $? != 0 ]; then
        printf "make install failed.\n"
        exit 1
    fi
    printf "installed.\n"
    cd ..
else
    printf "\tUsing OpenSSL 1.0.2 installed at $OPENSSL_1_0_2_INSTALL.\n"
fi

if [ -z "${WOLFSSL_INSTALL}" ]; then
    printf "\tWOLFSSL_INSTALL not set, installing wolfSSL..."
    git clone --depth=1 git@github.com:wolfssl/wolfssl.git &> $LOGFILE
    WOLFSSL_INSTALL=$PWD/wolfssl-install

    cd wolfssl
    ./autogen.sh &> /dev/null
    ./configure --enable-cmac --enable-keygen --enable-sha --enable-des3 --enable-aesctr --enable-aesccm --enable-x963kdf CPPFLAGS="-DHAVE_AES_ECB -DWOLFSSL_AES_DIRECT -DWC_RSA_NO_PADDING -DWOLFSSL_PUBLIC_MP -DECC_MIN_KEY_SZ=192 -DWOLFSSL_PSS_LONG_SALT -DWOLFSSL_PSS_SALT_LEN_DISCOVER" --prefix=$WOLFSSL_INSTALL ${EXTRA_WOLFSSL_OPTIONS} &> $LOGFILE
    if [ $? != 0 ]; then
        printf "config failed.\n"
        exit 1
    fi

    make install &> $LOGFILE
    if [ $? != 0 ]; then
        printf "make install failed.\n"
        exit 1
    fi

    cd ..
    WOLFSSL_DIR=${PWD}/wolfssl
    printf "installed.\n"

else
    printf "\tUsing wolfSSL installed at $WOLFSSL_INSTALL.\n"
fi
export LD_LIBRARY_PATH="$WOLFSSL_INSTALL/lib:$LD_LIBRARY_PATH"

if [ -z "${WOLFENGINE_1_1_1_INSTALL}" ]; then
    printf "\tWOLFENGINE_1_1_1_INSTALL not set, installing wolfEngine with OpenSSL 1.1.1..."
    git clone --depth=1 git@github.com:wolfssl/wolfEngine.git &> $LOGFILE
    WOLFENGINE_1_1_1_INSTALL=$PWD/wolfengine-1_1_1-install

    cd wolfEngine
    ./autogen.sh &> /dev/null
    ./configure --with-wolfssl=$WOLFSSL_INSTALL --with-openssl=$OPENSSL_1_1_1_INSTALL --prefix=$WOLFENGINE_1_1_1_INSTALL &> $LOGFILE
    if [ $? != 0 ]; then
        printf "config failed.\n"
        exit 1
    fi

    make install &> $LOGFILE
    if [ $? != 0 ]; then
        printf "make install failed.\n"
        exit 1
    fi
    printf "installed.\n"
    cd ..
else
    printf "\tUsing wolfEngine with OpenSSL 1.1.1 installed at $WOLFENGINE_1_1_1_INSTALL.\n"
fi

if [ -z "${WOLFENGINE_1_0_2_INSTALL}" ]; then
    printf "\tWOLFENGINE_1_0_2_INSTALL not set, installing wolfEngine with OpenSSL 1.0.2..."
    # We only need to clone the wolfEngine repo if it wasn't previously cloned
    # in the step above.
    if [ ! -d "wolfEngine" ]; then
        git clone --depth=1 git@github.com:wolfssl/wolfEngine.git &> $LOGFILE
    fi
    WOLFENGINE_1_0_2_INSTALL=$PWD/wolfengine-1_0_2-install

    cd wolfEngine
    ./autogen.sh &> /dev/null
    ./configure --with-wolfssl=$WOLFSSL_INSTALL --with-openssl=$OPENSSL_1_0_2_INSTALL --prefix=$WOLFENGINE_1_0_2_INSTALL &> $LOGFILE
    if [ $? != 0 ]; then
        printf "config failed.\n"
        exit 1
    fi

    make install &> $LOGFILE
    if [ $? != 0 ]; then
        printf "make install failed.\n"
        exit 1
    fi
    printf "installed.\n"
    cd ..

else
    printf "\tUsing wolfEngine with OpenSSL 1.0.2 installed at $WOLFENGINE_1_0_2_INSTALL.\n"
fi

printf "Done with setup.\n\n"

printf "Running interop tests...\n"

# Run the existing wolfSSL OpenSSL interop tests using wolfEngine.
cd $WOLFSSL_DIR
export WOLFSSL_OPENSSL_TEST=1
printf "\tTesting with OpenSSL version 1.1.1..."
export OPENSSL_ENGINES=${WOLFENGINE_1_1_1_INSTALL}/lib
export LD_LIBRARY_PATH=${OPENSSL_1_1_1_INSTALL}/lib
export OPENSSL=${OPENSSL_1_1_1_INSTALL}/bin/openssl

# check the engine can be found and used before running tests
$OPENSSL engine -tt libwolfengine &> $LOGFILE
if [ $? != 0 ]; then
    printf "not able to load engine.\n"
    printf "$OPENSSL engine -tt libwolfengine\n"
    FAILED=1
else
    grep "available" $LOGFILE &> /dev/null
    if [ $? != 0 ]; then
        printf "engine not available.\n"
    else
        ./scripts/openssl.test &> ${OPENSSL_1_1_1_RES}
        grep "Success\!" ${OPENSSL_1_1_1_RES} &> /dev/null
        if [ $? == 0 ]; then
            printf "ok.\n"
        else
            printf "failed.\n"
            cat ${OPENSSL_1_1_1_RES}
            FAILED=1
        fi
    fi
fi

printf "\tTesting with OpenSSL version 1.0.2..."
export OPENSSL_ENGINES=${WOLFENGINE_1_0_2_INSTALL}/lib
export LD_LIBRARY_PATH=${OPENSSL_1_0_2_INSTALL}/lib
export OPENSSL=${OPENSSL_1_0_2_INSTALL}/bin/openssl

# check the engine can be found and used before running tests
$OPENSSL engine -tt wolfengine &> $LOGFILE
if [ $? != 0 ]; then
    printf "not able to load engine.\n"
    printf "$OPENSSL engine -tt wolfengine\n"
    FAILED=1
else
    grep "available" $LOGFILE &> /dev/null
    if [ $? != 0 ]; then
        printf "engine not available.\n"
    else
        ./scripts/openssl.test &> ${OPENSSL_1_0_2_RES}
        grep "Success\!" ${OPENSSL_1_0_2_RES} &> /dev/null
        if [ $? == 0 ]; then
            printf "ok.\n"
        else
            printf "failed.\n"
            cat ${OPENSSL_1_0_2_RES}
            FAILED=1
        fi
    fi
fi

printf "Finished tests.\n"
printf "Results stored in the files:\n\t${OPENSSL_1_1_1_RES}\n"
printf "\t${OPENSSL_1_0_2_RES}\n"

if [ $FAILED == 1 ]; then
    printf "Failed.\n"
    exit 1
fi

printf "Succeeded.\n"
exit 0
