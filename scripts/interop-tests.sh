
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
    printf "WOLFSSL_DIR env needs set to location of wolfSSL\n"
    exit 1
fi

printf "Running wolfEngine cipher suite tests against OpenSSL version 1.1.1b\n"
printf "and OpenSSL version 1.0.2h.\n\n"


PWD=`pwd`
if [ -z ${LOGILE} ]; then
    LOGFILE=${PWD}/log.txt
fi
printf "Setting up ...\n"
if [ -z "${OPENSSL_1_1_1_INSTALL}" ]; then
    printf "\tOPENSSL_1_1_1_INSTALL not set, cloning it..."
    git clone --depth=1 -b OpenSSL_1_1_1b git@github.com:openssl/openssl.git openssl-1_1_1b &> $LOGFILE
    OPENSSL_1_1_1_INSTALL=$PWD/openssl-1_1_1b-install

    #Build the library
    printf " Building OpenSSL 1.1.1b..."
    cd openssl-1_1_1b
    ./config shared --prefix=$OPENSSL_1_1_1_INSTALL &> $LOGFILE
    if [ $? != 0 ]; then
        printf "config failed\n"
        exit 1
    fi

    make install &> $LOGFILE
    if [ $? != 0 ]; then
        printf "make failed\n"
        exit 1
    fi
    printf "done\n"
    cd ..
else
    printf "\tUsing OpenSSL 1.1.1 installed at $OPENSSL_1_1_1_INSTALL\n"
fi

if [ -z "${OPENSSL_1_0_2_INSTALL}" ]; then
    printf "\tOPENSSL_1_0_2_INSTALL not set, cloning it..."
    git clone --depth=1 -b OpenSSL_1_0_2h git@github.com:openssl/openssl.git openssl-1_0_2h &> $LOGFILE
    OPENSSL_1_0_2_INSTALL=${PWD}/openssl-1_0_2h-install

    #Build the library
    printf " Building OpenSSL 1.0.2h..."
    cd openssl-1_0_2h
    ./config shared --prefix=$OPENSSL_1_0_2_INSTALL &> $LOGFILE
    if [ $? != 0 ]; then
        printf "config failed\n"
        exit 1
    fi

    make install &> $LOGFILE
    if [ $? != 0 ]; then
        printf "make failed\n"
        exit 1
    fi
    printf "done\n"
    cd ..
else
    printf "\tUsing OpenSSL 1.0.2 installed at $OPENSSL_1_0_2_INSTALL\n"
fi


if [ -z "${WOLFSSL_INSTALL}" ]; then
    printf "\tWOLFSSL_INSTALL not set, cloning it..."
    git clone --depth=1 git@github.com:wolfssl/wolfssl.git &> $LOGFILE
    WOLFSSL_INSTALL=$PWD/wolfssl-install

    #Build the library
    printf " Building wolfSSL..."
    cd wolfssl
    ./autogen.sh &> /dev/null
    ./configure  --enable-cmac --enable-keygen --enable-sha --enable-des3 --enable-aesctr --enable-aesccm CPPFLAGS='-DHAVE_AES_ECB -DWOLFSSL_AES_DIRECT -DWC_RSA_NO_PADDING -DWOLFSSL_PUBLIC_MP -DECC_MIN_KEY_SZ=192'  --prefix=$WOLFSSL_INSTALL ${EXTRA_WOLFSSL_OPTIONS} &> $LOGFILE
    if [ $? != 0 ]; then
        printf "config failed\n"
        exit 1
    fi

    make install &> $LOGFILE
    if [ $? != 0 ]; then
        printf "make failed\n"
        exit 1
    fi

    cd ..
    WOLFSSL_DIR=${PWD}/wolfssl
    printf "done\n"

else
    printf "\tUsing wolfSSL installed at $WOLFSSL_INSTALL\n"
fi
export LD_LIBRARY_PATH="$WOLFSSL_INSTALL/lib:$LD_LIBRARY_PATH"


if [ -z "${WOLFENGINE_1_1_1_INSTALL}" ]; then
    printf "\tWOLENGINE_1_1_1_INSTALL not set, cloning it..."
    git clone --depth=1 git@github.com:wolfssl/wolfEngine.git &> $LOGFILE
    WOLFENGINE_1_1_1_INSTALL=$PWD/wolfengine-1_1_1-install

    #Build the library
    printf " Building wolfEngine..."
    cd wolfEngine
    ./autogen.sh &> /dev/null
    ./configure CPPFLAGS=-I${WOLFSSL_INSTALL}/include --with-openssl=$OPENSSL_1_1_1_INSTALL --prefix=$WOLFENGINE_1_1_1_INSTALL &> $LOGFILE
    if [ $? != 0 ]; then
        printf "config failed\n"
        exit 1
    fi

    make install &> $LOGFILE
    if [ $? != 0 ]; then
        printf "make failed\n"
        exit 1
    fi
    printf "done\n"
    cd ..

else
    printf "\tUsing wolfEngine 1.1.1 installed at $WOLFENGINE_1_1_1_INSTALL\n"
fi


if [ -z "${WOLFENGINE_1_0_2_INSTALL}" ]; then
    printf "\tWOLENGINE_1_0_2_INSTALL not set, cloning it..."
    git clone --depth=1 git@github.com:wolfssl/wolfEngine.git &> $LOGFILE
    WOLFENGINE_1_0_2_INSTALL=$PWD/wolfengine-1_0_2-install

    #Build the library
    printf " Building wolfEngine..."
    cd wolfEngine
    ./autogen.sh &> /dev/null
    ./configure CPPFLAGS=-I${WOLFSSL_INSTALL}/include --with-openssl=$OPENSSL_1_0_2_INSTALL --prefix=$WOLFENGINE_1_0_2_INSTALL &> $LOGFILE
    if [ $? != 0 ]; then
        printf "config failed\n"
        exit 1
    fi

    make install &> $LOGFILE
    if [ $? != 0 ]; then
        printf "make failed\n"
        exit 1
    fi
    printf "done\n"
    cd ..

else
    printf "\tUsing wolfEngine 1.0.2 installed at $WOLFENGINE_1_0_2_INSTALL\n"
fi

printf "Done with setup\n\n"

printf "Running interop tests...\n"

# run the existing wolfSSL openssl interop tests using wolfEngine
cd $WOLFSSL_DIR
export WOLFSSL_OPENSSL_TEST=1
printf "\tTesting with OpenSSL version 1.1.1..."
export OPENSSL_ENGINES=${WOLFENGINE_1_1_1_INSTALL}/lib
export OPENSSL_ENGINE_ID="libwolfengine"
export LD_LIBRARY_PATH=${OPENSSL_1_1_1_INSTALL}/lib
export OPENSSL=${OPENSSL_1_1_1_INSTALL}/bin/openssl

# check the engine can be found and used before running tests
$OPENSSL engine -tt libwolfengine &> $LOGFILE
if [ $? != 0 ]; then
    printf "not able to load engine\n"
    printf "$OPENSSL engine -tt libwolfengine\n"
    FAILED=1
else
    if [ $? != 0 ]; then
        printf "engine not available\n"
    else
        ./scripts/openssl.test &> $PWD/openssl_1_1_1.res
        grep "Success\!" $PWD/openssl_1_1_1.res &> /dev/null
        if [ $? == 0 ]; then
            printf "ok\n"
        else
            printf "failed\n"
            FAILED=1
        fi
    fi
fi

printf "\tTesting with OpenSSL version 1.0.2..."
export OPENSSL_ENGINES=${WOLFENGINE_1_0_2_INSTALL}/lib
export LD_LIBRARY_PATH=${OPENSSL_1_0_2_INSTALL}/lib
export OPENSSL=${OPENSSL_1_0_2_INSTALL}/bin/openssl
export OPENSSL_ENGINE_ID="wolfengine"

# check the engine can be found and used before running tests
$OPENSSL engine -tt wolfengine &> $LOGFILE
if [ $? != 0 ]; then
    printf "not able to load engine\n"
    printf "$OPENSSL engine -tt wolfengine\n"
    FAILED=1
else
    cat $LOGFILE
    grep "available" $LOGFILE
    if [ $? != 0 ]; then
        printf "engine not available\n"
    else
        ./scripts/openssl.test &> ${PWD}/openssl_1_0_2.res
        grep "Success\!" ${PWD}/openssl_1_0_2.res &> /dev/null
        if [ $? == 0 ]; then
            printf "ok\n"
        else
            printf "failed\n"
            FAILED=1
        fi
    fi
fi

printf "Finished\n"
printf "Results stored in the files:\n\t${PWD}/openssl_1_1_1.res\n"
printf "\t${PWD}/openssl_1_0_2.res\n"


if [ $FAILED == 1 ]; then
    printf "Fail...\n"
    exit 1
fi
printf "Success\n"
exit 0
