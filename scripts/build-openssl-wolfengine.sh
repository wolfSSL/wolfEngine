# This script is 'source'ed into testing scripts.
#
# This is the common rountines used to build wolfEngine

TEST_PATCH_DIR_102="$WOLFENGINE_ROOT/openssl_patches/1.0.2h/tests/"
TEST_PATCH_DIR_111="$WOLFENGINE_ROOT/openssl_patches/1.1.1b/tests/"

setup_openssl_install() {
    if [ -z "${OPENSSL_INSTALL}" ]; then
        OPENSSL_INSTALL=/usr
    fi

    if [ -n "${OLD_LD_LIBRARY_PATH}" ]; then
        LD_LIBRARY_PATH=${OLD_LD_LIBRARY_PATH}
    else
        OLD_LD_LIBRARY_PATH=${LD_LIBRARY_PATH}
    fi

    # If the OPENSSL_INSTALL directory has a "lib" subdirectory, use that.
    # Otherwise, we're working with an OpenSSL source directory, and the
    # libraries will be in the root, not a subdirectory.
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
    OPENSSL_VERS_STR="OpenSSL${OPENSSL_VERSION}"
}


apply_patches() {
    for PATCH in $PATCHES
    do
        # Try to patch. If doesn't work, check whether it has already been
        # applied.
        git apply $PATCH &>$LOGFILE || git apply $PATCH -R --check &>> $LOGFILE
        if [ $? != 0 ]; then
            printf "$PATCH failed to apply\n"
            do_cleanup
            exit 1
        fi
    done
}

patch_openssl_fips() {
    if [ "$WOLFSSL_FIPS" == 1 ]; then
        cd $OPENSSL_SOURCE
        printf "Patching unit tests to support wolfCrypt FIPS.\n"
        if [ -d "$TEST_PATCH_DIR/fips" ]; then
            PATCHES=`find $TEST_PATCH_DIR/fips -name "*.patch"`
            apply_patches
        fi
        printf "\tRebuilding patched tests..."
        make -j$MAKE_JOBS 2>&1 | tee -a $LOGFILE
        if [ "${PIPESTATUS[0]}" != 0 ]; then
            printf "failed\n"
            do_cleanup
            exit 1
        fi
        printf "ok.\n"
    else
        printf "Skipping unit test FIPS patches.\n"
    fi
}

patch_openssl() {
    printf "\tPatching unit tests to use wolfEngine.\n"
    PATCHES=`find $TEST_PATCH_DIR -maxdepth 1 -name "*.patch"`
    apply_patches
}


get_openssl_102h() {
    printf "Setting up OpenSSL 1.0.2h.\n"
    if [ -n "${OPENSSL_1_0_2_SOURCE}" ]; then
        printf "\tUsing OpenSSL 1.0.2h source code at $OPENSSL_1_0_2_SOURCE\n"
        return
    fi

    if [ -d "openssl-1_0_2h" ]; then
        return
    fi

    printf "\tCloning OpenSSL and checking out version 1.0.2h..."
    git clone --depth=1 -b OpenSSL_1_0_2h https://github.com/openssl/openssl.git openssl-1_0_2h >> $LOGFILE 2>&1
    if [ "$?" != 0 ]; then
        printf "failed\n"
        do_cleanup
        exit 1
    fi
    printf "ok.\n"
}

patch_openssl_102h() {
    cd openssl-1_0_2h
    patch_openssl
    cd ..
}

configure_openssl_102h() {
    if [ -n "${OPENSSL_NO_CONFIG}" ]; then
        return
    fi

    cd openssl-1_0_2h

    printf "\tConfiguring..."
    # Configure for debug.
    ./config shared no-asm --prefix=$OPENSSL_INSTALL_DIR \
             $OPENSSL_EXTRA_CFLAGS >> $LOGFILE 2>&1
    if [ "$?" != 0 ]; then
        printf "failed\n"
        do_cleanup
        exit 1
    fi
    printf "ok.\n"
    make clean >> $LOGFILE 2>&1

    cd ..
}

build_openssl_102h() {
    if [ -n "${OPENSSL_NO_BUILD}" ]; then
        return
    fi

    cd openssl-1_0_2h

    printf "\tBuilding..."
    make -j$MAKE_JOBS >> $LOGFILE 2>&1
    if [ "$?" != 0 ]; then
        printf "failed\n"
        do_cleanup
        exit 1
    fi
    printf "ok.\n"

    OPENSSL_1_0_2_SOURCE=`pwd`
    cd ..
}

install_openssl_102h() {
    if [ -n "${OPENSSL_NO_BUILD}" ]; then
        return
    fi

    cd openssl-1_0_2h

    printf "\tInstalling..."
    rm -rf ${OPENSSL_INSTALL_DIR}
    mkdir $OPENSSL_INSTALL_DIR
    mkdir $OPENSSL_INSTALL_DIR/include
    mkdir $OPENSSL_INSTALL_DIR/lib
    cp -rL include/* ${OPENSSL_INSTALL_DIR}/include/
    cp -r lib* $OPENSSL_INSTALL_DIR/lib/
    if [ "$?" != 0 ]; then
        printf "failed\n"
        do_cleanup
        exit 1
    fi
    printf "ok.\n"

    cd ..
}

get_openssl_111b() {
    printf "Setting up OpenSSL 1.1.1b.\n"
    if [ -n "${OPENSSL_1_1_1_SOURCE}" ]; then
        printf "\tUsing OpenSSL 1.1.1b source code at $OPENSSL_1_1_1_SOURCE\n"
        return
    fi

    if [ -d "openssl-1_1_1b" ]; then
        return
    fi

    printf "\tCloning OpenSSL and checking out version 1.1.1b..."
    git clone --depth=1 -b OpenSSL_1_1_1b https://github.com/openssl/openssl.git openssl-1_1_1b >> $LOGFILE 2>&1
    if [ "$?" != 0 ]; then
        printf "failed\n"
        do_cleanup
        exit 1
    fi
    printf "ok.\n"
}

patch_openssl_111b() {
    cd openssl-1_1_1b
    patch_openssl
    cd ..
}

configure_openssl_111b() {
    if [ -n "${OPENSSL_NO_CONFIG}" -o -n "${OPENSSL_NO_BUILD}" ]; then
        return
    fi

    cd openssl-1_1_1b

    if [ -z "${OPENSSL_INSTALL_DIR}" ]; then
        OPENSSL_INSTALL_DIR=/usr/local
    elif [ ! -d ${OPENSSL_INSTALL_DIR} ]; then
        mkdir -p ${OPENSSL_INSTALL_DIR}
    fi

    printf "\tConfiguring..."
    # Configure for debug.
    ./config shared no-asm --prefix=$OPENSSL_INSTALL_DIR \
             $OPENSSL_EXTRA_CFLAGS >> $LOGFILE 2>&1
    if [ "$?" != 0 ]; then
        printf "failed\n"
        do_cleanup
        exit 1
    fi
    printf "ok.\n"
    make clean >> $LOGFILE 2>&1

    cd ..
}

build_openssl_111b() {
    if [ -n "${OPENSSL_NO_BUILD}" ]; then
        return
    fi

    cd openssl-1_1_1b

    printf "\tBuilding..."
    make -j$MAKE_JOBS >> $LOGFILE 2>&1
    if [ "$?" != 0 ]; then
        printf "failed\n"
        do_cleanup
        exit 1
    fi
    printf "ok.\n"

    OPENSSL_1_1_1_SOURCE=`pwd`
    cd ..
}

install_openssl_111b() {
    if [ -n "${OPENSSL_NO_BUILD}" ]; then
        return
    fi

    cd openssl-1_1_1b

    printf "\tInstalling..."
    rm -rf ${OPENSSL_INSTALL_DIR}
    make -j$NAME_JOBS install >> $LOGFILE 2>&1
    if [ "$?" != 0 ]; then
        printf "failed\n"
        do_cleanup
        exit 1
    fi
    printf "ok.\n"

    cd ..
}

# Write out a OpenSSL configuration file that uses wolfEngine
write_conf_file() {
    if [ -z "${WE_DEBUG}" ]; then
        WE_DEBUG=1
    fi

    printf "\tWriting OpenSSL configuration file for wolfEngine\n"
    cat > ${WE_OPENSSL_CONF} << EOF
openssl_conf = openssl_init

[openssl_init]
engines = engine_section

[engine_section]
wolfengine = wolfengine_section

[wolfengine_section]
dynamic_path = ${WOLFENGINE_ROOT}/.libs/libwolfengine.so
default_algorithms = ALL
init = 1
enable_debug = ${WE_DEBUG}
EOF
    export OPENSSL_CONF=$WE_OPENSSL_CONF
}

build_wolfengine() {
    if [ -n "${WOLFENGINE_NO_BUILD}" ]; then
        return
    fi

    echo "Building wolfEngine" >> $LOGFILE

    printf "Setting up wolfEngine to use $OPENSSL_VERS_STR.\n"
    # Ensure wolfEngine has a configure file to create a Makefile with.
    if [ ! -f "./configure" ]; then
        printf "\tRunning autogen.sh..."
        ./autogen.sh >> $LOGFILE 2>&1
        if [ $? != 0 ]; then
            printf "failed.\n"
            do_failure
        fi
        printf "ok.\n"
    fi

    printf "\tConfiguring..."
    if [ -n "${OPENSSL_INSTALL}" ]; then
        ./configure $OPENSSL_CPPFLAGS $OPENSSL_LDFLAGS \
                    --with-openssl=$OPENSSL_INSTALL \
                    --enable-debug \
                    $WOLFENGINE_EXTRA_OPTS >> $LOGFILE 2>&1
    else
        # Tests have been patched to use debug logging - must enable debug.
        # User can set WOLFENGINE_EXTRA_LDFLAGS to provide extra LDFLAGS and
        # WOLFENGINE_EXTRA_CPPFLAGS to provide extra CPPFLAGS.
        ./configure LDFLAGS="-L$OPENSSL_SOURCE $WOLFENGINE_EXTRA_LDFLAGS" \
                    CPPFLAGS="$WOLFENGINE_EXTRA_CPPFLAGS" \
                    --with-openssl=$OPENSSL_SOURCE \
                    --enable-debug \
                    $WOLFENGINE_EXTRA_OPTS >> $LOGFILE 2>&1
    fi
    if [ "$?" != 0 ]; then
        printf "failed\n"
        do_cleanup
        exit 1
    fi
    printf "ok.\n"

    printf "\tBuilding..."
    make -j$MAKE_JOBS >> $LOGFILE 2>&1
    if [ "$?" != 0 ]; then
        printf "failed\n"
        do_cleanup
        exit 1
    fi
    printf "ok.\n"
}


