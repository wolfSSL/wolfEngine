#!/bin/sh

# commit-tests.sh
#
# Tests executed on each commit

# WOLFENGINE_OPENSSL_INSTALL - environment variable that when set will use
# the specified OpenSSL installation path for commit tests, setting the path
# with --with-openssl=WOLFENGINE_OPENSSL_INSTALL at configure time.

# make sure current config is ok
echo -e "\n\nTesting current config...\n\n"
make clean; make -j 8 test;
RESULT=$?
[ $RESULT -ne 0 ] && echo -e "\n\nCurrent config make test failed" && exit 1

# allow developer to set OpenSSL installation path using env variable
if test -n "$WOLFENGINE_OPENSSL_INSTALL"; then
    WITH_OPENSSL="--with-openssl=$WOLFENGINE_OPENSSL_INSTALL"
    echo -e "WOLFENGINE_OPENSSL_INSTALL is set: $WOLFENGINE_OPENSSL_INSTALL"
    export LD_LIBRARY_PATH=$WOLFENGINE_OPENSSL_INSTALL/lib:$LD_LIBRARY_PATH
else
    WITH_OPENSSL=""
    echo -e "WOLFENGINE_OPENSSL_INSTALL not set."
fi

# make sure default config is ok
echo -e "\n\nTesting default config:\n"
./configure $WITH_OPENSSL
RESULT=$?
[ $RESULT -ne 0 ] && echo -e "\n\nDefault config ./configure failed" && exit 1

make -j 8 test
RESULT=$?
[ $RESULT -ne 0 ] && echo -e "\n\nDefault config make test failed" && exit 1
 
# make sure config with all features is ok
echo -e "\n\nTesting config with all features...\n\n"
./configure $WITH_OPENSSL --enable-sha3 --enable-aesgcm --enable-aesccm
RESULT=$?
[ $RESULT -ne 0 ] && echo -e "\n\nConfig with all features ./configure --enable-sha3 --enable-aesgcm --enable-aesccm failed" && exit 1

make -j 8 test
RESULT=$?
[ $RESULT -ne 0 ] && echo -e "\n\nConfig with all features make test failed" && exit 1

# make sure static engine config is ok
echo -e "\n\nTesting static engine config...\n\n"
./configure $WITH_OPENSSL --enable-static --disable-dynamic-engine
RESULT=$?
[ $RESULT -ne 0 ] && echo -e "\n\nStatic engine config ./configure --enable-static --disable-dynamic-engine failed" && exit 1

make -j 8 test
RESULT=$?
[ $RESULT -ne 0 ] && echo -e "\n\nStatic engine config make test failed" && exit 1

exit 0
