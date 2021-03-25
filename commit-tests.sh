#!/bin/sh

# commit-tests.sh
#
# Tests executed on each commit

# make sure current config is ok
echo -e "\n\nTesting current config...\n\n"
make clean; make -j 8 test;
RESULT=$?
[ $RESULT -ne 0 ] && echo -e "\n\nCurrent config make test failed" && exit 1


# make sure default config is ok
echo -e "\n\nTesting default config...\n\n"
./configure ;
RESULT=$?
[ $RESULT -ne 0 ] && echo -e "\n\Default config ./configure failed" && exit 1

make -j 8 test;
RESULT=$?
[ $RESULT -ne 0 ] && echo -e "\n\Default config make test failed" && exit 1

# make sure static engine config is ok
echo -e "\n\nTesting static engine config...\n\n"
./configure --enable-static --disable-dynamic-engine;
RESULT=$?
[ $RESULT -ne 0 ] && echo -e "\n\Static engine config ./configure --enable-static --disable-dynamic-engine failed" && exit 1

make -j 8 test;
RESULT=$?
[ $RESULT -ne 0 ] && echo -e "\n\nStatic engine config make test failed" && exit 1

exit 0



