#!/bin/bash
START=1
END=`./test/unit.test --list | grep -c "test"`
LOGFILE="unit-test-valgrind.log"

if [ ! -z "$1" ]; then
    START=$1
fi

i=$START
printf "Running valgrind test on individual unit test:\n"
printf "(note use -DPURIFY with OpenSSL 1.0.2h)\n"
while [[ $i -le $END ]]; do
    printf "testing case $i ..."
    valgrind --tool=memcheck --track-origins=yes --leak-check=full --error-exitcode=5 --log-fd=9 --leak-check=full --show-leak-kinds=all ./test/unit.test --valgrind --static $i &> $LOGFILE
    if [ $? != 0 ]; then
        printf "failed\n"
        cat $LOGFILE
        printf "Error log stored in the file `pwd`/${LOGFILE}\n"
        exit 1
    fi
    printf "done\n"
    ((i = i + 1))
done
printf "Completed all tests\n"
rm $LOGFILE
exit 0

