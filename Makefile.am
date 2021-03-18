
SUFFIXES = 
TESTS =
noinst_PROGRAMS =
check_PROGRAMS =
DISTCLEANFILES =

ACLOCAL_AMFLAGS = -I m4

pkglib_LTLIBRARIES = libwolfengine.la

include src/include.am
include include/include.am

TEST_EXTENSIONS=.test
TESTS += $(check_PROGRAMS)

check_PROGRAMS   += unit.test
noinst_PROGRAMS  += unit.test
unit_test_SOURCES = unit.c src/openssl_bc.c
unit_test_CFLAGS = $(AM_CFLAGS)
DISTCLEANFILES+= .libs/unit.test

noinst_PROGRAMS += bench
bench_SOURCES    = bench.c src/openssl_bc.c
bench_CFLAGS = $(AM_CFLAGS)
DISTCLEANFILES+= .libs/bench

test: check


