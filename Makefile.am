
TESTS =
noinst_PROGRAMS =
check_PROGRAMS =
DISTCLEANFILES =

AUTOMAKE_OPTIONS = foreign
ACLOCAL_AMFLAGS = -I m4

pkglib_LTLIBRARIES = libwolfengine.la

libwolfengine_la_SOURCES = wolfengine.c openssl_bc.c

TEST_EXTENSIONS=.test
TESTS += $(check_PROGRAMS)

check_PROGRAMS   += unit.test
noinst_PROGRAMS  += unit.test
unit_test_SOURCES = unit.c openssl_bc.c
unit_test_CFLAGS = $(AM_CFLAGS)
DISTCLEANFILES+= .libs/unit.test

noinst_PROGRAMS += bench
bench_SOURCES    = bench.c openssl_bc.c
bench_CFLAGS = $(AM_CFLAGS)
DISTCLEANFILES+= .libs/bench

test: check


