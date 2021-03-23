
SUFFIXES = 
TESTS =
noinst_PROGRAMS =
check_PROGRAMS =
DISTCLEANFILES =

ACLOCAL_AMFLAGS = -I m4

pkglib_LTLIBRARIES = libwolfengine.la

include src/include.am
include include/include.am
include test/include.am

noinst_PROGRAMS += bench
bench_SOURCES    = bench.c src/openssl_bc.c
bench_CFLAGS = $(AM_CFLAGS)
DISTCLEANFILES+= .libs/bench

test: check
