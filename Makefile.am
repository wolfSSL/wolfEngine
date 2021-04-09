
SUFFIXES = 
TESTS =
noinst_PROGRAMS =
check_PROGRAMS =
dist_noinst_SCRIPTS =
DISTCLEANFILES =

ACLOCAL_AMFLAGS = -I m4

lib_LTLIBRARIES = libwolfengine.la

include src/include.am
include include/include.am
include test/include.am
include scripts/include.am

noinst_PROGRAMS += bench
bench_SOURCES    = bench.c
bench_LDADD      = libwolfengine.la
DISTCLEANFILES  += .libs/bench

test: check
