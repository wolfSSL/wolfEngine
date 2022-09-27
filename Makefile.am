SUFFIXES = 
TESTS =
noinst_PROGRAMS =
noinst_HEADERS =
check_PROGRAMS =
dist_noinst_SCRIPTS =
DISTCLEANFILES =
pkginclude_HEADERS =
EXTRA_DIST =

ACLOCAL_AMFLAGS = -I m4

AM_CPPFLAGS = -I$(top_srcdir)/include

lib_LTLIBRARIES = libwolfengine.la

include src/include.am
include include/include.am
include test/include.am
include scripts/include.am
include windows/include.am
include examples/include.am

noinst_PROGRAMS += bench
bench_SOURCES    = bench.c
bench_LDADD      = libwolfengine.la
DISTCLEANFILES  += .libs/bench

test: check

# By default, make distcheck will only add wolfEngine/ as an include directory.
# So, for example, a file like unit.h that has #include
# <wolfengine/we_logging.h> won't be able to find we_logging.h, because
# wolfEngine/include isn't an include directory. We add it here.
#
# The OpenSSL lib and include directories won't be visible to make distcheck
# either because make distcheck runs ./configure with no other options. If
# OpenSSL isn't installed in a standard location, this naked configure command
# will fail to find it. We tell it where to find the include and lib directory
# for OpenSSL here.
AM_DISTCHECK_CONFIGURE_FLAGS=CPPFLAGS="-I@abs_top_srcdir@/include \
                                         @OPENSSL_INCLUDES@" \
                             LDFLAGS="@OPENSSL_LDFLAGS@"

EXTRA_DIST += README.md \
              engine.conf \
              ChangeLog.md
