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
include rpm/include.am

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
#
# The '--with-wolfssl' doesn't get propagated during a distcheck either, but it
# is necessary when they are installed somewhere other than /usr/local.
AM_DISTCHECK_CONFIGURE_FLAGS=CPPFLAGS="-I@abs_top_srcdir@/include" --with-openssl=@OPENSSL_INSTALL_DIR@ --with-wolfssl=@WOLFSSL_INSTALL_DIR@

EXTRA_DIST += README.md \
              engine.conf \
              ChangeLog.md

# ---------------------------------------------------------------------------
# SBOM generation (CycloneDX + SPDX) via wolfssl's scripts/gen-sbom
# ---------------------------------------------------------------------------
# Requires WOLFSSL_DIR to point at a wolfssl checkout (for scripts/gen-sbom).
# wolfEngine has no generated options.h of its own; feature flags come from the
# installed wolfssl. WOLFSSL_INCLUDEDIR defaults to $(WOLFSSL_DIR)/include but
# can be overridden if wolfssl's headers live elsewhere.
WOLFSSL_DIR ?=
WOLFSSL_INCLUDEDIR ?= $(WOLFSSL_DIR)/include
PRODUCT      = wolfengine
VERSION      = $(shell grep -m1 'AC_INIT' $(srcdir)/configure.ac | sed "s/.*\[//;s/\].*//")
GEN_SBOM     = $(WOLFSSL_DIR)/scripts/gen-sbom

SBOM_OUT_DIR = $(builddir)
SBOM_CDX     = $(SBOM_OUT_DIR)/$(PRODUCT)-$(VERSION).cdx.json
SBOM_SPDX_J  = $(SBOM_OUT_DIR)/$(PRODUCT)-$(VERSION).spdx.json
SBOM_SPDX_TV = $(SBOM_OUT_DIR)/$(PRODUCT)-$(VERSION).spdx

.PHONY: sbom install-sbom uninstall-sbom

sbom: all
	@if test -z "$(WOLFSSL_DIR)"; then \
	    echo "ERROR: WOLFSSL_DIR not set. Usage: make sbom WOLFSSL_DIR=/path/to/wolfssl"; \
	    exit 1; \
	fi
	@if test -z "$(PYTHON3)"; then \
	    echo "ERROR: python3 not found in PATH."; exit 1; fi
	$(MAKE) install DESTDIR=$(abs_builddir)/_sbom_stage
	$(PYTHON3) $(GEN_SBOM) \
	    --name $(PRODUCT) \
	    --version $(VERSION) \
	    --supplier "wolfSSL Inc." \
	    --options-h $(WOLFSSL_INCLUDEDIR)/wolfssl/options.h \
	    --lib `find $(abs_builddir)/_sbom_stage$(libdir) -name 'libwolfengine.so.*.*.*' | head -1`
	rm -rf $(abs_builddir)/_sbom_stage

install-sbom: sbom
	$(MKDIR_P) $(DESTDIR)$(datadir)/doc/$(PRODUCT)
	$(INSTALL_DATA) $(SBOM_CDX) $(SBOM_SPDX_J) $(SBOM_SPDX_TV) \
	    $(DESTDIR)$(datadir)/doc/$(PRODUCT)/

uninstall-sbom:
	-rm -f $(DESTDIR)$(datadir)/doc/$(PRODUCT)/$(PRODUCT)-*.cdx.json
	-rm -f $(DESTDIR)$(datadir)/doc/$(PRODUCT)/$(PRODUCT)-*.spdx.json
	-rm -f $(DESTDIR)$(datadir)/doc/$(PRODUCT)/$(PRODUCT)-*.spdx

uninstall-hook: uninstall-sbom
