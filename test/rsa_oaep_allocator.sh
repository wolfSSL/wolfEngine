#!/bin/sh

set -eu

source_file="${srcdir:-.}/src/we_rsa.c"

grep -q 'CRYPTO_malloc(' "$source_file"
grep -q 'CRYPTO_free(label' "$source_file"

if grep -Eq 'OPENSSL_free\((rsa->oaepLabel|label)\)' "$source_file"; then
    exit 1
fi
