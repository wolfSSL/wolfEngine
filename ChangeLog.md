# wolfEngine Release 1.4.1 (August 27, 2026)

## Enhancements and Optimizations
* Modify AES-CTR to not reinitialize after being keyed (PR 213).
* Update the ECC and MAC modules to interoperate with OpenSSL 1.0.2r (PR 221).
* Replace AES_BLOCK_SIZE with WC_AES_BLOCK_SIZE throughout the sources
  (PR 222, PR 223).
* Add the new required FIPS initialization for current wolfSSL-FIPS (PR 220).
* Add simple build scripts (PR 219).
* Migrate the fix for a non-standard OpenSSL/wolfSSL install location (PR 216).

## Vulnerabilities
* [High] CVE-2026-81020 - AES-GCM explicit nonce reuse on TLS 1.2 and DTLS 1.2
  records. The 8-byte explicit nonce was generated once and was not incremented
  for each record, so every AES-GCM record within a connection was encrypted
  under the same key and nonce. Reusing a GCM key and nonce weakens
  confidentiality (identical keystream across records) and integrity
  (authentication tag forgery). TLS 1.3 and non-TLS use of AES-GCM are not
  affected. Affects wolfEngine 0.9.0 through 1.4.0, FIPS and non-FIPS. Update to
  1.4.1.
* [Medium] CVE-2026-81341 - AES-CCM explicit nonce reuse on TLS 1.2 and DTLS 1.2
  records. The explicit nonce was taken from the record input buffer instead of
  the TLS sequence number, so it did not change per record and every AES-CCM
  record within a connection was encrypted under the same key and nonce, with
  the same impact as the AES-GCM issue above. AES-CCM cipher suites are not
  enabled by default and must be explicitly selected, which limits exposure.
  wolfProvider is not affected by this AES-CCM issue. TLS 1.3 and non-TLS use of
  AES-CCM are not affected. Affects wolfEngine 0.9.0 through 1.4.0, FIPS and
  non-FIPS. Update to 1.4.1.

## Bug Fixes
* Unlock private key access for export in we_ec_export_key (PR 224).
* Fix clang warning errors (PR 225).
* Clean up memory leaks when building against OpenSSL 1.0.2, and zeroize AES-CTR
  state on initialization (PR 214).
* Remove a unit test that disabled FIPS, which current wolfSSL-FIPS forbids
  (PR 215).
* Security-review cleanup and hardening (PR 226): correct inverted NULL checks
  in the AES-ECB, AES-CBC, and DES3-CBC control handlers; initialize the AES-ECB
  key alongside wc_AesInit when a key is provided; handle a NULL output-length
  query in RSA private decrypt; propagate EVP_CIPHER_asn1_to_param failure in
  PBES2 key generation; free the RSA, DH, and ASN.1 key objects when the
  matching EVP_PKEY_assign fails; swap the GCM buffer only after a successful
  allocation; bound the ECDSA signature SEQUENCE and HMAC ASN.1 private-key
  lengths before narrowing; clamp the GCM IV increment loop and reject GCM IV
  generation longer than the IV buffer; validate the AES-CBC-HMAC TLS record
  length to prevent underflow; reject unknown digest names in the TLS1-PRF and
  HKDF ctrl_str handlers; accept a zero-length CMAC update to match OpenSSL;
  store the RSA-PSS salt length only in PSS mode; and zeroize private-key
  BIGNUMs, buffered GCM plaintext, the HKDF salt, and PBE-derived key and IV
  buffers.
* Reject a pre-set DH private key longer than the prime during key generation.
  Generating a key from such a private key caused an out-of-bounds heap write;
  this is a memory-safety fix.
* Reject undersized AES-GCM TLS records and free the AES object during cleanup
  only when it was initialized.
* Correct the AES-GCM control IV operation documentation.
* Additional AES-GCM and AES-CCM TLS record and authentication-state hardening.

## Notes
* Direct EVP callers: an AES-GCM or AES-CCM TLS record operation now requires an
  in-place buffer and the standard 12-byte nonce length; AES-GCM TLS encrypt
  requires EVP_CTRL_GCM_SET_IV_FIXED first, matching OpenSSL's
  EVP_CTRL_GCM_IV_GEN precondition; and AES-CCM cipher-operation failures now
  return -1 instead of 0. These match OpenSSL behavior and do not affect TLS use
  through wolfEngine.

# wolfEngine Release 1.4.0 (November 2, 2023)
* Added Call to PRIVATE_KEY_UNLOCK() and PRIVATE_KEY_LOCK() as needed.
* Allow user to override weak entropy source.

# wolfEngine Release 1.3.0 (January 16, 2023)
* Added RPM package support
* Added support and tests for OpenSSL HMAC to be called with -1 key length
* Updated examples to support use with OpenSSL 1.0.2

# wolfEngine Release 1.2.0 (September 29, 2022)
* ChangeLog.md is now shipped with releases.
* Random number generation now mixes in some additional weak entropy (e.g. PID)
to ensure unique numbers, even if the RNG state is copied into a forked process.
* Using wolfEngine with the wolfSSL FIPS 140-3 candidate code will now work as
intended in multi-threaded Windows applications. This was accomplished by adding
a `DllMain` function that calls `wolfCrypt_SetPrivateKeyReadEnable_fips` on new
thread creation.
* The RSA code now supports the `rsa_keygen_pubexp` control command string.
* The RSA code now has a `verify_recover` function.
* The automake code was adjusted to support builds not in the project root. This
is particularly useful for Yocto builds.
* The Visual Studio solution now has configurations to support the wolfSSL FIPS
140-3 candidate code.
* The random bytes function will now return success and do nothing if the
provided length is 0.
* Fixed a potential seg fault in `we_dh_compute_key_int` if `DH_get0_priv_key`
returned NULL.
* The DH code now supports the `dh_paramgen_prime_len` control command string.
* Attempting to use the control command `EVP_PKEY_CTRL_DH_PARAMGEN_GENERATOR`
will now return an error, as wolfCrypt doesn't support setting the generator for
DH.

# wolfEngine Release 1.1.0 (May 16, 2022)
* Updated README.md to refer to new wolfSSL configure flag `--enable-engine`.
* Fixed a double free bug in certain error cases in the ECC code.
* Added examples/ and engine.conf to the distribution.
* Fixed a bug in the AES-CTR implementation where partial block data from a
previous operation would leak into the current operation, even when the IV was
changed between operations.
* Added support for X9.31 padding with RSA signatures.

# wolfEngine Release 1.0.0 (March 7, 2022)
* Added the examples/ directory.
* Added logic to openssl-unit-tests.sh to support macOS.
* Reworked the AES-GCM implementation to support all OpenSSL use cases. Added a
unit test to exercise AES-GCM with the `EVP_Cipher()` API.
* Made some error return codes in the ECC code consistent with OpenSSL.
* Fixed some OpenSSL version gates in the ECC code.
* Adjusted wolfEngine initialization code to support FIPS v5 (140-3).
* Added control commands for enabling wolfSSL debug logging and setting the
wolfSSL debug log callback.
* Added a FIPS integrity check callback so that if the check fails, it's
reported to the user, along with the necessary hash value.
* Improved Visual Studio support.
* Added some additional HMAC functions that were needed when running the OpenSSL
1.1.1m unit tests with wolfEngine.

# wolfEngine Release 0.9.0 (November 12, 2021)

This is the first official release of wolfEngine. Please refer to README.md for
more information.
