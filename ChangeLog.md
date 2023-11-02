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
