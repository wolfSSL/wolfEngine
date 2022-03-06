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
