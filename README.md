# wolfEngine

wolfEngine is an [OpenSSL engine](https://www.openssl.org/docs/man1.0.2/man3/engine.html)
backed by wolfSSL's wolfCrypt cryptography library. wolfCrypt is
[FIPS-validated](https://csrc.nist.gov/Projects/cryptographic-module-validation-program/Certificate/3389),
so wolfEngine can be used to achieve FIPS compliance with OpenSSL, all without
having to touch the OpenSSL code itself.

## Features

* SHA-1
* SHA-224
* SHA-256
* SHA-384
* SHA-512
* SHA3-224
* SHA3-256
* SHA3-384
* SHA3-512
* DES3-CBC
* AES
    * 128, 192, and 256 bit keys
    * ECB
    * CBC
    * CTR
    * GCM
    * CCM
* DRBG
* RSA
* DH
* ECC
    * ECDSA
    * ECDH
    * EC key generation
    * Curve P-192
    * Curve P-224
    * Curve P-256
    * Curve P-384
    * Curve P-521
* HMAC
* CMAC
* HKDF
* PBKDF2
* TLS PRF

### OpenSSL Version Support
wolfEngine can be used with any OpenSSL version that supports the engine
framework. Engines are deprecated in OpenSSL 3.0.0. They're replaced with a
similar concept called [providers](https://www.openssl.org/docs/manmaster/man7/provider.html).
wolfSSL also offers a provider backed by wolfCrypt. Please reach out to
facts@wolfssl.com if you're interested in evaluating the wolfSSL provider. 

#### Caveats
* SHA-3 support is only available with OpenSSL versions 1.1.1+.
* EC_KEY_METHOD is only available with OpenSSL versions 1.1.1+.

## Building on \*nix

### TL;DR>
The quickest way to get up and running is to use the `scripts/util-*.sh`. There
is a `scripts/test-sanity.sh` that will pull all the required dependencies,
compile them as needed, and finally run a few tests to make sure things are
working as they should. For a more detailed step-by-step instruction,
continue reading.

### OpenSSL

Assuming you've downloaded OpenSSL source code into a directory called openssl:
```
cd openssl
./config shared
make
sudo make install
```

### wolfSSL

#### From FIPS Bundle

Use this configure command:
```
./configure --enable-engine
```

This adds support for `--enable-engine=fips-v2` automatically. Replace this with
`--enable-engine=fips-v5` if using a FIPSv5 140-3 bundle. Replace this with
`--enable-engine=fips-ready` if using a FIPS Ready bundle. If your wolfSSL
version doesn't support `--enable-engine`, use this instead:

```
./configure --enable-fips=v2 --enable-opensslcoexist --enable-cmac
--enable-keygen --enable-sha --enable-des3 --enable-aesctr --enable-aesccm
--enable-x963kdf CPPFLAGS="-DHAVE_AES_ECB -DWOLFSSL_AES_DIRECT
-DWC_RSA_NO_PADDING -DWOLFSSL_PUBLIC_MP -DECC_MIN_KEY_SZ=192 -DSha3=wc_Sha3
-DNO_OLD_SHA256_NAMES -DNO_OLD_MD5_NAME"
```

Change `--enable-fips=v2` to `--enable-fips=ready` if using a FIPS Ready bundle.

#### From Git

```
git clone https://github.com/wolfssl/wolfssl.git
cd wolfssl
./autogen.sh
./configure --enable-engine=no-fips
make
sudo make install
```

If your wolfSSL version doesn't support `--enable-engine`, use this instead:

```
./configure --enable-opensslcoexist --enable-cmac --enable-keygen --enable-sha
--enable-des3 --enable-aesctr --enable-aesccm --enable-x963kdf
CPPFLAGS="-DHAVE_AES_ECB -DWOLFSSL_AES_DIRECT -DWC_RSA_NO_PADDING
-DWOLFSSL_PUBLIC_MP -DECC_MIN_KEY_SZ=192 -DWOLFSSL_PSS_LONG_SALT
-DWOLFSSL_PSS_SALT_LEN_DISCOVER"
```

#### Additional Options
- Add `--enable-pwdbased` to the configure commands above if using PKCS#12.
- Add `--enable-debug` to turn on debug logging.

### wolfEngine

```
git clone https://github.com/wolfSSL/wolfEngine.git
cd wolfEngine
./autogen.sh
./configure --with-openssl=/path/to/openssl/installation --with-wolfssl=/path/to
/wolfssl/installation
make
make check
```

`make check` may fail if the OpenSSL or wolfSSL libraries aren't found. In this
case, try `export LD_LIBRARY_PATH=/path/to/openssl/installation/lib:/path/to/
wolfssl/installation/lib:$LD_LIBRARY_PATH` and re-run `make check`.

#### Customizing

* To build wolfEngine in single-threaded mode, add `--enable-singlethreaded` to
the configure command.
* To build wolfEngine with PBES support (used with PKCS #12), add
`--enable-pbe`. Note: wolfSSL must have been configured with
`--enable-pwdbased`.
* To disable support for loading wolfEngine dynamically, add
`--disable-dynamic-engine`.
* To build a static version of wolfEngine, add `--enable-static`.
* To use a custom user_settings.h file to override the defines produced by
`./configure`, add `--enable-usersettings` and place a user_settings.h file with
the defines you want in the include directory. See the root of the project for
an example user_settings.h.
* To build wolfEngine with debug support, add `--enable-debug`. Then, to
activate the debug logging at runtime, your application should send this control
command to wolfEngine (denoted "e" here): `ENGINE_ctrl_cmd(e, "enable_debug", 1,
NULL, NULL, 0)`.
* To build wolfEngine for use with OpenSSH, add `--enable-openssh`.

## Testing on \*nix

### Unit Tests

Run the unit tests with `make check`.

If you get an error like `error while loading shared libraries: libssl.so.3`
then the library cannot be found. Use the `LD_LIBRARY_PATH` environment variable
as described earlier.

### Integration Tests
See the scripts directory for integration tests with other applications (e.g.
OpenSSH, stunnel, etc.).

### Commit Tests

For wolfEngine developers running commit tests, a custom OpenSSL installation
location can be set using the `WOLFENGINE_OPENSSL_INSTALL` environment variable.
When set, wolfEngine commit tests will use the specified OpenSSL installation
path for commit tests, setting the path using
`--with-openssl=WOLFENGINE_OPENSSL_INSTALL` at configure time.

## Windows

Refer to `windows/README.md` for instructions for building wolfEngine using
Visual Studio.

## Examples

Example programs using wolfEngine can be found in the `examples/` subdirectory.

## Need Help?

Please reach out to support@wolfssl.com for technical support. If you're
interested in commercial licensing, FIPS operating environment additions,
consulting services, or other business engagements, please reach out to
facts@wolfssl.com.
