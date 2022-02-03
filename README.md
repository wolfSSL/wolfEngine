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

This adds support for `fips=v2` automatically. Replace this will `--enable-engine=fips-ready` if using a FIPS Ready bundle.

#### From Git

```
git clone https://github.com/wolfssl/wolfssl.git
cd wolfssl
./autogen.sh
./configure --enable-engine=no-fips
make
sudo make install
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

## Building on Windows

The `wolfEngine.sln` solution supplied in the root of the wolfEngine project 
expects the following directory structure:

```
.
├── openssl
├── wolfEngine
└── wolfssl
```

### OpenSSL

Follow the instructions in the OpenSSL `INSTALL` file. The list of commands to
run are:
```
    $ perl Configure { VC-WIN32 | VC-WIN64A | VC-WIN64I | VC-CE }
    $ nmake clean # This command needs to be run if OpenSSL has previously been
    built in this directory with a different configuration.
    $ nmake
```

### wolfSSL

Compile wolfSSL using one of the solution projects available in the 
project (`wolfssl.sln` or `wolfssl64.sln`). The following is a list of defines 
that are generated when using the configure script. You do not need to turn all
of them on but this list will provide full functionality. For ease of use, it is
recommended to add the desired defines to the `user_settings.h` file used in
the chosen wolfSSL Visual Studio solution. Please make sure to update the
defines in the wolfEngine `user_settings.h` file to match the defines used to
compile wolfSSL.

```
/* Settings generated by the configure script when compiling for wolfEngine */
#define HAVE_AES_ECB
#define WC_RSA_NO_PADDING
#define WOLFSSL_PUBLIC_MP
#define ECC_MIN_KEY_SZ 192
#define WOLFSSL_PSS_LONG_SALT
#define WOLFSSL_PSS_SALT_LEN_DISCOVER
#define WOLFSSL_TLS13
#define HAVE_TLS_EXTENSIONS
#define HAVE_SUPPORTED_CURVES
#define HAVE_FFDHE_2048
#define HAVE_THREAD_LS
#define TFM_TIMING_RESISTANT
#define ECC_TIMING_RESISTANT
#define WC_RSA_BLINDING
#define HAVE_AESCCM
#define WOLFSSL_AES_COUNTER
#define WOLFSSL_AES_DIRECT
#define WOLFSSL_SHA224
#define WOLFSSL_SHA512
#define WOLFSSL_SHA384
#define WOLFSSL_KEY_GEN
#define HAVE_HKDF
#define HAVE_X963_KDF
#define NO_DSA
#define HAVE_ECC
#define TFM_ECC256
#define ECC_SHAMIR
#define WC_RSA_PSS
#define WOLFSSL_BASE64_ENCODE
#define NO_RC4
#define WOLFSSL_CMAC
#define NO_HC128
#define NO_RABBIT
#define WOLFSSL_SHA3
#define WOLFSSL_SHAKE256
#define HAVE_POLY1305
#define HAVE_ONE_TIME_AUTH
#define HAVE_CHACHA
#define HAVE_HASHDRBG
#define HAVE_EXTENDED_MASTER
#define HAVE_ENCRYPT_THEN_MAC
#define NO_PSK
#define NO_MD4
#define NO_PWDBASED
#define USE_FAST_MATH
#define WC_NO_ASYNC_THREADING
#define HAVE_DH_DEFAULT_PARAMS
#define GCM_TABLE_4BIT
#define HAVE_AESGCM
#define HAVE_WC_INTROSPECTION
#define OPENSSL_COEXIST
#define NO_OLD_RNGNAME
#define NO_OLD_WC_NAMES
#define NO_OLD_SSL_NAMES
#define NO_OLD_SHA_NAMES
#define NO_OLD_MD5_NAME
```

### wolfEngine

It is enough to compile the wolfEngine solution to generate the DLL file. 
Please make sure that you have updated the `user_settings.h` header to match 
the defines used to compile wolfSSL. The `test` project in the wolfEngine 
solution compiles an executable file that is dynamically linked to the 
wolfEngine and OpenSSL libraries. The `test` solution copies the OpenSSL DLL 
files into the output directory. If you want to skip this step and use system
supplied versions of OpenSSL, delete the command under:

```
test Properties -> Configuration Properties -> Build Events -> Post-Build Event
-> Command Line
```

## Examples

Example programs using wolfEngine can be found in the `examples/` subdirectory.

## Need Help?

Please reach out to support@wolfssl.com for technical support. If you're
interested in commercial licensing, FIPS operating environment additions,
consulting services, or other business engagements, please reach out to
facts@wolfssl.com.
