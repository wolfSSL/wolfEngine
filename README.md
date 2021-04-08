
## Description

wolfEngine is a library that can be used as an Engine in OpenSSL.

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

### OpenSSL Version Caveats

* SHA-3 support is only available with OpenSSL versions 1.1.1+.
* EC_KEY_METHOD is only available with OpenSSL versions 1.1.1+.

Versions 1.1.1 and below of OpenSSL did not handle AES-GCM/CCM through the Engine interface.

The only change necessary is to add GCM/CCM mode to a switch statement.
For example, for OpenSSL 1.1.1, add the following to crypto/evp/evp_enc.c at line 188:

```
          switch (EVP_CIPHER_CTX_mode(ctx)) {
          ...

+         case EVP_CIPH_GCM_MODE:
+         case EVP_CIPH_CCM_MODE:
          case EVP_CIPH_CTR_MODE:
              ctx->num = 0;
              /* Don't reuse IV for CTR mode */
          ...
```

To get CBC cipher suites working in OpensSL 1.1.1, modify ssl/record/ssl3_record.c at 1125:

```

+        if ((EVP_CIPHER_mode(enc) != EVP_CIPH_GCM_MODE) &&
+            (EVP_CIPHER_mode(enc) != EVP_CIPH_CCM_MODE)) {
+            EVP_CIPHER_CTX_set_padding(ds, 0);
+        }
         /* TODO(size_t): Convert this call */
```

## Building

### OpenSSL

```
git clone https://github.com/openssl/openssl.git
cd openssl
./config no-fips
make
sudo make install
```

### wolfSSL

```
git clone https://github.com/wolfssl/wolfssl.git
cd wolfssl
./autogen.sh
./configure --enable-cmac --enable-keygen --enable-sha --enable-des3 --enable-aesctr --enable-aesccm CPPFLAGS="-DHAVE_AES_ECB -DWOLFSSL_AES_DIRECT -DWC_RSA_NO_PADDING -DWOLFSSL_PUBLIC_MP"
make
sudo make install
```

Add `--enable-fips=v2` to the configure command above if building from a FIPS bundle and not the git repository.

### wolfEngine

```
./autogen.sh
./configure
make
```

To build using a different OpenSSL installation directory (e.g. one at /usr/local/ssl) use:

```
./configure --with-openssl=/usr/local/ssl
make
export LD_LIBRARY_PATH=/usr/local/ssl/lib
make check
```

* To build wolfEngine in single-threaded mode, add `--enable-singlethreaded` to the configure command.
* AES-GCM is disabled by default because of the code changes required to OpenSSL. To enable it, add `--enable-aesgcm`.
* AES-CCM is disabled by default for the same reason. To enable it, add `--enable-aesccm`.
* To disable support for loading wolfEngine dynamically, add `--disable-dynamic-engine`.
* To build a static version of wolfEngine, add `--enable-static`.
* To use a custom user_settings.h file to override the defines produced by `./configure`, add `--enable-usersettings` and place a user_settings.h file with the defines you want in the include directory. See the root of the project for an example user_settings.h.
* To build wolfEngine with debug support, add `--enable-debug`. Then, to activate the debug logging at runtime, your application should send this control command to wolfEngine (denoted "e" here): `ENGINE_ctrl_cmd(e, "enable_debug", 1, NULL, NULL, 0)`.

## Testing

### Unit Tests
To run automated unit tests:

* `make test`

If you get an error like `error while loading shared libraries: libssl.so.3` then the library cannot be found. Use the `LD_LIBRARY_PATH` environment variable as described in the section above.

### Integration Tests
There are no automated integration tests, yet.
