
## Description

wolfengine is a shared library that can be used as an Engine in OpenSSL.

## Features

Supports the following algorithms:

* SHA-256
* SHA-384
* SHA-512
* AES128-GCM
* AES256-GCM
* ECDSA sign/verify
* EC Key Generation with curve parameter P-256
* ECDH

## Patching OpenSSL

Versions 1.1.1 and below of OpenSSL did not handle AES-GCM through the Engine 
interface.

The only change necessary is to add GCM mode to a switch statement.
For example, for OpenSSL 1.1.1, add the following to `crypto/evp/evp_enc.c` at
line 169:

```
          case EVP_CIPH_STREAM_CIPHER:
+         case EVP_CIPH_GCM_MODE:
          case EVP_CIPH_ECB_MODE:
```

## Building

### Openssl

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
./configure
make
sudo make install
```

### wolfEngine

```
./autogen.sh
./configure
make
```

To build using a different openssl library directory use:

```
./configure LDFLAGS="-L/usr/local/lib64"
make
export LD_LIBRARY_PATH=/usr/local/lib64
make check
```

## Testing

To run automated tests:

* `make test`

If you get an error like `error while loading shared libraries: libssl.so.3` then the library cannot be found. Use the `LD_LIBRARY_PATH` if not using the installed version. Example `export LD_LIBRARY_PATH=/usr/local/lib64`.
