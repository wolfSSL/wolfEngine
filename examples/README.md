# wolfEngine Examples

This directory contains example programs using wolfEngine on Linux. See below for more on each. Each program is also documented in its source code.

## Setting up wolfEngine

See README.md in the root source code directory for instructions on building wolfEngine. Configure wolfEngine with `--enable-debug` (or `-DWOLFENGINE_DEBUG` if not using the configure script) to see debug output from wolfEngine during execution.

## Building

To compile an example, run

```
gcc -I <path to openssl include dir> -L <path to openssl lib dir> <example .c file> -o example -lcrypto -g3 -O0
```

Replacing the <> placeholders with values appropriate to your system. Then, run it with

```
LD_LIBRARY_PATH=/path/to/openssl/lib ./example
```

## Examples

### conf_example.c

This example shows how to set up an application to use wolfEngine using a configuration file. The user must set the `OPENSSL_CONF` environment variable to their configuration file for this to work. See engine.conf in the directory above for an example configuration file. Make sure the configuration file has `enable_debug = 1` to produce debug messages.

### engine_by_id_example.c

This example shows how to set up an application to use wolfEngine without a configuration file, using the `ENGINE_by_id` OpenSSL function. The user must set the `OPENSSL_ENGINES` environment variable to the directory containing `libwolfengine.so` for this to work.
