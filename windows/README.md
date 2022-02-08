# Building on Windows

wolfEngine has Visual Studio support for both FIPS 140-2 and non-FIPS builds.
Both expect the following directory structure:

```
.
├── openssl
├── wolfEngine
└── wolfssl
```

## OpenSSL

Follow the instructions in the OpenSSL `INSTALL` file. The list of commands to
run are:

```
    $ perl Configure { VC-WIN32 | VC-WIN64A | VC-WIN64I | VC-CE }
    $ nmake clean # This command needs to be run if OpenSSL has previously been
    built in this directory with a different configuration.
    $ nmake
```

## wolfSSL

You should select the same configuration and platform combination that you plan
to use with wolfEngine (e.g. if you're going to build Debug|x64 for wolfEngine,
you should build the same for wolfSSL).

### FIPS 140-2

First, replace the contents of `IDE\WIN10\user_settings.h` in wolfSSL with the
contents of `windows\fips_140_2\user_settings.h` from wolfEngine. Then, compile
wolfSSL using `IDE\WIN10\wolfssl-fips.sln`.

### FIPS Ready

First, replace the contents of `IDE\WIN10\user_settings.h` in wolfSSL with the
contents of `windows\fips_ready\user_settings.h` from wolfEngine. Then, compile
wolfSSL using `IDE\WIN10\wolfssl-fips.sln`.

### Non-FIPS

First, replace the contents of `IDE\WIN\user_settings.h` in wolfSSL with the
contents of `windows\non_fips\user_settings.h` from wolfEngine. Then, compile
wolfSSL using `wolfssl64.sln`.

## wolfEngine

As mentioned above, first ensure that your configuration and platform match what
you just built for wolfSSL. Note that even if you do a "static" build (i.e. you
build both wolfSSL and wolfEngine as static libraries), wolfEngine will still
use OpenSSL as a dynamic library (DLL). To this end, the wolfEngine "test"
project copies the OpenSSL DLL into the test output directory. If you want to
skip this step and use system supplied versions of OpenSSL, delete the OpenSSL
DLL copy command under the test project's properties:

```
Properties -> Configuration Properties -> Build Events -> Post-Build Event ->
Command Line
```

There is currently no official support for using OpenSSL as a static library
with wolfEngine.

#### FIPS 140-2

Build wolfEngine using `windows\fips_140_2\wolfEngine.sln`. Run the test suite
by right-clicking on the "test" project in the Solution Explorer > Debug > Start
New instance. You are likely to encounter this error message:

```
in FIPS callback, ok = 0, err = -203
message = In Core Integrity check FIPS error
hash = 550122FD59F12AFA94F1B0D95AB361FF03E3EB8708C68974C36D6571524B675C
In core integrity hash check failure, copy above hash
into verifyCore[] in wolfSSL's (NOT wolfEngine) fips_test.c and rebuild
ERR: Failed to find engine!
```

Part of wolfSSL's FIPS self-test is an integrity check of the FIPS module. At
startup, the self-test computes an HMAC of the code and read-only data of the
FIPS module and compares the result to an expected value compiled into the
library. If these don't match, the FIPS module enters an error state and cannot
be used. The wolfEngine test program will print the above error message in this
case. If this happens, you should take the hash value printed out and replace
the `verifyCore` value wolfSSL's `wolfcrypt\src\fips_test.c` with it. Rebuild
wolfSSL, rebuild wolfEngine, and run the wolfEngine tests again. The integrity
check should pass this time.

#### FIPS Ready

Build wolfEngine using `windows\fips_ready\wolfEngine.sln`. Run the test suite
by right-clicking on the "test" project in the Solution Explorer > Debug > Start
New instance. The FIPS self-test notes above for FIPS 140-2 apply to FIPS Ready,
too, so you will need to update the expected hash value accordingly.

#### Non-FIPS

Build wolfEngine using `windows\non_fips\wolfEngine.sln`. Run the test suite by
right-clicking on the "test" project in the Solution Explorer > Debug > Start
New instance.
