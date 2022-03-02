# Building on Windows

wolfEngine has Visual Studio support for FIPS 140-2, FIPS Ready, and non-FIPS
builds. All expect the following directory structure:

```
.
├── openssl
├── wolfEngine
└── wolfssl
```

The build will not work unless the directories are named as above.

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

The wolfSSL FIPS module performs an integrity check over the code and read only
data contents of itself during the FIPS self-test. This requires that the
module be assembled in a specific order, with the object files wolfcrypt_first.o
and wolfcrypt_last.o marking the beginning and end of the FIPS module,
respectively. The only way we have found to reliably ensure this ordering on
Windows is by building wolfSSL as a DLL. As such, even static builds of
wolfEngine (i.e. the "Debug" and "Release" configurations) will use wolfSSL as a
DLL. All wolfEngine Visual Studio configurations also use OpenSSL as a DLL.

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

The wolfEngine "test" project copies the OpenSSL and wolfSSL DLLs into the test
output directory. If you want to skip the OpenSSL step and use system supplied
versions of OpenSSL, delete the OpenSSL DLL copy command under the test
project's properties:

```
Properties -> Configuration Properties -> Build Events -> Post-Build Event ->
Command Line
```

There is currently no official support for using OpenSSL as a static library
with wolfEngine.

### FIPS 140-2

Build wolfEngine using `windows\wolfEngine.sln`. Select one of the 4 FIPS 140-2
configurations (e.g. DLL Debug FIPS 140-2). Run the test suite by right-clicking
on the "test" project in the Solution Explorer > Debug > Start New Instance. You
are likely to encounter this error message:

```
in FIPS callback, ok = 0, err = -203
message = In Core Integrity check FIPS error
hash = 550122FD59F12AFA94F1B0D95AB361FF03E3EB8708C68974C36D6571524B675C
In core integrity hash check failure, copy above hash
into verifyCore[] in wolfSSL's (NOT wolfEngine) fips_test.c and rebuild
ERR: Failed to find engine!
```

As mentioned earlier, part of wolfSSL's FIPS self-test is an integrity check
of the FIPS module. At startup, the self-test computes an HMAC of the code and
read-only data of the FIPS module and compares the result to an expected value
compiled into the library. If these don't match, the FIPS module enters an error
state and cannot be used. The wolfEngine test program will print the above error
message in this case. If this happens, you should take the hash value printed
out and replace the `verifyCore` value in wolfSSL's `wolfcrypt\src\fips_test.c`
with it. Rebuild wolfSSL, rebuild wolfEngine, and run the wolfEngine tests
again. The integrity check should pass this time.

### FIPS Ready

Build wolfEngine using `windows\wolfEngine.sln`. Select one of the 4 FIPS Ready
configurations (e.g. DLL Debug FIPS Ready). Run the test suite by right-clicking
on the "test" project in the Solution Explorer > Debug > Start New Instance. The
FIPS self-test noted above for FIPS 140-2 applies to FIPS Ready, too, so you
will need to update the expected hash value accordingly.

### Non-FIPS

Build wolfEngine using `windows\wolfEngine.sln`. Select one of the 4 non-FIPS
configurations (e.g. DLL Debug Non-FIPS) Run the test suite by right-clicking on
the "test" project in the Solution Explorer > Debug > Start New Instance.

# Development

The build options for the various configurations are all held in property sheets
in the `windows\props\` directory. If you need to add a new build option (e.g.
a macro or compiler option), you should add it to the most general property
sheet possible. For example, if you are adding a compiler option that should be
applied to all debug configurations, add it to debug.props. If you are adding a
macro that should only be applied when building the test project with wolfSSL
FIPS (Ready or 140-2) and a debug configuration, add it to
debug_fips_test.props. Do NOT add properties directly to wolfEngine.vcxproj or
test.vcxproj unless absolutely necessary, but this will likely never be the
case.
