# Hash

This is a library which implements various hash functions, including:

* Message-Digest 5 (MD5) algorithm described in [RFC 1321](https://tools.ietf.org/html/rfc1321).
* Secure Hash Algorithm 1 (SHA-1) described in [RFC 3174](https://tools.ietf.org/html/rfc3174).
* Secure Hash Algorithm 2 (SHA-2), which is a set of related hash functions, described in [RFC 4634](https://tools.ietf.org/html/rfc4634).

In addition, the following hash function based algorithms are also included:

* Hash-based Message Authentication Code (HMAC) described in [RFC 2104](https://tools.ietf.org/html/rfc2104).
* Password-Based Key Derivation Function 2 (PBKDF2) described in [RFC 2989](https://tools.ietf.org/html/rfc2898).

## Usage

The `Hash` functions are used to compute digests of messages.  Each hash function differs in the actual algorithm, digest size, block size, and other characteristics.  The hash functions can be used to compute the digest of either a string or vector of data.

## Supported platforms / recommended toolchains

This is a portable C++11 library which depends only on the C++11 compiler and standard library, so it should be supported on almost any platform.  The following are recommended toolchains for popular platforms.

* Windows -- [Visual Studio](https://www.visualstudio.com/) (Microsoft Visual C++)
* Linux -- clang or gcc
* MacOS -- Xcode (clang)

## Building

This library is not intended to stand alone.  It is intended to be included in a larger solution which uses [CMake](https://cmake.org/) to generate the build system and build applications which will link with the library.

There are two distinct steps in the build process:

1. Generation of the build system, using CMake
2. Compiling, linking, etc., using CMake-compatible toolchain

### Prerequisites

* [CMake](https://cmake.org/) version 3.8 or newer
* C++11 toolchain compatible with CMake for your development platform (e.g. [Visual Studio](https://www.visualstudio.com/) on Windows)

### Build system generation

Generate the build system using [CMake](https://cmake.org/) from the solution root.  For example:

```bash
mkdir build
cd build
cmake -G "Visual Studio 15 2017" -A "x64" ..
```

### Compiling, linking, et cetera

Either use [CMake](https://cmake.org/) or your toolchain's IDE to build.
For [CMake](https://cmake.org/):

```bash
cd build
cmake --build . --config Release
```
