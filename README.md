# crypto

Cryptographic infrastructure 

# How to Build Only C Part

This project can use `CMake` tool for building. You only need to follow next
steps:

```bash
$ crypto > mkdir build
$ crypto > cd build 
$ crypto/build > cmake  ..
$ crypto/build > cmake --build .
```

*NOTE:* If you want to enable `debug` library version, you only need to add
`CMAKE_BUILD_TYPE` parameter:

```bash
$ crypto/build > cmake -DCMAKE_BUILD_TYPE=Debug ..
$ crypto/build > cmake --build .
```

These steps will generate target file `libconcordium-crypto.so.0.1` and some
links in Linux SO.

To install into your system, you will need call as `root` (or administrative
roll):

```bash
$ crypto/build > sudo cmake --build . --target install
```
*NOTE:* In this case we are using `sudo` to get administrative privileges to copy
target library into default prefix `/usr/local/lib/`

# How to Run Unit Test in C Part

As any other `CMake` project, you just need to follow next steps:

```bash
$ crypto/build > ctest 
```

or for a verbose output

```bash
$ crypto/build > ctest --verbose
```

