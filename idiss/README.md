# Description

This package provides a WASM export of the API needed by the identity provider.

# Prerequisites

In order to build you need the following
- the rust compiler, stable toolchain, a recent version. We've tested with
  1.45.2 and 1.46.
- clang development libraries. On ubuntu these can be installed with 
  ```
  apt install libclang-dev
  ```

# Building
  ```
  cargo build --relese
  ```
  
  will build the library and produce artifacts in `./target/release/`.
  - On linux this produces a shared library `libidiss.so` that needs to be
    loaded into a nodejs instance. To do this move/rename the generated shared library
    to `libidiss.node` (the extension is important, the name is not, it just has
    to match the import statement in javascript later on)
  
# Example
  After following the build instructions you you can try to run the script `example.js` as, e.g., 
  ```
  nodejs example.js
  ```

  It should print the output of each of the exposed calls.
  
  The script also illustrates the input formats of the values and whether
  exceptions can or cannot be raised.
