# Description

This package provides a WASM export of the API needed by the identity provider.

# Prerequisites

In order to build you need the following
- the rust compiler, stable toolchain
- wasm32 target for rust. This is easiest to install with the `rustup` tool as 
  ```
  rustup target add wasm32-unknown-unknown
  ```
- wasm-pack, see https://rustwasm.github.io/wasm-pack/installer/

# Building
  In order to build you should first build the `wasm` libraries via cargo as
  ```
  cargo build --release
  ```

  The default target is set to `wasm32-unknown-unknown` in
  [./cargo/config](./cargo/config), the full invocation otherwise would be
   ```
   cargo build --target=wasm32-unknown-unknown
   ```

  After that you should run the `wasm-pack` tool to prepare the generated code
  for inclusion into your project. Here we assume that the code is going to be
  used from `nodejs`, in which case you should run
  
  ```
  wasm-pack build --target nodejs --release
  ```
  
  This will generate a package inside `pkg` subdirectory of the current
  directory.
  
# Example
  After building you can try to run the script `example.js` as, e.g., 
  ```
  nodejs example.js
  ```

  It should print the output of each of the exposed calls.
  
  The script also illustrates the input formats of the values and whether
  exceptions can or cannot be raised.
  
# Typescript
  Running the `wasm-pack` tool also generates a file `idiss.d.ts` which contains
  the typescript types of the exposed functions.

# Changes

The changes from the previous version are in the way identity providers and
anonymity revokers are handled. Concretely this means that `validate_request`
requires an additional argument with a list of anonymity revokers supported by
the chain, and the identity provider.
