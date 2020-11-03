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

# API

The library exposes two functions
```javascript
  fn validate_request(ip_info: string, ars_infos: string, request: string): boolean | Error
```
which validates the given request and returns a boolean indicating its validity,
or an Error if an internal error occurred (this indicates something is wrong
with the setup, an Error will never occur due to a malformed request)

```javascript
  fn create_identity_object(ip_info: string, alist: string, request: string, ip_private_key: string, ip_cdi_private_key: string): {idObject: string; arRecord: string, initialAccount: string} | Error
```
which creates the identity object to be sent back to the user, as well as the
anonymity revocation record, and information about the initial account that must
be submitted to the chain. The Error case here can happen if the attribute
list (the `alist` argument) or any other arguments are malformed.
  
# Example
  After following the build instructions you can try to run the script `example.js` as, e.g., 
  ```
  nodejs example.js
  ```

  It should print the output of each of the exposed calls.
  
  The script also illustrates the input formats of the values and whether
  exceptions can or cannot be raised.
