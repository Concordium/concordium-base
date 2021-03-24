# Description

This package provides a streamlined API for the identity provider usable from non-Rust languages.
The core of the library is [src/lib.rs](src/lib.rs) file which defines two functions, `validate_request` and `create_identity_object`.
In addition to this we provide `nodejs` exports (optionally) via [src/nodejs_exports.rs](src/nodejs_exports.rs).
These can be enabled/disabled via the feature `nodejs`, which is currently enabled by default.

**If you need to use the identity issuer functionality from a Rust project this is not the library you want.**
In such a case it is much better to use the [../rust-src/id](../rust-src/id) crate directly since it provides support for serialization of all the relevant values.

# Outline of the identity issuance process.

The identity issuance consists of the following steps. The steps done by this library are marked with (*).

1. The wallet makes the request to the identity provider.
2. (*) The identity provider validates the request.
3. The identity provider checks whether an account already exists on the chain.
4. The identity provider does the identity verification process (e.g., taking photos, scans, etc). The output of this
   process should be whatever the identity issuer needs, and a list of attributes that go to the identity object.
5. (*) Create the initial account object that is sent to the chain, the identity object that is returned to the user, and the anonymity revocation record that is kept by the identity provider.
6. Try to create the initial account on the chain.
7. If all the above are successful return the identity object to the user.

# API

The exposed API consists of two functions `validate_request` and `create_identity_object`.

## `validate_request`

This function is designed to be used when the initial request is made by the user to the identity provider.
It will check cryptographic proofs in the request. All arguments are strings that contain JSON encodings of the relevant values.

The arguments are
- `global_context`, the context of (public) cryptographic parameters specific to the chain the identity object is destined for
- `ip_info`, the public keys of the identity provider. This data is also available on the chain the identity object is destined for.
- `ars_infos`, public keys of anonymity revokers the identity provider cooperates with.
- `request`, this is the request that the wallet sends which contains cryptographic values and proofs.

The result is a pair of
- a boolean indicating whether the request is valid. This means that all values are well-formed and cryptographic proofs are valid.
- an account address encoded as a string. This is the address of the initial account that would be created based on the request.

## `create_identity_object`

This creates the identity object, the initial account data, and the anonymity revocation record.

The arguments are
- `ip_info`, the public keys of the identity provider, same as for `validate_request`
- `request`, the same request as for `validate_request`
- `alist`, the attribute list obtained in step (4) of the identity issuance process (see above)
- `expiry`, the expiry time of the account creation message sent to the chain. This is just a unix timestamp that should be set to, e.g., now + 5 min.
- `ip_private_key`, the first part of the private key, used to sign the identity object sent back to the user
- `ip_cdi_private_key`, the second part of the private key, used to sign the initial account creation message.

The return value is either an error if some of the values are malformed, or a triple of Strings containing JSON encoded values.
The three values are

- the identity object that is returned to the user
- the anonymity revocation record
- the initial account creation object that is sent to the chain

Note that the anonymity revocation record only contains the cryptographic parts, the encryptions of data that the anonymity revoker decrypts.
It does not contain contact information for the user. It is the responsibility of the identity provider to maintain that data in addition to the anonymity revocation record.

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

# Javascript API

The library exposes two functions
```javascript
  fn validate_request(ip_info: string, ars_infos: string, request: string): { result: boolean, accountAddress: string } | Error
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
  
## Example
  After following the build instructions you can try to run the script `example.js` as, e.g., 
  ```
  nodejs example.js
  ```

  It should print the output of each of the exposed calls.
  
  The script also illustrates the input formats of the values and whether
  exceptions can or cannot be raised.
