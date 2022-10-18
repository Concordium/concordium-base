# Description

This package provides a streamlined API for the identity provider usable from non-Rust languages.
The core of the library is [src/lib.rs](src/lib.rs) file which defines five functions, `validate_request`, `create_identity_object`, `validate_request_v1`, `create_identity_object_v1` and `validate_recovery_request`.
In addition to this we provide `nodejs` and `C#` exports (optionally) via [src/nodejs_exports.rs](src/nodejs_exports.rs) and [src/csharp_exports.rs](src/csharp_exports.rs), respectively.
These can be enabled/disabled via the features `nodejs` and `csharp`, respectively.

**If you need to use the identity issuer functionality from a Rust project this is not the library you want.**
In such a case it is much better to use the [../rust-src/id](../rust-src/id) crate directly since it provides support for serialization of all the relevant values.

# Outline of the identity issuance process.

Two identity issuance flows are supported. The version 0 flow involves the creation of an initial account, the version 1 flow does not.

The version 0 identity issuance flow consists of the following steps. The steps done by this library are marked with (*).

1. The wallet makes the request to the identity provider.
2. (*) The identity provider validates the request.
3. The identity provider checks whether an account already exists on the chain.
4. The identity provider does the identity verification process (e.g., taking photos, scans, etc). The output of this
   process should be whatever the identity issuer needs, and a list of attributes that go to the identity object.
5. (*) Create the initial account object that is sent to the chain, the identity object that is returned to the user, and the anonymity revocation record that is kept by the identity provider.
6. Try to create the initial account on the chain.
7. If all the above are successful return the identity object to the user.

The version 1 identity issuance flow consists of the following steps. The steps done by this library are marked with (*).

1. The wallet makes the request to the identity provider.
2. (*) The identity provider validates the request.
3. The identity provider does the identity verification process (e.g., taking photos, scans, etc). The output of this
   process should be whatever the identity issuer needs, and a list of attributes that go to the identity object.
4. (*) The identity object is returned to the user, and the anonymity revocation record is kept by the identity provider.

# API

The exposed API consists of two functions `validate_request`, `create_identity_object`, `validate_request_v1`, `create_identity_object_v1` and `validate_recovery_request`.

## `validate_request`

This function is designed to be used in the version 0 flow when the initial request is made by the user to the identity provider.
It will check cryptographic proofs in the request. All arguments are strings that contain JSON encodings of the relevant values.

The arguments are
- `global_context`, the context of (public) cryptographic parameters specific to the chain the identity object is destined for
- `ip_info`, the public keys of the identity provider. This data is also available on the chain the identity object is destined for.
- `ars_infos`, public keys of anonymity revokers the identity provider cooperates with.
- `request`, this is the request that the wallet sends which contains cryptographic values and proofs.

In case of success, the return value is
- an account address encoded as a string. This is the address of the initial account that would be created based on the request.
Otherwise, the return value is an error.

## `create_identity_object`

This creates the version 0 identity object, the initial account data, and the anonymity revocation record.

The arguments are
- `ip_info`, the public keys of the identity provider, same as for `validate_request`
- `request`, the same request as for `validate_request`
- `alist`, the attribute list obtained in step (4) of the identity issuance process (see above)
- `expiry`, the expiry time of the account creation message sent to the chain. This is just a unix timestamp that should be set to, e.g., now + 5 min.
- `ip_private_key`, the first part of the private key, used to sign the identity object sent back to the user
- `ip_cdi_private_key`, the second part of the private key, used to sign the initial account creation message.

The return value is either an error if some of the values are malformed, or a struct containing

- the identity object that is returned to the user
- the anonymity revocation record
- the initial account creation object that is sent to the chain
- the address of the inital account

Note that the anonymity revocation record only contains the cryptographic parts, the encryptions of data that the anonymity revoker decrypts.
It does not contain contact information for the user. It is the responsibility of the identity provider to maintain that data in addition to the anonymity revocation record.
## `validate_request_v1`

This function is designed to be used for the version 1 when the initial request is made by the user to the identity provider.
It will check cryptographic proofs in the request. All arguments are strings that contain JSON encodings of the relevant values.

The arguments are
- `global_context`, the context of (public) cryptographic parameters specific to the chain the identity object is destined for
- `ip_info`, the public keys of the identity provider. This data is also available on the chain the identity object is destined for.
- `ars_infos`, public keys of anonymity revokers the identity provider cooperates with.
- `request`, this is the request that the wallet sends which contains cryptographic values and proofs.

In case of success, the return value is the unit type.
Otherwise, the return value is an error.

## `create_identity_object_v1`

This creates the version 1 identity object and the anonymity revocation record.

The arguments are
- `ip_info`, the public keys of the identity provider, same as for `validate_request`
- `request`, the same request as for `validate_request`
- `alist`, the attribute list obtained in step (4) of the identity issuance process (see above)
- `ip_private_key`, the first part of the private key, used to sign the identity object sent back to the user

The return value is either an error if some of the values are malformed, or a struct containing

- the identity object that is returned to the user
- the anonymity revocation record

Note that the anonymity revocation record only contains the cryptographic parts, the encryptions of data that the anonymity revoker decrypts.
It does not contain contact information for the user. It is the responsibility of the identity provider to maintain that data in addition to the anonymity revocation record.

## `validate_recovery_request`

This function validates a recovery request made by the user to the identity provider.
It will check the proof of knowledge of idCredSec in the request. All arguments are strings that contain JSON encodings of the relevant values.

The arguments are
- `global_context`, the context of (public) cryptographic parameters specific to the chain the identity object is destined for
- `ip_info`, the public keys of the identity provider. This data is also available on the chain the identity object is destined for.
- `request`, this is the request that the wallet sends which contains cryptographic values and proofs.

In case of success, the return value is the unit type.
Otherwise, the return value is an error.
# Prerequisites

In order to build you need the following
- the rust compiler, stable toolchain, a recent version. We've tested with
  1.62.
- clang development libraries. On ubuntu these can be installed with 
  ```
  apt install libclang-dev
  ```

# Building
To build the nodejs exports, do
  ```
  cargo build --release --features=nodejs
  ```
- On linux this produces a shared library `libidiss.so` that needs to be
  loaded into a nodejs instance. To do this move/rename the generated shared library
  to `libidiss.node` (the extension is important, the name is not, it just has
  to match the import statement in javascript later on). On Windows it produces
  a `idiss.dll` that (similarly) should be moved and renamed to `libidiss.node`.

To build the csharp exports, do instead
  ```
  cargo build --release --features=csharp
  ```
- On Windows this will produce `idiss.dll`. 

Both will build the library and produce artifacts in `./target/release/`.

# Javascript API

The library exposes the following functions
```javascript
  fn validate_request(global_context: string, ip_info: string, ars_infos: string, request: string): { accountAddress: string } | Error
```
which validates the given request and returns the account address of the initial account if the request is valid,
or an Error otherwise.

```javascript
  fn create_identity_object(ip_info: string, alist: string, request: string, ip_private_key: string, ip_cdi_private_key: string): {idObject: string; arRecord: string, initialAccount: string} | Error
```
which creates the identity object to be sent back to the user, as well as the
anonymity revocation record, and information about the initial account that must
be submitted to the chain. The Error case here can happen if the attribute
list (the `alist` argument) or any other arguments are malformed.

```javascript
  fn validate_request_v1(global_context: string, ip_info: string, ars_infos: string, request: string): undefined | Error
```
which validates the given request and returns undefined when successful, or an
error in case of an invalid request.

```javascript
  fn create_identity_object_v1(ip_info: string, alist: string, request: string, ip_private_key: string): {idObject: string; arRecord: string} | Error
```
which creates the identity object to be sent back to the user, as well as the
anonymity revocation record. The Error case here can happen if the attribute
list (the `alist` argument) or any other arguments are malformed.

```javascript
  fn validate_recovery_request(global_context: string, ip_info: string, request: string): undefined | Error
```
which validates a request for identity recovery, and returns `undefined` in case
of success, or an an `Error` if the request is malformed.
The recovery request has a property `timestamp` which is a unix timestamp in
seconds. The caller of the `validate_recovery_request` **must make sure that the
timestamp is withing 60 of the present**. This is not checked by the
`validate_recovery_request` function, but what is checked is that the claimed
timestamp matches the one in the provided proof.
  
## Example
  After following the build instructions you can try to run the script `example.js` as, e.g., 
  ```
  nodejs example.js
  ```

  It should print the output of each of the exposed calls.
  
  The script also illustrates the input formats of the values and whether
  exceptions can or cannot be raised.


# C# API

The library exposes five functions `validate_request_cs`, `create_identity_object_cs`, `validate_request_v1_cs`, `create_identity_object_v1_cs` and `validate_recovery_request_cs` that can be imported in C# by

```csharp
[DllImport("idiss.dll")]
private static extern IntPtr validate_request_cs(
[MarshalAs(UnmanagedType.LPArray)] byte[] ctx, int ctx_len, 
[MarshalAs(UnmanagedType.LPArray)] byte[] ip_info, int ip_info_len, 
[MarshalAs(UnmanagedType.LPArray)] byte[] ars_infos, int ars_infos_len, 
[MarshalAs(UnmanagedType.LPArray)] byte[] request, int request_len, out int out_length, out int out_success);
```
which validates the given request and returns a pointer to the account address of the initial account if the request is valid,
or a pointer to a bytearray describing an error. It writes to a variable `out_length` the length of the output. If the request is valid,
`1` is written to out_success, otherwise `-1` is written to out_success.

```csharp

[DllImport("idiss.dll")]
private static extern IntPtr create_identity_object_cs(
[MarshalAs(UnmanagedType.LPArray)] byte[] ip_info, int ip_info_len, 
[MarshalAs(UnmanagedType.LPArray)] byte[] request, int request_len, 
[MarshalAs(UnmanagedType.LPArray)] byte[] alist, int alist_len, 
UInt64 expiry,
[MarshalAs(UnmanagedType.LPArray)] byte[] ip_private_key, int ip_private_key_ptr_len,
[MarshalAs(UnmanagedType.LPArray)] byte[] ip_cdi_private_key, int ip_cdi_private_key_ptr_len,
out int out_length, out int out_success);
```
which returns a pointer to either the identity object to be sent back to the user, as well as the
anonymity revocation record, and information about the initial account that must
be submitted to the chain, or a pointer to a bytearray describing an error.
It writes to a variable `out_length` the length of the output. If identity creation went well,
`1` is written to out_success, otherwise `-1` is written to out_success.

```csharp
[DllImport("idiss.dll")]
private static extern IntPtr validate_request_v1_cs([MarshalAs(UnmanagedType.LPArray)] byte[] ctx, int ctx_len,
[MarshalAs(UnmanagedType.LPArray)] byte[] ip_info, int ip_info_len,
[MarshalAs(UnmanagedType.LPArray)] byte[] ars_infos, int ars_infos_len,
[MarshalAs(UnmanagedType.LPArray)] byte[] request, int request_len, out int out_length);
```
which validates the given request and returns a null pointer if the request is valid,
or a pointer to a bytearray describing an error. It writes to a variable `out_length` the length of the output.

```csharp
[DllImport("idiss.dll")]
private static extern IntPtr create_identity_object_v1_cs([MarshalAs(UnmanagedType.LPArray)] byte[] ip_info, int ip_info_len,
[MarshalAs(UnmanagedType.LPArray)] byte[] request, int request_len,
[MarshalAs(UnmanagedType.LPArray)] byte[] alist, int alist_len,
[MarshalAs(UnmanagedType.LPArray)] byte[] ip_private_key, int ip_private_key_ptr_len,
out int out_length, out int out_success);
```

which returns a pointer to either the version 1 identity object to be sent back to the user, as well as the
anonymity revocation record, or a pointer to a bytearray describing an error.
It writes to a variable `out_length` the length of the output. If identity creation went well,
`1` is written to out_success, otherwise `-1` is written to out_success.

```csharp
[DllImport("idiss.dll")]
private static extern IntPtr validate_recovery_request_cs([MarshalAs(UnmanagedType.LPArray)] byte[] ctx, int ctx_len,
[MarshalAs(UnmanagedType.LPArray)] byte[] ip_info, int ip_info_len,
[MarshalAs(UnmanagedType.LPArray)] byte[] request, int request_len, out int out_length);
```

which validates the given recovery request and returns a null pointer if the request is valid,
or a pointer to a bytearray describing an error. It writes to a variable `out_length` the length of the output.
