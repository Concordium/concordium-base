# Changelog

## Unreleased changes
  - Change the response format of `validate_request_js`. It now either returns the account address of the intial account (in case of success) or an error.
  - Add a `cs_exports.rs` module that exports the C functions `validate_request_cs` and `create_identity_object_cs` to be used from C#. 
    These take pointers to byte arrays representing JSON and invokes the functions `validate_request` and `create_identity_object` from `lib.rs`.
    The `validate_request_cs` then returns a pointer to a bytearray representing either
      * an account address (in case of validation success), or
      * an error string.
    The `create_identity_object_cs` returns a pointer to a bytearray representing either
      * the JSON serialization of an `IdentityCreation` instance, or
      * an error string. 

## 0.4.0

  - Fix an inadequate check when receiving an identity object request. The
    choiceArHandles value was not adequately checked.
