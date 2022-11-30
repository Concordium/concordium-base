# Changelog

## 0.23.0
- Changed parameter_to_json excepted encoding of schema field to be base64.

## 0.22.0
- Support `maxEnergy` in addition to `maxContractExecutionEnergy` in `Update`
  and `Init` payloads in the `create_account_transaction` function.

## 0.21.0
- Added function for proving id statements.

## 0.20.0
- Added a function serialize_token_transfer_parameters to serialize parameters for CIS-2 transfers from JSON.

## 0.19.0
- Added support for V3 schema

## 0.18.0
- Removed the function for converting a serialized account transaction (as bytes) into JSON.
- Removed the function for signing any account transaction.
- Added a function for converting serialized parameters for smart contract updates (as bytes) into JSON.
- Added a function `create_account_transaction` for creating and signing an account transaction.

## 0.17.0
- Added a function for signing any account transaction.
- Added a function for signing a message.
- Added a function for converting a serialized account transaction (as bytes) into JSON.

## 0.16.0
- Updated version of `key_derivation` library to `1.1.0` and started using the index of the identity provider for key derivation.

## 0.15.0
- Added function `generate_recovery_request` for creating identity recovery requests.

## 0.14.0
- Added function `create_id_request_and_private_data_v1` for creating an id request in the version 1 flow, where
  no initial account is created. Furthermore, IdCredSec, PrfKey and blinding randomness are determined determinstically from a seed.
- Added function `create_credential_v1` creating a credential where the signing key, verification key and attribute randomness
  are genereated deterministically from a seed.

## 0.13.0
- Added function `get_identity_keys_and_randomness` for deriving IdCredSec, PrfKey and blinding randomness from a seed.
- Added function `get_account_keys_and_randomness` for deriving signing key, verification key and attribute randomness from a seed.

## 0.12.0
  - JSON serialization of the Rust type `DelegationTarget` has been updated to be consistent with the JSON serialization of the corresponding Haskell type, due to the renaming of L-Pool to passive delegation.

## 0.11.0
  - JSON serialization of the Rust type `DelegationTarget` has been updated to be consistent with the JSON serialization of the corresponding Haskell type.
  - JSON serialization of commission rates have been updated so that now they are given as the actual rate,
    instead of parts per hundred thausands. This means for example that now `0.05` or `5.0e-2` should be used as input
    instead of `5000`.
  - The files `mobile_wallet.h`, `wallet.kt` and `android.rs` has been updated with the functions `generate_baker_keys`,
    `create_configure_baker_transaction` and `create_configure_delegation_transaction`.

## 0.10.0
  - New functions `create_configure_baker_transaction` and `create_configure_delegation_transaction`
    have been added to support the new transaction types `configure baker` and `configure delegation`
    that are introduced in Protocol Version 4.
  - A new function `generate_baker_keys` has been added.

## 0.9.0
   - The functions `create_transfer` and `create_encrypted_transfer` have been extended to support
     the new transfer types, i.e. transfer with memo and encrypted transfer with memo, respectively.
     If the JSON field `memo` is given in the input, `create_transfer` will use the payload for
     transfer with memo, and `create_encrypted_transfer` will use the payload for encrypted transfer
    with memo. If the `memo` is not given in the input, the functions will use the payloads for transfer
    and encrypted transfer, respectively. 

## 0.8.0
   - in the response `create_credential` the field `commitmentsRandomness` is added and
     contains the randomness from commitments used in proofs.
   - the input object of `create_id_request_and_private_data` has an additional optional field `arThreshold`.
     When used it must be at least 1 and no more than the number of anonymity revokers.
     When not used, the functionality is unaffected by this change.

## 0.7.0
   - in the response from `create_credential` the field `accountData` is renamed to
     `accountKeys` and its structure is changed. It is now a dictionary of
     dictionaries to reflect the two-level indexing of keys.
   - the "signatures" response from the transaction making functions is changed to
     reflect the two level indexing of signatures.
   - the `create_credential` function requires an additional field `expiry`, which
     should have the same format and has the same meaning as the `expiry` field
     when creating transactions, i.e., it is a u64 and denotes the number of
     seconds since the unix epoch.
   - the `credential` field object in the response from `create_credential` is modified.
     There is a new field `credentialPublicKeys` and the old field `account` is removed.
   - there is a new field inside the `credential` object in the response from `create_credential`.
     The field is `messageExpiry`, it is mandatory and has type `u64`.
