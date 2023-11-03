# Changelog

## Unreleased changes

## concordium-smart-contract-engine 3.1.0 (2023-10-18)

- Add `get_build_info` and `get_build_info_from_skeleton` utility functions for
  extracting build information from a Wasm module.

## concordium-smart-contract-engine 3.0.0 (2023-08-21)

- Functions that process V1 smart contract modules
  (`invoke_receive_*_from_source` and `invoke_init_*_from_source`) are now
  parameterized by a `ValidationConfig` which determines which Wasm features are
  allowed.
- `ReceiveParams` is extended with `support_account_signature_checks` flag, that
  enables or disables two new operations that can be `invoke`d. Querying account
  public keys and checking account signatures.
- `InvokeFailure` is extended with two new variants 
  `SignatureDataMalformed` and `SignatureCheckFailed` that can be triggered as a
  result of checking a signature.

## concordium-smart-contract-engine 2.0.0 (2023-06-16)

- Bump concordium-contracts-common to version 7.

## concordium-smart-contract-engine 1.2.0 (2023-05-08)

- Bump concordium-contracts-common to version 6.

## concordium-smart-contract-engine 1.1.0 (2023-04-12)

- Add `saturating_sub` method to `InterpreterEnergy`.
- Derive `PartialEq`/`Eq` for `Logs` and `InvokeFailure`.

## concordium-smart-contract-engine 1.0.1 (2023-03-20)

- Bump concordium-contracts-common dependency to 5.3.


## concordium-smart-contract-engine 1.0.0 (2023-02-03)

- Initial release.
