# Changelog

## Unreleased changes

- Functions that process V1 smart contract modules
  (`invoke_receive_*_from_source` and `invoke_init_*_from_source`) are now
  parameterized by a `ValidationConfig` which determines which Wasm features are
  allowed.


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
