# Changelog

## Unreleased changes

- Support for querying the module reference and contract name of an instance via
  `invoke` (for protocol version 7). These are enabled by a new
  `support_contract_inspection_queries` parameter in `ReceiveParams` and
  `call_receive_v1`. When enabled, `invoke` can generate the new interrupt
  types `QueryContractModuleReference` and `QueryContractName`.

## concordium-smart-contract-engine 4.0.0 (2024-01-22)

- Add a `branch_statistics` function to get insight into smart contract state
  tree structure.
- Remove `utils::WasmVersion` to instead reexport a similar type from `concordium_contracts_common`.
  This adds `Display`, `Default`, `TryFrom<u8>`, `serde::Serialize` and `serde::Deserialize` for `WasmVersion` and `From<WasmVersion>` for `u8`.
  The associated type `FromStr::Err` changes from `anyhow::Error` to `concordium_contracts_common::WasmVersionParseError`.
  The method `WasmVersin::read` is removed.

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
