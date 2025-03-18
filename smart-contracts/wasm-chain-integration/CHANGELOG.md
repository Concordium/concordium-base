# Changelog

## concordium-smart-contract-engine 6.1.0 (2025-03-18)

- Removed `TestResult` and `run_module_tests` since they will be moved to `cargo-concordium`. As part of this `TestHost.rng_used` has been made public.
- Support more smart contract host-functions in `TestHost` (used by cargo concordium test):
    - `get_slot_time`
    - `get_receive_self_address`
    - `get_receive_self_balance`
    - `get_parameter_size`
    - `get_parameter_section`
    - `get_init_origin`
    - `get_receive_invoker`
    - `get_receive_sender`
    - `get_receive_owner`
    - `get_receive_entrypoint`
    - `get_receive_entrypoint_size`
    - `verify_ed25519_signature`
    - `verify_ecdsa_secp256k1_signature`
    - `hash_sha2_256`
    - `hash_sha3_256`
    - `hash_keccak_256`
  Corresponding new host functions are introduced just for `TestHost` allowing for setting the result of the above:
    - `set_slot_time`
    - `set_receive_self_address`
    - `set_receive_self_balance`
    - `set_parameter`
    - `set_init_origin`
    - `set_receive_invoker`
    - `set_receive_sender`
    - `set_receive_owner`
    - `set_receive_entrypoint`
  Attempting to get a value before setting it will result in a runtime error.
  The following getters are also created just for the `TestHost`:
    - `get_event`
    - `get_event_size`

## concordium-smart-contract-engine 6.0.0 (2024-09-09)

- Bump `concordium-wasm` to version 5 used by Concordium node version 7.0.0.
  - Changes Wasm to `Artifact` compilation, meaning already compiled `Artifacts` will need to be recompiled.
  - Introduces a new version of cost assignment used in Concordium Protocol Version 7.
- Loose the minor version for `concordium-contracts-common` dependency.

## concordium-smart-contract-engine 5.0.0 (2024-03-25)

- `TestHost` no longer implements the `ValidateImportExport` trait, instead use `NoDuplicateImport` struct.
- `TestHost::new` now takes an instance state, allowing for support of host functions related to the smart contract key-value state.
- The function `utils::run_module_tests` now provides an empty in-memory instance state for each test case, allowing module tests to use host functions related to the smart contract key-value state.
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
