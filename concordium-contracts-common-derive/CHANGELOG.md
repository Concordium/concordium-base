# Changelog

## Unreleased changes

- Set minimum Rust version to 1.65.
- Add derive macros for `Reject`, `DeserialWithState`, `SchemaType`, `StateClone` and `Deletable` from `concordium_std_derive`.
- Add attribute macros `init`, `receive`, `concordium_test`, `concordium_cfg_test`, `concordium_cfg_not_test` and `concordium_quickcheck` from `concordium_std_derive` with their related features `wasm-test`, `build-schema` and `concordium-quickcheck`.

## concordium-contracts-common-derive 2.0.0 (2023-05-08)

- Set minimum Rust version to 1.60.
- Set Rust edition to 2021.
- Remove the `sdk` feature.
  - Migrate by adding `use concordium_rust_sdk::types::smart_contracts::concordium_contracts_common as concordium_std;`
    in the files where you derive `Serial` or `Deserial` with the help from this crate.

## concordium-contracts-common-derive 1.0.1 (2022-08-24)

- Fix metadata links.

## concordium-contracts-common-derive 1.0.0 (2022-08-04)

- Initial release moving derive macros from concordium-std.
