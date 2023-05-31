# Changelog

## Unreleased changes

- Set minimum Rust version to 1.65.

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
