# Changelog

## Unreleased changes

## concordium-contracts-common-derive 3.0.0 (2023-06-16)

- Set minimum Rust version to 1.65.
- Add derive macros for `Reject`, `DeserialWithState`, `SchemaType`, `StateClone` and `Deletable` from `concordium_std_derive`.
- Add attribute macros `init`, `receive`, `concordium_test`, `concordium_cfg_test`, `concordium_cfg_not_test` and `concordium_quickcheck` from `concordium_std_derive` with their related features `wasm-test`, `build-schema` and `concordium-quickcheck`.
- Deriving `Serial`, `Deserial`, `DeserialWithState` and `SchemaType` now produces an implementation which adds a bound to each of the type parameters to implement the relevant trait.
  Note that `Serial` and `DeserialWithState` skips this bound for `state_parameter` when/if this is provided. This is not the behavior of `Deserial` and `SchemaType` since they are incompatible with `DeserialWithState` and therefore `state_parameter` is never present in these cases.
- Deriving `SchemaType` will now produce an implementation even without the `build-schema` feature being enabled.
- Support adding attribute `#[concordium(transparent)]` to newtype structs causing a derived `SchemaType` to use the implementation of the single field and thereby hiding the newtype struct in the schema.
- Fix error message for deriving `Deserial` and `DeserialWithState`, for types with an invalid field attribute.

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
