# Changelog

## Unreleased changes

- Support returning types that reference host or state from `init` or `receive`
  entrypoints. The generated code extends lifetimes of the `host` and `ctx`
  sufficiently for it to compile.

## concordium-contracts-common-derive 4.0.1 (2023-10-18)

- Replaced usage of traits in suggestion, such as `&impl HasHost<..>` with the concrete types: `&Host<..>`.

## concordium-contracts-common-derive 4.0.0 (2023-08-21)

- Fix a bug in derivation macros for `Serial`, `Deserial`, `DeserialWithState`
  and `SchemaType` which incorrectly handled the case where the type had `where`
  predicates in its definition.
- Support adding `#[concordium(repr(u))]` for enum types, where `u` is either `u8` or `u16`. Setting this changes the integer serialization used for the variant tags in derive macros such as  `Serial`, `Deserial`, `DeserialWithState` and `SchemaType`.
- Support adding `#[concordium(tag = n)]` for enum variants, where `n` is some unsigned integer literal. Setting this attribute on a variant overrides the tag used in derive macros such as `Serial`, `Deserial`, `DeserialWithState` and `SchemaType`. Note that setting `#[concordium(repr(u*))]` is required when using this attribute.
- Support adding `#[concordium(forward = n)]`, for enum variants, where `n` is either an unsigned integer literal, `cis2_events`, `cis3_events`, `cis4_events` or an array of the same options.
  Setting this attribute on a variant overrides the (de)serialization to flatten with the (de)serialization of the inner field when using derive macros such as `Serial`, `Deserial`, `DeserialWithState` and `SchemaType`.
  Note that setting `#[concordium(repr(u*))]` is required when using this attribute.
- `derive(StateClone)` removed completely, as `StateClone` trait is removed from `concordium-std`

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
