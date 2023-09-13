# Changelog

## Unreleased changes

## concordium-contracts-common 8.0.0 (2023-08-21)

- Add signature and key types to `concordium-contracts-common`.
- Add `Display` trait to `VersionedModuleSchema` to display the `VersionedModuleSchema` as a JSON template.
- Add `Display` trait to `SchemaType` to display the `SchemaType` as a JSON template.
- Add associated function `from_base64_str` to `VersionedModuleSchema` to easily parse from base64
- Add `NonZeroThresholdU8`, and derived `AccountThreshold` and `SignatureThreshold` types.
- Bump version of `concordium-contracts-common-derive` to 4.

## concordium-contracts-common 7.0.0 (2023-06-16)

- Implement `serde::Serialize` and `serde::Deserialize` for `Duration` using
  `FromStr` and `Display` implementations, when feature `derive-serde` is
  enabled.
- Implement Serialize any `HashBytes<Purpose>` over any `Purpose`.
- Add `TryFrom` implementation to convert `Timestamp` to `chrono::DateTime`.
- Add a `Serial` implementation for any `&A` if `A: Serial`.
- Set minimum Rust version to 1.65.
- Add `smart-contract` feature to enable the macros which are only suitable for smart contract development using `concordium-std`. The feature is not enabled by default.
- Add macros `Reject`, `DeserialWithState`, `SchemaType`, `StateClone` and `Deletable`, `init`, `receive`, `concordium_test`, `concordium_cfg_test`, `concordium_cfg_not_test` and `concordium_quickcheck` from `concordium_std_derive` with their related features `wasm-test`, `build-schema` and `concordium-quickcheck`.

### Breaking changes
- Add a new error type `ToJsonError`, which is returned when deserializing a schema type fails.
- Add the member `JsonError::TraceError` to `JsonError`, which has trace information for the error produced when serializing a schema type fails.

## concordium-contracts-common 6.0.0 (2023-05-08)

- Remove the `Copy` requirement for deserialization of BTreeMap and BTreeSet.
  This allows using non-copyable (and non-clonable) types as map keys or set
  values.
- Add the method `serial_for_smart_contracts` to `OwnedPolicy`, which serializes the policy for easy consumption by smart contracts.
- Set minimum Rust version to 1.60.
- Set Rust edition to 2021.
- Remove the `sdk` feature.
  - Migrate by adding `use concordium_rust_sdk::types::smart_contracts::concordium_contracts_common as concordium_std;`
    in the files where you derive `Serial` or `Deserial` with the help from this crate.

## concordium-contracts-common 5.3.1 (2023-04-12)

- Fix schema JSON deserialization of negative signed numbers.
- Add `PartialEq` implementations for comparing `ReceiveName`, `ContractName`, and
  `EntrypointName` and their owned variants to `str`.

## concordium-contracts-common 5.3.0 (2023-03-16)

- Add `Display` implementation for `OwnedParameter` and `Parameter`, which uses
  hex encoding.
- Replace `From<Vec<u8>>` instance for `OwnedParameter`/`Parameter` with a `TryFrom`,
  which ensures a valid length, and the unchecked method `new_unchecked`.
  - Migrate from `From`/`Into`: Use `new_unchecked` instead (if known to be
    valid length).
- Make inner field in `OwnedParameter`/`Parameter` private, but add a `From`
  implementation for getting the raw bytes.
  - Migrate from `parameter.0`: use `parameter.into()` instead (for both of the affected
    types).
- For `ModuleReference`, replace `AsRef<[u8;32]>` with `AsRef<[u8]>` and make
  inner `bytes` public.
  - The change was necessary for internal reasons.
  - Migrate from `module_reference.as_ref()`: use `&module_reference.bytes` instead.
- Replace `OwnedParameter::new` with `OwnedParameter::from_serial`, which also
  ensures a valid length.
  - Migrate from `new(x)`: Use `from_serial(x).unwrap()` (if known to be valid length).
- Add an `empty` method for both `OwnedParameter` and `Parameter`.
- Implement `Default` for `Parameter`.
- Move `AccountBalance` from concordium-std.
- Add `to_owned` method to `EntrypointName` and `ContractName` types.
- Implement `Serial`/`Deserial` instances for tuples with 4, 5, and 6 elements.
- Add `checked_sub` to Amount type.

## concordium-contracts-common 5.2.0 (2023-02-08)

- Add methods `serial_value` and `serial_value_into` on the `Type`.
  They are more ergonomic to use than `write_bytes_from_json_schema_type` which
  is marked as deprecated and will be removed in future versions.
- Fix schema's `to_json` for contract addresses to that it outputs a value in
  the correct `{"index": ..., "subindex": ...}` format.
- Add `Display` implementations for `ContractName`, `ReceiveName`, and their
  owned variants.

## concordium-contracts-common 5.1.0 (2022-12-14)

- Implement `quickcheck::Arbitrary` for `Timestamp`, `AccountAddress`, `ContractAddress`, `Address`,  `ChainMetadata`, `AttributeTag`, `AttributeValue` and `OwnedPolicy`.

## concordium-contracts-common 5.0.0 (2022-11-21)

- Add support for smart contract V3 schemas.
- Add type `ModuleReference` representing a module reference.
- Implement `SchemaType` for `OwnedEntrypointName` and `OwnedParameter`.
- Add type `ExchangeRate` representing an exchange rate between two quantities.
- Make the following functions `const`: `Duration::from_millis`, `Duration::from_seconds`, `Duration::from_minutes`, `Duration::from_hours` and `Duration::from_days`.
- Add `is_account` and `is_contract` methods to the `Address` type.
- When deserializing according to `Enum` schema type, variant indices were
  erroneously parsed as `u32` when more than 256 enum variants are specified.
  These are now parsed as `u16` as intended.

## concordium-contracts-common 4.0.0 (2022-08-24)

- Add type aliases for `ContractIndex` and `ContractSubIndex`.
- Add `micro_ccd` getter for `Amount`.
- Add `AccountAddress::get_alias` function for finding account aliases.
- Implement converters to string for `ContractName`, `OwnedContractName` and a `serde` implementation when `derive-serde` is enabled.
- Implement `Ord` for `OwnedReceiveName`.
- Change the `serde` implementation for `Address` to use `AddressAccount` and `AddressContract` for the tag, matching the one used by Concordium Node.
- Make `AccountAddressParseError` public when `derive-serde` is enabled.
- Implement `Display` and `FromStr` for `ContractAddress` when `derive-serde` is enabled. The formatting is `<index, subindex>`, E.g `<145,0>` .
- Implement `Display` and `FromStr` for `Address` when `derive-serde` is enabled. The latter attempts to parse a contract address. If this fails it will attempt to parse an `AccountAddress`.
- Implement `FromStr` for `OwnedReceiveName`.
- Add `cursor_position` method to the `Seek` trait.
- Rework attribute values types (breaking change)
  - Change `AttributeValue` from a slice to a struct.
  - Remove `OwnedAttributeValue` type.
- Add support for smart contract v2 schemas.

## concordium-contracts-common 3.1.0 (2022-08-04)

- Extend schema type with `ULeb128`, `ILeb128`, `ByteList` and `ByteArray`.
  - `ULeb128` and `ILeb128` allow for integers of arbitrary size and are represented in JSON as a string containing the integer.
  - `ByteList` and `ByteArray` are byte specialized versions of `List` and `Array` and are represented in JSON as lowercase hex encoded strings.
- Add new schema version which include the versioning in the serialization.
- Use `schema::Type::ByteList` for `[u8]` implementation of `SchemaType`.
- Introduce `HasSize` trait.
- Implement `Seek` for `Cursor<T>` when `T` implements `HasSize`.
- Add traits `Serial`, `Deserial`, `SerialCtx` and `DeserialCtx`.
- Add procedural macros for deriving `Serial` and `Deserial`.
- Implement `std::error:Error` for error types, when `std` feature is enabled.

## concordium-contracts-common 3.0.0 (2022-05-17)

- Introduce Entrypoint and Parameter types, and their owned versions.
- Add a new schema version for V1 smart contracts.
  This adds schema for return values of init and receive functions, and removes the state schema.
- `get_chain_name`, `get_name_parts` have been moved from `OwnedReceiveName` to
  `ReceiveName`. The method `get_func_name` of `OwnedReceiveName` became
  `get_entrypoint_name` of `ReceiveName`.

## concordium-contracts-common 2.0.0 (2022-01-05)

- Update references to token to match token name (CCD).

## concordium-contracts-common 1.0.1 (2021-10-08)
- Fix deserialization of arrays.

## concordium-contracts-common 1.0.0 (2021-10-05)
- Add public validation functions to contract and receive names.
- Add new cases for NewContractNameError and NewReceiveNameError.
- Remove the needless reference in `to_owned` and `get_chain_name` methods.
- Implement `SchemaType` for `Address`.
- Derive `PartialOrd` and `Ord` for `ContractAddress` and `Address`.
- Derive `Hash` for `Amount`, `Timestamp`, `Duration`, `AccountAddress`, `ContractAddress`, `Address`, `ContractName`, `OwnedContractName`, `ReceiveName` and `OwnedReceiveName`.
- Add `HashMap` and `HashSet` from the `hashbrown` crate to support `no-std`.
- Make `HashMap` and `HashSet` default to the `fnv` hasher.
- Add functions for serializing and deserializing `HashMap` and `HashSet` without the length (`serial_hashmap_no_length`, `deserial_hashmap_no_length`, `deserial_hashset_no_length`, `deserial_hashset_no_length`).
- Use const generics in Serial, Deserial and SchemaType implementation for arrays.
- Bump minimum supported Rust version to 1.51.

## concordium-contracts-common 0.4.0 (2021-05-12)

- Add String to the schema.
- Add ContractName and ReceiveName to schema.
- Add ContractName and ReceiveName types for added type safety.
