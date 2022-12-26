# Changelog

## Unreleased changes

- Add methods `serial_value` and `serial_value_into` on the `Type`.
  They are more ergonomic to use than `write_bytes_from_json_schema_type` which
  is marked as deprecated and will be removed in future versions.
- Fix schema's `to_json` for contract addresses to that it outputs a value in
  the correct `{"index": ..., "subindex": ...}` format.

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
