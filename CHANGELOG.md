# Changelog

## Unreleased changes

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
