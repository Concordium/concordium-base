# Changelog

## Unreleased changes
- Add public validation functions to contract and receive names.
- Add new cases for NewContractNameError and NewReceiveNameError.
- Implement `SchemaType` for `Address`.
- Derive `PartialOrd` and `Ord` for `ContractAddress` and `Address`.
- Derive `Hash` for `Amount`, `Timestamp`, `Duration`, `AccountAddress`, `ContractAddress`, `Address`, `ContractName`, `OwnedContractName`, `ReceiveName` and `OwnedReceiveName`.
- Add `HashMap` and `HashSet` from the `hashbrown` crate to support `no-std`.
- Make `HashMap` and `HashSet` default to the `fnv` hasher.

## concordium-contracts-common 0.4.0 (2021-05-12)

- Add String to the schema.
- Add ContractName and ReceiveName to schema.
- Add ContractName and ReceiveName types for added type safety.
