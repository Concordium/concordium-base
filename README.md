
[![Contributor Covenant](https://img.shields.io/badge/Contributor%20Covenant-2.0-4baaaa.svg)](https://github.com/Concordium/.github/blob/main/.github/CODE_OF_CONDUCT.md)

This library provides the core API that can be used to write smart contracts
for the Concordium blockchain in the Rust programming language. It aims to
provide safe wrappers around the core primitives exposed by the chain and
accessible to smart contracts.

The functionality in this library is re-exported via the [concordium-std](https://crates.io/crates/concordium-std) and the [concordium-rust-sdk](https://github.com/Concordium/concordium-rust-sdk/) crate.

- The `concordium-std` crate is intended as the entry-point for development of smart contracts in Rust. It adds a number of helper macros and traits on top of the basic functionality available here.

- The `concordium-rust-sdk` crate is for off-chain development and interaction with smart contracts.

## Features

- `std` (enabled by default): Enables functionality that depends on the standard library.
- `derive-serde`: Enable serialization and deserialization via `serde`. Enables `std` as well.
- `fuzz`: Enable fuzzing via `arbitrary`. Enables `derive-serde` as well.
- `sdk`: Enable functionality only meant for `concordium-rust-sdk`. Enabling will change procedural macros to assume the context of the `concordium-rust-sdk` and enable functionality only meant for off-chain development.

## MSRV

The minimum supported rust version is 1.56

## Links

- [Crates.io](https://crates.io/crates/concordium-contracts-common)
- [Documentation](https://docs.rs/concordium-contracts-common/latest/concordium_contracts_common/)
