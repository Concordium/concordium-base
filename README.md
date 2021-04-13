
[![Contributor Covenant](https://img.shields.io/badge/Contributor%20Covenant-2.0-4baaaa.svg)](https://github.com/Concordium/.github/blob/main/.github/CODE_OF_CONDUCT.md)

This library provides the core API that can be used to write smart contracts
for the Concordium blockchain in the Rust programming language. It aims to
provide safe wrappers around the core primitives exposed by the chain and
accessible to smart contracts.

The functionality in this library is re-exported via the [concordium-std](https://crates.io/crates/concordium-std)
crate, which is intended as the entry-point for development of smart
contracts in Rust. `concordium-std` adds a number of helper macros and
traits on top of the basic functionality available here.

## Links

- [Crates.io](https://crates.io/crates/concordium-contracts-common)
- [Documentation](https://docs.rs/concordium-contracts-common/latest/concordium_contracts_common/)
