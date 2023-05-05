# Concordium Contracts Common library

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

## MSRV

The minimum supported rust version is 1.60.

## Links

- [Crates.io](https://crates.io/crates/concordium-contracts-common)
- [Documentation](https://docs.rs/concordium-contracts-common/latest/concordium_contracts_common/)

## Contributing

[![Contributor Covenant](https://img.shields.io/badge/Contributor%20Covenant-2.0-4baaaa.svg)](https://github.com/Concordium/.github/blob/main/.github/CODE_OF_CONDUCT.md)

This repository's CI automatically checks formatting and common problems in rust.
Changes to any of the packages must be such that

- ```cargo clippy --all``` produces no warnings
- ```rustfmt``` makes no changes.

Everything in this repository should build with rust version 1.60 however the `fmt` tool must be from a nightly release since some of the configuration options are not stable. One way to run the `fmt` tool is
```
cargo +nightly-2023-04-01 fmt
```

(the exact version used by the CI can be found in [.github/workflows/linter.yml](.github/workflows/linter.yml) file).
You will need to have a recent enough nightly version installed, which can be done via

```
rustup toolchain install nightly-2023-04-01
```

or similar, using the [rustup](https://rustup.rs/) tool. See the documentation of the tool for more details.

In order to contribute you should make a pull request and ask at least two people familiar with the code to do a review.
