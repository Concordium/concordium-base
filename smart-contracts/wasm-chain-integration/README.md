## concordium-smart-contract-engine

A library that provides an implementation of execution of smart contracts on top
of the `concordium-wasm` library that implements the underlying Wasm execution.

In particular this library is used by the [Concordium node](https://github.com/Concordium/concordium-node)
to execute both V0 and V1 smart contracts. It is also used by other Concordium tools, such as
[cargo-concordium](https://github.com/Concordium/concordium-smart-contract-tools/tree/main/cargo-concordium),
to provide build and test functionality.

## Versioning

This crate follows semantic versioning guidelines. Change in minimum supported
rust version will be accompanied by a minor version increase.
