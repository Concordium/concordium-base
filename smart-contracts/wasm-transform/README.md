## concordium-wasm

A library that provides an implementation of a [Wasm](https://webassembly.org/)
execution engine to suit Concordium's needs. In particular it implements
- parsing and validation of Wasm modules, where validation is according to [Wasm core 1 spec](https://www.w3.org/TR/2019/REC-wasm-core-1-20191205/) with additional restrictions necessary for blockchain use.
- a compiler to a lower-level format that is easier to execute
- an interpreter
- utilities for storing and loading processed code

This is a low-level library that implements only the Wasm parts of execution.

The companion library `concordium-smart-contract-engine` provides an integration
of the Wasm together with state management, and provides higher-level functions
for executing smart contract entrypoints.
