This library provides the common core API that can be used to write smart
contracts for the Concordium blockchain. The functionality in this library is
the common core between what contracts on the chain have access to, and what the
host has access to. Most users will wish to use
[concordium-std](https://github.com/Concordium/concordium-std) instead.

By default the library will be linked with the
[std](https://doc.rust-lang.org/std/) crate, the rust standard library,
however to minimize code size this library supports toggling compilation
with the `#![no_std]` attribute via the feature `std` which is enabled by
default. Compilation without the `std` feature requires a nightly version of
rust.

# Work in progress.

This library is under heavy development at the moment, so expect breaking
changes.
