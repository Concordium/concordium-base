# Contributing

This repository's CI automatically checks formatting and common problems in rust.
Changes to any of the packages must be such that
- ```cargo clippy --all``` produces no warnings
- ```rust fmt``` makes no changes.

Everything in this repository should build with stable rust at the moment (at least version 1.44 and up), however the fmt tool must be from a nightly release since some of the configuration options are not stable. One way to run the `fmt` tool is 
```
 cargo +nightly-2019-11-13 fmt
```
(the exact version used by the CI can be found in [.gitlab-ci.yml](./.gitlab-ci.yml) file). You will need to have the right nightly version installed, which can be done via
```
rustup toolchain install nightly-2019-11-13
```
or similar, using the [rustup](https://rustup.rs/) tool. See the documentation of the tool for more details.

In order to contribute you should make a merge request and not push directly to master.



# Smart Contracts

This repository contains several packages to support smart contracts on and off-chain.

Currently it consists of the following parts
- [rust-contracts](./rust-contracts) which is the collection of base libraries and example smart contracts written in Rust.
- [wasmer-interp](./wasmer-interp) which is a wrapper around the [wasmer](https://github.com/wasmerio/wasmer) interpreter providing the functionality needed by the scheduler to execute smart contracts.
- [wasmer-runner](./wasmer-runner) which is a small tool that uses the API exposed in wasmer-interp to execute smart contracts directly. It can initialize and update smart contracts, in a desired state. See the `--help` option of the tool for details on how to invoke it.

## Rust-contracts

The [rust-contracts](./rust-contracts) aims to be organized into two parts. The first [concordium-sc-base](./rust-contracts/concordium-sc-base) contains a Rust package that is meant to be developed into the core API all Rust smart contracts use. It wraps the primitives that are allowed to be used on the chain in safer wrappers. The goal is to provide an API that spans from low-level, requiring the user to be very careful, but allowing precise control over resources, to a high-level one with more safety, but less efficiency for more advanced uses.

The second, [example-contracts](./rust-contracts/example-contracts) is meant for, well, example contracts using the aforementioned API.
The list of currently implemented contracts is as follows:
- [counter](./rust-contracts/example-contracts/counter) a counter contract with a simple logic on who can increment the counter. This is the minimal example.
