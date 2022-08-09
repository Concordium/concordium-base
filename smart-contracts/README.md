# Contributing

[![Contributor Covenant](https://img.shields.io/badge/Contributor%20Covenant-2.0-4baaaa.svg)](https://github.com/Concordium/.github/blob/main/.github/CODE_OF_CONDUCT.md)

This repository's CI automatically checks formatting and common problems in rust.
Changes to any of the packages must be such that
- ```cargo clippy --all``` produces no warnings
- ```rust fmt``` makes no changes.

Everything in this repository should build with stable rust at the moment (at least version 1.44 and up), however the fmt tool must be from a nightly release since some of the configuration options are not stable. One way to run the `fmt` tool is
```
 cargo +nightly-2019-11-13 fmt
```
(the exact version used by the CI can be found in [.github/workflows/ci.yaml](.github/workflows/ci.yaml) file).
You will need to have a recent enough nightly version installed, which can be done via
```
rustup toolchain install nightly-2019-11-13
```
or similar, using the [rustup](https://rustup.rs/) tool. See the documentation of the tool for more details.

In order to contribute you should make a merge request and not push directly to master.

# Smart Contracts

This repository contains several packages to support smart contracts on and off-chain.

Currently it consists of the following parts
- [rust-contracts](./rust-contracts) which is the collection of base libraries and example smart contracts written in Rust.
- [wasm-transform](./wasm-transform), an interpreter and validator providing the functionality needed by the scheduler to execute smart contracts.
- [wasm-chain-integration](./wasm-chain-integration/) exposes the interface needed by the node

## Rust-contracts

The [rust-contracts](./rust-contracts) contains [example-contracts](./rust-contracts/example-contracts) is for testing.
**They are toy contracts utterly unsuitable for any production use.**
The list of currently implemented contracts is as follows:
- [counter](./rust-contracts/example-contracts/counter) a counter contract with a simple logic on who can increment the counter. This is the minimal example.
- [fib](./rust-contracts/example-contracts/fib) a contract calculating the requested fibonacci number, either directly or with recursive contract invocations; this is useful to demonstrate cost accounting.
- [simple-game](./rust-contracts/example-contracts/simple-game) a more complex smart contract which allows users to submit strings that are then hashed, and
  the lowest one wins after the game is over (which is determined by timeout).
  This contract uses
  - sending tokens to accounts
  - bringing in complex dependencies (containers, sha2, hex encoding)
  - more complex state, that is only partially updated.
- [escrow](./rust-contracts/example-contracts/escrow) a toy escrow contract which allows a buyer to submit a deposit which is held until the buyer is satisfied that they have received their goods, or an arbiter makes a judgement as a result of either the buyer or seller raising a dispute.
- [lockup](./rust-contracts/example-contracts/lockup) a contract which implements a CCD lockup, where those CCD vest over a pre-determined schedule, and vested CCD can be withdrawn by any one of potentially several account holders. The contract also allows for a set of accounts to have the power to veto the vesting of future CCD, e.g. for cases where an employee's vesting schedule is contingent on their continued employment.
- [erc20](./rust-contracts/example-contracts/erc20) an implementation of the [token standard](https://github.com/ethereum/EIPs/blob/master/EIPS/eip-20.md) popular in Ethereum used by other applications, such as wallets.

### When updating **concordium-rust-smart-contracts** dependency

The examples all depend on the libraries implemented in [concordium-rust-smart-contracts](https://github.com/Concordium/concordium-rust-smart-contracts). When working on these in tandem, it might make sense to change the dependencies in the `Cargo.toml` of the respective smart contract, to point at the local dev version of the libraries:

```toml
[dependencies.concordium-std]
# git = "https://github.com/Concordium/concordium-rust-smart-contracts.git"
# branch = "main"
path = "path/to/dev/concordium-rust-smart-contracts"
```

## Compiling smart contracts to Wasm

The process for compiling smart contracts to Wasm is always the same, and we
illustrate it here on the [counter](./rust-contracts/example-contracts/counter)
contract. To compile Rust to Wasm you need to

- install the rust wasm toolchain, for example by using
```
rustup target add wasm32-unknown-unknown
```
- run `cargo build` as
```
cargo build --target wasm32-unknown-unknown [--release]
```
(the `release` flag) is optional, by default it will build in debug builds,
which are slower and bigger.

Running `cargo build` will produce a single `.wasm` module in
`target/wasm32-unknown-unknown/release/counter.wasm` or
`target/wasm32-unknown-unknown/debug/counter.wasm`, depending on whether the
`--release` option was used or not.

By default the module will be quite big in size, depending on the options used
(e.g., whether it is compiled with `std` or not, it can be from 600+kB to more
than a MB). However most of that is debug information in custom sections and can be stripped away.
There are various tools and libraries for this. One such suite of tools is [Web
assembly binary toolkit (wabt)](https://github.com/WebAssembly/wabt) and its
tool `wasm-strip`.

Using `wasm-strip` on the produced module produces a module of size 11-13kB ,
depending on whether the `no_std` option was selected or not.

### Default toolchain

The default toolchain can be specified in the `.cargo/config` files inside the
project, as exemplified in the
[counter/.cargo/config](./rust-contracts/example-contracts/counter/.cargo/config)
file.

### Compilation options

Since a contract running on the chain will typically not be able to recover from
panics, and error traces are not reported, it is useful not to bloat code size
with them. Setting `panic=abort` will make it so that the compiler will generate
simple `Wasm` traps on any panic that occurs. This option can be specified
either in `.cargo/config` as exemplified in
[counter/.cargo/config](./rust-contracts/example-contracts/counter/.cargo/config),
or in the `Cargo.toml` file as

```
[profile.release]
# Don't unwind on panics, just trap.
panic = "abort"
```

The latter will only set this option in `release` builds, for debug builds use

```
[profile.dev]
# Don't unwind on panics, just trap.
panic = "abort"
```
instead.

An additional option that might be useful to minimize code size at the cost of
some performance in some cases is
```
[profile.release]
# Tell `rustc` to optimize for small code size.
opt-level = "s"
```
or even `opt-level = "z"`.

In some cases using `opt-level=3` actually leads to smaller code sizes, presumably due to more inlining and dead code removal as a result.


# Fuzzing the smart-contract interpreter

We provide a fuzzer for the [Wasm smart-contract interpreter](wasm-chain-integration) which allows to test the 
interpreter on randomly generated Wasm programs. In a nutshell,
we generate valid, type-correct Wasm programs as inputs to the interpreter, and use a mutation-based fuzzer to
make the nondeterministic choices that guide the random program generation. Specifically, the fuzzing cycle works as 
follows:

1. The fuzzer (a [Rust wrapper](https://crates.io/crates/libfuzzer-sys) around LLVM's 
   [libfuzzer](https://llvm.org/docs/LibFuzzer.html)) generates a random array `r` of bytes.
2. We generate a "random" Wasm smart contract `s`: whenever we need to make a nondeterministic choice (how many functions to 
   generate, whether to use a function call, arithmetic expression, variable, or literal to generate an integer value, 
   etc.) we consult bytes from array `r`.
3. A fuzzing utility ([cargo fuzz](https://crates.io/crates/cargo-fuzz)) instruments the interpreter code to make it
   suitable for collecting code-coverage information. This allows the fuzzer to keep track of the execution paths
   that were taken in each of the runs (more on that below).
4. We run the instrumented interpreter code on `s`, feeding information about code coverage back to the fuzzer.
5. This loop continues until an interpreter run results in a crash, at which point the fuzzer terminates with information
   on how to reproduce the crash.
   
In each iteration of this cycle, the fuzzer compares the code coverage of the previous interpreter run with the code 
coverage encountered so far. It then uses various heuristics to decide how to best change the created byte arrays in
order to explore new execution paths.

The random Wasm smart-contract generation is implemented in a [fork](https://github.com/Concordium/wasm-tools)
of the [wasm-smith Wasm program generator](https://docs.rs/wasm-smith/0.4.1/wasm_smith/)
which is described in a great [blog post](https://fitzgeraldnick.com/2020/08/24/writing-a-test-case-generator.html)
by Nick Fitzerald.

So far the fuzzer discovered three [bugs](wasm-chain-integration/fuzz/fixed_artifacts/interpreter), which we fixed.

## Software requirements
- [cargo-fuzz](https://crates.io/crates/cargo-fuzz) 
- for generating coverage information:
  * [cargo-cov](https://crates.io/crates/cargo-cov) (`cargo install cargo-cov`)
  * [cargo-profdata](https://crates.io/crates/cargo-profdata) (`cargo install cargo-profdata`)
  * [rustfilt](https://crates.io/crates/rustfilt) (`cargo instlal rustfilt`)
  * [python3](https://www.python.org/downloads/)
  * [tqdm](https://pypi.org/project/tqdm/) (`pip3 install tqdm`)

## Running the fuzzer
- `$ cd wasm-chain-integration` 
- `$ cargo +nightly fuzz run interpreter -- -max-len=1200000`

This will fuzz the smart-contract interpreter on randomly generated but valid Wasm programs, until the fuzzer finds
a crash.

## Visualizing code coverage

After the fuzzer runs for some time it will be discovering new execution paths slower and slower.
When that happens, it can be useful to see how many times it executed each of the instructions in the interpreter
source code. To generate source code that is annotated with the number of times that each line of code was executed, run

- `cd wasm-chain-integration`
- `fuzz/scripts/generate-coverage.py fuzz/corpus/interpreter`

# Contract schema
The state of a contract is a bunch of bytes and how to interpret these bytes into representations such as structs and enums is hidden away into the contract functions after compilation.
For the execution of the contract, this is exactly as intended, but reading and writing bytes directly is error prone and impractical for a user. To solve this we can embed a contract schema into the contract module.

A contract schema is a description of how to interpret these bytes, that optionally can be embedded into the smart contract on-chain, such that external tools can use this information to display and interact with the smart contract in some format other than just raw bytes.

Tool like `cargo concordium run init` can then check for an embedded schema and use this to parse the bytes of the state, or have the user supply parameters in a more readable format than bytes.

More technically the contract schema is serialized and embedded into the wasm module by setting a [custom section](https://webassembly.github.io/spec/core/appendix/custom.html) named `"contract-schema"`.


## Generating the schema in rust
The schema itself is embedded as bytes, and to automate this process the user can annotate the contract state and which parameters to include in the schema using `#[contract_state(contract = "my-contract")]` and including an `parameter` attribute in the `#[init(...)]` and `#[receive(...)]` proc-macros.

```rust
#[contract_state(contract = "my-contract")]
#[derive(SchemaType)]
struct MyState {
    ...
}
```
```rust
#[derive(SchemaType)]
enum MyParameter {
    ...
}

#[init(contract = "my-contract", parameter = "MyParameter")]
fn contract_init<...> (...){
    ...
}
```
For a type to be part of the schema it must implement the `SchemaType` trait, which is just a getter for the schema of the type, and for most cases of structs and enums this can be automatically derived using `#[derive(SchemaType)]` as seen above.
```rust
trait SchemaType {
    fn get_type() -> crate::schema::Type;
}
```

To build the schema, the `Cargo.toml` must include the `build-schema` feature, which is used by the contract building tool.
```toml
...
[features]
build-schema = []
...
```
Running `cargo concordium build` with either `--schema-embed` or `--schema-output=<file>` will then first compile the contract with the `build-schema` feature enabled, generate the schema from the contract module and then compile the contract again without the code for generating the schema, and either embed the schema as bytes into this or output the bytes into a file (or both).

The reason for compiling the contract again is to avoid including dependencies from the schema generation into the final contract, resulting in smaller modules.


# Removing Host Information from Binary
By default the compiled binary from a rust crate contains some information from the host machine, namely rust-related paths such as the path to `.cargo`. This can be seen by inspecting the produced binary:

Lets assume your username is `tom` and you have a smart contract `foo` located in your home folder, which you compiled in release-mode to WASM32.
By running the following command inside the `foo` folder, you will be able to see the paths included in the binary: `strings target/wasm32-unknown-unknown/release/foo.wasm | grep tom`

To remove the host information, the path prefixes can be remapped using a flag given to the compiler.
`RUSTFLAGS=--remap-path-prefix=/home/tom=secret cargo build --release --target wasm32-unknown-unknown`, where `/home/tom` is the prefix you want to change into `secret`.
The flag can be specified multiple times to remap multiple prefixes.

The flags can also be set permanently in the `.cargo/config` file in your crate, under the `build` section:

``` toml
[build]
rustflags = ["--remap-path-prefix=/home/tom=secret"]
```

**Important:**
[--remap-path-prefix does currently not work correctly if the `rust-src` component is present.](https://github.com/rust-lang/rust/issues/73167)
