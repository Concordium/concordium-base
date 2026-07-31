# Smart Contracts

This directory contains several packages to support smart contracts on and off-chain.

Currently it consists of the following parts
- [contracts-common](./contracts-common), library shared between smart contracts and other Rust targets like the Rust SDK and the Rust Scheduler in the node
- [concordium-wasm](./wasm-transform), an interpreter and validator providing the functionality needed by the scheduler to execute smart contracts.
- [concordium-smart-contract-engine](./wasm-chain-integration/) exposes the interface needed by the node
- [wasm-test](./wasm-test) implements tests of the WASM interpreter against official test vectors

### Compilation options for smart contracts

An option that might be useful to minimize code size at the cost of
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
- `$ cd wasm-fuzz`
- `$ cargo +nightly fuzz run interpreter -- -max-len=1200000`

This will fuzz the smart-contract interpreter on randomly generated but valid Wasm programs, until the fuzzer finds
a crash.

## Visualizing code coverage

After the fuzzer runs for some time it will be discovering new execution paths slower and slower.
When that happens, it can be useful to see how many times it executed each of the instructions in the interpreter
source code. To generate source code that is annotated with the number of times that each line of code was executed, run

- `cd wasm-fuzz`
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

Running `cargo concordium build` with either `--schema-embed` or `--schema-output=<file>` will then first compile the contract with the `build-schema` feature enabled, generate the schema from the contract module and then compile the contract again without the code for generating the schema, and either embed the schema as bytes into this or output the bytes into a file (or both).

The reason for compiling the contract again is to avoid including dependencies from the schema generation into the final contract, resulting in smaller modules.


# Removing host information from smart contract binary
By default the compiled binary from a rust crate contains some information from the host machine, namely rust-related paths such as the path to `.cargo`. This can be seen by inspecting the produced binary:

Lets assume your username is `tom` and you have a smart contract `foo` located in your home folder, which you compiled in release-mode to WASM32.
By running the following command inside the `foo` folder, you will be able to see the paths included in the binary: `strings target/wasm32v1-none/release/foo.wasm | grep tom`

To remove the host information, the path prefixes can be remapped using a flag given to the compiler.
`RUSTFLAGS=--remap-path-prefix=/home/tom=secret cargo build --release --target wasm32v1-none`, where `/home/tom` is the prefix you want to change into `secret`.
The flag can be specified multiple times to remap multiple prefixes.

The flags can also be set permanently in the `.cargo/config` file in your crate, under the `build` section:

``` toml
[build]
rustflags = ["--remap-path-prefix=/home/tom=secret"]
```

**Important:**
[--remap-path-prefix does currently not work correctly if the `rust-src` component is present.](https://github.com/rust-lang/rust/issues/73167)
