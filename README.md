# concordium-base

This repository contains core Rust and Haskell libraries used by various
components of the Concordium blockchain, as well as some tools used for testing
and development.

[![Contributor Covenant](https://img.shields.io/badge/Contributor%20Covenant-2.0-4baaaa.svg)](https://github.com/Concordium/.github/blob/main/.github/CODE_OF_CONDUCT.md)

## Haskell modules

### [haskell-src](./haskell-src)

Contains the Haskell package `concordium-base` which contains

- foreign imports of rust libraries that are needed in the rest of the project
- basic type definitions, e.g., account address, block hash, with serializations
  and basic functionality. These are used consistently throughout the rest of
  the project.

### [haskell-tests](./haskell-tests/)

Unit tests of the `concordium-base` Haskell library.

### [haskell-bench](./haskell-bench/)

Benchmarks of some functions that are of interest. This is ad-hoc and functions
are added there by need.

### [generate-update-keys](./haskell-bins/generate-update-keys)

Is a utility for generating authorization keys for different kinds of updates.
It is used for generating such keys for internal testing. The key generation it
supports is not very secure.

### [genesis](./haskell-bins/genesis/)

Is a tool that takes all the parameters, accounts, and other data that goes into
a genesis block, and combines them into a single file that is needed to start
the node.

### [testdata](./testdata/)

Contains auxiliary data files used by Haskell tests.

### Rust modules

### [rust-src](./rust-src)

Contains
- definitions of some core datatypes, such as account addresses, hashes,
  as well as serialization and basic functionality.
- implementations of all custom cryptographic protocols used by Concordium,
  e.g., custom sigma proofs, implementation of bulletproofs, and top-level
  functionality for anonymity revokers, identity providers, and the account
  holders.

### [idiss](./idiss)

This is the wrapper around the functionality in the [id](./rust-src/id) library
that exports the functionality needed by the identity provider in the format
that they need it. The library is currently tailored to be used from NodeJS.

`idiss` is an acronym, standing for "identity issuer".

### [identity-provider-service](./identity-provider-service)

Is a prototype implementation of a pure Rust identity provider we use for
testing.

### [mobile_wallet](./mobile_wallet)

This contains thin wrappers around the [wallet](./rust-src/wallet/) library that
exposes the necessary functions in a format suitable for use from Android and
iOS platforms, respectively.

### [rust-bins](./rust-bins/)

Contains various utilities that are used for testing and prototyping. From key generation to
generation to tools for analyzing the chain.

See documentation for
- [id-client](./rust-bins/docs/id-client.md) (identity layer interactions for testing)
- [keygen tool](./rust-bins/docs/keygen.md) key generation for identity
  providers and anonymity revokers
- [keygen genesis](./rust-bins/docs/keygen-genesis.md) (this uses a different
  key generation procedure that allows key recovery from a seed phrase)
- [genesis tool](./rust-bins/docs/genesis-tool.md) tool to generate data for
  test genesis blocks, allows creation of accounts and bakers

# Build requirements.

In order to build the components in this repository you need
- The [cargo](https://doc.rust-lang.org/cargo/) tool for building the Rust
components. The currently supported version is 1.62. Others may work, but we
do not regularly test with them. The easiest way to install it is via the
[rustup](https://rustup.rs/) tool.
- The [Haskell Stack](https://docs.haskellstack.org/en/stable/README/) tool for
building the Haskell components.

Some Rust components may require additional dependencies, see
[mobile_wallet/README.md](./mobile_wallet/README.md) and
[idiss/README.md](./idiss/README.md) for details.


# Contributing

## Haskell workflow

We typically use [stack](https://docs.haskellstack.org/en/stable/README/) to
build, run, and test the code. In order to build the haskell libraries the rust
dependencies must be pre-build, which is done automatically by the cabal setup
script.

Code should be formatted using [`fourmolu`](https://github.com/fourmolu/fourmolu)
version `0.9.0.0` and using the config `fourmolu.yaml` found in the project root.
The CI is setup to ensure the code follows this style.

To check the formatting locally run the following commnad from the project root:


**On unix-like systems**:

```
$ fourmolu --mode check $(git ls-files '*.hs')
```

To format run the following command from the project root:

**On unix-like systems**:

```
$ fourmolu --mode inplace $(git ls-files '*.hs')
```

Lines should strive to be at most 100 characters, naming and code style should
follow the scheme that already exists.

We do not use any linting tool on the CI. Running hlint might uncover common
issues.

## Rust workflow

We use **stable version** of rust, 1.62, to compile the code. This is the
minimal supported version.

The CI is configured to check two things
- the [clippy](https://github.com/rust-lang/rust-clippy) tool is run to check
  for common mistakes and issues. We try to have no clippy warnings. Sometimes
  what clippy thinks is not reasonable is necessary, in which case you should
  explicitly disable the warning on that site (a function or module), such as
  `#[allow(clippy::too_many_arguments)]`, but that is a method of last resort.
  Try to resolve the issue in a different way first.

- the [rust fmt](https://github.com/rust-lang/rustfmt) tool is run to check the
  formatting. Unfortunately the stable version of the tool is quite outdated, so
  we use a nightly version, which is updated a few times a year. Thus in order
  for the CI to pass you will need to install the relevant nightly version, see
  see the `rustfmt` job in the file [.github/workflows/build-test-sources.yaml](.github/workflows/build-test-sources.yaml),
  look for `nightly-...`).

## Overall workflow

The typical workflow should be the following.
- make changes, commit and push on a separate branch
- make a merge request to merge your branch into master. Assign somebody else
  with knowledge of the code to review the changes before they are merged.

# Licenses

Most of the sources in this repository are licensed under [MPL-2.0](./LICENSE).
Some Rust packages are licensed under [APACHE-2.0](./LICENSE-APACHE). The
`license` field in Cargo.toml package indicates which license the sources in
that package are under.
