## concordium_base

A library that defines common types and functionality that are needed by
Concordium Rust projects. The scope of this library is limited to core
definitions that are needed by most users.

Its functionality is meant to be re-exported by higher-level libraries, such as
the `concordium-rust-sdk`.

The library covers the following areas

- the full implementation of the identity layer cryptography. In particular the
  data structures, data exchange formats between the different parties, and zero-knowledge 
  proofs are implemented by this library.
- implementation of encrypted transfers, including data exchange formats and
  zero-knowledge proofs.
- implementation of ElGamal encryption over the curve abstraction defined in the
  library.
- implementation of bulletproofs over the curve abstraction.
- definition of transactions supported by Concordium, including their hashing,
  signing, and serialization.
- definition of the common serialization formats used by the chain.
- implementation of the VRF (Verifiable Random Function) used by the consensus
  protocol.

### Features

The library has no default features and the following optional ones:

- `encryption` - additionally exposes the `common::encryption` module for
  handling the encryption format used by various Concordium tools (such as
  wallet exports). This feature is covered by semver guidelines.
- `ffi` - enabling this feature adds a number of foreign exports to the library.
  These are not guaranteed to be stable and are only used when integrating the
  library into the node.
- `internal-test-helpers` - enabling this feature exposes some library internals
  that are needed in benchmarks. Functionality exposed by this feature has no
  stability guarantees.

### Guarantees

This library should always be possible to compile for **android/ARM**, **iOS**,
**Wasm**, and **x86 code**. Some parts may be feature gated to work around
platform specific limitations though.

### Minimum supported rust version

The minimum supported Rust version is stated in the `Cargo.toml` manifest.
Changes in this minimal supported version are going to be accompanied by at
least a minor version increase.
