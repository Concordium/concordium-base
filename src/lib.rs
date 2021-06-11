//! This library provides the core API that can be used to write smart contracts
//! for the Concordium blockchain in the Rust programming language. It aims to
//! provide safe wrappers around the core primitives exposed by the chain and
//! accessible to smart contracts.
//!
//! By default the library will be linked with the
//! [std](https://doc.rust-lang.org/std/) crate, the rust standard library,
//! however to minimize code size this library supports toggling compilation
//! with the `#![no_std]` attribute via the feature `std` which is enabled by
//! default.
//!
//! To use this library without the `std` feature you have to disable it, which
//! can be done, for example, as follows.
//! ```toml
//! [dependencies.concordium-contracts-common]
//! default-features = false
//! ```
//! In your project's `Cargo.toml` file.
//!
//! ## Wasm32
//! This crate supports both compilation to x86 native code, as well as
//! to the wasm32-unknown-unknown target. When there is a conflict, the
//! preference should always be to make the wasm32-unknown-unknown the more
//! efficient one.
//!
//! ## `concordium-std`
//! The functionality in this library is re-exported via the [concordium-std](https://crates.io/crates/concordium-std)
//! crate, which is intended as the entry-point for development of smart
//! contracts in Rust. `concordium-std` adds a number of helper macros and
//! traits on top of the basic functionality available here.
//!
//! ## Features
//!
//! This library supports two features, `std` and `derive-serde`. The former one
//! is enabled by default, but the latter is disabled.
//!
//! The `derive-serde` feature is intended to be used by off-chain tools to make
//! it easier to test smart contracts, as well as to inter-operate with them
//! once they are deployed. It can also be used in unit tests, since enabling
//! this feature exposes additional trait implementations on the defined types.
//!
//! The reason these trait implementations are not enabled by default is that
//! they have non-trivial dependencies, which tends to increase compilation
//! times, as well as code size, if used accidentally.
//!
//! # Traits
//! The main traits defined in this crate deal with binary serialization.
//! The general principles behind serialization is to consistently use
//! little-endian encoding. The native endianess of Wasm32 (when, e.g.,
//! reading from linear memory) is little endian, thus having serialization in
//! little endian means as little overhead as possible.
//!
//! The two core traits are [Serial](./trait.Serial.html) and
//! [Deserial](./trait.Deserial.html). The rest are helper traits there for
//! convenience.
//!
//! In particular, the [Get](./trait.Get.html) is noteworthy. It makes it
//! possible to omit writing the type explicitly, if it is already clear from
//! the context, allowing us to write, e.g.,
//!
//! ```rust
//! # fn deserial<R: concordium_contracts_common::Read>(source: &mut R) -> concordium_contracts_common::ParseResult<u8> {
//! #  use crate::concordium_contracts_common::Get;
//!    let n = source.get()?;
//! #   Ok(n)
//! # }
//! ```
//! instead of
//!
//! ```rust
//! # fn deserial<R: concordium_contracts_common::Read>(source: &mut R) -> concordium_contracts_common::ParseResult<u8> {
//! #  use crate::concordium_contracts_common::Deserial;
//!    let n = u8::deserial(source)?;
//! #   Ok(n)
//! # }
//! ```
//! The [Get](./trait.Get.html) trait has a generic implementation in terms of
//! [Deserial](./trait.Deserial.html), so only the latter should be implemented
//! for new types.

#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(not(feature = "std"))]
extern crate alloc;

#[macro_use]
mod traits;
#[macro_use]
mod impls;
pub mod constants;
pub mod schema;
mod types;
pub use impls::*;
pub use traits::*;
pub use types::*;
