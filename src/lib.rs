//! This library provides the core API that can be used to write smart contracts
//! for the Concordium blockchain. It aims to provide safe wrappers around the
//! core primitives exposed by the chain and accessible to smart contracts.
//!
//! By default the library will be linked with the
//! [std](https://doc.rust-lang.org/std/) crate, the rust standard library,
//! however to minimize code size this library supports toggling compilation
//! with the `#![no_std]` attribute via the feature `std` which is enabled by
//! default. Compilation without the `std` feature requires a nightly version of
//! rust.
//!
//! To use this library without the `std` feature you have to disable it, which
//! can be done, for example, as follows.
//! ```toml
//! [dependencies.concordium-contracts-common]
//! default-features = false
//! ```
//! In your project's `Cargo.toml` file.

#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(not(feature = "std"))]
extern crate alloc;

#[macro_use]
mod impls;
#[cfg(feature = "std")]
pub mod schema;
mod traits;
mod types;
pub use impls::*;
pub use traits::*;
pub use types::*;
