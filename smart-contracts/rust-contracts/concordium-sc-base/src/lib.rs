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
//! ```
//! [dependencies.concordium-sc-base]
//! default-features = false
//! ```
//! In your project's `Cargo.toml` file.

#![cfg_attr(not(feature = "std"), no_std, feature(alloc_error_handler))]

#[cfg(not(feature = "std"))]
extern crate alloc;

#[cfg(not(feature = "std"))]
#[alloc_error_handler]
fn on_oom(_layout: alloc::alloc::Layout) -> ! { panic!() }

#[cfg(not(feature = "std"))]
#[panic_handler]
fn abort_panic(_info: &core::panic::PanicInfo) -> ! { loop {} }

// Provide some re-exports to make it easier to use the library.
// This should be expanded in the future.
#[cfg(not(feature = "std"))]
pub use core::result::*;

#[cfg(not(feature = "std"))]
pub use alloc::collections;
#[cfg(not(feature = "std"))]
pub use alloc::{vec, vec::Vec};
#[cfg(not(feature = "std"))]
pub use core::convert;
#[cfg(feature = "std")]
pub use std::collections;
#[cfg(feature = "std")]
pub use std::convert;

mod impls;
mod prims;
mod types;
/// Re-export for ease of use.
pub use concordium_sc_derive::{init, receive};
pub use contracts_common::*;
pub use impls::{Create, HasParameter};
pub use prims::{actions::*, events};
pub use types::*;

extern crate wee_alloc;
// Use `wee_alloc` as the global allocator to reduce code size.
#[global_allocator]
static ALLOC: wee_alloc::WeeAlloc = wee_alloc::WeeAlloc::INIT;
