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
fn on_oom(_layout: alloc::alloc::Layout) -> ! { core::intrinsics::abort() }

/// Abort execution immediately.
#[cfg(not(feature = "std"))]
pub use core::intrinsics::abort as trap;
#[cfg(feature = "std")]
pub use std::process::abort as trap;

#[cfg(not(feature = "std"))]
#[panic_handler]
fn abort_panic(_info: &core::panic::PanicInfo) -> ! { loop {} }

// Provide some re-exports to make it easier to use the library.
// This should be expanded in the future.
#[cfg(not(feature = "std"))]
pub use core::result::*;

/// Re-export.
#[cfg(not(feature = "std"))]
pub use alloc::collections;
/// Re-export.
#[cfg(not(feature = "std"))]
pub use alloc::{string, string::String, string::ToString, vec, vec::Vec};
/// Re-export.
#[cfg(not(feature = "std"))]
pub use core::convert;
/// Re-export.
#[cfg(not(feature = "std"))]
pub use core::mem;

/// Re-export.
#[cfg(feature = "std")]
pub use std::collections;
/// Re-export.
#[cfg(feature = "std")]
pub use std::convert;
/// Re-export.
#[cfg(feature = "std")]
pub use std::mem;

mod impls;
mod prims;
mod traits;
mod types;
pub use concordium_sc_derive::{init, receive, Deserial, Serial, Serialize};
pub use contracts_common::*;
pub use traits::*;
pub use types::*;

extern crate wee_alloc;
// Use `wee_alloc` as the global allocator to reduce code size.
#[global_allocator]
static ALLOC: wee_alloc::WeeAlloc = wee_alloc::WeeAlloc::INIT;

pub mod test_infrastructure;
