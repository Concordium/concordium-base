#![cfg_attr(not(feature = "std"), no_std, feature(alloc_error_handler))]

#[cfg(not(feature = "std"))]
extern crate alloc;

#[cfg(not(feature = "std"))]
#[alloc_error_handler]
fn on_oom(_layout: alloc::alloc::Layout) -> ! { panic!() }

#[cfg(not(feature = "std"))]
#[panic_handler]
fn abort_panic(_info: &core::panic::PanicInfo) -> ! { loop {} }

/// Provide some re-exports to make it easier to use the library.
/// This should be expanded in the future.
#[cfg(not(feature = "std"))]
pub use core::result::*;

#[cfg(not(feature = "std"))]
pub use alloc::{vec, vec::Vec};

extern crate wee_alloc;

mod impls;
mod prims;
pub mod traits;
pub mod types;
pub use prims::{events, internal};
pub use types::*;

pub use crate::traits::{Read, Seek, SeekFrom, Serialize, Write};

// Use `wee_alloc` as the global allocator.
#[global_allocator]
static ALLOC: wee_alloc::WeeAlloc = wee_alloc::WeeAlloc::INIT;
