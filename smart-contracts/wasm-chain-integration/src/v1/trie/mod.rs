//! TODO: Get rid of the Default for freeze requirement (not important.)
#[cfg(test)]
mod tests;

mod api;
pub use api::*;
pub use low_level::Iterator;
mod foreign;
// We need the low-level module for testing and benchmarks, but we do not wish
// to expose it.
#[doc(hidden)]
pub mod low_level;
mod types;
pub use types::*;
