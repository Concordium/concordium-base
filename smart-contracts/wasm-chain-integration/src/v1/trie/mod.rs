//! TODO: Get rid of the Default for freeze requirement (not important.)
//! TODO: branch keys on 2 or 4 bits.
//! TODO: Once the point above is settled, consider using ArrayVec instead of
//! tinyvec, with fixed capacity.

#[cfg(test)]
mod tests;

mod api;
pub use api::*;
pub use low_level::Iterator;
pub mod foreign;
// This should ideally be private, however we need it in benchmarks.
#[doc(hidden)]
pub mod low_level;
mod types;
pub use types::*;
