//! Implementation of the contract state trie that is exposed as a key-value
//! store to smart contracts.

#[cfg(test)]
mod tests;

mod api;
pub use api::*;
pub use low_level::Iterator;
// We need this in some integration with the node, but we don't want to
// advertise it.
#[doc(hidden)]
pub mod foreign;
// We need the low-level module for testing and benchmarks, but we do not wish
// to expose it.
#[doc(hidden)]
pub mod low_level;
mod types;
pub use types::*;
