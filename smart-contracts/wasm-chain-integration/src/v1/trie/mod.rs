//! Implementation of the contract state trie that is exposed as a key-value
//! store to smart contracts.
//!
//! The main top-level types are [`PersistentState`] and [`MutableState`].
//! The [`PersistentState`] is used for long-term storage and is the state that
//! exists in between contract executions.
//!
//! During transaction execution we first [`thaw`](PersistentState::thaw) into a
//! [`MutableState`] on the first use of the state in the transaction. The
//! [`MutableState`] is designed for efficient sharing and rollabacks in case of
//! execution failure. For each part of execution, e.g., when starting execution
//! of an entrypoint, the [`MutableState`] is locked and the underlying
//! [`MutableTrie`] is obtained, via [`get_inner`](MutableState::get_inner) and
//! [lock](MutableStateInner::lock). The [`MutableTrie`] is the state that the
//! execution engine operates on.

#[cfg(test)]
mod tests;

mod api;
pub use api::*;
pub(crate) use low_level::Iterator;
pub(crate) mod foreign;
// We need the low-level module for testing and benchmarks, but we do not wish
// to expose it.
#[doc(hidden)]
pub mod low_level;
mod types;
pub use types::*;

pub use low_level::{MutableTrie, Node};
