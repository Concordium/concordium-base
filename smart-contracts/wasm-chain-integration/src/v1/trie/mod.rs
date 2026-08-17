//! Implementation of the contract state trie that is exposed as a key-value
//! store to smart contracts.
//!
//! The main top-level types are [`PersistentState`] and [`MutableState`].
//! The [`PersistentState`] is used for long-term storage and is the state that
//! exists in between contract executions.
//!
//! During transaction execution we first [`thaw`](PersistentState::thaw) into a
//! [`MutableState`] on the first use of the state in the transaction. The
//! [`MutableState`] is designed for efficient sharing and rollbacks in case of
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
// We need the low-level module for testing and benchmarks, but we do not wish
// to expose it.
#[doc(hidden)]
pub mod low_level;
mod types;
pub use types::*;

pub use low_level::{MutableTrie, Node};

/// An external function that loads a complete payload.
pub type LoadCallback = extern "C" fn(Reference) -> *mut Vec<u8>;

/// An external function that reads only the payload-length metadata.
/// The function returns zero and writes the length to `out_length` after a
/// successful read. It returns a nonzero value after a failed read.
pub type LoadLengthCallback = extern "C" fn(Reference, *mut u64) -> u8;

/// Named operations that give contract execution access to immutable backing
/// storage. The caller owns the callbacks. It must keep them alive during the
/// complete execution, including interruptions and resumed executions.
#[derive(Clone, Copy)]
pub struct BackingStoreLoadCallback {
    load: LoadCallback,
    load_length: LoadLengthCallback,
}

impl BackingStoreLoadCallback {
    pub fn new(load: LoadCallback, load_length: LoadLengthCallback) -> Self {
        Self { load, load_length }
    }
}

impl BackingStoreLoad for BackingStoreLoadCallback {
    type R = Vec<u8>;

    #[inline]
    fn load_raw(&mut self, location: Reference) -> LoadResult<Self::R> {
        let ptr = (self.load)(location);
        Ok(*unsafe { Box::from_raw(ptr) })
    }

    #[inline]
    fn load_raw_length(&mut self, location: Reference) -> LoadResult<u64> {
        let mut length = 0;
        if (self.load_length)(location, &mut length) == 0 {
            Ok(length)
        } else {
            Err(LoadError::CallbackFailure)
        }
    }
}

/// A [storer](BackingStoreStore) implemented by an external function.
/// The function is passed a pointer to data to store, and the size of data. It
/// should return the location where the data can be loaded via a
/// [`LoadCallback`].
pub type StoreCallback = extern "C" fn(data: *const u8, len: libc::size_t) -> Reference;

impl BackingStoreStore for StoreCallback {
    #[inline]
    fn store_raw(&mut self, data: &[u8]) -> StoreResult<Reference> {
        Ok(self(data.as_ptr(), data.len()))
    }
}
