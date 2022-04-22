//! Implementation of [BackingStoreLoad] and [BackingStoreStore] traits
//! for function pointers that are needed when integrating with foreign code.
use super::*;

/// Load a vector from the given location.
pub type LoadCallback = extern "C" fn(Reference) -> *mut Vec<u8>;

impl BackingStoreLoad for LoadCallback {
    type R = Vec<u8>;

    #[inline]
    fn load_raw(&mut self, location: Reference) -> LoadResult<Self::R> {
        Ok(*unsafe { Box::from_raw(self(location)) })
    }
}

/// Store the given data and return the location where it can later be
/// retrieved.
pub type StoreCallback = extern "C" fn(data: *const u8, len: libc::size_t) -> Reference;

impl BackingStoreStore for StoreCallback {
    #[inline]
    fn store_raw(&mut self, data: &[u8]) -> StoreResult<Reference> {
        Ok(self(data.as_ptr(), data.len()))
    }
}
