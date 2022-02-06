use super::low_level::{FlatLoadable, FlatStorable, LoadResult, Reference, StoreResult};

type LoadCallBack = extern "C" fn(Reference) -> *mut Vec<u8>;

impl FlatLoadable for LoadCallBack {
    type R = Vec<u8>;

    #[inline]
    fn load_raw(&mut self, location: Reference) -> LoadResult<Self::R> {
        Ok(*unsafe { Box::from_raw(self(location)) })
    }
}

type StoreCallBack = extern "C" fn(data: *const u8, len: libc::size_t) -> Reference;

impl FlatStorable for StoreCallBack {
    #[inline]
    fn store_raw(&mut self, data: &[u8]) -> StoreResult<Reference> {
        Ok(self(data.as_ptr(), data.len()))
    }
}
