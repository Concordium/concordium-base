//! Auxiliary types related to the trie implementation.

use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use derive_more::{AsRef, From, Into};
use sha2::Digest;
use std::{
    io::{Read, Seek, SeekFrom, Write},
    ops::{Index, IndexMut},
};
use thiserror::Error;

#[repr(transparent)]
#[derive(Default, Debug, Clone, Copy, Eq, PartialEq, From, Into)]
/// Reference to a storage location where an item may be retrieved.
pub struct Reference {
    reference: u64,
}

impl Reference {
    #[inline(always)]
    pub(crate) fn store(&self, sink: &mut impl std::io::Write) -> StoreResult<()> {
        sink.write_u64::<BigEndian>(self.reference)?;
        Ok(())
    }
}

#[derive(Debug, Error)]
/// An error that may occur when writing data to persistent storage.
pub enum WriteError {
    #[error("{0}")]
    IOError(#[from] std::io::Error),
}

/// Result of storing data in persistent storage.
pub type StoreResult<A> = Result<A, WriteError>;

#[derive(Debug, Error)]
/// An error that may occur when loading data from persistent storage.
pub enum LoadError {
    #[error("{0}")]
    IOError(#[from] std::io::Error),
    #[error("Incorrect tag")]
    IncorrectTag {
        // The tag that was provided.
        tag: u8,
    },
    #[error("Out of bounds read.")]
    OutOfBoundsRead,
}

/// Result of loading data from persistent storage.
pub type LoadResult<A> = Result<A, LoadError>;

/// Length of the stem that will be stored inline, i.e.,
/// the stem length will be encoded in the tag bit, as opposed to separate
/// 4 bytes.
pub(crate) const INLINE_STEM_LENGTH: usize = 0b0011_1111;

/// A trait that supports keeping track of resources during tree traversal, to
/// make sure that resource bounds are not exceeded.
pub trait TraversalCounter {
    type Err: std::fmt::Debug;
    fn tick(&mut self, num: u64) -> Result<(), Self::Err>;
}

/// A trait that supports counting new memory allocations in the tree.
pub trait AllocCounter<V> {
    type Err: std::fmt::Debug;
    /// Charge for allocating the given extra number of bytes.
    fn allocate(&mut self, data: &V) -> Result<(), Self::Err>;
}

/// A counter that does not count anything, and always returns Ok(()).
pub struct EmptyCounter;
#[derive(Debug, Copy, Clone, Error)]
/// An error that cannot happen, i.e., this type is not inhabited and is used as
/// an error type of an operation that cannot fail.
pub enum NoError {}

impl TraversalCounter for EmptyCounter {
    type Err = NoError;

    #[inline(always)]
    fn tick(&mut self, _num: u64) -> Result<(), Self::Err> { Ok(()) }
}

impl<V> AllocCounter<V> for EmptyCounter {
    type Err = NoError;

    #[inline(always)]
    fn allocate(&mut self, _data: &V) -> Result<(), Self::Err> { Ok(()) }
}

/// A type that can be used to collect auxiliary information while a mutable
/// trie is being frozen. Particular use-cases of this are collecting the size
/// of new data, as well as new persistent nodes.
/// TODO: Methods should probably return Result/Option so that we can terminate
/// early in case of out of energy.
pub trait Collector<V> {
    fn add_value(&mut self, data: &V);
    fn add_path(&mut self, path: usize);
    fn add_children(&mut self, num_children: usize);
}
/// Collector that does not collect anything.
pub struct EmptyCollector;

impl<V> Collector<V> for EmptyCollector {
    #[inline(always)]
    fn add_value(&mut self, _data: &V) {}

    #[inline(always)]
    fn add_path(&mut self, _path: usize) {}

    #[inline(always)]
    fn add_children(&mut self, _num_children: usize) {}
}

/// A collector that keeps track of how much additional data will be required to
/// store the tree.
#[derive(Default)]
pub struct SizeCollector {
    num_bytes: u64,
}

impl SizeCollector {
    pub fn collect(self) -> u64 { self.num_bytes }
}

// TODO: Make sure this is adequate. There is a bit of overhead with size length
// when we store data.
impl<V: AsRef<[u8]>> Collector<V> for SizeCollector {
    #[inline]
    fn add_value(&mut self, data: &V) {
        self.num_bytes += data.as_ref().len() as u64;
        self.num_bytes += 32; // store the hash of the value.
    }

    #[inline]
    fn add_path(&mut self, path: usize) {
        // 1 is for the tag of the value, 4 is for large key length.
        if path <= INLINE_STEM_LENGTH {
            self.num_bytes += 1 + path as u64;
        } else {
            self.num_bytes += 1 + 4 + path as u64;
        }
    }

    fn add_children(&mut self, num_children: usize) {
        // 1 for the key, 8 for the reference.
        self.num_bytes += (num_children as u64) * (1 + 8)
    }
}

/// Trait implemented by types that can be used to store binary data, and return
/// a handle for loading data.
pub trait BackingStoreStore {
    /// Store the provided value and return a reference that can be used
    /// to load it.
    fn store_raw(&mut self, data: &[u8]) -> Result<Reference, WriteError>;
}

/// Trait implemented by types that can load data from given locations.
pub trait BackingStoreLoad {
    type R: AsRef<[u8]>;
    /// Store the provided value and return a reference that can be used
    /// to load it.
    fn load_raw(&mut self, location: Reference) -> LoadResult<Self::R>;
}

impl BackingStoreStore for Vec<u8> {
    fn store_raw(&mut self, data: &[u8]) -> Result<Reference, WriteError> {
        let len = self.len();
        let data_len = data.len() as u64;
        self.extend_from_slice(&data_len.to_be_bytes());
        self.extend_from_slice(data);
        Ok((len as u64).into())
    }
}
#[derive(Debug)]
/// A generic wrapper that implements [BackingStoreStore] for any inner
/// type that implements [Seek] and [Write].
pub struct Storable<X> {
    inner: X,
}

impl<X: Seek + Write> BackingStoreStore for Storable<X> {
    fn store_raw(&mut self, data: &[u8]) -> Result<Reference, WriteError> {
        let pos = self.inner.seek(SeekFrom::Current(0))?;
        let data_len = data.len() as u32;
        self.inner.write_u32::<BigEndian>(data_len)?;
        self.inner.write_all(data)?;
        Ok(pos.into())
    }
}

/// Generic wrapper for a loader. This implements loadable for any S that can be
/// seen as a byte array. Since this type is often used with a `S = &[u8]` we
/// make it [Copy] to be able to share the backing buffer.
#[derive(Debug, Copy, Clone)]
pub struct Loader<S> {
    pub inner: S,
}

impl<S> Loader<S> {
    /// Construct a new loader from the given data.
    pub fn new(file: S) -> Self {
        Self {
            inner: file,
        }
    }
}

impl<'a, A: AsRef<[u8]>> BackingStoreLoad for Loader<A> {
    type R = Vec<u8>;

    // FIXME: This is inefficient. We allocate too many vectors.
    fn load_raw(&mut self, location: Reference) -> LoadResult<Self::R> {
        let slice = self.inner.as_ref();
        let mut c = std::io::Cursor::new(slice);
        let pos = c.seek(SeekFrom::Start(location.into()))?;
        let len = c.read_u64::<BigEndian>()?;
        let end = (pos + 8 + len) as usize;
        if end <= slice.len() {
            Ok(slice[pos as usize + 8..end].to_vec())
        } else {
            Err(LoadError::OutOfBoundsRead)
        }
    }
}

/// A trait implemented by types that can be loaded from a [BackingStoreLoad]
/// storage.
pub trait Loadable: Sized {
    fn load<S: std::io::Read, F: BackingStoreLoad>(
        loader: &mut F,
        source: &mut S,
    ) -> LoadResult<Self>;

    fn load_from_location<F: BackingStoreLoad>(
        loader: &mut F,
        location: Reference,
    ) -> LoadResult<Self> {
        let mut source = std::io::Cursor::new(loader.load_raw(location)?);
        Self::load(loader, &mut source)
    }
}

/// This loadable instance means that we can only retrieve the vector behind a
/// cachedref. But it saves on the length which is significant for the concrete
/// use-case, hence I opted for it.
impl Loadable for Vec<u8> {
    fn load<S: std::io::Read, F: BackingStoreLoad>(
        _loader: &mut F,
        source: &mut S,
    ) -> LoadResult<Self> {
        let mut ret = Vec::new();
        source.read_to_end(&mut ret)?;
        Ok(ret)
    }
}

impl<const N: usize> Loadable for [u8; N] {
    fn load<S: std::io::Read, F: BackingStoreLoad>(
        _loader: &mut F,
        source: &mut S,
    ) -> LoadResult<Self> {
        let mut ret = [0u8; N];
        source.read_exact(&mut ret)?;
        Ok(ret)
    }
}

impl Loadable for u64 {
    #[inline(always)]
    fn load<S: std::io::Read, F: BackingStoreLoad>(
        _loader: &mut F,
        source: &mut S,
    ) -> LoadResult<Self> {
        let x = source.read_u64::<BigEndian>()?;
        Ok(x)
    }
}

impl Loadable for Reference {
    #[inline(always)]
    fn load<S: std::io::Read, F: BackingStoreLoad>(
        loader: &mut F,
        source: &mut S,
    ) -> LoadResult<Self> {
        let reference = u64::load(loader, source)?;
        Ok(reference.into())
    }
}

impl<V: Loadable> Loadable for Hashed<V> {
    fn load<S: std::io::Read, F: BackingStoreLoad>(
        loader: &mut F,
        source: &mut S,
    ) -> LoadResult<Self> {
        let hash = Hash::read(source)?;
        let data = V::load(loader, source)?;
        Ok(Hashed {
            hash,
            data,
        })
    }
}

#[repr(transparent)]
#[derive(Clone, Copy, AsRef, From, PartialEq, Eq, Ord, PartialOrd)]
/// A SHA256 hash.
pub struct Hash {
    hash: [u8; 32],
}

impl AsRef<[u8]> for Hash {
    #[inline(always)]
    fn as_ref(&self) -> &[u8] { self.hash.as_ref() }
}

impl Hash {
    #[inline(always)]
    /// A hash value that consists of 32 `0` bytes.
    pub fn zero() -> Self {
        Self {
            hash: [0u8; 32],
        }
    }

    /// Read a hash value from the provided source, failing if not enough data
    /// is available.
    pub fn read(source: &mut impl Read) -> LoadResult<Self> {
        let mut hash = [0u8; 32];
        source.read_exact(&mut hash)?;
        Ok(Self {
            hash,
        })
    }
}

/// Display the hash in hex.
impl std::fmt::Debug for Hash {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for c in self.hash {
            write!(f, "{:x}", c)?;
        }
        Ok(())
    }
}

/// Compute SHA256 of data given the context. The context is sometimes needed
/// since data is not available in memory and must be first loaded from, e.g.,
/// external storage
pub trait ToSHA256<Ctx> {
    fn hash(&self, ctx: &mut Ctx) -> Hash;
}

impl<Ctx> ToSHA256<Ctx> for u64 {
    #[inline(always)]
    fn hash(&self, _ctx: &mut Ctx) -> Hash {
        let hash: [u8; 32] = sha2::Sha256::digest(&self.to_be_bytes()).into();
        Hash::from(hash)
    }
}

impl<Ctx> ToSHA256<Ctx> for Vec<u8> {
    #[inline(always)]
    fn hash(&self, _ctx: &mut Ctx) -> Hash {
        let mut hasher = sha2::Sha256::new();
        hasher.update(&(self.len() as u64).to_be_bytes());
        hasher.update(self);
        let hash: [u8; 32] = hasher.finalize().into();
        Hash::from(hash)
    }
}

impl<Ctx, const N: usize> ToSHA256<Ctx> for [u8; N] {
    #[inline(always)]
    fn hash(&self, _ctx: &mut Ctx) -> Hash {
        let mut hasher = sha2::Sha256::new();
        hasher.update(&(N as u64).to_be_bytes());
        hasher.update(self);
        let hash: [u8; 32] = hasher.finalize().into();
        Hash::from(hash)
    }
}

#[derive(Debug, Clone)]
/// Data together with a cached hash.
pub struct Hashed<V> {
    pub hash: Hash,
    pub data: V,
}

impl<V> Hashed<V> {
    #[inline(always)]
    pub fn new(hash: Hash, data: V) -> Self {
        Self {
            hash,
            data,
        }
    }
}

impl<V, Ctx> ToSHA256<Ctx> for Hashed<V> {
    #[inline(always)]
    fn hash(&self, _ctx: &mut Ctx) -> Hash { self.hash }
}

#[repr(transparent)]
#[derive(Debug, Clone, Copy, From)]
/// An identifier of an entry stored in the mutable trie.
pub struct EntryId {
    id: usize,
}

impl<A> Index<EntryId> for [A] {
    type Output = A;

    #[inline(always)]
    fn index(&self, index: EntryId) -> &Self::Output { self.index(index.id) }
}

impl<A> Index<EntryId> for Vec<A> {
    type Output = A;

    #[inline(always)]
    fn index(&self, index: EntryId) -> &Self::Output { self.index(index.id) }
}

impl<A> IndexMut<EntryId> for Vec<A> {
    fn index_mut(&mut self, index: EntryId) -> &mut Self::Output { self.index_mut(index.id) }
}

#[derive(Debug, Error, Eq, PartialEq)]
/// An error used to indicate when too many iterators were acquired at the same
/// location in the tree. The maximum number is [u32::MAX].
#[error("Too many iterators at the same root.")]
pub struct TooManyIterators;

#[derive(Debug, Error, Eq, PartialEq)]
/// An error used to indicate that an operation could not be completed because
/// the portion of the trie is locked
#[error("Trying to insert or delete in a locked part of the trie.")]
pub struct AttemptToModifyLockedArea;
