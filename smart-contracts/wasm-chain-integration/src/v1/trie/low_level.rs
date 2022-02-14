use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use derive_more::{AsRef, From, Into};
use sha2::Digest;
use std::{
    collections::HashMap,
    io::{Read, Seek, SeekFrom, Write},
    iter::once,
    slice::Iter,
    sync::{Arc, RwLock, RwLockReadGuard, RwLockWriteGuard},
};
use thiserror::*;

const INLINE_CAPACITY: usize = 8;

#[repr(transparent)]
#[derive(Default, Debug, Clone, Copy, Eq, PartialEq, From, Into)]
/// Reference to a storage location where an item may be retrieved
pub struct Reference {
    reference: u64,
}

#[derive(Debug, Error)]
pub enum WriteError {
    #[error("{0}")]
    IOError(#[from] std::io::Error),
}

pub type StoreResult<A> = Result<A, WriteError>;

#[derive(Debug, Error)]
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

pub type LoadResult<A> = Result<A, LoadError>;

impl Reference {
    #[inline(always)]
    pub fn store(&self, sink: &mut impl std::io::Write) -> StoreResult<()> {
        sink.write_u64::<BigEndian>(self.reference)?;
        Ok(())
    }
}

#[repr(transparent)]
#[derive(Clone, Copy, AsRef, From, PartialEq, Eq, Ord, PartialOrd)]
pub struct Hash {
    hash: [u8; 32],
}

impl AsRef<[u8]> for Hash {
    #[inline(always)]
    fn as_ref(&self) -> &[u8] { self.hash.as_ref() }
}

impl Hash {
    #[inline(always)]
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

#[derive(Debug)]
pub struct Link<V> {
    link: Arc<RwLock<V>>,
}

impl<V> Clone for Link<V> {
    #[inline(always)]
    fn clone(&self) -> Self {
        Self {
            link: self.link.clone(),
        }
    }
}

impl<V> Link<V> {
    pub fn new(value: V) -> Self {
        Self {
            link: Arc::new(RwLock::new(value)),
        }
    }

    #[inline(always)]
    pub fn borrow(&self) -> RwLockReadGuard<'_, V> { self.link.as_ref().read().unwrap() }

    #[inline(always)]
    pub fn borrow_mut(&self) -> RwLockWriteGuard<'_, V> { self.link.as_ref().write().unwrap() }

    #[inline(always)]
    pub fn try_unwrap(self) -> Result<V, Self> {
        Arc::try_unwrap(self.link)
            .map_err(|link| Link {
                link,
            })
            .map(|rc| rc.into_inner().expect("Thread panicked."))
    }
}

pub trait ToSHA256<Ctx> {
    fn hash(&self, ctx: &mut Ctx) -> Hash;
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

#[derive(Debug, Clone)]
pub enum CachedRef<V> {
    Disk {
        key: Reference,
    },
    Memory {
        value: V,
    },
    Cached {
        key:   Reference,
        value: V,
    },
}

/// The default hash implementation is not a valid value.
impl<V> Default for CachedRef<V> {
    fn default() -> Self {
        CachedRef::Disk {
            key: Default::default(),
        }
    }
}

impl<V: Loadable> CachedRef<V> {
    #[inline(always)]
    pub fn get(&self, loader: &mut impl FlatLoadable) -> V
    where
        V: Clone, {
        match self {
            CachedRef::Disk {
                key,
                ..
            } => V::load_from_location(loader, *key).unwrap(),
            CachedRef::Memory {
                value,
                ..
            } => value.clone(),
            CachedRef::Cached {
                value,
                ..
            } => value.clone(),
        }
    }

    /// Apply the supplied function to the contained value. The value is loaded
    /// if it is not yet cached. Note that this will **not** cache the
    /// value, the loaded value will be dropped.
    pub fn use_value<X>(&self, loader: &mut impl FlatLoadable, f: impl FnOnce(&V) -> X) -> X {
        match self {
            CachedRef::Disk {
                key,
            } => {
                let loaded = V::load_from_location(loader, *key).unwrap();
                f(&loaded)
            }
            CachedRef::Memory {
                value,
                ..
            } => f(value),
            CachedRef::Cached {
                value,
                ..
            } => f(value),
        }
    }
}

impl<V> CachedRef<V> {
    pub fn new(value: V) -> CachedRef<V> {
        CachedRef::Memory {
            value,
        }
    }

    pub fn load_and_cache<F: FlatLoadable>(&mut self, loader: &mut F) -> &mut V
    where
        V: Loadable, {
        match self {
            CachedRef::Disk {
                key,
            } => {
                let value = V::load_from_location(loader, *key).unwrap(); // TODO: Error handling.
                *self = CachedRef::Cached {
                    key: *key,
                    value,
                };
                if let CachedRef::Cached {
                    value,
                    ..
                } = self
                {
                    value
                } else {
                    unsafe { std::hint::unreachable_unchecked() }
                }
            }
            CachedRef::Memory {
                value,
            } => value,
            CachedRef::Cached {
                value,
                ..
            } => value,
        }
    }

    /// If the value is in memory, set it to cached with the given key.
    /// Otherwise do nothing. This of course has the precondition that the key
    /// stores the value in the relevant backing store. Internal use only.
    fn cache_with(&mut self, key: Reference) {
        if let CachedRef::Memory {
            ..
        } = self
        {
            let value = std::mem::replace(self, CachedRef::Disk {
                key,
            });
            if let CachedRef::Memory {
                value,
            } = value
            {
                *self = CachedRef::Cached {
                    value,
                    key,
                };
            } else {
                // this is unreachable since we hold a mutable reference to the cached value
                // and we know the value was a purely in-memory one
                unsafe { std::hint::unreachable_unchecked() }
            }
        }
    }

    pub fn store_and_cache<S: FlatStorable, W: std::io::Write>(
        &mut self,
        backing_store: &mut S,
        buf: &mut W,
    ) -> StoreResult<()>
    where
        V: AsRef<[u8]>, {
        match self {
            CachedRef::Disk {
                key,
            } => key.store(buf),
            CachedRef::Memory {
                value,
            } => {
                let key = backing_store.store_raw(value.as_ref())?;
                let value = std::mem::replace(self, CachedRef::Disk {
                    key,
                });
                if let CachedRef::Memory {
                    value,
                } = value
                {
                    *self = CachedRef::Cached {
                        value,
                        key,
                    };
                } else {
                    // this is unreachable since we hold a mutable reference to the cached value
                    // and we know the value was a purely in-memory one
                    unsafe { std::hint::unreachable_unchecked() }
                }
                key.store(buf)
            }
            CachedRef::Cached {
                key,
                ..
            } => key.store(buf),
        }
    }

    /// Get a mutable reference to the value, **if it is only in memory**.
    /// Otherwise return the key.
    #[inline]
    pub fn get_mut_or_key(&mut self) -> Result<&mut V, Reference> {
        match self {
            CachedRef::Disk {
                key,
            } => Err(*key),
            CachedRef::Memory {
                value,
            } => Ok(value),
            CachedRef::Cached {
                key,
                ..
            } => Err(*key),
        }
    }

    /// Get a mutable reference to the value, **if it is memory or cached**.
    /// If it is only on disk return None
    #[inline]
    pub fn get_value(self) -> Option<V> {
        match self {
            CachedRef::Disk {
                ..
            } => None,
            CachedRef::Memory {
                value,
            } => Some(value),
            CachedRef::Cached {
                value,
                ..
            } => Some(value),
        }
    }
}

pub type Key = u8;

#[derive(Debug, Clone)]
enum Stem {
    // the first byte is length, remaining is data.
    Short([u8; 16]),
    Long(Arc<[Key]>),
}

impl Stem {
    pub fn empty() -> Self { Self::Short([0u8; 16]) }

    fn extend(&mut self, mid: u8, second: &[u8]) {
        match self {
            Stem::Short(buf) => {
                let cur_len = usize::from(buf[0]);
                if cur_len + 1 + second.len() <= 15 {
                    buf[0] += 1 + second.len() as u8;
                    buf[cur_len + 1] = mid;
                    buf[cur_len + 2..cur_len + 2 + second.len()].copy_from_slice(second);
                } else {
                    let new = buf[1..cur_len + 1]
                        .iter()
                        .copied()
                        .chain(once(mid))
                        .chain(second.iter().copied())
                        .collect();
                    *self = Stem::Long(new);
                }
            }
            Stem::Long(arc) => {
                let new = arc
                    .as_ref()
                    .iter()
                    .copied()
                    .chain(once(mid))
                    .chain(second.iter().copied())
                    .collect();
                *self = Stem::Long(new);
            }
        }
    }
}

impl From<&[u8]> for Stem {
    #[inline(always)]
    fn from(s: &[u8]) -> Self {
        let len = s.len();
        if len <= 15 {
            let mut buf = [0u8; 16];
            buf[0] = len as u8;
            buf[1..1 + len].copy_from_slice(s);
            Self::Short(buf)
        } else {
            Self::Long(Arc::from(s))
        }
    }
}

impl From<Vec<u8>> for Stem {
    #[inline(always)]
    fn from(s: Vec<u8>) -> Self {
        let len = s.len();
        if len <= 15 {
            let mut buf = [0u8; 16];
            buf[0] = len as u8;
            buf[1..1 + len].copy_from_slice(&s);
            Self::Short(buf)
        } else {
            Self::Long(Arc::from(s))
        }
    }
}

// impl FromIterator<u8> for Stem {
//     #[inline(always)]
//     fn from_iter<T: IntoIterator<Item = u8>>(iter: T) -> Self where
//     {
//         let iter = iter.into_iter();
//         let len = iter.len();
//         if len < 15 {
//             let mut buf = [0u8; 16];
//             buf[0] = len as u8;
//             for (place, value) in buf[1..1+len].iter_mut().zip(iter) {
//                 *place = value;
//             }
//             Self::Short(buf)
//         } else {
//             Self::Long(Arc::from(iter))
//         }
//     }
// }

impl AsRef<[u8]> for Stem {
    #[inline(always)]
    fn as_ref(&self) -> &[u8] {
        match self {
            Stem::Short(s) => {
                let len = usize::from(s[0]);
                &s[1..1 + len]
            }
            Stem::Long(arc) => arc.as_ref(),
        }
    }
}

/// Recursive link to a child node.
type ChildLink<V> = Link<CachedRef<Hashed<Node<V>>>>;

#[derive(Debug)]
/// A persistent node. Cloning this is cheap, it only copies pointers and
/// increments reference counts.
pub struct Node<V> {
    /// Since a single node owns each value using Hashed<Cached<V>>
    /// here makes sense, it makes it so that the hash is stored inline.
    value:    Option<Link<Hashed<CachedRef<V>>>>,
    path:     Stem,
    // TODO: It might be better to have just an array or Box here.
    // The Rc has an advantage when thawing since we only copy the Rc
    // but is otherwise annoying.
    // In contrast to Hashed<Cached<..>> above for the value, here we store the hash
    // behind a pointer indirection. The reason for this is that there are going to be many
    // pointers to the same node, and we want to avoid duplicating node hashes.
    children: Vec<(Key, ChildLink<V>)>,
}

impl<V> Drop for Node<V> {
    fn drop(&mut self) {
        let mut stack = Vec::new();
        // if we are the only owner of the children we can deallocate them.
        let children = std::mem::take(&mut self.children);
        for (_, child) in children.into_iter() {
            if let Ok(only_child) = child.try_unwrap() {
                if let Some(memory_child) = only_child.get_value() {
                    stack.push(memory_child.data);
                }
            }
        }
        while let Some(mut node) = stack.pop() {
            let children = std::mem::take(&mut node.children);
            for (_, child) in children.into_iter() {
                if let Ok(only_child) = child.try_unwrap() {
                    if let Some(memory_child) = only_child.get_value() {
                        stack.push(memory_child.data);
                    }
                }
            }
        }
    }
}

impl<V> Clone for Node<V> {
    fn clone(&self) -> Self {
        Self {
            value:    self.value.clone(),
            path:     self.path.clone(),
            children: self.children.clone(),
        }
    }
}

#[derive(Debug, Clone)]
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

impl<Ctx> ToSHA256<Ctx> for Vec<u8> {
    #[inline(always)]
    fn hash(&self, _ctx: &mut Ctx) -> Hash {
        let mut hasher = sha2::Sha256::new();
        hasher.update(&(self.len() as u64).to_be_bytes());
        hasher.update(self);
        let hash = hasher.finalize().into();
        Hash {
            hash,
        }
    }
}

impl<Ctx, const N: usize> ToSHA256<Ctx> for [u8; N] {
    #[inline(always)]
    fn hash(&self, _ctx: &mut Ctx) -> Hash {
        let mut hasher = sha2::Sha256::new();
        hasher.update(&(N as u64).to_be_bytes());
        hasher.update(self);
        let hash = hasher.finalize().into();
        Hash {
            hash,
        }
    }
}

impl<V, Ctx> ToSHA256<Ctx> for Hashed<V> {
    #[inline(always)]
    fn hash(&self, _ctx: &mut Ctx) -> Hash { self.hash }
}

impl<V: Loadable, Ctx: FlatLoadable> ToSHA256<Ctx> for CachedRef<Hashed<V>>
where
    V: ToSHA256<Ctx>,
{
    #[inline(always)]
    fn hash(&self, ctx: &mut Ctx) -> Hash { self.use_value(ctx, |v| v.hash(&mut ())) }
}

// TODO: Review and revise for security and correctness.
impl<V, Ctx: FlatLoadable> ToSHA256<Ctx> for Node<V> {
    fn hash(&self, ctx: &mut Ctx) -> Hash {
        let mut hasher = sha2::Sha256::new();
        match &self.value {
            Some(value) => {
                hasher.update(&[1]);
                hasher.update(value.borrow().hash(ctx));
            }
            None => hasher.update(&[0]),
        }
        hasher.update(&self.path);
        let mut child_hasher = sha2::Sha256::new();
        child_hasher.update(&(self.children.len() as u16).to_be_bytes());
        for child in self.children.iter() {
            child_hasher.update(&[child.0]);
            child_hasher.update(child.1.borrow().hash(ctx));
        }
        hasher.update(child_hasher.finalize());
        Hash {
            hash: hasher.finalize().into(),
        }
    }
}

impl<Ctx> ToSHA256<Ctx> for u64 {
    #[inline(always)]
    fn hash(&self, _ctx: &mut Ctx) -> Hash {
        let hash = sha2::Sha256::digest(&self.to_be_bytes()).into();
        Hash {
            hash,
        }
    }
}

#[derive(Debug)]
struct MutableNode<V> {
    generation: u32,
    /// Pointer to the table of entries, if the node has a value.
    value:      Option<usize>,
    path:       Stem,
    children:   ChildrenCow<V>,
    /// Whether it is allowed to remove this node or append new children.
    /// Hence when a node is associated with an iterator it is not allowed to
    /// remove it or appending/removing new children.
    locked:     bool,
}

impl<V> ChildrenCow<V> {
    #[inline]
    fn len(&self) -> usize {
        match self {
            ChildrenCow::Borrowed(b) => b.len(),
            ChildrenCow::Owned {
                value,
                ..
            } => value.len(),
        }
    }
}

impl<V> Default for MutableNode<V> {
    fn default() -> Self {
        Self {
            generation: 0,
            value:      None,
            path:       Stem::empty(),
            children:   ChildrenCow::Owned {
                generation: 0,
                value:      tinyvec::TinyVec::new(),
            },
            locked:     false,
        }
    }
}

impl<V> MutableNode<V> {
    pub fn migrate(&self, entries: &mut Vec<Entry>, generation: u32) -> Self {
        let value = if let Some(idx) = self.value {
            let new_entry_idx = entries.len();
            let entry = entries[idx];
            let new_entry = if let Entry::Mutable {
                entry_idx,
            } = entry
            {
                Entry::ReadOnly {
                    entry_idx,
                    borrowed: false,
                }
            } else {
                entry
            };
            entries.push(new_entry);
            Some(new_entry_idx)
        } else {
            None
        };
        Self {
            generation,
            value,
            path: self.path.clone(), // this is a cheap clone as well.
            children: self.children.clone(),
            locked: self.locked,
        }
    }
}

#[derive(Debug, Clone, Copy)]
/// A checkpoint that is saved for a mutable trie so that we can cleanup on
/// state rollback. It stores which items were alive at the time of the
/// checkpoint, utilizing the fact that items are always just added to the end
/// of the relevant collections.
pub struct Checkpoint {
    pub num_nodes:          usize,
    pub num_values:         usize,
    pub num_borrowed_nodes: usize,
    pub num_entries:        usize,
}

#[derive(Debug)]
pub struct MutableTrie<V> {
    /// Roots for previous generations. The value is None if the tree for that
    /// generation is empty. The second component of the pair is the number
    /// of nodes that exist at the previous generation. This is used for
    /// pushing and popping generations.
    generation_roots: Vec<(Option<usize>, Checkpoint)>,
    entries:          Vec<Entry>,
    values:           Vec<V>,
    borrowed_values:  Vec<Link<Hashed<CachedRef<V>>>>,
    nodes:            Vec<MutableNode<V>>,
}

#[derive(Debug)]
enum ChildrenCow<V> {
    Borrowed(Vec<(Key, ChildLink<V>)>),
    Owned {
        generation: u32,
        value:      tinyvec::TinyVec<[KeyIndexPair; INLINE_CAPACITY]>,
    },
}

fn freeze_value<Ctx, V: Default + ToSHA256<Ctx>>(
    borrowed_values: &mut [Link<Hashed<CachedRef<V>>>],
    owned_values: &mut [V],
    entries: &[Entry],
    mutable: Option<usize>,
    loader: &mut Ctx,
) -> Option<Link<Hashed<CachedRef<V>>>> {
    let entry_idx = mutable?;
    match entries[entry_idx] {
        Entry::ReadOnly {
            borrowed,
            entry_idx,
            ..
        } => {
            if borrowed {
                Some(borrowed_values[entry_idx].clone())
            } else {
                let value = std::mem::take(&mut owned_values[entry_idx]);
                let hash = value.hash(loader);
                Some(Link::new(Hashed::new(hash, CachedRef::Memory {
                    value,
                })))
            }
        }
        Entry::Mutable {
            entry_idx,
            ..
        } => {
            let value = std::mem::take(&mut owned_values[entry_idx]);
            let hash = value.hash(loader);
            Some(Link::new(Hashed::new(hash, CachedRef::Memory {
                value,
            })))
        }
        Entry::Deleted => None,
    }
}

#[repr(transparent)]
#[derive(Default, Debug, Clone, Copy)]
struct KeyIndexPair {
    pub pair: usize,
}

impl KeyIndexPair {
    #[inline(always)]
    pub fn key(self) -> Key { (self.pair >> 56) as u8 }

    #[inline(always)]
    pub fn index(self) -> usize { self.pair & 0x00ff_ffff_ffff_ffff }

    #[inline(always)]
    pub fn new(key: Key, index: usize) -> Self {
        let pair = usize::from(key) << 56 | index;
        Self {
            pair,
        }
    }
}

impl<V> Clone for ChildrenCow<V> {
    fn clone(&self) -> Self {
        match self {
            ChildrenCow::Borrowed(rc) => ChildrenCow::Borrowed(rc.clone()),
            ChildrenCow::Owned {
                generation,
                value,
            } => ChildrenCow::Owned {
                generation: *generation,
                value:      value.clone(),
            },
        }
    }
}

pub trait Loadable: Sized {
    fn load<S: std::io::Read, F: FlatLoadable>(loader: &mut F, source: &mut S) -> LoadResult<Self>;

    fn load_from_location<F: FlatLoadable>(
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
    fn load<S: std::io::Read, F: FlatLoadable>(
        _loader: &mut F,
        source: &mut S,
    ) -> LoadResult<Self> {
        let mut ret = Vec::new();
        source.read_to_end(&mut ret)?;
        Ok(ret)
    }
}

impl<const N: usize> Loadable for [u8; N] {
    fn load<S: std::io::Read, F: FlatLoadable>(
        _loader: &mut F,
        source: &mut S,
    ) -> LoadResult<Self> {
        let mut ret = [0u8; N];
        source.read_exact(&mut ret)?;
        Ok(ret)
    }
}

pub trait FlatStorable {
    /// Store the provided value and return a reference that can be used
    /// to load it.
    fn store_raw(&mut self, data: &[u8]) -> Result<Reference, WriteError>;
}

pub trait FlatLoadable {
    type R: AsRef<[u8]>;
    /// Store the provided value and return a reference that can be used
    /// to load it.
    fn load_raw(&mut self, location: Reference) -> LoadResult<Self::R>;
}

impl FlatStorable for Vec<u8> {
    fn store_raw(&mut self, data: &[u8]) -> Result<Reference, WriteError> {
        let len = self.len();
        let data_len = data.len() as u64;
        self.extend_from_slice(&data_len.to_be_bytes());
        self.extend_from_slice(data);
        Ok((len as u64).into())
    }
}
#[derive(Debug)]
pub struct Storable<X> {
    inner: X,
}

impl<X: Seek + Write> FlatStorable for Storable<X> {
    fn store_raw(&mut self, data: &[u8]) -> Result<Reference, WriteError> {
        let pos = self.inner.seek(SeekFrom::Current(0))?;
        let data_len = data.len() as u32;
        self.inner.write_u32::<BigEndian>(data_len)?;
        self.inner.write_all(data)?;
        Ok(pos.into())
    }
}

/// Generic wrapper for a loader. This implements loadable for any S that
/// implements Seek + Read.
pub struct Loader<S> {
    pub inner: S,
}

impl<S> Loader<S> {
    pub fn new(file: S) -> Self {
        Self {
            inner: file,
        }
    }
}

impl<'a, A: AsRef<[u8]>> FlatLoadable for Loader<A> {
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

impl Loadable for u64 {
    #[inline(always)]
    fn load<S: std::io::Read, F: FlatLoadable>(
        _loader: &mut F,
        source: &mut S,
    ) -> LoadResult<Self> {
        let x = source.read_u64::<BigEndian>()?;
        Ok(x)
    }
}
impl Loadable for Reference {
    #[inline(always)]
    fn load<S: std::io::Read, F: FlatLoadable>(loader: &mut F, source: &mut S) -> LoadResult<Self> {
        let reference = u64::load(loader, source)?;
        Ok(reference.into())
    }
}

impl<V: Loadable> Loadable for Hashed<V> {
    fn load<S: std::io::Read, F: FlatLoadable>(loader: &mut F, source: &mut S) -> LoadResult<Self> {
        let hash = Hash::read(source)?;
        let data = V::load(loader, source)?;
        Ok(Hashed {
            hash,
            data,
        })
    }
}

impl<V> Loadable for CachedRef<V> {
    #[inline(always)]
    fn load<S: std::io::Read, F: FlatLoadable>(loader: &mut F, source: &mut S) -> LoadResult<Self> {
        let reference = Reference::load(loader, source)?;
        Ok(CachedRef::Disk {
            key: reference,
        })
    }
}

impl<V> Loadable for Node<V> {
    fn load<S: std::io::Read, F: FlatLoadable>(loader: &mut F, source: &mut S) -> LoadResult<Self> {
        let tag = source.read_u8()?;
        let path_len = if tag & 0b1000_0000 == 0 {
            // stem length is encoded in the tag
            u32::from(tag & 0b0011_1111)
        } else {
            // stem length follows as a u32
            source.read_u32::<BigEndian>()?
        };
        let mut path = vec![0u8; path_len as usize];
        source.read_exact(&mut path)?;
        let path = Stem::from(path);
        let value = if (tag & 0b100_0000) != 0 {
            let val = Hashed::<CachedRef<V>>::load(loader, source)?;
            Some(Link::new(val))
        } else {
            None
        };
        let num_branches = source.read_u16::<BigEndian>()?;
        let mut branches = Vec::with_capacity(num_branches.into());
        for _ in 0..num_branches {
            let key = source.read_u8()?;
            let reference = CachedRef::<Hashed<Node<V>>>::load(loader, source)?;
            branches.push((key, Link::new(reference)));
        }
        Ok(Node {
            value,
            path,
            children: branches,
        })
    }
}

impl<V: Loadable> Node<V> {
    /// The entire tree in memory.
    pub fn cache<F: FlatLoadable>(&mut self, loader: &mut F) {
        if let Some(v) = self.value.as_mut() {
            v.borrow_mut().data.load_and_cache(loader);
        }
        let mut stack = Vec::new();
        for c in self.children.iter() {
            stack.push(c.1.clone());
        }
        while let Some(node) = stack.pop() {
            let mut node_borrow = node.borrow_mut();
            let node = node_borrow.load_and_cache(loader);
            if let Some(v) = node.data.value.as_mut() {
                v.borrow_mut().data.load_and_cache(loader);
            }
            for c in node.data.children.iter() {
                stack.push(c.1.clone());
            }
        }
    }
}

impl<V: AsRef<[u8]>> Hashed<Node<V>> {
    pub fn store_update<S: FlatStorable>(
        &mut self,
        backing_store: &mut S,
    ) -> Result<Vec<u8>, WriteError> {
        let mut buf = Vec::new();
        self.store_update_buf(backing_store, &mut buf)?;
        Ok(buf)
    }

    pub fn store_update_buf<S: FlatStorable, W: std::io::Write>(
        &mut self,
        backing_store: &mut S,
        buf: &mut W,
    ) -> StoreResult<()> {
        buf.write_all(&self.hash.as_ref())?;
        self.data.store_update_buf(backing_store, buf)
    }
}

impl<V: AsRef<[u8]>> Node<V> {
    pub fn store_update_buf<S: FlatStorable, W: std::io::Write>(
        &mut self,
        backing_store: &mut S,
        buf: &mut W,
    ) -> StoreResult<()> {
        let mut stack = Vec::new();
        for (_, ch) in self.children.iter().rev() {
            stack.push((ch.clone(), false));
        }
        let store_node = |node: &mut Node<V>,
                          buf: &mut Vec<u8>,
                          backing_store: &mut S,
                          ref_stack: &mut Vec<Reference>|
         -> StoreResult<()> {
            let stem_len = node.path.as_ref().len();
            let value_mask: u8 = if node.value.is_none() {
                0
            } else {
                0b0100_0000
            };
            // if the first bit is 0 then the first byte encodes
            // path length + presence of value
            if stem_len <= 0b0011_1111 {
                let tag = stem_len as u8 | value_mask;
                buf.write_u8(tag)?;
            } else {
                // TODO: We could optimize this as well by using variable-length encoding.
                // But it probably does not matter in practice since paths should really always
                // be < 64 in length.
                let tag = 0b1000_0000 | value_mask;
                buf.write_u8(tag)?;
                buf.write_u32::<BigEndian>(stem_len as u32)?;
            }
            // store the path
            buf.write_all(node.path.as_ref())?;
            // store the value
            if let Some(v) = &mut node.value {
                let mut borrowed = v.borrow_mut();
                buf.write_all(borrowed.hash.as_ref())?;
                borrowed.data.store_and_cache(backing_store, buf)?;
            }
            // TODO: Revise this when branching on 4 bits.
            // now store the children.
            buf.write_u16::<BigEndian>(node.children.len() as u16)?;
            for (k, _) in node.children.iter() {
                buf.write_u8(*k)?;
                ref_stack.pop().unwrap().store(buf)?;
            }
            Ok(())
        };
        let mut ref_stack = Vec::<Reference>::new();
        let mut tmp_buf = Vec::new();
        while let Some((node_ref, children_processed)) = stack.pop() {
            let node_ref_clone = node_ref.clone();
            let mut node_ref_mut = node_ref.borrow_mut();
            match node_ref_mut.get_mut_or_key() {
                Ok(hashed_node) => {
                    if children_processed {
                        tmp_buf.clear();
                        tmp_buf.write_all(hashed_node.hash.as_ref())?;
                        store_node(
                            &mut hashed_node.data,
                            &mut tmp_buf,
                            backing_store,
                            &mut ref_stack,
                        )?;
                        let key = backing_store.store_raw(&tmp_buf)?;
                        ref_stack.push(key);
                        node_ref_mut.cache_with(key);
                    } else {
                        stack.push((node_ref_clone, true));
                        for (_, ch) in hashed_node.data.children.iter().rev() {
                            stack.push((ch.clone(), false));
                        }
                    }
                }
                Err(key) => {
                    ref_stack.push(key);
                }
            }
        }
        tmp_buf.clear();
        store_node(self, &mut tmp_buf, backing_store, &mut ref_stack)?;
        buf.write_all(&tmp_buf)?;
        Ok(())
    }
}

/// Make the children owned, and return whether the node has a value, and a
/// mutable reference to the children.
fn make_owned<'a, 'b, V>(
    idx: usize,
    borrowed_values: &mut Vec<Link<Hashed<CachedRef<V>>>>,
    owned_nodes: &'a mut Vec<MutableNode<V>>,
    entries: &'a mut Vec<Entry>,
    loader: &'b mut impl FlatLoadable,
) -> (bool, &'a mut tinyvec::TinyVec<[KeyIndexPair; INLINE_CAPACITY]>) {
    let owned_nodes_len = owned_nodes.len();
    let node = unsafe { owned_nodes.get_unchecked(idx) };
    let node_generation = node.generation;
    let has_value = node.value.is_some();
    let res = {
        match &node.children {
            ChildrenCow::Borrowed(children) => {
                let mut new_nodes = Vec::with_capacity(children.len());
                let c = children
                    .clone()
                    .iter()
                    .zip(owned_nodes_len..)
                    .map(|((k, node), idx)| {
                        new_nodes.push(node.borrow().thaw(
                            borrowed_values,
                            entries,
                            node_generation,
                            loader,
                        ));
                        KeyIndexPair::new(*k, idx)
                    })
                    .collect();
                Some((new_nodes, c))
            }
            ChildrenCow::Owned {
                generation,
                value,
            } => {
                if *generation == node_generation {
                    None
                } else {
                    let mut new_nodes = Vec::with_capacity(value.len());
                    let c = value
                        .iter()
                        .zip(owned_nodes_len..)
                        .map(|(pair, idx)| {
                            new_nodes
                                .push(owned_nodes[pair.index()].migrate(entries, node_generation));
                            KeyIndexPair::new(pair.key(), idx)
                        })
                        .collect();
                    Some((new_nodes, c))
                }
            }
        }
    };
    if let Some((mut to_add, children)) = res {
        owned_nodes.append(&mut to_add);
        let node = unsafe { owned_nodes.get_unchecked_mut(idx) };
        node.children = ChildrenCow::Owned {
            generation: node_generation,
            value:      children,
        };
    }
    match &mut unsafe { owned_nodes.get_unchecked_mut(idx) }.children {
        ChildrenCow::Borrowed(_) => unsafe { std::hint::unreachable_unchecked() },
        ChildrenCow::Owned {
            value: ref mut children,
            ..
        } => (has_value, children),
    }
}

#[derive(Debug, Clone, Copy)]
enum Entry {
    /// An entry is only borrowed as a read-only entry.
    ReadOnly {
        /// Link to the actual entry. If in the borrowed array then this is
        /// true.
        borrowed:  bool,
        entry_idx: usize,
    },
    /// An entry has been made mutable for the relevant generation.
    Mutable {
        /// Index in the array of values. Borrowed entries are never mutable,
        /// so this is an index in the array of normal entries.
        entry_idx: usize,
    },
    /// The entry is deleted.
    Deleted,
}

type Position = u16;

#[derive(Debug)]
pub struct Iterator {
    /// pointer to the table of nodes.
    pub(crate) root:       usize,
    /// Key at the current position of the iterator.
    pub(crate) key:        Vec<u8>,
    /// Next child to look at. This is None if
    /// we have to give out the value at the current node, and Some(_)
    /// otherwise.
    pub(crate) next_child: Option<Position>,
    /// Stack of parents and next positions, and key lengths of parents
    pub(crate) stack:      Vec<(usize, Position, usize)>,
}

impl Iterator {
    pub fn get_key(&self) -> &[u8] { &self.key }
}

impl<V> CachedRef<Hashed<Node<V>>> {
    fn thaw(
        &self,
        borrowed_values: &mut Vec<Link<Hashed<CachedRef<V>>>>,
        entries: &mut Vec<Entry>,
        generation: u32,
        loader: &mut impl FlatLoadable,
    ) -> MutableNode<V> {
        match self {
            CachedRef::Disk {
                key,
                ..
            } => {
                let node: Node<V> =
                    Node::<V>::load_from_location(loader, *key).expect("Failed to read.");
                node.thaw(borrowed_values, entries, generation)
            }
            CachedRef::Memory {
                value,
                ..
            } => value.data.thaw(borrowed_values, entries, generation),
            CachedRef::Cached {
                value,
                ..
            } => value.data.thaw(borrowed_values, entries, generation),
        }
    }
}

impl<V> Node<V> {
    fn thaw(
        &self,
        borrowed_values: &mut Vec<Link<Hashed<CachedRef<V>>>>,
        entries: &mut Vec<Entry>,
        generation: u32,
    ) -> MutableNode<V> {
        let entry = self.value.as_ref().map(|v| {
            let entry_idx = borrowed_values.len();
            borrowed_values.push(v.clone());
            Entry::ReadOnly {
                borrowed: true,
                entry_idx,
            }
        });
        let entry_idx = entry.map(|e| {
            let len = entries.len();
            entries.push(e);
            len
        });
        MutableNode {
            generation,
            value: entry_idx,
            path: self.path.clone(),
            children: ChildrenCow::Borrowed(self.children.clone()),
            locked: false,
        }
    }

    pub fn make_mutable(&self, generation: u32) -> MutableTrie<V> {
        let mut borrowed_values = Vec::new();
        let mut entries = Vec::new();
        let root_node = self.thaw(&mut borrowed_values, &mut entries, generation);
        MutableTrie {
            generation_roots: vec![(Some(0), Checkpoint {
                num_nodes:          0,
                num_values:         0,
                num_borrowed_nodes: 0,
                num_entries:        0,
            })],
            values: Vec::new(),
            nodes: vec![root_node],
            borrowed_values,
            entries,
        }
    }
}

impl<V> MutableTrie<V> {
    pub fn empty() -> Self {
        Self {
            generation_roots: vec![(None, Checkpoint {
                num_nodes:          0,
                num_values:         0,
                num_borrowed_nodes: 0,
                num_entries:        0,
            })],
            values:           Vec::new(),
            nodes:            Vec::new(),
            borrowed_values:  Vec::new(),
            entries:          Vec::new(),
        }
    }

    /// Check whether the current generation is an empty tree.
    pub fn is_empty(&self) -> bool { self.generation_roots.last().map_or(false, |x| x.0.is_none()) }
}

pub type EntryId = usize;

impl<V> MutableTrie<V> {
    pub fn new_generation(&mut self) {
        let num_nodes = self.nodes.len();
        let num_values = self.values.len();
        let num_borrowed_nodes = self.borrowed_values.len();
        let num_entries = self.entries.len();
        if let Some((maybe_root_idx, _)) = self.generation_roots.last() {
            if let Some(root_idx) = maybe_root_idx {
                let root = &self.nodes[*root_idx];
                let current_generation = root.generation;
                let new_root_node = root.migrate(&mut self.entries, current_generation + 1);
                let new_root_idx = self.nodes.len();
                self.nodes.push(new_root_node);
                self.generation_roots.push((Some(new_root_idx), Checkpoint {
                    num_nodes,
                    num_values,
                    num_borrowed_nodes,
                    num_entries,
                }));
            } else {
                self.generation_roots.push((None, Checkpoint {
                    num_nodes,
                    num_values,
                    num_borrowed_nodes,
                    num_entries,
                }));
            }
        }
    }

    /// Pop a generation, removing all data that is only accessible from newer
    /// generations. Return None if no generations are left.
    pub fn pop_generation(&mut self) -> Option<()> {
        let (_, num_remaining) = self.generation_roots.pop()?;
        self.nodes.truncate(num_remaining.num_nodes);
        self.values.truncate(num_remaining.num_values);
        self.borrowed_values.truncate(num_remaining.num_borrowed_nodes);
        self.entries.truncate(num_remaining.num_entries);
        Some(())
    }

    /// Modify the tree so that the given root is the latest trie generation.
    /// If that root is already the latest, or does not even exist, this does
    /// nothing.
    pub fn normalize(&mut self, root: u32) {
        let new_len = root as usize + 1;
        let one_past_new_root = self.generation_roots.get(new_len).copied();
        if let Some((_, num_remaining)) = one_past_new_root {
            self.generation_roots.truncate(new_len);
            self.nodes.truncate(num_remaining.num_nodes);
            self.values.truncate(num_remaining.num_values);
            self.borrowed_values.truncate(num_remaining.num_borrowed_nodes);
            self.entries.truncate(num_remaining.num_entries);
        }
    }

    /// Get a mutable reference to an entry, if the entry exists. This copies
    /// the data pointed to by the entry unless the entry was already
    /// mutable.
    pub fn get_mut(&mut self, entry: EntryId, loader: &mut impl FlatLoadable) -> Option<&mut V>
    where
        V: Clone + Loadable, {
        let values = &mut self.values;
        let borrowed_entries = &mut self.borrowed_values;
        let entries = &mut self.entries;
        match entries[entry] {
            Entry::ReadOnly {
                borrowed,
                entry_idx,
            } => {
                let value_idx = values.len();
                if borrowed {
                    values.push(borrowed_entries[entry_idx].borrow().data.get(loader));
                } else {
                    values.push(values[entry_idx].clone());
                }
                self.entries[entry] = Entry::Mutable {
                    entry_idx: value_idx,
                };
                values.last_mut()
            }
            Entry::Mutable {
                entry_idx,
            } => values.get_mut(entry_idx),
            Entry::Deleted => None,
        }
    }

    pub fn next(
        &mut self,
        loader: &mut impl FlatLoadable,
        iterator: &mut Iterator,
    ) -> Option<EntryId> {
        let owned_nodes = &mut self.nodes;
        let borrowed_values = &mut self.borrowed_values;
        let entries = &mut self.entries;
        loop {
            let node_idx = iterator.root;
            let node = &owned_nodes[node_idx];
            let next_child = if let Some(next_child) = iterator.next_child {
                next_child
            } else {
                iterator.next_child = Some(0);
                if node.value.is_some() {
                    return node.value;
                }
                0
            };
            if usize::from(next_child) < node.children.len() {
                // we have to visit this child.
                iterator.stack.push((node_idx, next_child + 1, iterator.key.len()));
                iterator.next_child = None;
                let (_, children) =
                    make_owned(node_idx, borrowed_values, owned_nodes, entries, loader);
                let child = children[usize::from(next_child)];
                iterator.root = child.index();
                iterator.key.push(child.key());
                iterator.key.extend_from_slice(owned_nodes[iterator.root].path.as_ref());
            } else {
                // pop back up.
                if let Some((parent_idx, next_child, key_len)) = iterator.stack.pop() {
                    iterator.key.truncate(key_len);
                    iterator.root = parent_idx;
                    iterator.next_child = Some(next_child);
                } else {
                    // we are done
                    return None;
                }
            }
        }
    }

    pub fn iter_delete(&mut self, loader: &mut impl FlatLoadable, iterator: &mut Iterator) {
        while let Some(entry) = self.next(loader, iterator) {
            match self.entries[entry] {
                Entry::ReadOnly {
                    borrowed,
                    entry_idx,
                } => {
                    todo!()
                }
                Entry::Mutable {
                    entry_idx,
                } => {
                    let owned_nodes = &mut self.nodes;
                    let node = unsafe { owned_nodes.get_unchecked_mut(entry_idx) };
                    node.locked = false;
                }
                Entry::Deleted => todo!(),
            }
        }
    }

    pub fn iter(&mut self, loader: &mut impl FlatLoadable, key: &[Key]) -> Option<Iterator> {
        let mut key_iter = key.iter();
        let owned_nodes = &mut self.nodes;
        let borrowed_values = &mut self.borrowed_values;
        let entries = &mut self.entries;
        let mut node_idx = self.generation_roots.last()?.0?;
        loop {
            let node = unsafe { owned_nodes.get_unchecked_mut(node_idx) };
            // We lock the node for modifications
            node.locked = true;
            let mut stem_iter = node.path.as_ref().iter();
            match follow_stem(&mut key_iter, &mut stem_iter) {
                FollowStem::Equal => {
                    return Some(Iterator {
                        root:       node_idx,
                        key:        key.into(),
                        next_child: None,
                        stack:      Vec::new(),
                    })
                }
                FollowStem::KeyIsPrefix {
                    stem_step,
                } => {
                    let stem_slice = stem_iter.as_slice();
                    let mut root_key = Vec::with_capacity(key.len() + 1 + stem_slice.len());
                    root_key.extend_from_slice(key);
                    root_key.push(stem_step);
                    root_key.extend_from_slice(stem_slice);
                    return Some(Iterator {
                        root:       node_idx,
                        key:        root_key,
                        next_child: None,
                        stack:      Vec::new(),
                    });
                }
                FollowStem::StemIsPrefix {
                    key_step,
                } => {
                    let (_, children) =
                        make_owned(node_idx, borrowed_values, owned_nodes, entries, loader);
                    let key_usize = usize::from(key_step) << 56;
                    let pair = children
                        .binary_search_by(|ck| (ck.pair & 0xff00_0000_0000_0000).cmp(&key_usize))
                        .ok()?;
                    node_idx = unsafe { children.get_unchecked(pair) }.index();
                }
                FollowStem::Diff {
                    ..
                } => {
                    return None;
                }
            };
        }
    }

    /// Set the entry value to the given value. Return a mutable reference to
    /// the value if successful. This is analogous to `get_mut`, except that
    /// it avoids copying the value in case the value is currently not owned
    /// for the relevant generation.
    pub fn set(&mut self, entry: EntryId, new_value: V) -> Option<&mut V> {
        let values = &mut self.values;
        let entries = &mut self.entries;
        match entries[entry] {
            Entry::ReadOnly {
                ..
            } => {
                let value_idx = values.len();
                values.push(new_value);
                entries[entry] = Entry::Mutable {
                    entry_idx: value_idx,
                };
                values.last_mut()
            }
            Entry::Mutable {
                entry_idx,
            } => {
                values[entry_idx] = new_value;
                values.get_mut(entry_idx)
            }
            Entry::Deleted => None,
        }
    }

    /// Use the entry. This does not modify any structure.
    pub fn with_entry<X, F>(
        &self,
        entry: EntryId,
        loader: &mut impl FlatLoadable,
        f: F,
    ) -> Option<X>
    where
        F: FnOnce(&V) -> X,
        V: Loadable, {
        let values = &self.values;
        let borrowed_values = &self.borrowed_values;
        match self.entries[entry] {
            Entry::ReadOnly {
                borrowed,
                entry_idx,
            } => {
                if borrowed {
                    borrowed_values.get(entry_idx).map(|v| v.borrow().data.use_value(loader, f))
                } else {
                    values.get(entry_idx).map(f)
                }
            }
            Entry::Mutable {
                entry_idx,
            } => return values.get(entry_idx).map(f),
            Entry::Deleted => None,
        }
    }

    /// TODO: It might be useful to return a list of new nodes so that they
    /// may be persisted quicker than traversing the tree again.
    /// Freeze the current generation. Returns None if the tree was empty.
    pub fn freeze<Ctx: FlatLoadable>(self, loader: &mut Ctx) -> Option<Hashed<Node<V>>>
    where
        V: ToSHA256<Ctx> + Default, {
        let mut owned_nodes = self.nodes;
        let mut values = self.values;
        let entries = self.entries;
        let mut borrowed_values = self.borrowed_values;
        let root_idx = self.generation_roots.last()?.0?;
        // get the reachable owned nodes.
        let mut reachable_stack = vec![root_idx];
        let mut reachable = Vec::new();
        while let Some(idx) = reachable_stack.pop() {
            reachable.push(idx);
            if let ChildrenCow::Owned {
                value,
                ..
            } = &owned_nodes[idx].children
            {
                for c in value.iter() {
                    reachable_stack.push(c.index());
                }
            }
        }
        // The 'reachable' array now has all reachable nodes in the order such that
        // a child of a node is always after the node itself. The root is at the
        // beginning of the array.
        let mut nodes = HashMap::new();
        for node_idx in reachable.into_iter().rev() {
            let node = std::mem::take(&mut owned_nodes[node_idx]);
            match node.children {
                ChildrenCow::Borrowed(children) => {
                    let value = Node {
                        value: freeze_value(
                            &mut borrowed_values,
                            &mut values,
                            &entries,
                            node.value,
                            loader,
                        ),
                        path: node.path,
                        children,
                    };
                    let hash = value.hash(loader);
                    nodes.insert(node_idx, Hashed::new(hash, value));
                }
                ChildrenCow::Owned {
                    value: owned,
                    ..
                } => {
                    let mut children = Vec::with_capacity(owned.len());
                    for child in owned {
                        let child_node = nodes.remove(&child.index()).unwrap();
                        children.push((
                            child.key(),
                            Link::new(CachedRef::Memory {
                                value: child_node,
                            }),
                        ));
                    }
                    let new_node = Node {
                        value: freeze_value(
                            &mut borrowed_values,
                            &mut values,
                            &entries,
                            node.value,
                            loader,
                        ),
                        path: node.path,
                        children,
                    };
                    let hash = new_node.hash(loader);
                    nodes.insert(node_idx, Hashed::new(hash, new_node));
                }
            }
        }
        let mut nodes_iter = nodes.into_iter();
        if let Some((_, root)) = nodes_iter.next() {
            assert!(nodes_iter.next().is_none(), "Invariant violation.");
            Some(root)
        } else {
            unreachable!("Invariant violation. Root not in the nodes map.");
        }
    }

    pub fn get_entry(&mut self, loader: &mut impl FlatLoadable, key: &[Key]) -> Option<EntryId> {
        let mut key_iter = key.iter();
        let owned_nodes = &mut self.nodes;
        let borrowed_values = &mut self.borrowed_values;
        let entries = &mut self.entries;
        let mut node_idx = self.generation_roots.last()?.0?;
        loop {
            let node = unsafe { owned_nodes.get_unchecked(node_idx) };
            match follow_stem(&mut key_iter, &mut node.path.as_ref().iter()) {
                FollowStem::Equal => {
                    return node.value;
                }
                FollowStem::KeyIsPrefix {
                    ..
                } => {
                    return None;
                }
                FollowStem::StemIsPrefix {
                    key_step,
                } => {
                    let (_, children) =
                        make_owned(node_idx, borrowed_values, owned_nodes, entries, loader);
                    let key_usize = usize::from(key_step) << 56;
                    let pair = children
                        .binary_search_by(|ck| (ck.pair & 0xff00_0000_0000_0000).cmp(&key_usize))
                        .ok()?;
                    node_idx = unsafe { children.get_unchecked(pair) }.index();
                }
                FollowStem::Diff {
                    ..
                } => {
                    return None;
                }
            };
        }
    }

    pub fn delete(&mut self, loader: &mut impl FlatLoadable, key: &[Key]) -> Option<EntryId> {
        let mut key_iter = key.iter();
        let owned_nodes = &mut self.nodes;
        let borrowed_values = &mut self.borrowed_values;
        let entries = &mut self.entries;
        let mut father = None;
        let mut node_idx = self.generation_roots.last()?.0?;
        loop {
            let node = unsafe { owned_nodes.get_unchecked_mut(node_idx) };
            if node.locked {
                // The node is locked so we cannot delete it.
                return None;
            }
            match follow_stem(&mut key_iter, &mut node.path.as_ref().iter()) {
                FollowStem::Equal => {
                    // we found it, delete the value first and save it for returning.
                    let rv = std::mem::take(&mut node.value);
                    if let Some(entry) = rv {
                        // We mark the entry as `Deleted` such that other ids pointing to the entry
                        // are automatically invalidated.
                        entries[entry] = Entry::Deleted;
                    }
                    let (_, children) =
                        make_owned(node_idx, borrowed_values, owned_nodes, entries, loader);
                    if children.len() == 1 {
                        // collapse path from father
                        if let Some(child) = children.pop() {
                            let child_1 = std::mem::take(&mut owned_nodes[child.index()]);
                            let node = &mut owned_nodes[node_idx];
                            node.path.extend(child.key(), child_1.path.as_ref());
                            node.children = child_1.children;
                            node.value = child_1.value;
                        }
                    } else if children.is_empty() {
                        // no children are left, and also no value, we need to delete the child from
                        // the father.
                        if let Some((child_idx, father_idx)) = father {
                            let (has_value, father_children) = make_owned(
                                father_idx,
                                borrowed_values,
                                owned_nodes,
                                entries,
                                loader,
                            );
                            father_children.remove(child_idx);
                            // the father must have had
                            // - either at least two children
                            // - or a value
                            // otherwise it would have been path compressed.
                            // if it had a value there is nothing left to do. It must stay as is.
                            // if it had exactly two children we must now path-compress it
                            if !has_value && father_children.len() == 1 {
                                if let Some(child) = father_children.pop() {
                                    let child_1 = std::mem::take(&mut owned_nodes[child.index()]);
                                    let node = &mut owned_nodes[father_idx];
                                    node.path.extend(child.key(), child_1.path.as_ref());
                                    node.children = child_1.children;
                                    node.value = child_1.value;
                                }
                            }
                        } else {
                            // otherwise this must be the root. Delete it.
                            self.generation_roots.last_mut()?.0 = None;
                        }
                    }
                    return rv;
                }
                FollowStem::KeyIsPrefix {
                    ..
                } => {
                    return None;
                }
                FollowStem::StemIsPrefix {
                    key_step,
                } => {
                    let (_, children) =
                        make_owned(node_idx, borrowed_values, owned_nodes, entries, loader);
                    if let Ok(c_idx) = children.binary_search_by(|ck| ck.key().cmp(&key_step)) {
                        let pair = unsafe { children.get_unchecked(c_idx) };
                        father = Some((c_idx, node_idx));
                        node_idx = pair.index();
                    } else {
                        return None;
                    }
                }
                FollowStem::Diff {
                    ..
                } => {
                    return None;
                }
            };
        }
    }

    /// Delete the entire subtree whose keys match the given prefix, that is,
    /// where the given key is a prefix.
    pub fn delete_prefix(&mut self, loader: &mut impl FlatLoadable, key: &[Key]) -> Option<()> {
        let mut key_iter = key.iter();
        let owned_nodes = &mut self.nodes;
        let borrowed_values = &mut self.borrowed_values;
        let entries = &mut self.entries;
        let mut parent_idx = None;
        let mut node_idx = self.generation_roots.last()?.0?;
        loop {
            let node = unsafe { owned_nodes.get_unchecked_mut(node_idx) };
            if node.locked {
                // the subtree is locked so we cannot remove it
                return None;
            }
            match follow_stem(&mut key_iter, &mut node.path.as_ref().iter()) {
                FollowStem::StemIsPrefix {
                    key_step,
                } => {
                    let (_, children) =
                        make_owned(node_idx, borrowed_values, owned_nodes, entries, loader);
                    if let Ok(c_idx) = children.binary_search_by(|ck| ck.key().cmp(&key_step)) {
                        let pair = unsafe { children.get_unchecked(c_idx) };
                        parent_idx = Some((c_idx, node_idx));
                        node_idx = pair.index();
                    } else {
                        return None;
                    }
                }
                FollowStem::Diff {
                    ..
                } => {
                    return None;
                }
                _ => {
                    // invalidate entry of the node and all of its children.
                    // collect the immediate children we need to invalidate.
                    let mut nodes_to_invalidate = vec![node_idx];
                    // traverse each child subtree and invalidate them.
                    while let Some(node_idx) = nodes_to_invalidate.pop() {
                        let to_invalidate = &owned_nodes[node_idx];
                        if let Some(entry) = to_invalidate.value {
                            entries[entry] = Entry::Deleted;
                        }

                        match &to_invalidate.children {
                            ChildrenCow::Borrowed(_) => (),
                            ChildrenCow::Owned {
                                generation,
                                value,
                            } => {
                                if to_invalidate.generation == *generation {
                                    for v in value.iter() {
                                        nodes_to_invalidate.push(v.index())
                                    }
                                }
                            }
                        }
                    }
                    // we found the subtree to remove. Now traverse up and fixup the remaining part
                    // of the tree. if we deleted the root the tree is empty, so set it as such.
                    if let Some((child_idx, parent_idx)) = parent_idx {
                        let (has_value, children) =
                            make_owned(parent_idx, borrowed_values, owned_nodes, entries, loader);

                        children.remove(child_idx);
                        // if the node does not have a value and it has one child, then it should be
                        // collapsed (path compressed)
                        if !has_value && children.len() == 1 {
                            // collapse path.
                            if let Some(child) = children.pop() {
                                let child_1 = std::mem::take(&mut owned_nodes[child.index()]);
                                let node = &mut owned_nodes[parent_idx];
                                node.path.extend(child.key(), child_1.path.as_ref());
                                node.children = child_1.children;
                                node.value = child_1.value;
                            }
                        }
                    } else {
                        self.generation_roots.last_mut()?.0 = None;
                        return Some(());
                    }
                    return Some(());
                }
            };
        }
    }

    /// Returns the new entry id, and potentially an existing one if the value
    /// at the key existed.
    pub fn insert(
        &mut self,
        loader: &mut impl FlatLoadable,
        key: &[Key],
        new_value: V,
    ) -> Option<(EntryId, Option<EntryId>)> {
        let mut key_iter = key.iter();
        let generation_root =
            self.generation_roots.last().expect("There should always be at least 1 generation.").0;
        // if the tree is empty we must create a new root
        let mut node_idx = if let Some(root) = generation_root {
            root
        } else {
            // the tree is empty
            let value_idx = self.values.len();
            self.values.push(new_value);
            let generation = (self.generation_roots.len() - 1) as u32;
            let root_idx = self.nodes.len();
            let entry_idx = self.entries.len();
            self.entries.push(Entry::Mutable {
                entry_idx: value_idx,
            });
            self.nodes.push(MutableNode {
                generation,
                value: Some(entry_idx),
                path: key.into(),
                children: ChildrenCow::Owned {
                    generation,
                    value: tinyvec::TinyVec::new(),
                },
                locked: false,
            });
            self.generation_roots
                .last_mut()
                .expect("We already checked the list is not empty.")
                .0 = Some(root_idx);
            return Some((entry_idx, None));
        };
        let generation = self.nodes[node_idx].generation;
        let owned_nodes = &mut self.nodes;
        let borrowed_values = &mut self.borrowed_values;
        let entries = &mut self.entries;
        loop {
            let key_slice = key_iter.as_slice();
            let owned_nodes_len = owned_nodes.len();
            let node = unsafe { owned_nodes.get_unchecked_mut(node_idx) };

            if node.locked {
                // The node is locked so we cannot insert new children.
                return None;
            }
            let mut stem_iter = node.path.as_ref().iter();
            match follow_stem(&mut key_iter, &mut stem_iter) {
                FollowStem::Equal => {
                    let value_idx = self.values.len();
                    self.values.push(new_value);
                    let old_entry_idx = node.value;
                    // insert new entry
                    let entry_idx = self.entries.len();
                    self.entries.push(Entry::Mutable {
                        entry_idx: value_idx,
                    });
                    node.value = Some(entry_idx);
                    return Some((entry_idx, old_entry_idx));
                }
                FollowStem::KeyIsPrefix {
                    stem_step,
                } => {
                    // create a new branch with the value being the new_value since the key ends
                    // here.
                    let remaining_stem: Stem = stem_iter.as_slice().into();
                    let value_idx = self.values.len();
                    self.values.push(new_value);
                    let entry_idx = self.entries.len();
                    self.entries.push(Entry::Mutable {
                        entry_idx: value_idx,
                    });
                    // if the node had an entry before we need to update it if it was borrowed.
                    let node_value = std::mem::replace(&mut node.value, Some(entry_idx));
                    let node_children = std::mem::replace(&mut node.children, ChildrenCow::Owned {
                        generation,
                        value: tinyvec::TinyVec::new(),
                    });
                    node.path = key_slice.into();
                    let new_node_idx = owned_nodes_len;
                    node.children = ChildrenCow::Owned {
                        generation,
                        value: tinyvec::tiny_vec![[_; INLINE_CAPACITY] => KeyIndexPair::new(stem_step, new_node_idx)],
                    };
                    owned_nodes.push(MutableNode {
                        generation,
                        value: node_value,
                        path: remaining_stem,
                        children: node_children,
                        locked: false,
                    });
                    return Some((entry_idx, None));
                }
                FollowStem::StemIsPrefix {
                    key_step,
                } => {
                    let (_, children) =
                        make_owned(node_idx, borrowed_values, owned_nodes, entries, loader);
                    let idx = children.binary_search_by(|kk| kk.key().cmp(&key_step));
                    match idx {
                        Ok(idx) => {
                            node_idx = unsafe { children.get_unchecked(idx).index() };
                        }
                        Err(place) => {
                            // need to create a new node.
                            let remaining_key: Stem = key_iter.as_slice().into();
                            let new_key_node_idx = owned_nodes_len;
                            children.insert(place, KeyIndexPair::new(key_step, new_key_node_idx));
                            let value_idx = self.values.len();
                            self.values.push(new_value);
                            // insert new entry
                            let entry_idx = entries.len();
                            entries.push(Entry::Mutable {
                                entry_idx: value_idx,
                            });
                            owned_nodes.push(MutableNode {
                                generation,
                                value: Some(entry_idx),
                                path: remaining_key,
                                children: ChildrenCow::Owned {
                                    generation,
                                    value: tinyvec::TinyVec::new(),
                                },
                                locked: false,
                            });
                            return Some((entry_idx, None));
                        }
                    }
                }
                FollowStem::Diff {
                    key_step,
                    stem_step,
                } => {
                    // create a new branch with the value being the new_value since the key ends
                    // here.
                    let remaining_stem: Stem = stem_iter.as_slice().into();
                    let remaining_key_len = key_iter.as_slice().len();
                    let remaining_key: Stem = key_iter.as_slice().into();
                    let new_stem =
                        Stem::from(&key_slice[0..key_slice.len() - remaining_key_len - 1]);
                    let key_node_idx = owned_nodes_len;
                    let node_value = std::mem::take(&mut node.value);
                    let node_children = std::mem::replace(&mut node.children, ChildrenCow::Owned {
                        generation,
                        value: tinyvec::TinyVec::new(),
                    });
                    let stem_node_idx = owned_nodes_len + 1;
                    // Insert the children in the correct order.
                    let children = if key_step < stem_step {
                        tinyvec::tiny_vec![
                            [_; INLINE_CAPACITY] =>
                            KeyIndexPair::new(key_step, key_node_idx),
                            KeyIndexPair::new(stem_step, stem_node_idx),
                        ]
                    } else {
                        tinyvec::tiny_vec![
                            [_; INLINE_CAPACITY] =>
                            KeyIndexPair::new(stem_step, stem_node_idx),
                            KeyIndexPair::new(key_step, key_node_idx),
                        ]
                    };
                    node.path = new_stem;
                    node.children = ChildrenCow::Owned {
                        generation,
                        value: children,
                    };
                    let value_idx = self.values.len();
                    self.values.push(new_value);
                    // insert new entry
                    let entry_idx = self.entries.len();
                    self.entries.push(Entry::Mutable {
                        entry_idx: value_idx,
                    });
                    owned_nodes.push(MutableNode {
                        generation,
                        value: Some(entry_idx),
                        path: remaining_key,
                        children: ChildrenCow::Owned {
                            generation,
                            value: tinyvec::TinyVec::new(),
                        },
                        locked: false,
                    });
                    owned_nodes.push(MutableNode {
                        generation,
                        value: node_value,
                        path: remaining_stem,
                        children: node_children,
                        locked: false,
                    });
                    return Some((entry_idx, None));
                }
            }
        }
    }
}

impl<V> Node<V> {
    pub fn empty() -> Self { Self::default() }
}

impl<V> Default for Node<V> {
    fn default() -> Self {
        Self {
            value:    None,
            children: Vec::new(),
            path:     Stem::empty(),
        }
    }
}

enum FollowStem {
    Equal,
    KeyIsPrefix {
        stem_step: Key,
    },
    StemIsPrefix {
        key_step: Key,
    },
    Diff {
        key_step:  Key,
        stem_step: Key,
    },
}

#[inline(always)]
fn follow_stem(key_iter: &mut Iter<Key>, stem_iter: &mut Iter<Key>) -> FollowStem {
    for &stem_step in stem_iter {
        if let Some(&key_step) = key_iter.next() {
            if stem_step != key_step {
                return FollowStem::Diff {
                    key_step,
                    stem_step,
                };
            }
        } else {
            // key is a prefix of stem
            return FollowStem::KeyIsPrefix {
                stem_step,
            };
        }
    }
    if let Some(&key_step) = key_iter.next() {
        FollowStem::StemIsPrefix {
            key_step,
        }
    } else {
        FollowStem::Equal
    }
}

impl<V: Clone> Node<V> {
    /// TODO: This is not very efficient. It involves cloning nodes, which is
    /// not all that cheap.
    /// We also don't need this in production, so it is low priority to fix.
    pub fn lookup(
        &self,
        loader: &mut impl FlatLoadable,
        key: &[Key],
    ) -> Option<Link<Hashed<CachedRef<V>>>> {
        let mut key_iter = key.iter();
        let mut path = self.path.as_ref().to_vec();
        let mut children = self.children.clone();
        let mut value = self.value.clone();
        let mut tmp = Vec::new();
        loop {
            match follow_stem(&mut key_iter, &mut path.iter()) {
                FollowStem::Equal => {
                    return value;
                }
                FollowStem::KeyIsPrefix {
                    ..
                } => {
                    return None;
                }
                FollowStem::StemIsPrefix {
                    key_step,
                } => {
                    let (_, c) = children.iter().find(|&&(ck, _)| ck == key_step)?;
                    c.borrow().use_value(loader, |node| {
                        path.clear();
                        path.extend_from_slice(node.data.path.as_ref());
                        tmp.clear();
                        tmp.extend_from_slice(&node.data.children);
                        value = node.data.value.clone();
                    });
                    children.clear();
                    children.append(&mut tmp);
                }
                FollowStem::Diff {
                    ..
                } => {
                    return None;
                }
            }
        }
    }

    /// Check that the node is stored, that is, that its value and
    /// children are already stored in persistent storage, and possibly in
    /// memory.
    pub fn is_stored(&self) -> bool {
        if let Some(value) = &self.value {
            if let CachedRef::Memory {
                ..
            } = value.borrow().data
            {
                return false;
            }
        }
        for child in self.children.iter() {
            if let CachedRef::Memory {
                ..
            } = &*child.1.borrow()
            {
                return false;
            }
        }
        true
    }

    /// Check that the entire tree is cached, meaning that it is in memory,
    /// either purely in memory or on disk and in memory.
    /// WARNING: Note that this method is recursive, and thus should only be
    /// used for small trees.
    pub fn is_cached(&self) -> bool {
        if let Some(value) = &self.value {
            if let CachedRef::Disk {
                ..
            } = value.borrow().data
            {
                return false;
            }
        }
        for child in self.children.iter() {
            match &*child.1.borrow() {
                CachedRef::Disk {
                    key: _,
                } => {
                    return false;
                }
                CachedRef::Memory {
                    value,
                } => {
                    if !value.data.is_cached() {
                        return false;
                    }
                }
                CachedRef::Cached {
                    key: _,
                    value,
                } => {
                    if !value.data.is_cached() {
                        return false;
                    }
                }
            }
        }
        true
    }
}
