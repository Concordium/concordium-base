//! This module provides the low-level primitives that are used to build
//! the state implementation for V1 smart contracts.
//!
//! Functions in this module are, as the name of the module suggests, low-level
//! and generally have many preconditions, violation of which will make them
//! unsafe, could trigger panics, or memory corruption. For this reason
//! functions should only be used via the exposed high-level api in the
//! `super::api` module, which is re-exported at the top-level.
//!
//! The low-level api is structured around two main structures, the [`Node`] and
//! the [`MutableTrie`]. The former is used to express persistent trees that,
//! once constructed, are never modified. The latter is used during transaction
//! execution to efficiently update the state.
//!
//! The [`MutableTrie`] exists for the entire duration of the transaction, and
//! is destroyed at the end. It supports generations, which are used for
//! checkpointing and corresponding rollbacks.
//!
//! The overall flow of operations is as follows. Execution starts with the
//! current contract state, which is a root [`Node`] (or an empty state). This
//! node is then converted into a [`MutableTrie`] via
//! [`make_mutable`](CachedRef::make_mutable)). The contract execution engine
//! operates on this structure, which supports all the necessary operations,
//! e.g., lookup, insert, creation and use of iterators.
//!
//! In case execution of contract `A` `invoke`'s contract `A` again (either
//! directly, or via intermediate contract) execution of the inner contract `A`
//! starts in the state at the time of `invoke`. Since the execution of the
//! inner contract `A` might fail we must be able to roll back any state changes
//! it has done up to that point. This is achieved via checkpointing which is
//! achieved via generations. When the inner contract starts execution we create
//! a checkpoint by starting a new generation of the [`MutableTrie`]. This
//! allows for relatively efficient updates and rollbacks. If the execution of
//! the inner contract succeeds then the outer `A` resumes in the newest
//! generation. If it fails, the newest generation is deleted, along with any
//! modifications.
//!
//! Thus generations in effect achieve a persistent data structure, but in such
//! a way that updates are still almost as efficient as for a mutable trie.
use super::types::*;
use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
#[cfg(feature = "display-state")]
use ptree::TreeBuilder;
use sha2::Digest;
use slab::Slab;
use std::{
    collections::HashMap,
    fmt::{self, Debug, Display, Formatter, LowerHex},
    io::{Read, Write},
    iter::once,
    num::NonZeroU32,
    ops::Deref,
    sync::{Arc, RwLock, RwLockReadGuard, RwLockWriteGuard},
};

/// Children of a node are sometimes stored in a [tinyvec::TinyVec]. This
/// constant determines how many values (at most) are stored inline. If the
/// number of children exceeds this number then a normal [Vec] is allocated.
/// The idea of a [tinyvec::TinyVec] is that storing elements inline is more
/// efficient since it removes a pointer indirection. The best constant to use
/// must be a tradeoff between wasted space and performance (note that with too
/// large a constant performance also degrades since fewer nodes fit into the
/// cache).
const INLINE_CAPACITY: usize = 4;

/// Maximum size (inclusive) of a value up to which it will be stored inline
/// with the node, and the hash will not be stored explicitly. Values bigger
/// than this bound are stored via a [CachedRef] indirection, and the hash is
/// explicitly stored inline with the node.
/// This must never be more than `0b1111_1110`.
const INLINE_VALUE_LEN: usize = 64;

#[derive(Default, Debug, Clone)]
/// An inner node in the [PrefixesMap]. The default instance produces an empty
/// node with no values and no children.
struct InnerNode {
    value:    Option<NonZeroU32>,
    /// Children ordered by increasing keys.
    children: Vec<KeyIndexPair<8>>,
}

#[derive(Debug, Clone)]
/// A prefix map that efficiently stores a list of keys and supports the
/// following operations
/// - insert with reference counting
/// - delete
/// - check whether the given key is extended by any value in the collection
/// - check whether the given key either extends any value or is extended by any
///   value
///
/// The data structure is a basic trie. Instead of using pointers to children
/// node we use a slab of nodes, and children are pointers in this vector. This
/// is to avoid issues with lifetimes and ownership when traversing and
/// modifying the tree.
pub(crate) struct PrefixesMap {
    /// Root of the map. This is [None] if and only if the map is empty.
    /// If this is Some then the index is the key in the [PrefixesMap::nodes]
    /// slab below.
    root:  Option<usize>,
    /// All the live nodes in the tree.
    nodes: Slab<InnerNode>,
}

impl PrefixesMap {
    pub fn new() -> Self {
        PrefixesMap {
            root:  None,
            nodes: Slab::new(),
        }
    }

    #[cfg(test)]
    pub fn is_empty(&self) -> bool { self.root.is_none() }

    pub fn insert(&mut self, key: &[u8]) -> Result<(), TooManyIterators> {
        let mut node_idx = if let Some(root) = self.root {
            root
        } else {
            let root = self.nodes.insert(InnerNode::default());
            self.root = Some(root);
            root
        };
        for k in key {
            let node = unsafe { self.nodes.get_unchecked_mut(node_idx) };
            match node.children.binary_search_by_key(&Chunk::new(*k), |x| x.key()) {
                Ok(idx) => {
                    let c = unsafe { node.children.get_unchecked(idx) };
                    node_idx = c.index();
                }
                Err(idx) => {
                    let new_node = self.nodes.insert(InnerNode::default());
                    // look up again to not have issues with double mutable borrow.
                    // This could be improved.
                    let node = unsafe { self.nodes.get_unchecked_mut(node_idx) };
                    node.children.insert(idx, KeyIndexPair::new(Chunk::new(*k), new_node));
                    node_idx = new_node;
                }
            }
        }
        let node = unsafe { self.nodes.get_unchecked_mut(node_idx) };
        if let Some(value) = node.value {
            let new_value = value.get().checked_add(1).ok_or(TooManyIterators)?;
            node.value = Some(unsafe { NonZeroU32::new_unchecked(new_value) });
        } else {
            node.value = Some(unsafe { NonZeroU32::new_unchecked(1) });
        }
        Ok(())
    }

    /// Return whether the given key has a prefix in the prefix map.
    #[inline]
    pub fn check_has_no_prefix(&self, key: &[u8]) -> Result<(), AttemptToModifyLockedArea> {
        let mut node_idx = if let Some(root) = self.root {
            root
        } else {
            // empty tree
            return Ok(());
        };
        for k in key {
            let node = unsafe { self.nodes.get_unchecked(node_idx) };
            // if there is a value at this node, then we have found our prefix.
            if node.value.is_some() {
                return Err(AttemptToModifyLockedArea);
            }
            if let Ok(idx) = node.children.binary_search_by_key(&Chunk::new(*k), |x| x.key()) {
                let c = unsafe { node.children.get_unchecked(idx) };
                node_idx = c.index();
            } else {
                return Ok(());
            }
        }
        // we found a node that either has a value, or has children, in the first case
        // the given key is a prefix of some value in the trie. In the latter it is not,
        // the entire tree is below it.
        let node = unsafe { self.nodes.get_unchecked(node_idx) };
        if node.value.is_some() {
            Err(AttemptToModifyLockedArea)
        } else {
            Ok(())
        }
    }

    /// Return whether any key in the trie **is a prefix of the given key**, or
    /// whether the given key **is extended by** any keys in the map.
    pub fn is_or_has_prefix(&self, key: &[u8]) -> bool {
        let mut node_idx = if let Some(root) = self.root {
            root
        } else {
            // empty tree
            return false;
        };
        for k in key {
            let node = unsafe { self.nodes.get_unchecked(node_idx) };
            // if there is a value at this node, then we have found our prefix.
            if node.value.is_some() {
                return true;
            }
            if let Ok(idx) = node.children.binary_search_by_key(&Chunk::new(*k), |x| x.key()) {
                let c = unsafe { node.children.get_unchecked(idx) };
                node_idx = c.index();
            } else {
                return false;
            }
        }
        // we found a node that either has a value, or has children. In the first case
        // it matches the key exactly, so is a prefix of it. In the latter, a key
        // extends this node.
        true
    }

    /// Delete the given key from the map. That is, decrease the reference count
    /// by 1, and if this is the last occurrence of the key remove it from the
    /// map. Return whether the key was in the map.
    pub fn delete(&mut self, key: &[u8]) -> bool {
        let mut node_idx = if let Some(root) = self.root {
            root
        } else {
            // empty tree
            return false;
        };
        let mut stack = Vec::new();
        for k in key {
            let node = unsafe { self.nodes.get_unchecked(node_idx) };
            if let Ok(idx) = node.children.binary_search_by_key(&Chunk::new(*k), |x| x.key()) {
                let c = unsafe { node.children.get_unchecked(idx) };
                stack.push((node_idx, idx));
                node_idx = c.index();
            } else {
                return false;
            }
        }
        let node = unsafe { self.nodes.get_unchecked_mut(node_idx) };
        let have_removed = node.value.is_some();
        match node.value {
            Some(ref mut value) if value.get() > 1 => {
                *value = unsafe { NonZeroU32::new_unchecked(value.get() - 1) };
                return true;
            }
            _ => node.value = None,
        }
        // back up and delete subtrees if needed
        if node.children.is_empty() {
            self.nodes.remove(node_idx);
            while let Some((node_idx, child_idx)) = stack.pop() {
                let node = unsafe { self.nodes.get_unchecked_mut(node_idx) };
                node.children.remove(child_idx);
                if !node.children.is_empty() || node.value.is_some() {
                    break;
                } else {
                    self.nodes.remove(node_idx);
                }
            }
            // delete the root, if needed
            if let Some(root) = self.root {
                if !self.nodes.contains(root) {
                    self.root = None;
                }
            }
        }
        have_removed
    }
}

#[derive(Debug)]
/// A link to a shared occurrence of a value V.
/// This is used in this module to construct trees, allowing for sharing of
/// values in trees and subtrees in case of the persistent tree.
///
/// This [Link] achieves the following properties
/// - it is cheap to clone
/// - it allows for inner mutability
/// - it is safe to use in a concurrent context.
///
/// The cheap cloning is necessary to have efficient persistent trees. The
/// [Link] is used to point to children, as well as values, in the persistent
/// tree. Modifying the value at a given point means we need to create copies of
/// the spine of the tree up to the root. This involves cloning pointers to any
/// parts that have not been modified. Thus these have to be cheap, so we use an
/// [Arc].
///
/// Inner mutability is needed so that the persistent tree may be loaded from
/// disk, as well as written to disk. This is achieved in combination with
/// [CachedRef]. Instead of using an [RwLock] we could instead use a
/// [Mutex](std::sync::Mutex) which would achieve the same API. However based on
/// benchmarks the RwLock has negligible overhead in the case of a single
/// reader, and thus the [RwLock] seems the more natural choice since it allows
/// concurrent reads of the tree.
///
/// Finally, the reference counting must be atomic since parts of the tree are
/// dropped concurrently. While all the operations of the smart contract
/// execution engine are sequential, multiple states may be derived from the
/// same state in different threads. Currently this happens when using
/// invokeContract, but in the future with parallel block execution it might
/// also happen during normal block processing.
/// Additionally, if the Haskell runtime is configured with the parallel garbage
/// collector then parts of the tree might be dropped concurrently. This also
/// requires atomic reference counting.
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
    /// Immutably borrow the pointed to value.
    pub fn borrow(&self) -> RwLockReadGuard<'_, V> { self.link.as_ref().read().unwrap() }

    #[inline(always)]
    /// Mutably borrow the value that is pointed to.
    pub fn borrow_mut(&self) -> RwLockWriteGuard<'_, V> { self.link.as_ref().write().unwrap() }

    #[inline(always)]
    /// Attempt to consume the link. If the pointed to value has a single owner
    /// this will return Ok(_), otherwise it will return an error.
    pub fn try_unwrap(self) -> Result<V, Self> {
        Arc::try_unwrap(self.link)
            .map_err(|link| Link {
                link,
            })
            .map(|rc| rc.into_inner().expect("Thread panicked."))
    }
}

#[derive(Debug, Clone)]
/// A potentially cached value V. This is a value that can either be purely in
/// memory, purely in backing storage, or both in memory and in backing storage.
pub enum CachedRef<V> {
    Disk {
        reference: Reference,
    },
    Memory {
        value: V,
    },
    Cached {
        reference: Reference,
        value:     V,
    },
}

pub enum MaybeOwned<'a, V, R: ?Sized = V> {
    Borrowed(&'a R),
    Owned(V),
}

impl<'a, V: Clone> MaybeOwned<'a, V> {
    /// Extract an owned value, cloning the contained reference if necessary.
    pub(crate) fn make_owned(self) -> V {
        match self {
            MaybeOwned::Borrowed(b) => b.clone(),
            MaybeOwned::Owned(o) => o,
        }
    }
}

impl<'a> Deref for MaybeOwned<'a, Box<[u8]>, [u8]> {
    type Target = [u8];

    #[inline(always)]
    fn deref(&self) -> &Self::Target {
        match self {
            MaybeOwned::Borrowed(v) => v,
            MaybeOwned::Owned(o) => &*o,
        }
    }
}

impl<'a, V> Deref for MaybeOwned<'a, V> {
    type Target = V;

    #[inline(always)]
    fn deref(&self) -> &Self::Target {
        match self {
            MaybeOwned::Borrowed(v) => v,
            MaybeOwned::Owned(o) => &*o,
        }
    }
}

impl<V: Loadable> CachedRef<V> {
    /// Get a reference to the contained value. In case the value is only on
    /// disk this will load it.
    #[inline]
    pub fn get<L: BackingStoreLoad>(&self, loader: &mut L) -> MaybeOwned<V> {
        match self {
            CachedRef::Disk {
                reference,
            } => {
                let loaded = V::load_from_location(loader, *reference).unwrap();
                MaybeOwned::Owned(loaded)
            }
            CachedRef::Memory {
                value,
                ..
            } => MaybeOwned::Borrowed(value),
            CachedRef::Cached {
                value,
                ..
            } => MaybeOwned::Borrowed(value),
        }
    }
}

impl<V> CachedRef<V> {
    /// If the value only exists in the backing store load it and cache it.
    /// This function assumes that the backing store contains data at the given
    /// reference, and will panic otherwise.
    pub(crate) fn load_and_cache<F: BackingStoreLoad>(&mut self, loader: &mut F) -> &mut V
    where
        V: Loadable, {
        match self {
            CachedRef::Disk {
                reference,
            } => {
                let value = V::load_from_location(loader, *reference).unwrap();
                *self = CachedRef::Cached {
                    reference: *reference,
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

    /// If the value is in memory, uncache it with the given key.
    /// Otherwise do nothing. This of course has the precondition that the key
    /// stores the value in the relevant backing store. Internal use only.
    fn uncache(&mut self, reference: Reference) {
        *self = CachedRef::Disk {
            reference,
        }
    }

    /// If the value is purely in memory then store it the backing store and
    /// uncache it. Store the reference (in the backing store) into the
    /// provided buffer.
    pub(crate) fn store_and_uncache<S: BackingStoreStore, W: std::io::Write>(
        &mut self,
        backing_store: &mut S,
        buf: &mut W,
    ) -> StoreResult<()>
    where
        V: AsRef<[u8]>, {
        match self {
            CachedRef::Disk {
                reference,
            } => reference.store(buf),
            CachedRef::Memory {
                value,
            } => {
                let reference = backing_store.store_raw(value.as_ref())?;
                // Take the value out of the cachedref and temporarily replace it with
                // a dummy value.
                // and now write the cached value back in.
                *self = CachedRef::Disk {
                    reference,
                };
                reference.store(buf)
            }
            CachedRef::Cached {
                reference,
                value: _,
            } => {
                let res = reference.store(buf);
                *self = CachedRef::Disk {
                    reference: *reference,
                };
                res
            }
        }
    }

    /// Migrate the reference to the new backing store, loading the value
    /// using the existing loader. The resulting reference is purely on disk.
    /// Write the reference in the new backing store into the provided buffer.
    pub(crate) fn load_and_store<S: BackingStoreStore, L: BackingStoreLoad, W: std::io::Write>(
        &mut self,
        backing_store: &mut S,
        loader: &mut L,
        buf: &mut W,
    ) -> LoadStoreResult<Self>
    where
        V: AsRef<[u8]> + Loadable + Clone, {
        match self {
            CachedRef::Disk {
                reference,
            } => {
                let value = V::load_from_location(loader, *reference)?;
                let new_reference = backing_store.store_raw(value.as_ref())?;
                new_reference.store(buf)?;
                Ok(Self::Disk {
                    reference: new_reference,
                })
            }
            CachedRef::Memory {
                value,
            } => {
                let reference = backing_store.store_raw(value.as_ref())?;
                reference.store(buf)?;
                Ok(Self::Disk {
                    reference,
                })
            }
            CachedRef::Cached {
                value,
                ..
            } => {
                let reference = backing_store.store_raw(value.as_ref())?;
                reference.store(buf)?;
                Ok(Self::Disk {
                    reference,
                })
            }
        }
    }

    /// Get a mutable reference to the value, **if it is only in memory**.
    /// Otherwise return the reference to the backing store.
    #[inline]
    pub(crate) fn get_mut_or_reference(&mut self) -> Result<&mut V, Reference> {
        match self {
            CachedRef::Disk {
                reference,
            } => Err(*reference),
            CachedRef::Memory {
                value,
            } => Ok(value),
            CachedRef::Cached {
                reference,
                ..
            } => Err(*reference),
        }
    }

    /// Get a mutable reference to the value, **if it is memory or cached**.
    /// If it is only on disk return None
    #[inline]
    pub(crate) fn get_value(self) -> Option<V> {
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

#[derive(Debug, Clone)]
/// A stem is a sequence of [Chunk]s. It is an optimization of the node
/// representation where common parts of the key are stored inline in a single
/// node instead of having many nodes with a single child.
struct Stem {
    pub(crate) data:         Box<[u8]>,
    /// Whether the last chunk is partial or not, i.e., whether all the bytes of
    /// [`data`](Self::data) are in used, or whether only the first 4 bits
    /// of the last byte are used.
    pub(crate) last_partial: bool,
}

#[derive(Debug, Clone)]
/// A mutable version of the stem.
/// This is an implementation detail of the iterator.
struct MutStem {
    pub(crate) data:         Vec<u8>,
    /// Whether the last chunk is partial or not, i.e., whether all the bytes of
    /// [`data`](Self::data) are in used, or whether only the first 4 bits
    /// of the last byte are used.
    pub(crate) last_partial: bool,
}

impl MutStem {
    #[inline(always)]
    /// Push a new chunk to the end of the stem.
    pub fn push(&mut self, elem: Chunk<4>) {
        if self.last_partial {
            self.last_partial = false;
            *self.data.last_mut().expect("Odd implies at least one element") |= elem.value;
        } else {
            self.last_partial = true;
            self.data.push(elem.value << 4);
        }
    }

    /// Truncate the stem to the **given number of chunks.**
    /// It is asssumed that the given length is no more than the current length
    /// of the stem.
    pub fn truncate(&mut self, len: usize) {
        if len % 2 == 0 {
            self.data.truncate(len / 2);
            self.last_partial = false;
        } else {
            self.data.truncate(len / 2 + 1);
            *self.data.last_mut().expect("Odd implies at least one element.") &= 0xf0;
            self.last_partial = true;
        }
    }

    /// Extend the current stem by the content of the given stem.
    fn extend(&mut self, second: &Stem) {
        if second.data.is_empty() {
            return;
        }
        if self.last_partial {
            let start = self.data.len();
            // take the first 4 bits of the extension stem
            let left = second.data[0] & 0xf0;
            *self
                .data
                .last_mut()
                .expect("Since the last element is partial data has at least one field.") |=
                left >> 4;
            // now the `self` is complete, i.e., the last byte is fully used. We now extend
            // it with any remaining part of the extension stem.
            if second.last_partial {
                // first just append all the remaining bytes. This skips the second byte of the
                // extension stem.
                self.data.extend_from_slice(&second.data[1..]);
                // and then shift them to the right by 4 bits, inserting the nibble we skipped.
                // This means traversing all the bytes.
                let mut right = second.data[0] & 0x0f;
                for place in self.data.iter_mut().skip(start) {
                    let tmp = *place & 0x0f;
                    *place >>= 4;
                    *place |= right << 4;
                    right = tmp;
                }
                self.last_partial = false;
            } else {
                // similar to the previous case, except we append the entire extension stem.
                self.data.extend_from_slice(&second.data);
                // and then **shift left** by 4 bits so that we don't duplicate the first 4 bits
                // of the extension stem.
                for (place, next) in self
                    .data
                    .iter_mut()
                    .skip(start)
                    .zip(second.data.iter().skip(1).copied().chain(once(0)))
                {
                    *place <<= 4;
                    *place |= (next & 0xf0) >> 4;
                }
                self.last_partial = true;
            }
        } else {
            self.data.extend_from_slice(&second.data);
            self.last_partial = second.last_partial;
        }
    }

    #[inline(always)]
    /// Return the number of **chunks** in the stem.
    pub fn len(&self) -> usize {
        let len = self.data.len();
        if self.last_partial {
            2 * len - 1
        } else {
            2 * len
        }
    }
}

impl Stem {
    #[inline(always)]
    /// Construct a new stem from the given byte array and length, which should
    /// be the **number of chunks** in the byte array.
    pub fn new(data: Box<[u8]>, len: usize) -> Self {
        Self {
            data,
            last_partial: len % 2 == 1,
        }
    }

    /// Return an iterator over the chunks of the stem.
    pub fn iter(&self) -> StemIter {
        StemIter {
            data: &self.data,
            pos:  0,
            len:  self.len(),
        }
    }

    /// Construct an empty slice.
    pub fn empty() -> Self {
        Self {
            data:         Box::new([]),
            last_partial: false,
        }
    }

    #[inline(always)]
    /// Return the number of **chunks** in the stem.
    pub fn len(&self) -> usize {
        let len = self.data.len();
        if self.last_partial {
            2 * len - 1
        } else {
            2 * len
        }
    }

    #[inline(always)]
    /// Convert the stem to a slice. Return **the number of chunks** and a slice
    /// view. If the number of chunks is odd then the last 4 bits of the
    /// slice are 0.
    pub fn to_slice(&self) -> (usize, &[u8]) { (self.len(), &self.data) }

    #[inline(always)]
    /// Prepend the given data (first, then mid, then self).
    pub fn prepend_parts(&mut self, first: Stem, mid: Chunk<4>) {
        let new_len = first.len() + 1 + self.len();
        let mut data = Vec::with_capacity(new_len / 2 + new_len % 2);
        data.extend_from_slice(&first.data);
        if first.last_partial {
            *data.last_mut().expect("Odd implies at least one element.") |= mid.value;
            data.extend_from_slice(&self.data);
        } else {
            let start = data.len();
            data.extend_from_slice(&self.data);
            if self.last_partial {
                self.last_partial = false;
            } else {
                data.push(0);
                self.last_partial = true;
            };
            let mut old = mid.value << 4;
            for place in data.iter_mut().skip(start) {
                let tmp = *place & 0x0f;
                *place = old | (*place >> 4);
                old = tmp << 4;
            }
        }
        self.data = data.into_boxed_slice();
    }
}

impl Display for Stem {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        let mut stem_iter = self.iter();
        if let Some(chunk) = stem_iter.next() {
            write!(f, "0x{:x}", chunk)?;
            while let Some(chunk) = stem_iter.next() {
                write!(f, "{:x}", chunk)?
            }
        } else {
            write!(f, "[]")?;
        }
        Ok(())
    }
}

impl From<&[u8]> for Stem {
    #[inline(always)]
    fn from(data: &[u8]) -> Self {
        Self {
            data:         data.into(),
            last_partial: false,
        }
    }
}

impl From<&[u8]> for MutStem {
    #[inline(always)]
    fn from(data: &[u8]) -> Self {
        Self {
            data:         data.into(),
            last_partial: false,
        }
    }
}
struct StemIter<'a> {
    data: &'a [u8],
    /// Current position (in chunks).
    pos:  usize,
    /// Number of chunks in the data slice.
    len:  usize,
}

impl<'a> StemIter<'a> {
    /// Construct an iterator from the entire input.
    pub fn new(data: &'a [u8]) -> Self {
        Self {
            data,
            pos: 0,
            len: 2 * data.len(),
        }
    }

    /// Return the next chunk if any are remaining.
    #[allow(clippy::branches_sharing_code)] // see https://github.com/rust-lang/rust-clippy/issues/7452
    pub fn next(&mut self) -> Option<Chunk<4>> {
        if self.pos < self.len {
            // This access is safe since we have already checked the bound.
            // Using an unchecked access here is about 10% faster for lookups on
            // current benchmarks (tree size 100k).
            let v = unsafe { *self.data.get_unchecked(self.pos / 2) };
            if self.pos % 2 == 0 {
                self.pos += 1;
                Some(Chunk::new((v & 0xf0) >> 4))
            } else {
                self.pos += 1;
                Some(Chunk::new(v & 0x0f))
            }
        } else {
            None
        }
    }

    #[inline(always)]
    /// Convert the remaining part of the iterator into a stem.
    pub fn to_stem(&self) -> Stem { self.last_to_stem(self.pos) }

    // NB: Consumed - 1 to stem!
    #[inline(always)]
    /// Convert the consumed parts (**without the last element**) of the
    /// iterator into a stem. The strange behaviour is what is needed.
    pub fn consumed_to_stem(&self) -> Stem {
        if self.pos == 0 {
            Stem::empty()
        } else {
            let new_len = self.pos - 1;
            if new_len % 2 == 0 {
                Stem::new(self.data[..new_len / 2].into(), new_len)
            } else {
                let mut data = self.data[..new_len / 2].to_vec();
                data.push(self.data[new_len / 2] & 0xf0);
                Stem::new(data.into_boxed_slice(), new_len)
            }
        }
    }

    #[inline(always)]
    /// Convert the data from the given position (inclusive) into a stem.
    fn last_to_stem(&self, pos: usize) -> Stem {
        let new_len = self.len - pos;
        if pos % 2 == 0 {
            let data = &self.data[pos / 2..];
            Stem::new(data.into(), new_len)
        } else {
            let mut data = Vec::with_capacity(new_len + 1);
            let mut left = (self.data[pos / 2] & 0x0f) << 4;
            for &byte in &self.data[pos / 2 + 1..] {
                data.push(left | (byte & 0xf0) >> 4);
                left = (byte & 0x0f) << 4;
            }
            if new_len % 2 == 1 {
                data.push(left);
            }
            Stem::new(data.into_boxed_slice(), new_len)
        }
    }
}

#[derive(Copy, Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
#[repr(transparent)]
/// A wrapper around u8 that indicates an N-bit value. N must be between 1 and
/// 8.
struct Chunk<const N: usize> {
    value: u8,
}

impl LowerHex for Chunk<4> {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result { write!(f, "{:x}", self.value) }
}

impl<const N: usize> Chunk<N> {
    #[inline(always)]
    pub fn new(value: u8) -> Self {
        Chunk {
            value,
        }
    }
}

/// Recursive link to a child node.
type ChildLink = Link<CachedRef<Hashed<Node>>>;

/// Link to a value.
type ValueLink = Link<InlineOrHashed>;

#[derive(Debug)]
/// A value that is either stored inline without a hash, or with a cached hash
/// and a pointer to the actual value. The intention is that small values will
/// be stored inline and larger values behind and indirection.
pub enum InlineOrHashed {
    /// The value stored inline.
    Inline {
        len:  u8,
        data: [u8; INLINE_VALUE_LEN],
    },
    /// A value stored together with a hash. The value is stored behind an
    /// indirection, the hash is stored inline.
    Indirect(Hashed<CachedRef<Box<[u8]>>>),
}

#[inline(always)]
/// Read an inline buffer **assuming `len <= INLINE_VALUE_LEN`. Otherwise this
/// function will panic.
fn read_buf(source: &mut impl std::io::Read, len: u8) -> LoadResult<InlineOrHashed> {
    let mut data = [0u8; INLINE_VALUE_LEN];
    source.read_exact(&mut data[0..usize::from(len)])?;
    Ok(InlineOrHashed::Inline {
        len,
        data,
    })
}

/// A slice of bytes, either owned or borrowed.
pub type ByteSlice<'a> = MaybeOwned<'a, Box<[u8]>, [u8]>;

impl InlineOrHashed {
    /// Construct a new value from the provided byte array. The value is hashed
    /// in the provided context in case it is larger than
    /// [INLINE_VALUE_LEN].
    pub fn new<Ctx>(ctx: &mut Ctx, value: Vec<u8>) -> Self {
        if value.len() <= INLINE_VALUE_LEN {
            let mut data: [u8; INLINE_VALUE_LEN] = [0u8; INLINE_VALUE_LEN];
            data[0..value.len()].copy_from_slice(&value);
            Self::Inline {
                len: value.len() as u8,
                data,
            }
        } else {
            Self::Indirect(Hashed::new(value.hash(ctx), CachedRef::Memory {
                value: value.into_boxed_slice(),
            }))
        }
    }

    #[inline(always)]
    /// Get a reference to the contained value. In case the value is only on
    /// disk it is loaded using the provided loader.
    pub(crate) fn get(&self, loader: &mut impl BackingStoreLoad) -> ByteSlice {
        match self {
            InlineOrHashed::Inline {
                len,
                data,
            } => MaybeOwned::Borrowed(&data[0..usize::from(*len)]),
            InlineOrHashed::Indirect(indirect) => {
                let b = indirect.data.get(loader);
                match b {
                    MaybeOwned::Borrowed(b) => MaybeOwned::Borrowed(&b[..]),
                    MaybeOwned::Owned(o) => MaybeOwned::Owned(o),
                }
            }
        }
    }

    #[inline(always)]
    /// Get a reference to the contained value as well as the hash in case the
    /// value is stored with an explicit hash. In case the value is stored
    /// inline, and thus without an explicit hash, no hash is returned.
    pub(crate) fn get_ref_and_hash(
        &self,
        loader: &mut impl BackingStoreLoad,
    ) -> (Option<&Hash>, ByteSlice) {
        match self {
            InlineOrHashed::Inline {
                len,
                data,
            } => (None, MaybeOwned::Borrowed(&data[0..usize::from(*len)])),
            InlineOrHashed::Indirect(indirect) => {
                let b = indirect.data.get(loader);
                let hash = Some(&indirect.hash);
                match b {
                    MaybeOwned::Borrowed(b) => (hash, MaybeOwned::Borrowed(&b[..])),
                    MaybeOwned::Owned(o) => (hash, MaybeOwned::Owned(o)),
                }
            }
        }
    }

    pub(crate) fn load_and_cache<F: BackingStoreLoad>(&mut self, loader: &mut F) {
        match self {
            InlineOrHashed::Inline {
                ..
            } => (), // already loaded
            InlineOrHashed::Indirect(indirect) => {
                indirect.data.load_and_cache(loader);
            }
        }
    }

    /// Clone the contained value and return it. **This does not change any
    /// structure, e.g., it does not cache the value.**
    pub fn get_copy(&self, loader: &mut impl BackingStoreLoad) -> Vec<u8> {
        match self {
            InlineOrHashed::Inline {
                len,
                data,
            } => data[0..usize::from(*len)].to_vec(),
            InlineOrHashed::Indirect(indirect) => Vec::from(indirect.data.get(loader).make_owned()),
        }
    }
}

impl<Ctx: BackingStoreLoad> ToSHA256<Ctx> for InlineOrHashed {
    #[inline(always)]
    fn hash(&self, ctx: &mut Ctx) -> Hash {
        match self {
            InlineOrHashed::Inline {
                len,
                data,
            } => (&data[0..usize::from(*len)]).hash(ctx),
            InlineOrHashed::Indirect(indirect) => indirect.hash(ctx),
        }
    }
}

#[derive(Debug)]
/// A persistent node. Cloning this is relatively cheap, it only copies pointers
/// and increments reference counts.
pub struct Node {
    /// An optional value at the node. Nodes may not have values if they are
    /// branch nodes, that is, if they have two or more children. In general
    /// a node should either have at least two children, or a value. It should
    /// never be the case that the node does not have a value and only has one
    /// child. In that case the `path` would be extended.
    value:    Option<ValueLink>,
    /// The path above this node which is unique to this node from the parent
    /// node. That is, there is no branching on that path, nor are there any
    /// values. This achieves more compact trie representation.
    path:     Stem,
    /// Children, **ordered by increasing key**.
    /// In contrast to `Hashed<Cached<..>>` above for the value, here we store
    /// the hash behind a pointer indirection. The reason for this is that
    /// there are going to be many pointers to the same node, and we want to
    /// avoid duplicating node hashes.
    children: Vec<(Chunk<4>, ChildLink)>,
}

impl Drop for Node {
    fn drop(&mut self) {
        let mut stack = Vec::new();
        let children = std::mem::take(&mut self.children);
        for (_, child) in children.into_iter() {
            // if we are the only owner of the child we can deallocate them.
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

impl Clone for Node {
    fn clone(&self) -> Self {
        Self {
            value:    self.value.clone(),
            path:     self.path.clone(),
            children: self.children.clone(),
        }
    }
}

impl<V: Loadable, Ctx: BackingStoreLoad> ToSHA256<Ctx> for CachedRef<Hashed<V>>
where
    V: ToSHA256<Ctx>,
{
    #[inline(always)]
    fn hash(&self, ctx: &mut Ctx) -> Hash {
        let v = self.get(ctx);
        v.hash(ctx)
    }
}

impl<Ctx: BackingStoreLoad> ToSHA256<Ctx> for Node {
    fn hash(&self, ctx: &mut Ctx) -> Hash {
        let mut hasher = sha2::Sha256::new();
        match &self.value {
            Some(value) => {
                hasher.update(&[1]);
                hasher.update(value.borrow().hash(ctx));
            }
            None => hasher.update(&[0]),
        }
        let (stem_len, stem_ref) = self.path.to_slice();
        hasher.update((stem_len as u64).to_le_bytes());
        hasher.update(stem_ref);
        let mut child_hasher = sha2::Sha256::new();
        child_hasher.update(&(self.children.len() as u16).to_be_bytes());
        for child in self.children.iter() {
            child_hasher.update(&[child.0.value]);
            child_hasher.update(child.1.borrow().hash(ctx));
        }
        hasher.update(child_hasher.finalize());
        let hash: [u8; 32] = hasher.finalize().into();
        Hash::from(hash)
    }
}

#[derive(Debug, Clone)]
struct MutableNode {
    generation: u32,
    /// Pointer to the table of entries, if the node has a value.
    value:      Option<EntryId>,
    path:       Stem,
    children:   ChildrenCow,
    /// This is None if the node is modified
    origin:     Option<CachedRef<Hashed<Node>>>,
}

impl ChildrenCow {
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

impl Default for MutableNode {
    fn default() -> Self {
        Self {
            generation: 0,
            value:      None,
            path:       Stem::empty(),
            children:   ChildrenCow::Owned {
                generation: 0,
                value:      tinyvec::TinyVec::new(),
            },
            origin:     None,
        }
    }
}

impl MutableNode {
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
            Some(new_entry_idx.into())
        } else {
            None
        };
        Self {
            generation,
            value,
            path: self.path.clone(), // this is a cheap clone as well.
            children: self.children.clone(),
            origin: self.origin.clone(),
        }
    }
}

#[derive(Debug, Clone, Copy)]
/// A checkpoint that is saved for a mutable trie so that we can cleanup on
/// state rollback. It stores which items were alive at the time of the
/// checkpoint, utilizing the fact that items are always just added to the end
/// of the relevant collections.
struct Checkpoint {
    pub num_nodes:          usize,
    pub num_values:         usize,
    pub num_borrowed_nodes: usize,
    pub num_entries:        usize,
}

#[derive(Debug, Clone)]
/// A generation of the [MutableTrie]. This keeps track of the current root of
/// the tree, together with the enough data to be able to go back to the
/// previous generation. Generations are used to checkpoint the tree. This
/// structure only makes sense in the context of a [MutableTrie], since it
/// maintains pointers into other parts of the trie.
struct Generation {
    /// Pointer to the root node of the trie at this generation. This is [None]
    /// if and only if the trie at this generation is empty.
    root:           Option<usize>,
    /// Checkpoint that allows us to clean up the trie when going back to the
    /// **previous** generation.
    checkpoint:     Checkpoint,
    /// Map of prefixes that are locked by iterators.
    iterator_roots: PrefixesMap,
}

impl Generation {
    /// Construct a generation that contains the given root, no locks, and the
    /// checkpoint which goes back to the beginning of the trie.
    fn new(root: Option<usize>) -> Self {
        Generation {
            root,
            checkpoint: Checkpoint {
                num_nodes:          0,
                num_values:         0,
                num_borrowed_nodes: 0,
                num_entries:        0,
            },
            iterator_roots: PrefixesMap::new(),
        }
    }

    /// Construct a generation that contains the given root and checkpoint, and
    /// no locks.
    fn new_with_checkpoint(root: Option<usize>, checkpoint: Checkpoint) -> Self {
        Generation {
            root,
            checkpoint,
            iterator_roots: PrefixesMap::new(),
        }
    }
}

#[derive(Debug, Clone)]
/// A mutable trie that exists during execution of a smart contract.
/// Generally the [MutableTrie] is derived from a [Node], i.e., a persistent
/// trie. After that, during execution, some parts are modified. When that
/// happens the relevant part of the trie are copied so that the original
/// persistent trie remains unmodified.
/// In contrast to the [Node], all modifications on values purely owned by the
/// [MutableTrie] are in-place, i.e., this structure is not persistent.
///
/// At the end of execution this trie is [frozen](MutableTrie::freeze) to obtain
/// a new persistent trie.
pub struct MutableTrie {
    /// Roots for previous generations.
    generations:     Vec<Generation>,
    /// Entries. These are pointers to either [MutableTrie::values] or
    /// [MutableTrie::borrowed_values].
    entries:         Vec<Entry>,
    /// Values that are owned by this trie. This generally means that either
    /// they have been modified from values in the persistent trie, or newly
    /// created.
    values:          Vec<Vec<u8>>,
    /// Values borrowed from a persistent tree. These are the values that have
    /// not been modified from the versions that exist in the persistent tree.
    borrowed_values: Vec<ValueLink>,
    /// List of all the nodes for all generations. Nodes for new generations are
    /// always added at the end.
    nodes:           Vec<MutableNode>,
}

#[derive(Debug)]
enum ChildrenCow {
    Borrowed(Vec<(Chunk<4>, ChildLink)>),
    Owned {
        generation: u32,
        value:      tinyvec::TinyVec<[KeyIndexPair<4>; INLINE_CAPACITY]>,
    },
}

impl ChildrenCow {
    /// Return a reference to the owned value, if the enum is an owned variant.
    /// Otherwise return [None].
    #[inline]
    pub fn get_owned(&self) -> Option<(u32, &[KeyIndexPair<4>])> {
        if let ChildrenCow::Owned {
            generation,
            value,
        } = self
        {
            Some((*generation, value))
        } else {
            None
        }
    }

    /// Return a mutable reference to the owned value, if the enum is an owned
    /// variant. Otherwise return [None].
    #[inline]
    pub fn get_owned_mut(&mut self) -> Option<(u32, &mut [KeyIndexPair<4>])> {
        if let ChildrenCow::Owned {
            generation,
            value,
        } = self
        {
            Some((*generation, value))
        } else {
            None
        }
    }
}

fn freeze_value<Ctx, C: Collector<Vec<u8>>>(
    borrowed_values: &mut [ValueLink],
    owned_values: &mut [Vec<u8>],
    entries: &[Entry],
    mutable: Option<EntryId>,
    loader: &mut Ctx,
    collector: &mut C,
) -> (bool, Option<ValueLink>) {
    let entry_idx = if let Some(entry_idx) = mutable {
        entry_idx
    } else {
        return (false, None);
    };
    match entries[entry_idx] {
        Entry::ReadOnly {
            borrowed,
            entry_idx,
            ..
        } => {
            if borrowed {
                (false, Some(borrowed_values[entry_idx].clone()))
            } else {
                let value = std::mem::take(&mut owned_values[entry_idx]);
                collector.add_value(&value);
                (true, Some(Link::new(InlineOrHashed::new(loader, value))))
            }
        }
        Entry::Mutable {
            entry_idx,
            ..
        } => {
            let value = std::mem::take(&mut owned_values[entry_idx]);
            collector.add_value(&value);
            (true, Some(Link::new(InlineOrHashed::new(loader, value))))
        }
        Entry::Deleted => (true, None),
    }
}

#[repr(transparent)]
#[derive(Default, Clone, Copy)]
/// A pair of a key and index in the vector of nodes.
/// This only makes sense in the context of some vector of values where this
/// index points to. Which vector that is is context dependent.
/// The first N bits of the value are the key, the remaining are the index.
struct KeyIndexPair<const N: usize> {
    pub pair: usize,
}

/// Format the [KeyIndexPair] as a pair of a key and index.
impl<const N: usize> std::fmt::Debug for KeyIndexPair<N> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        (self.key(), self.index()).fmt(f)
    }
}

impl<const N: usize> KeyIndexPair<N> {
    #[inline(always)]
    pub fn key(self) -> Chunk<N> { unsafe { std::mem::transmute((self.pair >> (64 - N)) as u8) } }

    #[inline(always)]
    pub fn index(self) -> usize { self.pair & (0xffff_ffff_ffff_ffff >> N) }

    #[inline(always)]
    pub fn new(key: Chunk<N>, index: usize) -> Self {
        let pair = usize::from(key.value) << (64 - N) | index;
        Self {
            pair,
        }
    }
}

impl Clone for ChildrenCow {
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

impl<V> Loadable for CachedRef<V> {
    #[inline(always)]
    fn load<S: std::io::Read, F: BackingStoreLoad>(
        loader: &mut F,
        source: &mut S,
    ) -> LoadResult<Self> {
        let reference = Reference::load(loader, source)?;
        Ok(CachedRef::Disk {
            reference,
        })
    }
}

impl Loadable for Node {
    fn load<S: std::io::Read, F: BackingStoreLoad>(
        loader: &mut F,
        source: &mut S,
    ) -> LoadResult<Self> {
        let (path, has_value) = read_node_path_and_value_tag(source)?;
        let value = if has_value {
            let tag = source.read_u8()?;
            let val = if usize::from(tag) <= INLINE_VALUE_LEN {
                read_buf(source, tag)?
            } else {
                InlineOrHashed::Indirect(Hashed::<CachedRef<Box<[u8]>>>::load(loader, source)?)
            };
            Some(Link::new(val))
        } else {
            None
        };
        let num_branches = source.read_u8()?;
        let mut branches = Vec::with_capacity(num_branches.into());
        for _ in 0..num_branches {
            let key = Chunk::new(source.read_u8()?);
            let reference = CachedRef::<Hashed<Node>>::load(loader, source)?;
            branches.push((key, Link::new(reference)));
        }
        Ok(Node {
            value,
            path,
            children: branches,
        })
    }
}

impl Node {
    /// Load the entire tree into memory, retaining pointers to where it was
    /// loaded from in the backing store.
    pub fn cache<F: BackingStoreLoad>(&mut self, loader: &mut F) {
        if let Some(v) = self.value.as_mut() {
            v.borrow_mut().load_and_cache(loader);
        }
        let mut stack = Vec::new();
        for c in self.children.iter() {
            stack.push(c.1.clone());
        }
        while let Some(node) = stack.pop() {
            let mut node_borrow = node.borrow_mut();
            let node = node_borrow.load_and_cache(loader);
            if let Some(v) = node.data.value.as_mut() {
                v.borrow_mut().load_and_cache(loader);
            }
            for c in node.data.children.iter() {
                stack.push(c.1.clone());
            }
        }
    }

    #[cfg(feature = "display-state")]
    pub fn display_tree(&self, builder: &mut TreeBuilder, loader: &mut impl BackingStoreLoad) {
        let value = if let Some(ref value) = self.value {
            let value_ref = value.borrow();
            let value = value_ref.get(loader);
            format!(", value = {:?}", &*value)
        } else {
            String::new()
        };
        let text = format!("Node (path = {}{})", self.path, value);
        builder.add_empty_child(text);
        for (key, node) in &self.children {
            builder.begin_child(format!("Child {:#x}", *key));
            let node = node.borrow();
            let node = node.get(loader).data.clone();
            node.display_tree(builder, loader);
            builder.end_child();
        }
    }
}

impl Hashed<Node> {
    pub fn store_update<S: BackingStoreStore>(
        &mut self,
        backing_store: &mut S,
    ) -> Result<Vec<u8>, WriteError> {
        let mut buf = Vec::new();
        self.store_update_buf(backing_store, &mut buf)?;
        Ok(buf)
    }

    pub fn store_update_buf<S: BackingStoreStore, W: std::io::Write>(
        &mut self,
        backing_store: &mut S,
        buf: &mut W,
    ) -> StoreResult<()> {
        buf.write_all(self.hash.as_ref())?;
        self.data.store_update_buf(backing_store, buf)
    }

    pub fn migrate<S: BackingStoreStore, L: BackingStoreLoad, W: std::io::Write>(
        &self,
        backing_store: &mut S,
        loader: &mut L,
        buf: &mut W,
    ) -> LoadStoreResult<Self> {
        buf.write_all(self.hash.as_ref())?;
        let inner = self.data.migrate(backing_store, loader, buf)?;
        Ok(Self {
            hash: self.hash,
            data: inner,
        })
    }
}

impl Node {
    pub fn store_update<S: BackingStoreStore>(
        &mut self,
        backing_store: &mut S,
    ) -> Result<Vec<u8>, WriteError> {
        let mut buf = Vec::new();
        self.store_update_buf(backing_store, &mut buf)?;
        Ok(buf)
    }

    /// Store the node into the provided `buf`, and store and children
    /// (transitively) into the provided `backing_store`. Only the children that
    /// are not yet cached are stored. This modifies the node recursively so
    /// that children pointers are [CachedRef::Cached] or [CachedRef::Disk].
    pub fn store_update_buf<S: BackingStoreStore, W: std::io::Write>(
        &mut self,
        backing_store: &mut S,
        buf: &mut W,
    ) -> StoreResult<()> {
        // This function would be very natural to write recursively, essentially
        // - recursively write all the children that are only in memory
        // - this would return Reference's to where these children are written in the
        //   backing store
        // - use these to write the node into the provided buffer (`buf`).
        //
        // However this would be prone to stack overflow since Rust generally has little
        // control on stack size. Thus we write the function with an explicit
        // stack, modelling the recursive function that way without using any explicit
        // recursion. This gives more control and predictability.

        // The stack of nodes to process. Initialized by all the children of the node.
        let mut stack = Vec::new();
        for (_, ch) in self.children.iter() {
            stack.push((ch.clone(), false));
        }
        // A closure that stores the node (including the value) assuming all its
        // children have already been stored and are in the correct positions in
        // the `ref_stack`.
        let store_node = |node: &mut Node,
                          buf: &mut Vec<u8>,
                          backing_store: &mut S,
                          ref_stack: &mut Vec<Reference>|
         -> StoreResult<()> {
            let (stem_len, stem_ref) = node.path.to_slice();
            write_node_path_and_value_tag(stem_len, node.value.is_none(), buf)?;
            // store the path
            buf.write_all(stem_ref)?;
            // store the value
            if let Some(v) = &mut node.value {
                let mut borrowed = v.borrow_mut();
                match &mut *borrowed {
                    InlineOrHashed::Inline {
                        len,
                        data,
                    } => {
                        // write length as a single byte.
                        buf.write_u8(*len)?;
                        buf.write_all(&data[0..usize::from(*len)])?;
                    }
                    InlineOrHashed::Indirect(indirect) => {
                        // Since `INLINE_VALUE_LEN` is no more than `0b1111_1110`
                        // the length of the inline variant will never have all 8 bits set.
                        // We utilize this here to use this special tag value to indicate the
                        // variant.
                        buf.write_u8(0b1111_1111u8)?;
                        buf.write_all(indirect.hash.as_ref())?;
                        indirect.data.store_and_uncache(backing_store, buf)?;
                    }
                }
            }
            // Since we branch on 4 bits there can be at most 16 children.
            // So using u8 is safe.
            buf.write_u8(node.children.len() as u8)?;
            for (k, _) in node.children.iter() {
                buf.write_u8(k.value)?;
                ref_stack.pop().unwrap().store(buf)?;
            }
            Ok(())
        };
        // the stack of References. When a node is fully stored then its reference (to
        // the location in the backing store) is pushed to this stack.
        let mut ref_stack = Vec::<Reference>::new();
        // A reusable buffer where nodes are stored before being written to the backing
        // store. This is to reduce on the amount of small allocations
        // compared to allocating a new vector for each of the child nodes.
        let mut tmp_buf = Vec::new();
        while let Some((node_ref, children_processed)) = stack.pop() {
            let node_ref_clone = node_ref.clone();
            let mut node_ref_mut = node_ref.borrow_mut();
            match node_ref_mut.get_mut_or_reference() {
                Ok(hashed_node) => {
                    // the node is not stored in the backing store yet. So we need to do it.
                    if children_processed {
                        // The node's children have already been processed. Store the node.
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
                        node_ref_mut.uncache(key);
                    } else {
                        // the node's children have not yet been processed. Push the node back onto
                        // the stack recording that now the children have
                        // been processed.
                        stack.push((node_ref_clone, true));
                        // and then push all the children to be processed.
                        for (_, ch) in hashed_node.data.children.iter() {
                            stack.push((ch.clone(), false));
                        }
                    }
                }
                Err(key) => {
                    // the node is already stored on disk (either cached or not). So we do not need
                    // to recurse down to the children since a general invariant
                    // is that a cached (on disk) node has children and values that are cached or on
                    // disk.
                    ref_stack.push(key);
                }
            }
        }
        tmp_buf.clear();
        store_node(self, &mut tmp_buf, backing_store, &mut ref_stack)?;
        buf.write_all(&tmp_buf)?;
        Ok(())
    }

    /// Store node into the provided backing store, loading it as necessary. All
    /// the children are (recursively) in the [CachedRef::Disk] variant.
    ///
    /// This is used during protocol updates to migrate state from one database
    /// to another.
    pub fn migrate<S: BackingStoreStore, L: BackingStoreLoad, W: std::io::Write>(
        &self,
        backing_store: &mut S,
        loader: &mut L,
        buf: &mut W,
    ) -> LoadStoreResult<Self> {
        // This function would be very natural to write recursively, essentially
        // - recursively write all the children that are only in memory
        // - this would return Reference's to where these children are written in the
        //   backing store
        // - use these to write the node into the provided buffer (`buf`).
        //
        // However this would be prone to stack overflow since Rust generally has little
        // control on stack size. Thus we write the function with an explicit
        // stack, modelling the recursive function that way without using any explicit
        // recursion. This gives more control and predictability.

        // The stack of nodes to process. Initialized by all the children of the node.
        let mut stack = Vec::new();
        for (_, ch) in self.children.iter() {
            let ch = ch.borrow().get(loader).make_owned();
            stack.push((ch, false));
        }
        // A closure that stores the node (including the value) assuming all its
        // children have already been stored and are in the correct positions in
        // the `ref_stack`.
        let store_node = |mut node: Node,
                          buf: &mut Vec<u8>,
                          backing_store: &mut S,
                          loader: &mut L,
                          ref_stack: &mut Vec<Reference>|
         -> LoadStoreResult<Self> {
            let (stem_len, stem_ref) = node.path.to_slice();
            write_node_path_and_value_tag(stem_len, node.value.is_none(), buf)
                .map_err(|x| LoadWriteError::Write(x.into()))?;
            // store the path
            buf.write_all(stem_ref).map_err(|x| LoadWriteError::Write(x.into()))?;
            // store the value
            if let Some(v) = &mut node.value {
                let mut borrowed = v.borrow_mut();
                match &mut *borrowed {
                    InlineOrHashed::Inline {
                        len,
                        data,
                    } => {
                        // write length as a single byte.
                        buf.write_u8(*len)?;
                        buf.write_all(&data[0..usize::from(*len)])?;
                    }
                    InlineOrHashed::Indirect(indirect) => {
                        // Since `INLINE_VALUE_LEN` is no more than `0b1111_1110`
                        // the length of the inline variant will never have all 8 bits set.
                        // We utilize this here to use this special tag value to indicate the
                        // variant. buf.write_u8(0b1111_1111u8)?;
                        buf.write_u8(0b1111_1111u8)?;
                        buf.write_all(indirect.hash.as_ref())?;
                        indirect.data.load_and_store(backing_store, loader, buf)?;
                    }
                }
            }
            // Since we branch on 4 bits there can be at most 16 children.
            // So using u8 is safe.
            buf.write_u8(node.children.len() as u8)?;
            for (k, ch) in node.children.iter_mut() {
                buf.write_u8(k.value)?;
                let reference = ref_stack.pop().unwrap();
                reference.store(buf)?;
                // Set the child pointer to the correct value, and drop
                // the child from memory.
                *ch.borrow_mut() = CachedRef::Disk {
                    reference,
                };
            }
            Ok(node)
        };
        // the stack of References. When a node is fully stored then its
        // reference (to the location in the backing store) is pushed to this
        // stack. The value is popped from the stack when its parent is being stored
        // or at the very end for the top-level node.
        let mut ref_stack = Vec::<Reference>::new();
        // A reusable buffer where nodes are stored before being written to the backing
        // store. This is to reduce on the amount of small allocations
        // compared to allocating a new vector for each of the child nodes.
        let mut tmp_buf = Vec::new();
        while let Some((hashed_node, children_processed)) = stack.pop() {
            // the node is not stored in the backing store yet. So we need to do it.
            if children_processed {
                // The node's children have already been processed. Store the node.
                tmp_buf.clear();
                tmp_buf.write_all(hashed_node.hash.as_ref())?;
                store_node(hashed_node.data, &mut tmp_buf, backing_store, loader, &mut ref_stack)?;
                let key = backing_store.store_raw(&tmp_buf)?;
                ref_stack.push(key);
            } else {
                // the node's children have not yet been processed. Push the node back onto
                // the stack recording that now the children have
                // been processed.
                stack.push((hashed_node.clone(), true));
                // and then push all the children to be processed.
                for (_, ch) in hashed_node.data.children.iter() {
                    let ch = ch.borrow().get(loader).make_owned();
                    stack.push((ch, false));
                }
            }
        }
        tmp_buf.clear();
        let ret = store_node(self.clone(), &mut tmp_buf, backing_store, loader, &mut ref_stack)?;
        buf.write_all(&tmp_buf)?;
        Ok(ret)
    }
}

/// Make the children owned, and return whether the node has a value, the new
/// length of owned_nodes, and a mutable reference to the children.
fn make_owned<'a, 'b>(
    idx: usize,
    borrowed_values: &mut Vec<ValueLink>,
    owned_nodes: &'a mut Vec<MutableNode>,
    entries: &'a mut Vec<Entry>,
    loader: &'b mut impl BackingStoreLoad,
) -> (bool, usize, &'a mut tinyvec::TinyVec<[KeyIndexPair<4>; INLINE_CAPACITY]>) {
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
    let owned_nodes_len = owned_nodes.len();
    match &mut unsafe { owned_nodes.get_unchecked_mut(idx) }.children {
        ChildrenCow::Borrowed(_) => unsafe { std::hint::unreachable_unchecked() },
        ChildrenCow::Owned {
            value: ref mut children,
            ..
        } => (has_value, owned_nodes_len, children),
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

impl Entry {
    /// Return whether the entry is still alive, i.e., not [Entry::Deleted].
    pub fn is_alive(&self) -> bool { !matches!(self, Self::Deleted) }

    /// Return whether the entry is owned, i.e., mutable. If so, return the
    /// value it points to.
    #[inline]
    pub fn is_owned(self) -> Option<usize> {
        if let Self::Mutable {
            entry_idx,
        } = self
        {
            Some(entry_idx)
        } else {
            None
        }
    }
}

type Position = u8;

#[derive(Debug)]
pub struct Iterator {
    /// The root of the iterator. This is stored to allow removal of the
    /// iterator.
    root:         Box<[u8]>,
    /// Pointer to the table of nodes where the iterator is currently anchored.
    current_node: usize,
    /// Key at the current position of the iterator.
    key:          MutStem,
    /// Next child to look at. This is None if
    /// we have to give out the value at the current node, and Some(_)
    /// otherwise.
    next_child:   Option<Position>,
    /// Stack of parents and next positions, and key lengths of parents
    stack:        Vec<(usize, Position, usize)>,
    /// Whether [MutableTrie::next] has already been called on the iterator or
    /// not. This is only useful for the `get_key` method.
    started:      bool,
}

impl Iterator {
    /// Get key the iterator is currently pointing at. When the iterator is
    /// created this points to the prefix the iterator was created with.
    /// **After each call to next** this points to the key of the entry that
    /// was returned.
    #[inline(always)]
    pub fn get_key(&self) -> &[u8] {
        if self.started {
            // key at any node with a value should always be full (i.e., even length), so
            // length is ignored.
            &self.key.data
        } else {
            &self.root
        }
    }

    /// Get the key of which the iterator was initialized with.
    #[inline(always)]
    pub fn get_root(&self) -> &[u8] { &self.root }
}

impl CachedRef<Hashed<Node>> {
    fn thaw(
        &self,
        borrowed_values: &mut Vec<ValueLink>,
        entries: &mut Vec<Entry>,
        generation: u32,
        loader: &mut impl BackingStoreLoad,
    ) -> MutableNode {
        match self {
            CachedRef::Disk {
                reference,
                ..
            } => {
                let node: Hashed<Node> = Hashed::<Node>::load_from_location(loader, *reference)
                    .expect("Failed to read.");
                node.data.thaw(self, borrowed_values, entries, generation)
            }
            CachedRef::Memory {
                value,
                ..
            } => value.data.thaw(self, borrowed_values, entries, generation),
            CachedRef::Cached {
                value,
                ..
            } => value.data.thaw(self, borrowed_values, entries, generation),
        }
    }

    pub fn make_mutable(&self, generation: u32, loader: &mut impl BackingStoreLoad) -> MutableTrie {
        let mut borrowed_values = Vec::new();
        let mut entries = Vec::new();
        let root_node = self.thaw(&mut borrowed_values, &mut entries, generation, loader);
        MutableTrie {
            generations: vec![Generation::new(Some(0))],
            values: Vec::new(),
            nodes: vec![root_node],
            borrowed_values,
            entries,
        }
    }

    pub fn store_update<S: BackingStoreStore>(
        &mut self,
        backing_store: &mut S,
    ) -> Result<Vec<u8>, WriteError> {
        let mut buf = Vec::new();
        self.store_update_buf(backing_store, &mut buf)?;
        Ok(buf)
    }

    pub fn store_update_buf<S: BackingStoreStore, W: std::io::Write>(
        &mut self,
        backing_store: &mut S,
        buf: &mut W,
    ) -> StoreResult<()> {
        let reference = match self.get_mut_or_reference() {
            Ok(node) => {
                let data: Vec<u8> = node.store_update(backing_store)?;
                backing_store.store_raw(&data)?
            }
            Err(reference) => reference,
        };
        reference.store(buf)
    }

    /// Migrate the stored value to the new backing store. The value is not
    /// retained in memory. Only a disk reference is maintained.
    pub fn migrate<S: BackingStoreStore, L: BackingStoreLoad>(
        &self,
        backing_store: &mut S,
        loader: &mut L,
    ) -> LoadStoreResult<Self> {
        let mut buf = Vec::new();
        let _ = self.get(loader).migrate(backing_store, loader, &mut buf)?;
        let reference = backing_store.store_raw(&buf)?;
        Ok(Self::Disk {
            reference,
        })
    }
}

impl Node {
    fn thaw(
        &self,
        origin: &CachedRef<Hashed<Node>>,
        borrowed_values: &mut Vec<ValueLink>,
        entries: &mut Vec<Entry>,
        generation: u32,
    ) -> MutableNode {
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
            len.into()
        });
        MutableNode {
            generation,
            value: entry_idx,
            path: self.path.clone(),
            children: ChildrenCow::Borrowed(self.children.clone()),
            origin: Some(origin.clone()),
        }
    }
}

impl MutableTrie {
    pub fn empty() -> Self {
        Self {
            generations:     vec![Generation::new(None)],
            values:          Vec::new(),
            nodes:           Vec::new(),
            borrowed_values: Vec::new(),
            entries:         Vec::new(),
        }
    }

    /// Check whether the current generation is an empty tree.
    pub fn is_empty(&self) -> bool { self.generations.last().map_or(false, |x| x.root.is_none()) }
}

impl MutableTrie {
    /// Construct a new generation so that further modifications of the trie
    /// will be reflected in that generation. All existing generations will not
    /// be affected.
    /// The effects of this method can be undone with
    /// [`pop_generation`](Self::pop_generation).
    pub fn new_generation(&mut self) {
        let num_nodes = self.nodes.len();
        let num_values = self.values.len();
        let num_borrowed_nodes = self.borrowed_values.len();
        let num_entries = self.entries.len();
        if let Some(generation) = self.generations.last() {
            let checkpoint = Checkpoint {
                num_nodes,
                num_values,
                num_borrowed_nodes,
                num_entries,
            };
            if let Some(root_idx) = generation.root {
                let root = &self.nodes[root_idx];
                let current_generation = root.generation;
                let new_root_node = root.migrate(&mut self.entries, current_generation + 1);
                let new_root_idx = self.nodes.len();
                self.nodes.push(new_root_node);
                let new_generation =
                    Generation::new_with_checkpoint(Some(new_root_idx), checkpoint);
                self.generations.push(new_generation);
            } else {
                let new_generation = Generation::new_with_checkpoint(None, checkpoint);
                self.generations.push(new_generation);
            }
        }
    }

    /// Pop a generation, removing all data that is only accessible from the
    /// most recent generation. Return [None] if no generations are left.
    /// Inverse to [`new_generation`](Self::new_generation).
    pub fn pop_generation(&mut self) -> Option<()> {
        let generation = self.generations.pop()?;
        let checkpoint = generation.checkpoint;
        self.nodes.truncate(checkpoint.num_nodes);
        self.values.truncate(checkpoint.num_values);
        self.borrowed_values.truncate(checkpoint.num_borrowed_nodes);
        self.entries.truncate(checkpoint.num_entries);
        Some(())
    }

    /// Modify the tree so that the given root is the latest trie generation.
    /// If that root is already the latest, or does not even exist, this does
    /// nothing. More recent generations are all dropped.
    /// Analogous to [`pop_generation`](Self::pop_generation) except it
    /// can be used to forget multiple generations more efficiently.
    pub fn normalize(&mut self, root: u32) {
        let new_len = root as usize + 1;
        let generation = self.generations.get(new_len);
        if let Some(generation) = generation {
            self.nodes.truncate(generation.checkpoint.num_nodes);
            self.values.truncate(generation.checkpoint.num_values);
            self.borrowed_values.truncate(generation.checkpoint.num_borrowed_nodes);
            self.entries.truncate(generation.checkpoint.num_entries);
        }
        self.generations.truncate(new_len);
    }

    /// Get a mutable reference to an entry, if the entry exists. This copies
    /// the data pointed to by the entry unless the entry was already
    /// mutable. The counter is invoked in case a copy of the entry must be made
    /// and gives the caller the ability to terminate if too much data must
    /// be copied.
    pub fn get_mut<A: AllocCounter<Vec<u8>>>(
        &mut self,
        entry: EntryId,
        loader: &mut impl BackingStoreLoad,
        counter: &mut A,
    ) -> Result<Option<&mut Vec<u8>>, A::Err> {
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
                    let data = borrowed_entries[entry_idx].borrow().get_copy(loader);
                    counter.allocate(&data)?;
                    values.push(data);
                } else {
                    let data = {
                        let data = &values[entry_idx];
                        counter.allocate(data)?;
                        data.clone()
                    };
                    values.push(data);
                }
                self.entries[entry] = Entry::Mutable {
                    entry_idx: value_idx,
                };
                Ok(values.last_mut())
            }
            Entry::Mutable {
                entry_idx,
            } => Ok(values.get_mut(entry_idx)),
            Entry::Deleted => Ok(None),
        }
    }

    /// Set the entry to contain the given value, overwriting any existing
    /// value.
    fn set_entry_value(&mut self, entry: EntryId, value: Vec<u8>) {
        let values = &mut self.values;
        let entries = &mut self.entries;
        let entry = &mut entries[entry];
        if let Some(v) = entry.is_owned() {
            values[v] = value
        } else {
            let value_idx = values.len();
            values.push(value);
            *entry = Entry::Mutable {
                entry_idx: value_idx,
            }
        };
    }

    /// Advance the iterator. The `counter` is used to keep track of resources
    /// since in general advancing the iterator may have to traverse a large
    /// part of the tree.
    ///
    /// The return value is an `Err` if the resource counter signals resource
    /// exhaustion. Otherwise it is `None` if there is no further value to
    /// be given out, and a pointer to an entry in case there is.
    pub fn next<L: BackingStoreLoad, C: TraversalCounter>(
        &mut self,
        loader: &mut L,
        iterator: &mut Iterator,
        counter: &mut C,
    ) -> Result<Option<EntryId>, C::Err> {
        let owned_nodes = &mut self.nodes;
        let borrowed_values = &mut self.borrowed_values;
        let entries = &mut self.entries;
        iterator.started = true;
        loop {
            let node_idx = iterator.current_node;
            let node = &owned_nodes[node_idx];
            let next_child = if let Some(next_child) = iterator.next_child {
                next_child
            } else {
                iterator.next_child = Some(0);
                counter.count_key_traverse_part(node.path.len() as u64)?;
                if node.value.is_some() {
                    return Ok(node.value);
                }
                0
            };
            if usize::from(next_child) < node.children.len() {
                // we have to visit this child.
                iterator.stack.push((node_idx, next_child + 1, iterator.key.len()));
                iterator.next_child = None;
                let (_, _, children) =
                    make_owned(node_idx, borrowed_values, owned_nodes, entries, loader);
                let child = children[usize::from(next_child)];
                iterator.current_node = child.index();
                counter.count_key_traverse_part(1)?;
                iterator.key.push(child.key());
                let child_node = &owned_nodes[child.index()];
                iterator.key.extend(&child_node.path);
            } else {
                // pop back up.
                if let Some((parent_idx, next_child, key_len)) = iterator.stack.pop() {
                    counter.count_key_traverse_part(
                        iterator.key.len().saturating_sub(key_len) as u64
                    )?;
                    iterator.key.truncate(key_len);
                    iterator.current_node = parent_idx;
                    iterator.next_child = Some(next_child);
                } else {
                    // we are done
                    return Ok(None);
                }
            }
        }
    }

    /// Deletes an iterator.
    /// If an iterator was deleted then return `true` otherwise `false`.
    pub fn delete_iter(&mut self, iterator: &Iterator) -> bool {
        let generations = &mut self.generations;
        if let Some(generation) = generations.last_mut() {
            generation.iterator_roots.delete(iterator.get_root())
        } else {
            false
        }
    }

    pub fn iter(
        &mut self,
        loader: &mut impl BackingStoreLoad,
        key: &[u8],
    ) -> Result<Option<Iterator>, TooManyIterators> {
        let mut key_iter = StemIter::new(key);
        let owned_nodes = &mut self.nodes;
        let borrowed_values = &mut self.borrowed_values;
        let entries = &mut self.entries;
        let generation = if let Some(generation) = self.generations.last_mut() {
            generation
        } else {
            return Ok(None);
        };
        let mut node_idx = if let Some(node_idx) = generation.root {
            node_idx
        } else {
            return Ok(None);
        };
        loop {
            let node = unsafe { owned_nodes.get_unchecked_mut(node_idx) };
            let mut stem_iter = node.path.iter();
            match follow_stem(&mut key_iter, &mut stem_iter) {
                FollowStem::Equal => {
                    generation.iterator_roots.insert(key)?;
                    return Ok(Some(Iterator {
                        root:         key.into(),
                        current_node: node_idx,
                        key:          key.into(),
                        next_child:   None,
                        stack:        Vec::new(),
                        started:      false,
                    }));
                }
                FollowStem::KeyIsPrefix {
                    stem_step,
                } => {
                    generation.iterator_roots.insert(key)?;
                    let root: Box<[u8]> = key.into();
                    let mut key: MutStem = key.into();
                    key.push(stem_step);
                    while let Some(chunk) = stem_iter.next() {
                        key.push(chunk);
                    }
                    return Ok(Some(Iterator {
                        root,
                        current_node: node_idx,
                        key,
                        next_child: None,
                        stack: Vec::new(),
                        started: false,
                    }));
                }
                FollowStem::StemIsPrefix {
                    key_step,
                } => {
                    let (_, _, children) =
                        make_owned(node_idx, borrowed_values, owned_nodes, entries, loader);
                    let key_usize = usize::from(key_step.value) << 60;
                    let pair = if let Ok(pair) = children
                        .binary_search_by(|ck| (ck.pair & 0xf000_0000_0000_0000).cmp(&key_usize))
                    {
                        pair
                    } else {
                        return Ok(None);
                    };
                    node_idx = unsafe { children.get_unchecked(pair) }.index();
                }
                FollowStem::Diff {
                    ..
                } => {
                    return Ok(None);
                }
            }
        }
    }

    /// Set the entry value to the given value. Return a mutable reference to
    /// the value if successful. This is analogous to `get_mut`, except that
    /// it avoids copying the value in case the value is currently not owned
    /// for the relevant generation.
    pub fn set(&mut self, entry: EntryId, new_value: Vec<u8>) -> Option<&mut Vec<u8>> {
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
    ///
    /// Note that in case the entry is borrowed, i.e., in the persistent part of
    /// the tree, the callback is called while a read lock to the specific
    /// value is acquired. The lock is released after the closure returns.
    /// Thus a precondition to this function is that a write lock is not
    /// acquired to the specific value, and the callback does not attempt to
    /// acquire it.
    pub fn with_entry<X>(
        &self,
        entry: EntryId,
        loader: &mut impl BackingStoreLoad,
        f: impl FnOnce(&[u8]) -> X,
    ) -> Option<X> {
        let values = &self.values;
        let borrowed_values = &self.borrowed_values;
        match self.entries[entry] {
            Entry::ReadOnly {
                borrowed,
                entry_idx,
            } => {
                if borrowed {
                    let v = borrowed_values.get(entry_idx)?;
                    let v_ref = v.borrow();
                    let x = v_ref.get(loader);
                    Some(f(&*x))
                } else {
                    values.get(entry_idx).map(|b| f(&b[..]))
                }
            }
            Entry::Mutable {
                entry_idx,
            } => return values.get(entry_idx).map(|b| f(&b[..])),
            Entry::Deleted => None,
        }
    }

    /// Freeze the current generation. Returns None if the tree was empty.
    //
    // Note that as an optimization opportunity it might be useful to return a
    // list of new nodes so that they may be persisted quicker than
    // traversing the tree again. At the moment it is not always true that once
    // a tree is frozen it will be persisted, but returning a list of node pointers
    // might still be worth it. If we return a list of pointers there should be
    // relatively small overhead.
    pub fn freeze<Ctx: BackingStoreLoad, C: Collector<Vec<u8>>>(
        self,
        loader: &mut Ctx,
        collector: &mut C,
    ) -> Option<CachedRef<Hashed<Node>>> {
        let mut owned_nodes = self.nodes;
        let mut values = self.values;
        let entries = self.entries;
        let mut borrowed_values = self.borrowed_values;
        let root_idx = self.generations.last()?.root?;
        // get the reachable owned nodes.
        let mut reachable_stack = vec![root_idx];
        let mut reachable = Vec::new();
        while let Some(idx) = reachable_stack.pop() {
            reachable.push(idx);
            if let Some((_, children)) = owned_nodes[idx].children.get_owned() {
                for c in children {
                    reachable_stack.push(c.index());
                }
            }
        }
        // The 'reachable' array now has all reachable nodes in the order such that
        // a child of a node is always after the node itself. The root is at the
        // beginning of the array.
        // Now traverse the nodes bottom up, right to left.
        let mut nodes = HashMap::new();
        for node_idx in reachable.into_iter().rev() {
            let node = std::mem::take(&mut owned_nodes[node_idx]);
            match node.children {
                ChildrenCow::Borrowed(children) => {
                    let (changed, value) = freeze_value(
                        &mut borrowed_values,
                        &mut values,
                        &entries,
                        node.value,
                        loader,
                        collector,
                    );
                    if let Some(origin) = node.origin {
                        if !changed {
                            nodes.insert(node_idx, (false, origin));
                            continue;
                        }
                    }
                    collector.add_path(node.path.len());
                    collector.add_children(children.len());
                    let value = Node {
                        value,
                        path: node.path,
                        children,
                    };
                    let hash = value.hash(loader);
                    nodes.insert(
                        node_idx,
                        (true, CachedRef::Memory {
                            value: Hashed::new(hash, value),
                        }),
                    );
                }
                ChildrenCow::Owned {
                    value: owned,
                    ..
                } => {
                    let mut children = Vec::with_capacity(owned.len());
                    let mut changed = false;
                    for child in owned {
                        let (child_changed, child_node) = nodes.remove(&child.index()).unwrap();
                        changed = changed || child_changed;
                        children.push((child.key(), Link::new(child_node)));
                    }
                    let (value_changed, value) = freeze_value(
                        &mut borrowed_values,
                        &mut values,
                        &entries,
                        node.value,
                        loader,
                        collector,
                    );
                    if let Some(origin) = node.origin {
                        if !value_changed && !changed {
                            nodes.insert(node_idx, (false, origin));
                            continue;
                        }
                    }
                    collector.add_path(node.path.len());
                    collector.add_children(children.len());
                    let new_node = Node {
                        value,
                        path: node.path,
                        children,
                    };
                    let hash = new_node.hash(loader);
                    nodes.insert(
                        node_idx,
                        (true, CachedRef::Memory {
                            value: Hashed::new(hash, new_node),
                        }),
                    );
                }
            }
        }
        let mut nodes_iter = nodes.into_iter();
        if let Some((_, root)) = nodes_iter.next() {
            assert!(nodes_iter.next().is_none(), "Invariant violation.");
            Some(root.1)
        } else {
            unreachable!("Invariant violation. Root not in the nodes map.");
        }
    }

    pub fn get_entry(&mut self, loader: &mut impl BackingStoreLoad, key: &[u8]) -> Option<EntryId> {
        let mut key_iter = StemIter::new(key);
        let owned_nodes = &mut self.nodes;
        let borrowed_values = &mut self.borrowed_values;
        let entries = &mut self.entries;
        let mut node_idx = self.generations.last()?.root?;
        loop {
            let node = unsafe { owned_nodes.get_unchecked(node_idx) };
            match follow_stem(&mut key_iter, &mut node.path.iter()) {
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
                    let (_, _, children) =
                        make_owned(node_idx, borrowed_values, owned_nodes, entries, loader);
                    let key_usize = usize::from(key_step.value) << 60;
                    let pair = children
                        .binary_search_by(|ck| (ck.pair & 0xf000_0000_0000_0000).cmp(&key_usize))
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

    /// Delete the given key from the trie. If the entry is in a part of the
    /// tree that is locked this returns an error. Otherwise return whether
    /// an entry existed.
    pub fn delete(
        &mut self,
        loader: &mut impl BackingStoreLoad,
        key: &[u8],
    ) -> Result<bool, AttemptToModifyLockedArea> {
        let mut key_iter = StemIter::new(key);
        let owned_nodes = &mut self.nodes;
        let borrowed_values = &mut self.borrowed_values;
        let owned_values = &mut self.values;
        let entries = &mut self.entries;
        let mut grandfather = None;
        let mut father = None;
        let generation = if let Some(generation) = self.generations.last_mut() {
            generation
        } else {
            return Ok(false);
        };
        let mut node_idx = if let Some(node_idx) = generation.root {
            node_idx
        } else {
            return Ok(false);
        };
        generation.iterator_roots.check_has_no_prefix(key)?;
        loop {
            let node = unsafe { owned_nodes.get_unchecked_mut(node_idx) };
            match follow_stem(&mut key_iter, &mut node.path.iter()) {
                FollowStem::Equal => {
                    // we found it, delete the value first and save it for returning.
                    let rv;
                    if let Some(entry) = std::mem::take(&mut node.value) {
                        // We mark the entry as `Deleted` such that other ids pointing to the entry
                        // are automatically invalidated.
                        let existing_entry = std::mem::replace(&mut entries[entry], Entry::Deleted);
                        // if this entry was owned we now also clean up the stored value to
                        // deallocate any storage.
                        if let Some(value_idx) = existing_entry.is_owned() {
                            std::mem::take(&mut owned_values[value_idx]);
                        }
                        rv = existing_entry.is_alive();
                    } else {
                        // no value here, so no entry was found
                        return Ok(false);
                    }
                    // mark the node as modified
                    node.origin = None;
                    let (_, _, children) =
                        make_owned(node_idx, borrowed_values, owned_nodes, entries, loader);
                    if children.len() == 1 {
                        // collapse path from father
                        if let Some(child) = children.pop() {
                            let node = std::mem::take(&mut owned_nodes[node_idx]); // invalidate the node.
                            let child_node = &mut owned_nodes[child.index()];
                            child_node.path.prepend_parts(node.path, child.key());
                            child_node.origin = None;
                            if let Some((child_idx, father_idx)) = father {
                                // skip the current node
                                // father's child pointer should point directly to the node's child,
                                // instead of the node.
                                // the only thing that needs to be transferred from the node to the
                                // child is (potentially) the stem of the node.
                                let father_node: &mut MutableNode =
                                    unsafe { owned_nodes.get_unchecked_mut(father_idx) };
                                if let Some((_, children)) = father_node.children.get_owned_mut() {
                                    let child_place: &mut KeyIndexPair<4> =
                                        &mut children[child_idx];
                                    let step = child_place.key();
                                    *child_place = KeyIndexPair::new(step, child.index());
                                } else {
                                    unsafe { std::hint::unreachable_unchecked() }
                                }
                            } else {
                                // set the root to the new child
                                generation.root = Some(child.index());
                            }
                        } else {
                            unsafe {
                                // we checked length is 1 before popping.
                                std::hint::unreachable_unchecked();
                            }
                        }
                    } else if children.is_empty() {
                        // no children are left, and also no value, we need to delete the child from
                        // the father.
                        if let Some((child_idx, father_idx)) = father {
                            {
                                // the node will have a child removed, mark it as modified.
                                let father_node: &mut MutableNode =
                                    unsafe { owned_nodes.get_unchecked_mut(father_idx) };
                                father_node.origin = None;
                            }
                            let (has_value, _, father_children) = make_owned(
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
                                // collapse path from grandfather
                                if let Some(child) = father_children.pop() {
                                    let node = std::mem::take(&mut owned_nodes[father_idx]); // invalidate the node.
                                    let child_node = &mut owned_nodes[child.index()];
                                    child_node.path.prepend_parts(node.path, child.key());
                                    child_node.origin = None;
                                    if let Some((child_idx, grandfather_idx)) = grandfather {
                                        // skip the current node
                                        // grandfather's child pointer should point directly to the
                                        // node's child, instead of the node.
                                        // the only thing that needs to be transferred from the node
                                        // to the child is (potentially) the stem of the node.
                                        let grandfather_node: &mut MutableNode = unsafe {
                                            owned_nodes.get_unchecked_mut(grandfather_idx)
                                        };
                                        // the node was modified
                                        grandfather_node.origin = None;
                                        if let Some((_, children)) =
                                            grandfather_node.children.get_owned_mut()
                                        {
                                            let child_place: &mut KeyIndexPair<4> =
                                                &mut children[child_idx];
                                            let step = child_place.key();
                                            *child_place = KeyIndexPair::new(step, child.index());
                                        } else {
                                            unsafe { std::hint::unreachable_unchecked() }
                                        }
                                    } else {
                                        // grandfather did not exist
                                        // set the root to the new child
                                        generation.root = Some(child.index());
                                    }
                                } else {
                                    // we checked length is 1.
                                    unsafe { std::hint::unreachable_unchecked() }
                                }
                            }
                        } else {
                            // otherwise this must be the root. Delete it.
                            generation.root = None;
                        }
                    }
                    return Ok(rv);
                }
                FollowStem::KeyIsPrefix {
                    ..
                } => {
                    return Ok(false);
                }
                FollowStem::StemIsPrefix {
                    key_step,
                } => {
                    let (_, _, children) =
                        make_owned(node_idx, borrowed_values, owned_nodes, entries, loader);
                    if let Ok(c_idx) = children.binary_search_by(|ck| ck.key().cmp(&key_step)) {
                        let pair = unsafe { children.get_unchecked(c_idx) };
                        grandfather = std::mem::replace(&mut father, Some((c_idx, node_idx)));
                        node_idx = pair.index();
                    } else {
                        return Ok(false);
                    }
                }
                FollowStem::Diff {
                    ..
                } => {
                    return Ok(false);
                }
            };
        }
    }

    /// Delete the entire subtree whose keys match the given prefix, that is,
    /// where the given key is a prefix. Return
    /// - either an error caused by the counter
    /// - an error caused by attempting to modify a locked part of the tree
    /// - otherwise return whether anything was deleted
    pub fn delete_prefix<L: BackingStoreLoad, C: TraversalCounter>(
        &mut self,
        loader: &mut L,
        key: &[u8],
        counter: &mut C,
    ) -> Result<Result<bool, AttemptToModifyLockedArea>, C::Err> {
        let mut key_iter = StemIter::new(key);
        let owned_nodes = &mut self.nodes;
        let borrowed_values = &mut self.borrowed_values;
        let owned_values = &mut self.values;
        let entries = &mut self.entries;
        let mut grandparent_idx = None;
        let mut parent_idx = None;
        let generation = if let Some(generation) = self.generations.last_mut() {
            generation
        } else {
            return Ok(Ok(false));
        };
        let mut node_idx = if let Some(idx) = generation.root {
            idx
        } else {
            return Ok(Ok(false));
        };
        if generation.iterator_roots.is_or_has_prefix(key) {
            return Ok(Err(AttemptToModifyLockedArea));
        }
        loop {
            let node = unsafe { owned_nodes.get_unchecked_mut(node_idx) };
            match follow_stem(&mut key_iter, &mut node.path.iter()) {
                FollowStem::StemIsPrefix {
                    key_step,
                } => {
                    let (_, _, children) =
                        make_owned(node_idx, borrowed_values, owned_nodes, entries, loader);
                    if let Ok(c_idx) = children.binary_search_by(|ck| ck.key().cmp(&key_step)) {
                        let pair = unsafe { children.get_unchecked(c_idx) };
                        grandparent_idx =
                            std::mem::replace(&mut parent_idx, Some((c_idx, node_idx)));
                        node_idx = pair.index();
                    } else {
                        return Ok(Ok(false));
                    }
                }
                FollowStem::Diff {
                    ..
                } => {
                    return Ok(Ok(false));
                }
                _ => {
                    // We found the subtree to remove.
                    // First we check that the root of the subtree and it's children are not locked.
                    // Second, invalidate entry of the node and all of its children.
                    let mut nodes_to_invalidate = vec![node_idx];
                    // traverse each child subtree and invalidate them.
                    while let Some(node_idx) = nodes_to_invalidate.pop() {
                        let to_invalidate = &owned_nodes[node_idx];
                        counter.count_key_traverse_part(to_invalidate.path.len() as u64 + 1)?; // + 1 is for the step from the parent.
                        if let Some(entry) = to_invalidate.value {
                            let old_entry = std::mem::replace(&mut entries[entry], Entry::Deleted);
                            if let Some(idx) = old_entry.is_owned() {
                                std::mem::take(&mut owned_values[idx]);
                            }
                        }

                        // if children are borrowed then by construction there are no entries
                        // in them. Hence we only need to recurse into owned children.
                        if let Some((generation, children)) = to_invalidate.children.get_owned() {
                            // if children are of a previous generation then, again, we
                            // do not have to recurse, since all entries will be in fully owned
                            // nodes, and that means they will be of
                            // current generation.
                            if to_invalidate.generation == generation {
                                for v in children.iter() {
                                    nodes_to_invalidate.push(v.index())
                                }
                            }
                        }
                    }
                    // Now fix up the tree. We deleted a child of the parent. If the
                    // parent now has a single remaining child and no value we must collapse it with
                    // its parent, the grandfather, if it exists. If either the father nor the
                    // grandfather exist then they are in effect the root, so we change the root
                    // pointer to point to the relevant node, or None if we
                    // deleted the entire tree.
                    if let Some((child_idx, parent_idx)) = parent_idx {
                        {
                            // mark the parent as modified since we remove one if its children
                            let parent_node: &mut MutableNode =
                                unsafe { owned_nodes.get_unchecked_mut(parent_idx) };
                            parent_node.origin = None;
                        }
                        let (has_value, _, children) =
                            make_owned(parent_idx, borrowed_values, owned_nodes, entries, loader);

                        children.remove(child_idx);
                        // if the node does not have a value and it has one child, then it should be
                        // collapsed (path compressed)
                        if !has_value && children.len() == 1 {
                            // collapse path.
                            if let Some(child) = children.pop() {
                                let parent_node: MutableNode =
                                    std::mem::take(&mut owned_nodes[parent_idx]);
                                let child_node = &mut owned_nodes[child.index()];
                                child_node.path.prepend_parts(parent_node.path, child.key());
                                child_node.origin = None;
                                if let Some((child_idx, grandparent_idx)) = grandparent_idx {
                                    // skip the parent
                                    // grandfather's child pointer should point directly to the
                                    // node's child, instead of the node.
                                    // the only thing that needs to be transferred from the node
                                    // to the child is (potentially) the stem of the node.
                                    // All other values in the node are empty.
                                    let grandparent_node: &mut MutableNode =
                                        unsafe { owned_nodes.get_unchecked_mut(grandparent_idx) };
                                    // grandparent was modified
                                    grandparent_node.origin = None;
                                    if let Some((_, children)) =
                                        grandparent_node.children.get_owned_mut()
                                    {
                                        let child_place: &mut KeyIndexPair<4> =
                                            &mut children[child_idx];
                                        let step = child_place.key();
                                        *child_place = KeyIndexPair::new(step, child.index());
                                    } else {
                                        unsafe { std::hint::unreachable_unchecked() }
                                    }
                                } else {
                                    // grandparent did not exist
                                    // set the root to the new child
                                    if let Some(generation) = self.generations.last_mut() {
                                        generation.root = Some(child.index());
                                    }
                                }
                            } else {
                                unsafe { std::hint::unreachable_unchecked() }
                            }
                        }
                    } else {
                        generation.root = None;
                        return Ok(Ok(true));
                    }
                    return Ok(Ok(true));
                }
            };
        }
    }

    /// Returns the new entry id, and a boolean indicating whether
    /// an entry already existed at the key. If it did, it was replaced.
    pub fn insert(
        &mut self,
        loader: &mut impl BackingStoreLoad,
        key: &[u8],
        new_value: Vec<u8>,
    ) -> Result<(EntryId, bool), AttemptToModifyLockedArea> {
        let (current_generation, older_generations) = self
            .generations
            .split_last_mut()
            .expect("There should always be at least 1 generation.");
        current_generation.iterator_roots.check_has_no_prefix(key)?;
        // if the tree is empty we must create a new root
        let mut node_idx = if let Some(root) = current_generation.root {
            root
        } else {
            // the tree is empty
            let value_idx = self.values.len();
            self.values.push(new_value);
            let generation_idx = older_generations.len() as u32;
            let root_idx = self.nodes.len();
            let entry_idx: EntryId = self.entries.len().into();
            self.entries.push(Entry::Mutable {
                entry_idx: value_idx,
            });
            self.nodes.push(MutableNode {
                generation: generation_idx,
                value:      Some(entry_idx),
                path:       key.into(),
                children:   ChildrenCow::Owned {
                    generation: generation_idx,
                    value:      tinyvec::TinyVec::new(),
                },
                origin:     None,
            });
            current_generation.root = Some(root_idx);
            return Ok((entry_idx, false));
        };
        let owned_nodes = &mut self.nodes;
        let borrowed_values = &mut self.borrowed_values;
        let entries = &mut self.entries;
        // the parent node index and the index of the parents child we're visiting.
        let mut parent_node_idxs: Option<(usize, usize)> = None;
        let generation = owned_nodes[node_idx].generation;
        let mut key_iter = StemIter::new(key);
        loop {
            let owned_nodes_len = owned_nodes.len();
            let node = unsafe { owned_nodes.get_unchecked_mut(node_idx) };
            node.origin = None; // the node is on the modified path
            let mut stem_iter = node.path.iter();
            let checkpoint = key_iter.pos;
            match follow_stem(&mut key_iter, &mut stem_iter) {
                FollowStem::Equal => {
                    let old_entry_idx = node.value;
                    if let Some(idx) = old_entry_idx {
                        self.set_entry_value(idx, new_value);
                        return Ok((idx, true));
                    }
                    // insert the new value.
                    let value_idx = self.values.len();
                    self.values.push(new_value);
                    // insert new entry
                    let entry_idx: EntryId = self.entries.len().into();
                    self.entries.push(Entry::Mutable {
                        entry_idx: value_idx,
                    });
                    node.value = Some(entry_idx);
                    return Ok((entry_idx, false));
                }
                FollowStem::KeyIsPrefix {
                    stem_step,
                } => {
                    // create a new branch with the value being the new_value since the key ends
                    // here.
                    let remaining_stem: Stem = stem_iter.to_stem();
                    let value_idx = self.values.len();
                    self.values.push(new_value);
                    let entry_idx: EntryId = self.entries.len().into();
                    self.entries.push(Entry::Mutable {
                        entry_idx: value_idx,
                    });

                    node.path = remaining_stem;
                    let new_node_idx = owned_nodes_len;

                    // Update the parents children index with the new child
                    if let Some((parent_node_idx, child_idx)) = parent_node_idxs {
                        let parent_node = unsafe { owned_nodes.get_unchecked_mut(parent_node_idx) };
                        if let Some((_, children)) = parent_node.children.get_owned_mut() {
                            if let Some(key_and_index) = children.get_mut(child_idx) {
                                let key = key_and_index.key();
                                *key_and_index = KeyIndexPair::new(key, new_node_idx);
                            }
                        }
                    } else {
                        current_generation.root = Some(new_node_idx);
                    }
                    // FIXME: Need argument of whether to use all or without the last one.
                    let new_node = MutableNode {
                        generation,
                        value: Some(entry_idx),
                        path: key_iter.last_to_stem(checkpoint),
                        children: ChildrenCow::Owned {
                            generation,
                            value: tinyvec::tiny_vec![[_; INLINE_CAPACITY] => KeyIndexPair::new(stem_step, node_idx)],
                        },
                        origin: None,
                    };
                    owned_nodes.push(new_node);
                    return Ok((entry_idx, false));
                }
                FollowStem::StemIsPrefix {
                    key_step,
                } => {
                    // make_owned may insert additional nodes. Hence we have to update our
                    // owned_nodes_len to make sure we have the up-to-date
                    // value.
                    let (_, owned_nodes_len, children) =
                        make_owned(node_idx, borrowed_values, owned_nodes, entries, loader);
                    let idx = children.binary_search_by(|kk| kk.key().cmp(&key_step));
                    match idx {
                        Ok(idx) => {
                            parent_node_idxs = Some((node_idx, idx));
                            node_idx = unsafe { children.get_unchecked(idx).index() };
                        }
                        Err(place) => {
                            // need to create a new node.
                            let remaining_key: Stem = key_iter.to_stem();
                            let new_key_node_idx = owned_nodes_len;
                            children.insert(place, KeyIndexPair::new(key_step, new_key_node_idx));
                            let value_idx = self.values.len();
                            self.values.push(new_value);
                            // insert new entry
                            let entry_idx: EntryId = entries.len().into();
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
                                origin: None,
                            });
                            return Ok((entry_idx, false));
                        }
                    }
                }
                FollowStem::Diff {
                    key_step,
                    stem_step,
                } => {
                    // create a new branch with the value being the new_value since the key ends
                    // here.
                    let remaining_stem: Stem = stem_iter.to_stem();
                    let remaining_key: Stem = key_iter.to_stem();
                    let new_stem = stem_iter.consumed_to_stem();
                    // index of the node that continues along the remaining key
                    let remaining_key_node_idx = owned_nodes_len;
                    // index of the new node that will have two children
                    let new_node_idx = owned_nodes_len + 1;
                    node.path = remaining_stem;
                    // insert new entry
                    let value_idx = self.values.len();
                    self.values.push(new_value);
                    let entry_idx: EntryId = self.entries.len().into();
                    self.entries.push(Entry::Mutable {
                        entry_idx: value_idx,
                    });
                    {
                        let remaining_key_node = MutableNode {
                            generation,
                            value: Some(entry_idx),
                            path: remaining_key,
                            children: ChildrenCow::Owned {
                                generation: generation as u32,
                                value:      tinyvec::TinyVec::new(),
                            },
                            origin: None,
                        };
                        owned_nodes.push(remaining_key_node);
                    }

                    // construct the new node with two children
                    {
                        let children = if key_step < stem_step {
                            tinyvec::tiny_vec![
                                [_; INLINE_CAPACITY] =>
                                KeyIndexPair::new(key_step, remaining_key_node_idx),
                                KeyIndexPair::new(stem_step, node_idx),
                            ]
                        } else {
                            tinyvec::tiny_vec![
                                [_; INLINE_CAPACITY] =>
                                KeyIndexPair::new(stem_step, node_idx),
                                KeyIndexPair::new(key_step, remaining_key_node_idx),
                            ]
                        };
                        let new_node = MutableNode {
                            generation,
                            value: None,
                            path: new_stem,
                            children: ChildrenCow::Owned {
                                generation,
                                value: children,
                            },
                            origin: None,
                        };
                        owned_nodes.push(new_node);
                    }

                    // Update the parents children index with the new child
                    if let Some((parent_node_idx, child_idx)) = parent_node_idxs {
                        let parent_node = unsafe { owned_nodes.get_unchecked_mut(parent_node_idx) };
                        if let Some((_, children)) = parent_node.children.get_owned_mut() {
                            if let Some(key_and_index) = children.get_mut(child_idx) {
                                let key = key_and_index.key();
                                *key_and_index = KeyIndexPair::new(key, new_node_idx);
                            }
                        }
                    } else {
                        current_generation.root = Some(new_node_idx);
                    }
                    return Ok((entry_idx, false));
                }
            }
        }
    }
}

/// Store the node's value tag (whether the value is present or not) together
/// with the length of the stem. This should match
/// [read_node_path_and_value_tag] below.
/// The value tag encodes both the presence of the value in the node, as well as
/// potentially the length of the node stem. The latter is only in the case the
/// node stem fits into the 6 bits, otherwise we explicitly record the length as
/// a big endian u32.
#[inline(always)]
fn write_node_path_and_value_tag(
    stem_len: usize,
    no_value: bool,
    out: &mut impl Write,
) -> Result<(), std::io::Error> {
    // the second bit of the u8 encodes whether the node has a value (1) or not (0)
    let value_mask: u8 = if no_value {
        0
    } else {
        0b0100_0000
    };
    // The first bit encodes whether there the length is encoded explicitly (1) or
    // in the first byte (0).
    if stem_len <= INLINE_STEM_LENGTH {
        let tag = stem_len as u8 | value_mask;
        out.write_u8(tag)
    } else {
        // We could optimize this as well by using variable-length encoding.
        // But it probably does not matter in practice since paths should really always
        // be < 64 in length.
        let tag = 0b1000_0000 | value_mask;
        out.write_u8(tag)?;
        out.write_u32::<BigEndian>(stem_len as u32)
    }
}

#[inline(always)]
/// Read a node path and whether the value exists. This should match
/// [write_node_path_and_value_tag] above.
fn read_node_path_and_value_tag(source: &mut impl Read) -> Result<(Stem, bool), std::io::Error> {
    let tag = source.read_u8()?;
    let path_len = if tag & 0b1000_0000 == 0 {
        // first bit is 1, stem length is encoded in the last 6 bits of the tag.
        u32::from(tag & 0b0011_1111)
    } else {
        // stem length follows as a u32
        source.read_u32::<BigEndian>()?
    };
    let num_bytes = path_len / 2 + path_len % 2;
    let mut path = vec![0u8; num_bytes as usize];
    source.read_exact(&mut path)?;
    let path = Stem::new(path.into_boxed_slice(), path_len as usize);
    // Whether the node has a value or not is encoded in the second bit of the tag.
    // Extract it.
    let has_value = tag & 0b0100_0000 != 0;
    Ok((path, has_value))
}

/// A dummy invalid reference used in the `deserialize` method below where we
/// have to "consume" nodes from a vector without changing indices. We do this
/// by replacing nodes with a (cheap) value.
const INVALID_NODE_CACHED_REF: CachedRef<Hashed<Node>> = CachedRef::Disk {
    reference: Reference {
        reference: 0,
    },
};

impl Hashed<Node> {
    /// Serialize the node and its children into a byte array.
    /// Note that this serializes the entire tree together with its children, so
    /// it is different from store_update which only traverses the part of
    /// the tree that is in memory.
    pub fn serialize(
        &self,
        loader: &mut impl BackingStoreLoad,
        out: &mut impl std::io::Write,
    ) -> anyhow::Result<()> {
        // this limits the tree size to 4 billion nodes.
        let mut node_counter: u32 = 0;
        let mut queue = std::collections::VecDeque::new();
        queue.push_back((self.clone(), node_counter));
        while let Some((node, idx)) = queue.pop_front() {
            out.write_u32::<BigEndian>(node_counter - idx)?;
            out.write_all(node.hash.as_ref())?;
            let node = &node.data;
            let (stem_len, stem_ref) = node.path.to_slice();
            write_node_path_and_value_tag(stem_len, node.value.is_none(), out)?;
            // store the path
            out.write_all(stem_ref)?;
            // store the value
            if let Some(v) = node.value.as_ref() {
                let borrowed = v.borrow();
                let (mhash, v) = borrowed.get_ref_and_hash(loader);
                let len = v.as_ref().len();
                out.write_u32::<BigEndian>(len as u32)?;
                if let Some(hash) = mhash {
                    out.write_all(hash.as_ref())?;
                }
                out.write_all(v.as_ref())?
            }
            // There can be at most 16 children, this is safe.
            out.write_u8(node.children.len() as u8)?;
            let parent_idx = node_counter;
            for (key, child) in node.children.iter() {
                out.write_u8(key.value)?;
                let child_ref = child.borrow();
                let nd = child_ref.get(loader);
                queue.push_back((nd.clone(), parent_idx));
            }
            node_counter += 1;
        }
        Ok(())
    }

    /// The inverse of [serialize](Self::serialize).
    pub fn deserialize(source: &mut impl std::io::Read) -> anyhow::Result<Self> {
        let mut parents: Vec<Link<CachedRef<Hashed<Node>>>> = Vec::new();
        let mut todo = std::collections::VecDeque::new();
        todo.push_back(0); // dummy initial value, will not be used.
        while let Some(key) = todo.pop_front() {
            let idx = source.read_u32::<BigEndian>()?;
            let hash = Hash::read(source)?;
            let (path, has_value) = read_node_path_and_value_tag(source)?;
            let value = if has_value {
                let value_len = source.read_u32::<BigEndian>()?;
                if value_len as usize <= INLINE_VALUE_LEN {
                    Some(Link::new(read_buf(source, value_len as u8)?))
                } else {
                    let value_hash = Hash::read(source)?;
                    let mut val = vec![0u8; value_len as usize];
                    source.read_exact(&mut val)?;
                    Some(Link::new(InlineOrHashed::Indirect(Hashed::new(
                        value_hash,
                        CachedRef::Memory {
                            value: val.into(),
                        },
                    ))))
                }
            } else {
                None
            };
            let num_children = source.read_u8()?;
            let new_node = Link::new(CachedRef::Memory {
                value: Hashed::new(hash, Node {
                    value,
                    path,
                    children: Vec::new(),
                }),
            });
            if idx > 0 {
                let mut parent = parents[parents.len() - idx as usize].borrow_mut();
                if let CachedRef::Memory {
                    value,
                } = &mut *parent
                {
                    value.data.children.push((Chunk::new(key), new_node.clone()));
                } else {
                    // all values are allocated in this function, so in-memory.
                    unsafe { std::hint::unreachable_unchecked() };
                }
            }
            for _ in 0..num_children {
                let key = source.read_u8()?;
                todo.push_back(key);
            }
            parents.push(new_node);
        }
        if let Some(root) = parents.into_iter().next() {
            let rw = std::mem::replace(&mut *root.borrow_mut(), INVALID_NODE_CACHED_REF);
            if let CachedRef::Memory {
                value,
            } = rw
            {
                Ok(value)
            } else {
                // all values are allocated in this function, so in-memory.
                unsafe { std::hint::unreachable_unchecked() };
            }
        } else {
            // all values are allocated in this function, so in-memory, and there is at
            // least one.
            unsafe { std::hint::unreachable_unchecked() };
        }
    }
}

/// Result of [follow_stem] below.
enum FollowStem {
    /// Iterators were equal. Both were consumed to the end.
    Equal,
    /// The key iterator is a strict prefix of the stem iterator.
    /// The first item of the stem past the key is returned.
    KeyIsPrefix {
        stem_step: Chunk<4>,
    },
    /// The stem iterator is a strict prefix of the key iterator.
    /// The first item of the key past the stem is returned.
    StemIsPrefix {
        key_step: Chunk<4>,
    },
    /// The stem and key iterators differ. The items where they differ are
    /// returned.
    Diff {
        key_step:  Chunk<4>,
        stem_step: Chunk<4>,
    },
}

#[inline(always)]
/// Given two iterators, representing the key and the stem of the node, advance
/// them stepwise until either at least one of them is exhausted or the steps
/// differ. Return which option occurred.
fn follow_stem(key_iter: &mut StemIter, stem_iter: &mut StemIter) -> FollowStem {
    while let Some(stem_step) = stem_iter.next() {
        if let Some(key_step) = key_iter.next() {
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
    if let Some(key_step) = key_iter.next() {
        FollowStem::StemIsPrefix {
            key_step,
        }
    } else {
        FollowStem::Equal
    }
}

impl Node {
    /// **This is not efficient.** It involves cloning nodes, which is
    /// not all that cheap, even with reference counting.
    /// This should only be used in testing/debugging and not in production.
    pub fn lookup(&self, loader: &mut impl BackingStoreLoad, key: &[u8]) -> Option<ValueLink> {
        let mut key_iter = StemIter::new(key);
        let mut path = self.path.clone();
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
                    {
                        let node_ref = c.borrow();
                        let node = node_ref.get(loader);
                        path = node.data.path.clone();
                        tmp.clear();
                        tmp.extend_from_slice(&node.data.children);
                        value = node.data.value.clone();
                    }
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
            if let InlineOrHashed::Indirect(value) = &*value.borrow() {
                if let CachedRef::Memory {
                    ..
                } = value.data
                {
                    return false;
                }
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
            if let InlineOrHashed::Indirect(value) = &*value.borrow() {
                return !matches!(&value.data, CachedRef::Disk { .. });
            } else {
                // [InlineOrHashed::Inline] are not [CachedRef]'s
                return false;
            }
        }

        for child in self.children.iter() {
            match &*child.1.borrow() {
                CachedRef::Disk {
                    reference: _,
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
                    reference: _,
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

#[cfg(test)]
/// Tests for the prefix map.
mod prefix_map_tests {
    use super::PrefixesMap;
    const NUM_TESTS: u64 = 100000;
    #[test]
    fn prop_insert_delete() {
        let prop = |keys: Vec<Vec<u8>>| -> anyhow::Result<()> {
            let mut map = PrefixesMap::new();
            for key in keys.iter() {
                if map.insert(key).is_err() {
                    // ignore tests which cause overflow
                    return Ok(());
                }
            }
            for key in keys.iter() {
                anyhow::ensure!(map.delete(key), "Every inserted key should be deleted.");
            }
            anyhow::ensure!(map.is_empty(), "Deleting everything should leave the map empty.");
            anyhow::ensure!(map.nodes.is_empty(), "Slab should be empty.");
            Ok(())
        };
        quickcheck::QuickCheck::new()
            .tests(NUM_TESTS)
            .quickcheck(prop as fn(_) -> anyhow::Result<()>);
    }

    #[test]
    fn prop_is_prefix() {
        let prop = |keys: Vec<Vec<u8>>, prefixes: Vec<Vec<u8>>| -> anyhow::Result<()> {
            let mut map = PrefixesMap::new();
            for key in keys.iter() {
                // ignore tests which cause overflow
                if map.insert(key).is_err() {
                    return Ok(());
                }
            }
            for prefix in prefixes.iter() {
                let has_any_prefix = keys.iter().any(|key| prefix.starts_with(key));
                let res = map.check_has_no_prefix(prefix);
                anyhow::ensure!(
                    has_any_prefix == res.is_err(),
                    "Reference ({}) differs from actual ({:?}).",
                    has_any_prefix,
                    res
                );
            }
            Ok(())
        };
        quickcheck::QuickCheck::new()
            .tests(NUM_TESTS)
            .quickcheck(prop as fn(_, _) -> anyhow::Result<()>);
    }

    #[test]
    fn prop_has_prefix() {
        let prop = |keys: Vec<Vec<u8>>, prefixes: Vec<Vec<u8>>| -> anyhow::Result<()> {
            let mut map = PrefixesMap::new();
            for key in keys.iter() {
                // ignore tests which cause overflow
                if map.insert(key).is_err() {
                    return Ok(());
                }
            }
            for prefix in prefixes.iter() {
                let has_any_as_prefix =
                    keys.iter().any(|key| key.starts_with(prefix) || prefix.starts_with(key));
                let res = map.is_or_has_prefix(prefix);
                anyhow::ensure!(
                    has_any_as_prefix == res,
                    "Reference ({}) differs from actual ({}).",
                    has_any_as_prefix,
                    res
                );
            }
            Ok(())
        };
        quickcheck::QuickCheck::new()
            .tests(NUM_TESTS)
            .quickcheck(prop as fn(_, _) -> anyhow::Result<()>);
    }
}
