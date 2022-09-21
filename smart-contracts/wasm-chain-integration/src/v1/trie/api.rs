//! The high-level API that is meant to be used by the rest of the project.
//! It exposes two main constructs, the [`PersistentState`] and [`MutableState`]
//! that provide all the needed functionality for the implementation of contract
//! state.
//!
//! The [`PersistentState`] is immutable. It is "persistent" in the sense of
//! persistent data structures, meaning that we never modify it in-place, but
//! always create new versions. This state is used for recording the state of a
//! smart contract at the end of a transaction execution.
//!
//! State modifications are done via the [`MutableState`] which exists during
//! transaction execution. This type is modified in-place and supports rollbacks
//! which are sometimes necessary during the transaction due to contract calls.
//!
//! The overall flow is that a [`PersistentState`] is
//! [thawed](PersistentState::thaw) into a [`MutableState`] when the contract
//! starts execution. Then a contract is executed, and if it terminates with
//! success the resulting state is [frozen](MutableState::freeze) into a
//! [`PersistentState`]. During this process only the part of the original state
//! that has been modified is copied. The new [`PersistentState`] in general
//! retains pointers to parts of the original state. This allows for efficient
//! state updates where we only have to store the parts of the state that are
//! new.
use super::{
    low_level::{self, CachedRef, MutableTrie, Node},
    types::*,
};
use byteorder::{ReadBytesExt, WriteBytesExt};
#[cfg(feature = "display-state")]
use ptree::TreeBuilder;
use sha2::Digest;
use std::{
    iter::FusedIterator,
    sync::{Arc, Mutex, MutexGuard},
};

pub type Value = Vec<u8>;

/// The persistent contract state.
/// Clone on this structure is designed to be cheap, and it is a shallow copy.
#[derive(Debug, Clone)]
pub enum PersistentState {
    Empty,
    Root(CachedRef<Hashed<Node>>),
}

impl From<CachedRef<Hashed<Node>>> for PersistentState {
    fn from(root: CachedRef<Hashed<Node>>) -> Self { Self::Root(root) }
}

/// Load the persistent state. This only loads the root of the tree. In order to
/// cache the entire tree into memory use [PersistentState::cache] afterwards.
impl Loadable for PersistentState {
    fn load<S: std::io::Read, F: BackingStoreLoad>(
        loader: &mut F,
        source: &mut S,
    ) -> LoadResult<Self> {
        match source.read_u8()? {
            0 => Ok(Self::Empty),
            1 => Ok(Self::Root(CachedRef::load(loader, source)?)),
            tag => Err(LoadError::IncorrectTag {
                tag,
            }),
        }
    }
}

impl PersistentState {
    /// Store the tree into the backing store, and modify the tree so that it
    /// records where parts of it are stored. The root of the tree is written
    /// into the provided buffer.
    pub fn store_update_buf<S: BackingStoreStore, W: std::io::Write>(
        &mut self,
        backing_store: &mut S,
        buf: &mut W,
    ) -> StoreResult<()> {
        match self {
            PersistentState::Empty => {
                buf.write_u8(0)?;
                Ok(())
            }
            PersistentState::Root(node) => {
                buf.write_u8(1)?;
                node.store_update_buf(backing_store, buf)
            }
        }
    }

    /// Like [Self::store_update_buf], but returns a freshly allocated buffer
    /// for the root instead of using the provided one.
    pub fn store_update<S: BackingStoreStore>(
        &mut self,
        backing_store: &mut S,
    ) -> StoreResult<Reference> {
        let mut top = Vec::new();
        self.store_update_buf(backing_store, &mut top)?;
        backing_store.store_raw(&top)
    }

    /// Migrate the tree from one backing store to another.
    pub fn migrate<S: BackingStoreStore, L: BackingStoreLoad>(
        &mut self,
        backing_store: &mut S,
        loader: &mut L,
    ) -> LoadStoreResult<Self> {
        match self {
            PersistentState::Empty => Ok(PersistentState::Empty),
            PersistentState::Root(node) => {
                let new_node = node.migrate(backing_store, loader)?;
                Ok(PersistentState::Root(new_node))
            }
        }
    }

    /// Serialize the tree into the provided buffer. Note that this is very
    /// different from [Self::store_update]. Whereas that stores the part of
    /// the tree that are only in memory into the provided backing store, this
    /// function loads the entire tree and serializes it, in a custom format,
    /// into the provided buffer. As a result this is an expensive operation
    /// that should only be used when incrementally storing the tree is not
    /// an option.
    pub fn serialize(
        &self,
        loader: &mut impl BackingStoreLoad,
        out: &mut impl std::io::Write,
    ) -> anyhow::Result<()> {
        match self {
            PersistentState::Empty => out.write_u8(0)?,
            PersistentState::Root(ht) => {
                out.write_u8(1)?;
                let node = ht.get(loader);
                node.serialize(loader, out)?;
            }
        }
        Ok(())
    }

    /// Dual to [Self::serialize].
    pub fn deserialize(source: &mut impl std::io::Read) -> anyhow::Result<Self> {
        match source.read_u8()? {
            0 => Ok(Self::Empty),
            1 => {
                let node = Hashed::<Node>::deserialize(source)?;
                Ok(PersistentState::Root(CachedRef::Memory {
                    value: node,
                }))
            }
            tag => anyhow::bail!("Invalid persistent tree tag: {}", tag),
        }
    }

    /// Lookup a key in the tree and return a copy of the value stored.
    pub fn lookup(&self, loader: &mut impl BackingStoreLoad, key: &[u8]) -> Option<Value> {
        match self {
            PersistentState::Empty => None,
            PersistentState::Root(root_node) => {
                // we do lookups in the mutable trie to improve performance, and to
                // avoid issues with stack overflow.
                let mut trie = root_node.make_mutable(0, loader);
                let entry = trie.get_entry(loader, key)?;
                trie.with_entry(entry, loader, |x| x.to_vec())
            }
        }
    }

    /// Derive a fresh mutable trie from the [`PersistentState`] using the given
    /// loader. In contrast to using [`thaw`](Self::thaw) and then using
    /// [`MutableState::get_inner`] this directly yields a mutable trie that
    /// can be used. However this mutable trie is not shareable and does not
    /// have checkpointing in contrast to the [`MutableState`].
    ///
    /// This is intended when the persistent trie is used in read-only way. It
    /// gives access to the efficient implementations of lookup and
    /// traversal for the mutable trie. In particular converting
    /// [`PersistentState`] to [`MutableTrie`] should be preffered over
    /// [`lookup`](Self::lookup) if multiple lookups will be performed on
    /// the resulting [`MutableTrie`].
    pub fn into_trie(self, loader: &mut impl BackingStoreLoad) -> MutableTrie {
        match self {
            PersistentState::Empty => MutableTrie::empty(),
            PersistentState::Root(root_node) => root_node.make_mutable(0, loader),
        }
    }

    /// Get an iterator over the (key, value) pairs stored in the persistent
    /// state. The iterator yields keys in ascending lexicographic order.
    pub fn into_iterator<L: BackingStoreLoad>(self, loader: &mut L) -> PersistentStateIterator<L> {
        let mut state = self.into_trie(loader);
        // get an iterator over the entire state (starting at root)
        match state.iter(loader, &[]) {
            Err(_) => {
                unreachable!("We just created the trie, so it has no iterators.")
            }
            Ok(iterator) => PersistentStateIterator {
                state,
                iterator,
                loader,
            },
        }
    }

    /// Construct a [PersistentState] from an iterator. If the iterator has
    /// duplicate keys then values at later keys override earlier ones.
    /// The resulting state lies entirely in memory and so can be used with any
    /// [`Loader`].
    pub fn from_iterator<'a, I: IntoIterator<Item = (&'a [u8], Vec<u8>)>>(iter: I) -> Self {
        let mut loader = Loader {
            inner: Vec::new(),
        };
        let mut trie = MutableTrie::empty();
        for (k, v) in iter {
            trie.insert(&mut loader, k, v).expect("Tree is fresh, so insert cannot fail.");
        }
        match trie.freeze(&mut loader, &mut EmptyCollector) {
            Some(root) => Self::Root(root),
            None => Self::Empty,
        }
    }

    #[cfg(feature = "async")]
    /// Construct a [PersistentState] from a stream of key-value pairs,
    /// but where the stream might yield errors at some point. This is intended
    /// to be used when the stream is coming, e.g., over the network, and might
    /// be interrupted.
    ///
    /// If the stream yields duplicate keys then values at later keys
    /// override earlier ones. The resulting state lies entirely in memory
    /// and so can be used with any [`Loader`]. If any item in the stream yields
    /// an error this function returns early with the given error.
    pub async fn try_from_stream<E, S>(mut s: S) -> Result<Self, E>
    where
        S: futures::stream::Stream<Item = Result<(Vec<u8>, Vec<u8>), E>> + Unpin, {
        use futures::StreamExt;
        let mut loader = Loader {
            inner: Vec::new(),
        };
        let mut trie = MutableTrie::empty();
        while let Some(item) = s.next().await {
            let (k, v) = item?;
            trie.insert(&mut loader, &k, v).expect("Tree is fresh, so insert cannot fail.");
        }
        Ok(match trie.freeze(&mut loader, &mut EmptyCollector) {
            Some(root) => Self::Root(root),
            None => Self::Empty,
        })
    }

    #[cfg(feature = "async")]
    /// Construct a [PersistentState] from a stream of key-value pairs.
    /// If the stream yields duplicate keys then values at later keys
    /// override earlier ones. The resulting state lies entirely in memory
    /// and so can be used with any [`Loader`].
    ///
    /// This function should be preferred over
    /// [`try_from_stream`](Self::try_from_stream) when it is applicable.
    pub async fn from_stream<S>(s: S) -> Self
    where
        S: futures::stream::Stream<Item = (Vec<u8>, Vec<u8>)> + Unpin, {
        use futures::StreamExt;
        enum Empty {}
        match Self::try_from_stream::<Empty, _>(s.map(Result::Ok)).await {
            Ok(s) => s,
            Err(e) => match e {},
        }
    }

    /// Generate a fresh mutable state from the persistent state.
    pub fn thaw(&self) -> MutableState {
        MutableState {
            inner:      None,
            persistent: self.clone(),
        }
    }

    /// Compute the hash of the persistent state. This is a cheap operation
    /// since the state hash is stored precomputed, however if the tree is not
    /// loaded into memory then the hash will have to be retrieved from the
    /// backing store using the provided loader.
    pub fn hash(&self, loader: &mut impl BackingStoreLoad) -> super::Hash {
        match self {
            PersistentState::Empty => {
                // hash of the node starts with either a 0 or 1 byte. This makes it distinct,
                // but is otherwise an arbitrary choice.
                super::Hash::from(<[u8; 32]>::from(sha2::Sha256::digest(b"empty contract state")))
            }
            PersistentState::Root(root) => root.hash(loader),
        }
    }

    /// Cache the state, that is, load the entire state into memory from the
    /// backing store. References to the backing store are retained.
    pub fn cache<F: BackingStoreLoad>(&mut self, loader: &mut F) {
        if let PersistentState::Root(node) = self {
            node.load_and_cache(loader).data.cache(loader);
        }
    }

    #[cfg(feature = "display-state")]
    pub fn display_tree(&self, builder: &mut TreeBuilder, loader: &mut impl BackingStoreLoad) {
        match self {
            Self::Empty => {}
            Self::Root(node) => {
                let tree = node.get(loader);
                tree.data.display_tree(builder, loader)
            }
        }
    }
}

/// Iterator over all (key, value) pairs stored in the persistent state.
/// Values are returned in increasing order of keys.
pub struct PersistentStateIterator<'a, L> {
    state:    MutableTrie,
    iterator: Option<low_level::Iterator>,
    loader:   &'a mut L,
}

impl<'a, L: BackingStoreLoad> Iterator for PersistentStateIterator<'a, L> {
    type Item = (Vec<u8>, Vec<u8>);

    fn next(&mut self) -> Option<Self::Item> {
        let iterator = self.iterator.as_mut()?;
        match self.state.next(self.loader, iterator, &mut EmptyCounter) {
            Ok(v) => {
                let entry = v?;
                let key = iterator.get_key();
                self.state.with_entry(entry, self.loader, |value| (key.to_vec(), value.to_vec()))
            }
            Err(empty) => match empty {},
        }
    }
}

/// This marker instance informs the compiler, and the users, that once the
/// iterator returns [`None`] it will always return [`None`], which could be
/// used to optimize usage.
impl<'a, L: BackingStoreLoad> FusedIterator for PersistentStateIterator<'a, L> {}

#[derive(Debug, Clone)]
/// This type is a technical device to support lazy conversion of
/// [`PersistentState`] to [`MutableState`]. It contains the runtime
/// representation of the tree that supports efficient updates.
/// [`Clone`] on this structure is designed to be cheap, **and it is a shallow
/// copy**. Modifications of the inner [`MutableTrie`] on either the clone or
/// the original propagate to the other.
pub struct MutableStateInner {
    /// Current root of the tree. The current generation. Generations are a
    /// device to support rollbacks. Rollbacks are necessary because of
    /// re-entrancy.
    ///
    /// If a contract A calls another contract (i.e., using
    /// `invoke`) it might call contract A (either directly, or indirectly
    /// via some intermediate contracts). Since during execution of the
    /// inner A the state may be modified, and then the execution might fail
    /// (e.g., logic rejection, or runtime failure), we must be able to roll
    /// back the state changes that occurred in the inner call when we
    /// resume execution of the outer A. Generations support this. When we start
    /// execution of the inner A we start a new generation. The process here is
    /// really very similar to how we start a [`MutableState`] from a
    /// [`PersistentState`] when we start the transaction, except that the
    /// representation of generations is and the [`MutableTrie`] is quite
    /// different, and more efficient than the representation of the
    /// [`PersistentState`].
    root:  u32,
    /// The mutable trie itself. The root is an index in the array of generation
    /// roots.
    /// The idea is that the mutex is acquired at the start of execution of the
    /// contract and released at the end.
    /// The reason for the Arc is that we need to be able to clone this so
    /// that we can share it inside the single transaction.
    state: Arc<Mutex<MutableTrie>>,
}

impl MutableStateInner {
    #[inline(always)]
    /// Get exclusive access to the state trie. The state trie must be dropped
    /// to release the lock.
    pub fn lock(&self) -> StateTrie { self.state.lock().expect("Another thread panicked.") }
}

/// A lock guard derived from [MutableStateInner]. Only one can exist at the
/// time.
pub type StateTrie<'a> = MutexGuard<'a, MutableTrie>;

/// The mutable contract state.
#[derive(Debug, Clone)]
pub struct MutableState {
    inner:      Option<MutableStateInner>,
    /// The original state this mutable state is derived from, or after
    /// freezing, the new persistent state.
    persistent: PersistentState,
}

impl MutableState {
    /// Initial state, i.e., the state that the contract's init method starts
    /// executing in.
    pub fn initial_state() -> Self {
        Self {
            inner:      None,
            persistent: PersistentState::Empty,
        }
    }

    /// Get the inner mutable state. If it does not yet exist create it,
    /// otherwise return it.
    pub fn get_inner<'a, 'b>(
        &'a mut self,
        loader: &'b mut impl BackingStoreLoad,
    ) -> &'a mut MutableStateInner {
        if let Some(inner) = self.inner.as_mut() {
            inner.lock().normalize(inner.root);
        } else {
            let root = 0;
            match &self.persistent {
                PersistentState::Empty => {
                    let state = Arc::new(Mutex::new(MutableTrie::empty()));
                    self.inner = Some(MutableStateInner {
                        root,
                        state,
                    });
                }
                PersistentState::Root(root_node) => {
                    let state = Arc::new(Mutex::new(root_node.make_mutable(0, loader)));
                    self.inner = Some(MutableStateInner {
                        root,
                        state,
                    });
                }
            }
        }
        self.inner.as_mut().expect("This cannot fail since we just set self.inner to Some.")
    }

    /// Get a fresh mutable state generation. Modifications on this generation
    /// will not be reflected in the current one. To resume execution of the
    /// previous generation the inner state must first be normalized to the
    /// previous generation.
    pub fn make_fresh_generation(&mut self, loader: &mut impl BackingStoreLoad) -> Self {
        if let Some(inner) = self.inner.as_mut() {
            let mut trie = inner.lock();
            // make sure to forget any newer generations that might have been pushed and not
            // yet cleaned up.
            trie.normalize(inner.root);
            // and start a new one.
            trie.new_generation();
            Self {
                inner:      Some(MutableStateInner {
                    root:  inner.root + 1,
                    state: inner.state.clone(),
                }),
                persistent: self.persistent.clone(),
            }
        } else {
            let root = 0;
            match &self.persistent {
                PersistentState::Empty => {
                    let state = Arc::new(Mutex::new(MutableTrie::empty()));
                    self.inner = Some(MutableStateInner {
                        root,
                        state,
                    });
                }
                PersistentState::Root(root_node) => {
                    let state = Arc::new(Mutex::new(root_node.make_mutable(0, loader)));
                    self.inner = Some(MutableStateInner {
                        root,
                        state,
                    });
                }
            }
            self.clone()
        }
    }

    /// Make the state persistent. This leaves the mutable state empty.
    /// This function is idempotent.
    pub fn freeze<C: Collector<Value>>(
        &mut self,
        loader: &mut impl BackingStoreLoad,
        collector: &mut C,
    ) -> PersistentState {
        // Replace the inner mutable state with None.
        let inner = self.inner.take();
        match inner {
            Some(inner) => {
                let mut trie = std::mem::replace(&mut *inner.lock(), MutableTrie::empty());
                trie.normalize(inner.root);
                self.persistent = match trie.freeze(loader, collector) {
                    Some(node) => PersistentState::Root(node),
                    None => PersistentState::Empty,
                };
                self.persistent.clone()
            }
            None => self.persistent.clone(),
        }
    }
}
