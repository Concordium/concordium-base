//! The high-level API that is meant to be used by the rest of the project.
//! It exposes two main constructs, the [PersistentState] and [MutableState]
//! that provide all the needed functionality for the implementation of contract
//! state.
use super::{
    low_level::{CachedRef, MutableTrie, Node},
    types::*,
};
use byteorder::{ReadBytesExt, WriteBytesExt};
#[cfg(feature = "display-state")]
use ptree::TreeBuilder;
use sha2::Digest;
use std::sync::{Arc, Mutex, MutexGuard};

pub type Value = Vec<u8>;

/// The persistent contract state.
/// Clone on this structure is designed to be cheap, and it is a shallow copy.
#[derive(Debug, Clone)]
pub enum PersistentState {
    Empty,
    Root(CachedRef<Hashed<Node<Value>>>),
}

impl From<CachedRef<Hashed<Node<Value>>>> for PersistentState {
    fn from(root: CachedRef<Hashed<Node<Value>>>) -> Self { Self::Root(root) }
}

/// Load the persistent state. This only loads the root of the tree. In order to
/// cache the entire tree into memory use [PersistentTree::cache] afterwards.
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
                ht.use_value_(loader, |loader, node| node.serialize(loader, out))?
            }
        }
        Ok(())
    }

    /// Dual to [Self::serialize].
    pub fn deserialize(source: &mut impl std::io::Read) -> anyhow::Result<Self> {
        match source.read_u8()? {
            0 => Ok(Self::Empty),
            1 => {
                let node = Hashed::<Node<_>>::deserialize(source)?;
                Ok(PersistentState::Root(CachedRef::Memory {
                    value: node,
                }))
            }
            tag => anyhow::bail!("Invalid persistent tree tag: {}", tag),
        }
    }

    /// Lookup a key in the tree. This is only meant for testing
    /// since performance is slow compared to lookup in the mutable tree.
    pub fn lookup(&self, loader: &mut impl BackingStoreLoad, key: &[u8]) -> Option<Value> {
        match self {
            PersistentState::Empty => None,
            PersistentState::Root(node) => {
                let data = node.use_value_(loader, |loader, node| node.data.lookup(loader, key))?;
                let borrowed = data.borrow();
                Some(borrowed.data.get(loader))
            }
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
                node.use_value_(loader, |loader, tree| tree.data.display_tree(builder, loader))
            }
        }
    }
}

#[derive(Debug, Clone)]
/// This type is a technical device to support lazy conversion of
/// [PersistentState] to [MutableState]. It contains the runtime representation
/// of the tree that supports efficient updates.
/// Clone on this structure is designed to be cheap, **and it is a shallow
/// copy**. Modifications of the inner MutableTrie on either the clone or the
/// original propagate to the other.
pub struct MutableStateInner {
    /// Current root of the tree. The current generation.
    root:      u32,
    /// The mutable trie itself. The root is an index in the array of generation
    /// roots.
    /// The idea is that the mutex is acquired at the start of execution of the
    /// contract and released at the end.
    /// The reason for the mutex is that we need to be able to clone this so
    /// that we can share it inside the single transaction.
    pub state: Arc<Mutex<MutableTrie<Value>>>,
}

/// A lock guard derived from [MutableStateInner]. Only one can exist at the
/// time.
pub type StateTrie<'a> = MutexGuard<'a, MutableTrie<Value>>;

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
            inner.state.lock().expect("Another thread panicked").normalize(inner.root);
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
            let mut trie = inner.state.lock().expect("Another thread panicked.");
            trie.normalize(inner.root);
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
                let mut trie = std::mem::replace(
                    &mut *inner.state.lock().expect("Another thread panicked."),
                    MutableTrie::empty(),
                );
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
