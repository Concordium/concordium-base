use super::{
    low_level::{MutableTrie, Node},
    types::*,
};
use byteorder::{ReadBytesExt, WriteBytesExt};
#[cfg(feature = "display-state")]
use ptree::TreeBuilder;
use std::sync::{Arc, Mutex, MutexGuard};

pub type Value = Vec<u8>;

/// The persistent contract state.
/// Clone on this structure is designed to be cheap, and it is a shallow copy.
#[derive(Debug, Clone)]
pub enum PersistentState {
    Empty,
    Root(Hashed<Node<Value>>),
}

impl From<Hashed<Node<Value>>> for PersistentState {
    fn from(root: Hashed<Node<Value>>) -> Self { Self::Root(root) }
}

impl Loadable for PersistentState {
    fn load<S: std::io::Read, F: BackingStoreLoad>(
        loader: &mut F,
        source: &mut S,
    ) -> LoadResult<Self> {
        match source.read_u8()? {
            0 => Ok(Self::Empty),
            1 => Ok(Self::Root(Hashed::<Node<Value>>::load(loader, source)?)),
            tag => Err(LoadError::IncorrectTag {
                tag,
            }),
        }
    }
}

impl PersistentState {
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

    pub fn store_update<S: BackingStoreStore>(
        &mut self,
        backing_store: &mut S,
    ) -> StoreResult<Reference> {
        let mut top = Vec::new();
        self.store_update_buf(backing_store, &mut top)?;
        backing_store.store_raw(&top)
    }

    pub fn serialize(
        &self,
        loader: &mut impl BackingStoreLoad,
        out: &mut impl std::io::Write,
    ) -> anyhow::Result<()> {
        match self {
            PersistentState::Empty => out.write_u8(0)?,
            PersistentState::Root(ht) => {
                out.write_u8(1)?;
                ht.serialize(loader, out)?
            }
        }
        Ok(())
    }

    pub fn deserialize(source: &mut impl std::io::Read) -> anyhow::Result<Self> {
        match source.read_u8()? {
            0 => Ok(Self::Empty),
            1 => Ok(Self::Root(Hashed::<Node<_>>::deserialize(source)?)),
            tag => anyhow::bail!("Invalid persistent tree tag: {}", tag),
        }
    }

    /// Lookup a key in the tree. This is only meant for testing
    /// since performance is slow compared to lookup in the mutable tree.
    pub fn lookup(&self, loader: &mut impl BackingStoreLoad, key: &[u8]) -> Option<Value> {
        match self {
            PersistentState::Empty => None,
            PersistentState::Root(node) => {
                let data = node.data.lookup(loader, key)?;
                let borrowed = data.borrow();
                Some(borrowed.data.get(loader))
            }
        }
    }

    #[cfg(feature = "display-state")]
    pub fn display_tree(&self, builder: &mut TreeBuilder, loader: &mut impl BackingStoreLoad) {
        match self {
            Self::Empty => {}
            Self::Root(node) => node.data.display_tree(builder, loader),
        }
    }
}

#[derive(Debug, Clone)]
/// Clone on this structure is designed to be cheap, and it is a shallow copy.
/// Modifications of the inner MutableTrie on either the clone or the original
/// propagate to the other.
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

pub type StateTrie<'a> = MutexGuard<'a, MutableTrie<Value>>;

/// The mutable contract state.
#[derive(Debug, Clone)]
pub struct MutableState {
    inner:  Option<MutableStateInner>,
    /// The original persistent state from which this mutable one is derived.
    origin: PersistentState,
}

impl PersistentState {
    pub fn thaw(&self) -> MutableState {
        MutableState {
            inner:  None,
            origin: self.clone(),
        }
    }

    pub fn hash(&self) -> super::Hash {
        match self {
            PersistentState::Empty => super::Hash::zero(), /* FIXME: Think about what */
            // the correct thing would
            // be.
            PersistentState::Root(root) => root.hash,
        }
    }

    pub fn cache<F: BackingStoreLoad>(&mut self, loader: &mut F) {
        if let PersistentState::Root(node) = self {
            node.data.cache(loader)
        }
    }
}

impl MutableState {
    /// Initial state, i.e., the state that the contract's init method starts
    /// executing in.
    pub fn initial_state() -> Self {
        Self {
            inner:  None,
            origin: PersistentState::Empty,
        }
    }

    /// Get the inner mutable state. If it does not yet exist create it,
    /// otherwise return it.
    pub fn get_inner(&mut self) -> &mut MutableStateInner {
        if let Some(inner) = self.inner.as_mut() {
            inner.state.lock().expect("Another thread panicked").normalize(inner.root);
        } else {
            let root = 0;
            match &self.origin {
                PersistentState::Empty => {
                    let state = Arc::new(Mutex::new(MutableTrie::empty()));
                    self.inner = Some(MutableStateInner {
                        root,
                        state,
                    });
                }
                PersistentState::Root(root_node) => {
                    let state = Arc::new(Mutex::new(root_node.data.make_mutable(0)));
                    self.inner = Some(MutableStateInner {
                        root,
                        state,
                    });
                }
            }
        }
        self.inner.as_mut().expect("This cannot fail since we just set self.inner to Some.")
    }

    /// Get a frsh mutable state generation.
    pub fn make_fresh_generation(&mut self) -> Self {
        if let Some(inner) = self.inner.as_mut() {
            let mut trie = inner.state.lock().expect("Another thread panicked.");
            trie.normalize(inner.root);
            trie.new_generation();
            Self {
                inner:  Some(MutableStateInner {
                    root:  inner.root + 1,
                    state: inner.state.clone(),
                }),
                origin: self.origin.clone(),
            }
        } else {
            let root = 0;
            match &self.origin {
                PersistentState::Empty => {
                    let state = Arc::new(Mutex::new(MutableTrie::empty()));
                    self.inner = Some(MutableStateInner {
                        root,
                        state,
                    });
                }
                PersistentState::Root(root_node) => {
                    let state = Arc::new(Mutex::new(root_node.data.make_mutable(0)));
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
    pub fn freeze<C: Collector<Value>>(
        &mut self,
        loader: &mut impl BackingStoreLoad,
        collector: &mut C,
    ) -> PersistentState {
        let inner = self.inner.take();
        match inner {
            Some(inner) => {
                let mut trie = std::mem::replace(
                    &mut *inner.state.lock().expect("Another thread panicked."),
                    MutableTrie::empty(),
                );
                trie.normalize(inner.root);
                self.origin = match trie.freeze(loader, collector) {
                    Some(node) => PersistentState::Root(node),
                    None => PersistentState::Empty,
                };
                self.origin.clone()
            }
            None => self.origin.clone(),
        }
    }
}

// DONE
// load
// free
// write
// hash
// freeze (need to add loader)
// thaw
// cache

// TODO
// get_new_state_size
// serialize persistent state
// deserialize persistent state
