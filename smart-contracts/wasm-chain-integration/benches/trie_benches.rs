use criterion::*;
use sha2::Digest;
use std::collections::BTreeMap;
use wasm_chain_integration::v1::trie::{low_level::*, *};

/// Amount of data to generate.
const N: usize = 100000;

/// Seed for generating data.
const SEED: u64 = 17;

struct GenData {
    hasher: sha2::Sha512,
    count:  usize,
}

impl std::iter::Iterator for GenData {
    type Item = Vec<u8>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.count < N {
            let data = self.hasher.finalize_reset();
            let len = (self.count % 64) + 1;
            self.hasher.update(data);
            self.count += 1;
            Some(data[0..len].to_vec())
        } else {
            None
        }
    }
}

/// Generate data deterministically from a seed with repeated hashing.
fn get_data() -> Vec<Vec<u8>> {
    let mut hasher = sha2::Sha512::new();
    hasher.update(&SEED.to_be_bytes());
    GenData {
        hasher,
        count: 0,
    }
    .collect::<Vec<_>>()
}

type VecLoader = Loader<Vec<u8>>;

fn make_btree(words: &[Vec<u8>]) -> BTreeMap<&[u8], Box<[u8]>> {
    let mut tree = BTreeMap::new();
    for w in words {
        tree.insert(&w[..], (w.len() as u64).to_ne_bytes().into());
    }
    tree
}

#[allow(clippy::type_complexity)] // this is a test, so a bit of complexity is OK.
fn make_trie(words: &[Vec<u8>]) -> (Option<CachedRef<Hashed<Node>>>, VecLoader) {
    let (trie, mut loader) = make_mut_trie(words);
    (trie.freeze(&mut loader, &mut EmptyCollector), loader)
}

fn make_mut_trie(words: &[Vec<u8>]) -> (MutableTrie, VecLoader) {
    let mut node = MutableTrie::empty();
    let mut loader = Loader {
        inner: Vec::<u8>::new(),
    };
    for w in words {
        node.insert(&mut loader, w, (w.len() as u64).to_ne_bytes().into())
            .expect("No locks, so cannot fail.");
    }
    (node, loader)
}

fn btree_insert(b: &mut Criterion) {
    let words = get_data();
    b.bench_function("BTreeMap insert", |b| b.iter(|| make_btree(&words)));
}

fn btree_get(b: &mut Criterion) {
    let words = get_data();
    let tree = make_btree(&words);
    b.bench_function("BTreeMap get", |b| {
        b.iter(|| {
            for w in words.iter() {
                if tree.get(&w[..]).is_none() {
                    panic!("Failure.");
                }
            }
        })
    });
}

fn trie_insert(b: &mut Criterion) {
    let words = get_data();
    b.bench_function("trie insert", |b| b.iter(|| make_trie(&words)));
}

fn mut_trie_insert(b: &mut Criterion) {
    let words = get_data();
    b.bench_function("trie mut insert", |b| b.iter(|| make_mut_trie(&words)));
}

fn trie_serialize(b: &mut Criterion) {
    let words = get_data();
    let setup = || make_trie(&words);
    b.bench_function("trie serialize", |b| {
        b.iter_batched(
            setup,
            |(trie, _)| {
                let mut trie = trie.unwrap();
                trie.store_update_buf(&mut Vec::new(), &mut Vec::new())
                    .expect("Storing should succeed.");
            },
            BatchSize::SmallInput,
        )
    });
}

fn trie_deserialize(b: &mut Criterion) {
    let words = get_data();
    let (trie, _) = make_trie(&words);
    let mut trie = trie.unwrap();
    let mut backing_store = Vec::new();
    let mut buf = Vec::new();
    trie.store_update_buf(&mut backing_store, &mut buf).expect("Storing should succeed.");
    let root = backing_store.store_raw(&buf).expect("Storing should succeed.");
    b.bench_function("trie deserialize", |b| {
        b.iter(|| {
            let mut loader = Loader {
                inner: &backing_store,
            };
            let trie = Node::load_from_location(&mut loader, root);
            assert!(trie.is_ok(), "Tree deserialization failed.");
        })
    });
}

fn trie_cache(b: &mut Criterion) {
    let words = get_data();
    let (trie, _) = make_trie(&words);
    let mut trie = trie.unwrap();
    let mut backing_store = Vec::new();
    let mut buf = Vec::new();
    trie.store_update_buf(&mut backing_store, &mut buf).expect("Storing should succeed.");
    let root = backing_store.store_raw(&buf).expect("Storing should succeed.");
    b.bench_function("trie cache", |b| {
        b.iter(|| {
            let mut loader = Loader {
                inner: &backing_store,
            };
            let mut trie = Node::load_from_location(&mut loader, root);
            assert!(trie.is_ok(), "Tree deserialization failed.");
            trie.as_mut().unwrap().cache(&mut loader);
            assert!(trie.unwrap().is_cached(), "Tree is not cached.")
        })
    });
}

fn trie_get(b: &mut Criterion) {
    let words = get_data();
    let (trie, mut loader) = make_trie(&words);
    let trie = trie.unwrap().get(&mut loader).to_owned().data;
    b.bench_function("trie get", |b| {
        b.iter(|| {
            for w in words.iter() {
                if trie.lookup(&mut loader, w.as_ref()).is_none() {
                    panic!("Failure.");
                }
            }
        })
    });
}

fn trie_hash(b: &mut Criterion) {
    let words = get_data();
    let (trie, mut loader) = make_trie(&words);
    let trie = trie.unwrap();
    b.bench_function("trie hash", |b| {
        b.iter(|| {
            trie.hash(&mut loader);
        })
    });
    b.bench_function("hash data", |b| {
        b.iter(|| {
            let _: [u8; 32] = sha2::Sha256::digest([17u8; 0]).into();
        })
    });
}

fn mut_trie_get(b: &mut Criterion) {
    let words = get_data();
    let (trie, mut loader) = make_trie(&words);
    let mut trie = trie.unwrap().make_mutable(0, &mut loader);
    b.bench_function("trie mut get", |b| {
        b.iter(|| {
            for w in words.iter() {
                if trie.get_entry(&mut loader, w.as_ref()).is_none() {
                    panic!("Failure.");
                }
            }
        })
    });
}

fn mut_trie_get_from_mut(b: &mut Criterion) {
    let words = get_data();
    let (mut trie, mut loader) = make_mut_trie(&words);
    b.bench_function("trie mut get from mut", |b| {
        b.iter(|| {
            for w in words.iter() {
                if trie.get_entry(&mut loader, w.as_ref()).is_none() {
                    panic!("Failure.");
                }
            }
        })
    });
}

fn mut_trie_delete(b: &mut Criterion) {
    let words = get_data();
    let (mut trie, mut loader) = make_mut_trie(&words);
    b.bench_function("trie mut delete", |b| {
        b.iter(|| {
            for w in words.iter() {
                trie.delete(&mut loader, w.as_ref()).expect("No locks, so cannot fail.");
            }
            assert!(trie.is_empty(), "After deleting everything the tree should be empty.");
        })
    });
}

fn trie_thaw_delete(b: &mut Criterion) {
    let words = get_data();
    let (trie, mut loader) = make_trie(&words);
    let mut trie = trie.unwrap().make_mutable(0, &mut loader);
    b.bench_function("trie thaw delete", |b| {
        b.iter(|| {
            for w in words.iter() {
                trie.delete(&mut loader, &w[..]).expect("No locks, so cannot fail.");
            }
            assert!(trie.is_empty(), "After deleting everything the tree should be empty.");
        })
    });
}

/// Benchmark freezing a mutable trie.
fn mut_trie_freeze(b: &mut Criterion) {
    let words = get_data();
    let (trie, mut loader) = make_mut_trie(&words);
    b.bench_function("trie mut freeze", |b| {
        b.iter_batched(
            || trie.clone(),
            |trie| {
                trie.freeze(&mut loader, &mut EmptyCollector).expect("Freezing succeeds");
            },
            BatchSize::LargeInput,
        );
    });
}

/// Benchmark looking up from a frozen tree.
fn mut_trie_freeze_get(b: &mut Criterion) {
    let words = get_data();
    let (trie, mut loader) = make_mut_trie(&words);
    let frozen =
        trie.freeze(&mut loader, &mut EmptyCollector).unwrap().get(&mut loader).to_owned().data;
    b.bench_function("trie mut freeze get", |b| {
        b.iter(|| {
            for w in words.iter() {
                if frozen.lookup(&mut loader, &w[..]).is_none() {
                    panic!("Failure.");
                }
            }
        })
    });
}

criterion_group!(
    benches,
    btree_insert,
    btree_get,
    trie_serialize,
    trie_deserialize,
    trie_cache,
    trie_insert,
    trie_get,
    trie_hash,
    mut_trie_insert,
    mut_trie_get_from_mut,
    mut_trie_get,
    mut_trie_delete,
    trie_thaw_delete,
    mut_trie_freeze,
    mut_trie_freeze_get
);

criterion_main!(benches);
