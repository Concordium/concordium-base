use super::{low_level::*, *};
use anyhow::{bail, ensure, Context};
use quickcheck::*;
use std::collections::BTreeMap;

const NUM_TESTS: u64 = 100000;

/// Construct a mutable trie with the given contents.
/// The loader that was used during construction is returned, but in reality it
/// is not needed since the entire tree is in-memory.
fn make_mut_trie<A: AsRef<[u8]>>(words: Vec<(A, Value)>) -> (MutableTrie, Loader<Value>) {
    let mut node = MutableTrie::empty();
    let mut loader = Loader {
        inner: Vec::<u8>::new(),
    };
    for (key, value) in words {
        node.insert(&mut loader, key.as_ref(), value)
            .expect("No iterators are present, so insert should succeed");
    }
    (node, loader)
}

fn compare_to_reference(
    trie: &mut MutableTrie,
    loader: &mut Loader<Vec<u8>>,
    reference: &BTreeMap<Vec<u8>, Value>,
) -> anyhow::Result<()> {
    let mut iterator = if let Some(i) =
        trie.iter(loader, &[]).expect("This is the first iterator, so no overflow.")
    {
        i
    } else {
        ensure!(reference.is_empty(), "Reference map is empty, but trie is not.");
        return Ok(());
    };
    for (k, v) in reference.iter() {
        let entry = trie
            .next(loader, &mut iterator, &mut EmptyCounter)
            .expect("Empty counter does not fail.")
            .context("Trie iterator ends early.")?;
        ensure!(
            trie.with_entry(entry, loader, |ev| v == ev).unwrap_or(false),
            "Reference value does not match the trie value."
        );
        let it_key = iterator.get_key();
        ensure!(
            it_key == k,
            "Iterator returns incorrect key, {:?} != {:?}, {:#?}, {:#?}",
            it_key,
            k,
            iterator,
            trie
        );
    }
    ensure!(
        trie.next(loader, &mut iterator, &mut EmptyCounter)
            .expect("Empty counter does not fail.")
            .is_none(),
        "Trie iterator has remaining values."
    );
    Ok(())
}

#[test]
/// Check that deleting and then freezing behaves correctly, and the
/// resulting tree is correct.
fn prop_delete_freeze_lookup() {
    let prop = |inputs: Vec<(Vec<u8>, Value)>, key: Vec<u8>| -> anyhow::Result<()> {
        // construct the tree first
        let mut reference = inputs.iter().cloned().collect::<BTreeMap<_, _>>();
        let (trie, mut loader) = make_mut_trie(inputs);
        // freeze it
        let frozen = if let Some(t) = trie.freeze(&mut loader, &mut EmptyCollector) {
            t
        } else {
            ensure!(reference.is_empty(), "Reference map is empty, but trie is not.");
            return Ok(());
        };
        // then thaw it. This makes the tree persistent, and only the root mutable.
        let mut thawed = frozen.make_mutable(0, &mut loader);
        // then delete from the thawed tree
        let existed =
            thawed.delete(&mut loader, &key).expect("No iterators, so no part should be locked.");
        let existed_reference = reference.remove(&key);
        ensure!(
            existed == existed_reference.is_some(),
            "Incorrect removal result ({}) compared to reference ({}).",
            existed,
            existed_reference.is_some()
        );
        // freeze it again
        let frozen = if let Some(t) = thawed.freeze(&mut loader, &mut EmptyCollector) {
            t
        } else {
            ensure!(reference.is_empty(), "Reference map is empty, but trie is not.");
            return Ok(());
        };
        // and then make sure the frozen tree matches the (updated) reference.
        let mut trie = frozen.make_mutable(0, &mut loader);
        compare_to_reference(&mut trie, &mut loader, &reference)
    };
    QuickCheck::new().tests(NUM_TESTS).quickcheck(prop as fn(_, _) -> anyhow::Result<()>);
}

#[test]
/// Check that inserting and then freezing behaves correctly, and the
/// resulting tree is correct.
fn prop_insert_freeze_lookup() {
    let prop = |inputs: Vec<(Vec<u8>, Value)>, key: Vec<u8>| -> anyhow::Result<()> {
        // construct the tree first
        let mut reference = inputs.iter().cloned().collect::<BTreeMap<_, _>>();
        let (trie, mut loader) = make_mut_trie(inputs);
        // freeze it
        let frozen = if let Some(t) = trie.freeze(&mut loader, &mut EmptyCollector) {
            t
        } else {
            ensure!(reference.is_empty(), "Reference map is empty, but trie is not.");
            return Ok(());
        };
        // then thaw it. This makes the tree persistent, and only the root mutable.
        let mut thawed = frozen.make_mutable(0, &mut loader);
        // then insert into the thawed tree
        let existed = thawed
            .insert(&mut loader, &key, Vec::new())
            .expect("No iterators, so no part should be locked.");
        let existed_reference = reference.insert(key, Vec::new());
        ensure!(
            existed.1 == existed_reference.is_some(),
            "Incorrect insertion result ({}) compared to reference ({}).",
            existed.1,
            existed_reference.is_some()
        );
        // freeze it again
        let frozen = if let Some(t) = thawed.freeze(&mut loader, &mut EmptyCollector) {
            t
        } else {
            ensure!(reference.is_empty(), "Reference map is empty, but trie is not.");
            return Ok(());
        };
        // and then make sure the frozen tree matches the (updated) reference.
        let mut trie = frozen.make_mutable(0, &mut loader);
        compare_to_reference(&mut trie, &mut loader, &reference)
    };
    QuickCheck::new().tests(NUM_TESTS).quickcheck(prop as fn(_, _) -> anyhow::Result<()>);
}

#[test]
/// Check that storing also uncaches the data.
fn prop_storing_uncaches() {
    let prop = |inputs: Vec<(Vec<u8>, Value)>| -> anyhow::Result<()> {
        let reference = inputs.iter().cloned().collect::<BTreeMap<_, _>>();
        let (trie, mut loader) = make_mut_trie(inputs);
        let mut frozen = if let Some(t) = trie.freeze(&mut loader, &mut EmptyCollector) {
            t
        } else {
            ensure!(
                reference.is_empty(),
                "Reference map is empty, but trie
 is not."
            );
            return Ok(());
        };
        let mut ser = Vec::new();
        let _ = frozen.store_update(&mut ser);
        ensure!(!frozen.get(&mut loader).data.is_cached(), "Data should not be cached.");
        Ok(())
    };
    QuickCheck::new().tests(NUM_TESTS).quickcheck(prop as fn(Vec<_>) -> anyhow::Result<()>);
}

#[test]
/// Check that migration works.
/// This test creates a random tree, stores it to one backing store, then
/// migrates it to a new one. Then the new tree is compared to the reference
/// implementation.
fn prop_migration_retains_semantics() {
    let prop = |inputs: Vec<(Vec<u8>, Value)>| -> anyhow::Result<()> {
        let reference = inputs.iter().cloned().collect::<BTreeMap<_, _>>();
        let (trie, mut loader) = make_mut_trie(inputs);
        let mut frozen = if let Some(t) = trie.freeze(&mut loader, &mut EmptyCollector) {
            t
        } else {
            ensure!(reference.is_empty(), "Reference map is empty, but trie is not.");
            return Ok(());
        };
        let mut backing_store = Vec::new();
        let top =
            frozen.store_update(&mut backing_store).context("Serialization should succeed.")?;
        let _ = backing_store.store_raw(&top).expect("Storing to a vector should succeed.");
        let mut loader = Loader {
            inner: backing_store,
        };
        let mut new_backing_store = Vec::new();
        let migrated = frozen
            .migrate(&mut new_backing_store, &mut loader)
            .context("Migration should succeed.")?;
        let mut loader = Loader {
            inner: new_backing_store,
        };
        let mut mutable = migrated.make_mutable(0, &mut loader);
        compare_to_reference(&mut mutable, &mut loader, &reference)?;
        Ok(())
    };
    QuickCheck::new().tests(NUM_TESTS).quickcheck(prop as fn(Vec<_>) -> anyhow::Result<()>);
}

#[test]
/// Check that storing computes the correct size, and that it can be
/// deserialized.
fn prop_storing() {
    let prop = |inputs: Vec<(Vec<u8>, Value)>| -> anyhow::Result<()> {
        let reference = inputs.iter().cloned().collect::<BTreeMap<_, _>>();
        let (trie, mut loader) = make_mut_trie(inputs);
        let mut collector = SizeCollector::default();
        let mut frozen = if let Some(t) = trie.freeze(&mut loader, &mut collector) {
            // Check that the computed size at least accounts for all the data.
            // Keys are partially shared so we cannot easily bound those.
            let data_size = reference.values().map(|v| v.len() as u64).sum::<u64>();
            let calculated_size = collector.collect();
            ensure!(
                calculated_size > data_size,
                "Calculated size ({}) does not account for data size ({}).",
                calculated_size,
                data_size
            );
            t
        } else {
            ensure!(reference.is_empty(), "Reference map is empty, but trie is not.");
            return Ok(());
        };
        let mut backing_store = Vec::new();
        let top = frozen.store_update(&mut backing_store).expect("Storing succeeds.");
        let root = backing_store.store_raw(&top).expect("Storing to a vector succeeds.");
        let mut loader = Loader {
            inner: backing_store,
        };
        let trie = CachedRef::<Hashed<Node>>::load_from_location(&mut loader, root)
            .context("Could not deserialize.")?;
        let mut mutable = trie.make_mutable(0, &mut loader);
        let mut iterator = mutable
            .iter(&mut loader, &[])
            .expect("This is the first iterator, so no overflow.")
            .expect("Trie is not empty, so this should succeed.");
        for ((k, v), i) in reference.iter().zip(0..) {
            let entry = mutable
                .next(&mut loader, &mut iterator, &mut EmptyCounter)
                .expect("Empty counter does not fail.")
                .context("Trie iterator ends early.")?;
            mutable
                .with_entry(entry, &mut loader, |ev| -> anyhow::Result<()> {
                    ensure!(
                        v == ev,
                        "Reference value does not match the trie value {:?} != {:?} ({})",
                        v,
                        ev,
                        i
                    );
                    Ok(())
                })
                .context("Entry should exist.")??;
            let it_key = iterator.get_key();
            ensure!(
                it_key == k,
                "Iterator returns incorrect key, {:?} != {:?}, {:#?}",
                it_key,
                k,
                mutable
            );
        }

        Ok(())
    };
    QuickCheck::new().tests(NUM_TESTS).quickcheck(prop as fn(Vec<_>) -> anyhow::Result<()>);
}

#[test]
/// Check that serializing a tree, and then deserializing it, succeeds.
fn prop_serialization() {
    let prop = |inputs: Vec<(Vec<u8>, Value)>| -> anyhow::Result<()> {
        let reference = inputs.iter().cloned().collect::<BTreeMap<_, _>>();
        let (trie, mut loader) = make_mut_trie(inputs);
        let frozen = if let Some(t) = trie.freeze(&mut loader, &mut EmptyCollector) {
            t
        } else {
            ensure!(reference.is_empty(), "Reference map is empty, but trie is not.");
            return Ok(());
        };
        let mut out = Vec::new();
        let node = frozen.get(&mut loader);
        node.serialize(&mut loader, &mut out).context("Serialization failed.")?;
        let original_hash = frozen.hash(&mut loader);
        let mut source = std::io::Cursor::new(&out);
        let deserialized = CachedRef::Memory {
            value: Hashed::<Node>::deserialize(&mut source).context("Failed to deserialize")?,
        };
        ensure!(source.position() == out.len() as u64, "Some input was not consumed.");
        let deserialized_hash = deserialized.hash(&mut loader);
        ensure!(
            original_hash == deserialized_hash,
            "Hashes of the original and deserialized tree differ."
        );
        let mut mutable = deserialized.make_mutable(0, &mut loader);
        compare_to_reference(&mut mutable, &mut loader, &reference)
    };
    QuickCheck::new().tests(NUM_TESTS).quickcheck(prop as fn(Vec<_>) -> anyhow::Result<()>);
}

#[test]
/// Check that the storing preserves the hash of the tree.
fn prop_storing_preseves_hash() {
    let prop = |inputs: Vec<(Vec<u8>, Value)>| -> anyhow::Result<()> {
        let reference = inputs.iter().cloned().collect::<BTreeMap<_, _>>();
        let (trie, mut loader) = make_mut_trie(inputs);
        let mut frozen = if let Some(t) = trie.freeze(&mut loader, &mut EmptyCollector) {
            t
        } else {
            ensure!(reference.is_empty(), "Reference map is empty, but trie is not.");
            return Ok(());
        };
        let hash_1 = frozen.hash(&mut loader);
        let mut backing_store = Vec::new();
        let top = frozen.store_update(&mut backing_store).expect("Storing succeeds.");
        let root = backing_store.store_raw(&top).expect("Storing to a vector succeeds.");
        let mut loader = Loader {
            inner: backing_store,
        };
        let trie = CachedRef::<Hashed<Node>>::load_from_location(&mut loader, root)
            .context("Failed to deserialize.")?;
        let hash_2 = trie.hash(&mut loader);
        ensure!(hash_1 == hash_2, "Hashes differ.");
        Ok(())
    };
    QuickCheck::new().tests(NUM_TESTS).quickcheck(prop as fn(Vec<_>) -> anyhow::Result<()>);
}

#[test]
/// Check that the hash of the tree is independent of the order of insertions,
/// provided there are no duplicates.
fn prop_hash_independent_of_order() {
    let prop =
        |mut inputs: Vec<(Vec<u8>, Value)>, swaps: Vec<(usize, usize)>| -> anyhow::Result<()> {
            inputs.sort_by(|(l, _), (r, _)| l.cmp(r));
            inputs.dedup_by(|(l, _), (r, _)| l == r);
            let (trie, mut loader) = make_mut_trie(inputs.clone());
            let frozen = if let Some(t) = trie.freeze(&mut loader, &mut EmptyCollector) {
                t
            } else {
                ensure!(inputs.is_empty(), "Empty tree, but non-empty inputs.");
                return Ok(());
            };
            let hash = frozen.hash(&mut loader);
            // swap pairs and make another tree
            let len = inputs.len(); // we know this is non-zero.
            for (l, r) in swaps {
                inputs.swap(l % len, r % len);
            }
            let (trie_1, mut loader_1) = make_mut_trie(inputs);
            let frozen_1 = if let Some(t) = trie_1.freeze(&mut loader_1, &mut EmptyCollector) {
                t
            } else {
                bail!("The first tree was not empty, but the second one is.");
            };
            let hash_1 = frozen_1.hash(&mut loader);
            ensure!(hash == hash_1, "Hashes differ.");
            Ok(())
        };
    QuickCheck::new().tests(NUM_TESTS).quickcheck(prop as fn(Vec<_>, Vec<_>) -> anyhow::Result<()>);
}

#[test]
/// Check that the mutable trie and its iterator match the reference
/// implementation.
fn prop_matches_reference_basic() {
    let prop = |inputs: Vec<(Vec<u8>, Value)>| -> anyhow::Result<()> {
        let reference = inputs.iter().cloned().collect::<BTreeMap<_, _>>();
        let (mut trie, mut loader) = make_mut_trie(inputs);
        compare_to_reference(&mut trie, &mut loader, &reference)
    };
    QuickCheck::new().tests(NUM_TESTS).quickcheck(prop as fn(Vec<_>) -> anyhow::Result<()>);
}

#[test]
/// Check that the mutable trie and its iterator match the reference
/// implementation, after deleting a prefix/subtree.
fn prop_matches_reference_delete_subtree() {
    let prop = |inputs: Vec<(Vec<u8>, Value)>| -> anyhow::Result<()> {
        for (prefix, _) in inputs.iter() {
            let reference = inputs
                .iter()
                .filter(|(key, _)| {
                    !(key.len() >= prefix.len() && prefix[..] == key[0..prefix.len()])
                })
                .cloned()
                .collect::<BTreeMap<_, _>>();
            let (mut trie, mut loader) = make_mut_trie(inputs.clone());

            // Remember the entry ids of entries that were inserted and should be deleted
            // since they are under the prefix.
            let mut entries_under_prefix = vec![];
            for input in &inputs {
                if input.0.starts_with(&prefix[..]) {
                    if let Some(e) = trie.get_entry(&mut loader, &input.0) {
                        entries_under_prefix.push(e);
                    } else {
                        bail!("The key {:?} should have been present in the trie.", input.0);
                    }
                }
            }

            ensure!(
                Ok(true)
                    == trie.delete_prefix(&mut loader, &prefix[..], &mut EmptyCounter).unwrap(),
                "There is at least one value with the given prefix, so deleting should succeed."
            );

            for entry in entries_under_prefix {
                ensure!(
                    trie.with_entry(entry, &mut loader, |_| ()).is_none(),
                    "Entry {:?} should have been invalidated ({:?}).",
                    entry,
                    prefix
                )
            }

            compare_to_reference(&mut trie, &mut loader, &reference)?;
        }
        Ok(())
    };
    QuickCheck::new().tests(NUM_TESTS).quickcheck(prop as fn(Vec<_>) -> anyhow::Result<()>);
}

#[test]
/// Test the following scenarios
/// - creating iterators placed in arbitrary locations in the tree prevents us
///   from deleting in those areas
/// - but still allows us to create and delete in areas that are not locked
fn prop_iterator_locked_for_modification_multiple() {
    let prop = |inputs: Vec<(Vec<u8>, Value)>,
                prefixes_to_lock: Vec<Vec<u8>>,
                to_insert: Vec<Vec<u8>>|
     -> anyhow::Result<()> {
        let (mut trie, mut loader) = make_mut_trie(inputs);
        let mut stop = false;
        for len_to_consider in 0.. {
            if stop {
                break;
            }
            let mut locked_prefixes = Vec::new();
            stop = true;
            for prefix in &prefixes_to_lock {
                if prefix.len() >= len_to_consider {
                    if let Ok(option_iterator) = trie.iter(&mut loader, prefix) {
                        if let Some(iterator) = option_iterator {
                            locked_prefixes.push(iterator);
                        }
                    } else {
                        // We are not testing overflow behaviour here, so just terminate the test.
                        return Ok(());
                    }
                    stop = false;
                }
            }
            for (candidate, data) in to_insert.iter().zip(0u64..) {
                // find out if the candidate can or cannot be inserted
                let not_allowed =
                    locked_prefixes.iter().any(|iter| candidate.starts_with(iter.get_root()));
                if not_allowed {
                    ensure!(
                        trie.insert(&mut loader, candidate, data.to_be_bytes().to_vec()).is_err(),
                        "{:?} extends one of the iterator keys.",
                        candidate
                    );
                    ensure!(
                        trie.delete(&mut loader, candidate).is_err(),
                        "{:?} extends one of the iterator keys, so deletion is not allowed.",
                        candidate
                    );
                    ensure!(
                        trie.delete_prefix(&mut loader, candidate, &mut EmptyCounter)
                            .expect("Empty counter does not fail.")
                            .is_err(),
                        "{:?} extends one of the iterator keys, but delete_prefix succeded.",
                        candidate
                    )
                } else {
                    ensure!(
                        trie.insert(&mut loader, candidate, data.to_be_bytes().to_vec()).is_ok(),
                        "{:?} does not extend any of the iterator keys, but insertion failed.",
                        candidate
                    );
                    let not_allowed_delete_subtree =
                        locked_prefixes.iter().any(|iter| iter.get_key().starts_with(candidate));
                    if !not_allowed_delete_subtree {
                        if data % 2 == 0 {
                            // now delete the just inserted entry
                            ensure!(
                                trie.delete(&mut loader, candidate).is_ok(),
                                "{:?} does not extend any of the iterator keys, but deletion \
                                 failed.",
                                candidate
                            );
                        } else {
                            ensure!(
                                trie.delete_prefix(&mut loader, candidate, &mut EmptyCounter)
                                    .expect("Empty counter does not fail.")
                                    .is_ok(),
                                "{:?} is not extended by any of iterator keys, nor does it extend \
                                 them, but delete_prefix failed.",
                                candidate
                            )
                        }
                    } else {
                        // now delete the just inserted entry
                        ensure!(
                            trie.delete(&mut loader, candidate).is_ok(),
                            "{:?} does not extend any of the iterator keys, but deletion failed.",
                            candidate
                        );
                    }
                }
            }
            // cleanup the trie
            for iter in &locked_prefixes {
                ensure!(trie.delete_iter(iter), "Deletion should succeed.");
            }
        }
        Ok(())
    };
    QuickCheck::new()
        .tests(NUM_TESTS)
        .quickcheck(prop as fn(Vec<_>, Vec<_>, Vec<_>) -> anyhow::Result<()>);
}

type PrefixesToLock = Vec<Vec<u8>>;
type KeysToInsert = Vec<Vec<u8>>;
#[test]
/// Test the following scenarios
/// - creating iterators placed in arbitrary locations in the tree prevents us
///   from deleting in those areas,
/// - but still allows us to create and delete in areas that are not locked
/// - making a new generation clears all locks and we can make new iterators and
///   insert/delete
fn prop_iterator_locked_for_modification_generations() {
    // tests is a list of pairs of (prefixes_to_lock, keys to insert/delete)
    let prop = |inputs: Vec<(Vec<u8>, Value)>,
                tests_by_generation: Vec<(PrefixesToLock, KeysToInsert)>|
     -> anyhow::Result<()> {
        let (mut trie, mut loader) = make_mut_trie(inputs);
        let mut generation_cleanup_stack = Vec::new();
        let mut tester = |prefixes_to_lock: &[Vec<u8>], to_insert: &[Vec<u8>], pop_gen: bool| {
            if pop_gen {
                trie.pop_generation().context(
                    "We are iterating over the same list, so we should alwasy succeed in popping.",
                )?;
                if let Some(locked_prefixes) = generation_cleanup_stack.pop() {
                    for iter in &locked_prefixes {
                        ensure!(trie.delete_iter(iter), "Iterator {:?} should be removed", iter,);
                    }
                }
            }
            let mut locked_prefixes = Vec::new();
            for prefix in prefixes_to_lock {
                if let Ok(Some(iterator)) = trie.iter(&mut loader, prefix) {
                    locked_prefixes.push(iterator);
                }
            }
            for (candidate, data) in to_insert.iter().zip(0u64..) {
                // find out if the candidate can or cannot be inserted
                let not_allowed =
                    locked_prefixes.iter().any(|iter| candidate.starts_with(iter.get_root()));
                if not_allowed {
                    ensure!(
                        trie.insert(&mut loader, candidate, data.to_be_bytes().to_vec()).is_err(),
                        "{:?} extends one of the iterator keys.",
                        candidate
                    );
                    ensure!(
                        trie.delete(&mut loader, candidate).is_err(),
                        "{:?} extends one of the iterator keys, so deletion is not allowed.",
                        candidate
                    );
                    ensure!(
                        trie.delete_prefix(&mut loader, candidate, &mut EmptyCounter)
                            .expect("Empty counter does not fail.")
                            .is_err(),
                        "{:?} extends one of the iterator keys, but delete_prefix succeded.",
                        candidate
                    )
                } else {
                    ensure!(
                        trie.insert(&mut loader, candidate, data.to_be_bytes().to_vec()).is_ok(),
                        "{:?} does not extend any of the iterator keys, but insertion failed.",
                        candidate
                    );
                    let not_allowed_delete_subtree =
                        locked_prefixes.iter().any(|iter| iter.get_key().starts_with(candidate));
                    if !not_allowed_delete_subtree {
                        if data % 2 == 0 {
                            // now delete the just inserted entry
                            ensure!(
                                trie.delete(&mut loader, candidate).is_ok(),
                                "{:?} does not extend any of the iterator keys but deletion \
                                 failed, {:#?}, iterator {:#?}",
                                candidate,
                                trie,
                                locked_prefixes,
                            );
                        } else {
                            ensure!(
                                trie.delete_prefix(&mut loader, candidate, &mut EmptyCounter)
                                    .expect("Empty counter does not fail.")
                                    .is_ok(),
                                "{:?} is not extended by any of iterator keys, nor does it extend \
                                 them, but delete_prefix failed.",
                                candidate
                            )
                        }
                    } else {
                        // now delete the just inserted entry
                        ensure!(
                            trie.delete(&mut loader, candidate).is_ok(),
                            "{:?} does not extend any of the iterator keys, but deletion failed.",
                            candidate
                        );
                    }
                }
            }
            if !pop_gen {
                generation_cleanup_stack.push(locked_prefixes);
                trie.new_generation();
            }
            Ok(())
        };
        for (prefixes_to_lock, to_insert) in &tests_by_generation {
            tester(prefixes_to_lock, to_insert, false)?;
        }
        for (prefixes_to_lock, to_insert) in tests_by_generation.iter().rev() {
            tester(prefixes_to_lock, to_insert, true)?;
        }
        ensure!(trie.pop_generation().is_some(), "We should have one generation left.");
        ensure!(trie.pop_generation().is_none(), "We should have exhausted the generations.");
        Ok(())
    };
    QuickCheck::new().tests(NUM_TESTS).quickcheck(prop as fn(Vec<_>, Vec<_>) -> anyhow::Result<()>);
}

#[test]
/// Check that areas locked by iterators cannot be altered by insertion or
/// deletion.
fn prop_iterator_locked_for_modification() {
    let prop = |inputs: Vec<(Vec<u8>, Value)>| -> anyhow::Result<()> {
        let (mut trie, mut loader) = make_mut_trie(inputs.clone());
        for (prefix, _) in inputs.iter() {
            let locked_prefix = prefix.clone();

            if let Some(iter) = trie
                .iter(&mut loader, &locked_prefix)
                .expect("This is the first iterator, so no overflow.")
            {
                let mut locked_prefix_extended = locked_prefix.clone();
                locked_prefix_extended.push(0);
                ensure!(
                    trie.insert(&mut loader, &locked_prefix_extended, vec![]).is_err(),
                    "The subtree should be locked for locked_prefix_extended (insertion)."
                );
                ensure!(
                    trie.delete(&mut loader, &locked_prefix_extended).is_err(),
                    "The subtree should be locked for locked_prefix_extended (removal)."
                );
                ensure!(
                    trie.delete_prefix(&mut loader, &locked_prefix_extended, &mut EmptyCounter)
                        .expect("Empty counter does not fail.")
                        .is_err(),
                    "The subtree should be locked for locked_prefix_extended (prefix removal)."
                );
                // test that we can insert at another part of the tree
                let mut step_up = locked_prefix.clone();
                if let Some(popped) = step_up.pop() {
                    let to_go = if popped == 0 {
                        42
                    } else {
                        0
                    };
                    let mut new_path = step_up.clone();
                    new_path.push(to_go);
                    ensure!(
                        trie.insert(&mut loader, &new_path, vec![]).is_ok(),
                        "The subtree should be open for new_path (inserting)."
                    );
                    ensure!(
                        trie.delete(&mut loader, &new_path).is_ok(),
                        "The subtree should be open for new_path (removal)."
                    );
                    ensure!(
                        trie.insert(&mut loader, &new_path, vec![]).is_ok(),
                        "The subtree should be open for new_path (inserting before prefix \
                         removal)."
                    );
                    ensure!(
                        trie.delete_prefix(&mut loader, &new_path, &mut EmptyCounter)
                            .expect("Empty counter does not fail.")
                            .is_ok(),
                        "The subtree should be locked for new_path (prefix removal)."
                    );
                }
                ensure!(
                    trie.delete_prefix(&mut loader, &step_up, &mut EmptyCounter)
                        .expect("Empty counter does not fail.")
                        .is_err(),
                    "The subtree should be locked for step_up (prefix removal), {:#?}, {:?}, {:?}",
                    trie,
                    prefix,
                    step_up
                );

                ensure!(trie.delete_iter(&iter), "Iterator should be removed");
                ensure!(
                    trie.insert(&mut loader, &locked_prefix_extended, vec![]).is_ok(),
                    "The subtree should not be locked for locked_prefix_extended (insertion): \
                     {:#?}, {:#?}, {:?}",
                    trie,
                    iter,
                    locked_prefix_extended
                );
                ensure!(
                    trie.delete(&mut loader, &locked_prefix_extended).is_ok(),
                    "The subtree should not be locked for locked_prefix_extended (removal)."
                );
                ensure!(
                    trie.insert(&mut loader, &locked_prefix_extended, vec![]).is_ok(),
                    "The subtree should not be locked for locked_prefix_extended (insertion)."
                );
                ensure!(
                    trie.delete_prefix(&mut loader, &locked_prefix_extended, &mut EmptyCounter)
                        .expect("Empty counter does not fail.")
                        .is_ok(),
                    "The subtree should not be locked for locked_prefix_extended (prefix removal)."
                );
                ensure!(
                    trie.delete_prefix(&mut loader, &step_up, &mut EmptyCounter)
                        .expect("Empty counter does not fail.")
                        .is_ok(),
                    "The subtree should not be locked for locked_prefix_extended (prefix removal \
                     - step up). {:#?}, {:?}",
                    trie,
                    step_up
                );
            }
        }
        Ok(())
    };
    QuickCheck::new().tests(NUM_TESTS).quickcheck(prop as fn(Vec<_>) -> anyhow::Result<()>);
}

#[test]
/// Check that the mutable trie delete prefix does not affect generations that
/// are frozen.
fn prop_matches_reference_checkpoint_delete_subtree() {
    let prop = |inputs: Vec<(Vec<u8>, Value)>| -> anyhow::Result<()> {
        let (mut trie, mut loader) = make_mut_trie(inputs.clone());
        let reference = inputs.iter().cloned().collect::<BTreeMap<_, _>>();
        for (prefix, _) in inputs.iter() {
            trie.new_generation();
            trie.delete_prefix(&mut loader, &prefix[..], &mut EmptyCounter)
                .unwrap()
                .context("No iterators are present, so we should be able to delete the prefix.")?;
        }
        trie.normalize(0);
        compare_to_reference(&mut trie, &mut loader, &reference)
    };
    QuickCheck::new().tests(NUM_TESTS).quickcheck(prop as fn(Vec<_>) -> _);
}

#[test]
/// Check that the mutable trie and its iterator match the reference
/// implementation, after deleting a single value.
fn prop_matches_reference_delete() {
    let prop = |inputs: Vec<(Vec<u8>, Value)>| -> anyhow::Result<()> {
        for (to_delete, _) in inputs.iter() {
            let reference = inputs
                .iter()
                .filter(|(key, _)| key != to_delete)
                .cloned()
                .collect::<BTreeMap<_, _>>();
            let (mut trie, mut loader) = make_mut_trie(inputs.clone());
            if trie.delete(&mut loader, &to_delete[..]).is_err() {
                bail!("Failed to delete.");
            }
            compare_to_reference(&mut trie, &mut loader, &reference)?;
        }
        Ok(())
    };
    QuickCheck::new().tests(NUM_TESTS).quickcheck(prop as fn(Vec<_>) -> _);
}

#[test]
/// Check that the mutable trie and its iterator match the reference
/// implementation after a freeze/thaw step.
fn prop_matches_reference_after_freeze_thaw() {
    let prop = |inputs: Vec<(Vec<u8>, Value)>| -> anyhow::Result<()> {
        let reference = inputs.iter().cloned().collect::<BTreeMap<_, _>>();
        let (trie, mut loader) = make_mut_trie(inputs);
        let trie = if let Some(trie) = trie.freeze(&mut loader, &mut EmptyCollector) {
            trie
        } else if reference.is_empty() {
            return Ok(());
        } else {
            bail!("Failure to freeze should only happen for an empty collection.");
        };
        let mut trie = trie.make_mutable(0, &mut loader);
        compare_to_reference(&mut trie, &mut loader, &reference)
    };
    QuickCheck::new().tests(NUM_TESTS).quickcheck(prop as fn(Vec<_>) -> _);
}

/// Check that it costs nothing to freeze a tree that is not modified.
#[test]
/// Check that the mutable trie and its iterator match the reference
/// implementation after a freeze/thaw step.
/// Check also that the collector result is unaffected by freeze/thaw and
/// storing.
fn prop_freeze_unmodified() {
    let prop = |inputs: Vec<(Vec<u8>, Value)>, new: Vec<Vec<u8>>| -> anyhow::Result<()> {
        let reference = inputs.iter().cloned().collect::<BTreeMap<_, _>>();
        let (trie, mut loader) = make_mut_trie(inputs);
        let trie = if let Some(trie) = trie.freeze(&mut loader, &mut EmptyCollector) {
            trie
        } else {
            ensure!(reference.is_empty(), "Cannot freeze, but reference is not empty.");
            return Ok(());
        };
        let mut m1 = trie.make_mutable(0, &mut loader);

        for k in &new {
            m1.get_entry(&mut loader, k);
        }

        let mut collector = SizeCollector::default();
        m1.freeze(&mut loader, &mut collector).expect("Freezing m1 should succeed.");
        let s1 = collector.collect();
        ensure!(s1 == 0, "Non-zero cost {}.", s1);
        Ok(())
    };
    QuickCheck::new().tests(NUM_TESTS).quickcheck(prop as fn(Vec<_>, _) -> _);
}

#[test]
/// Check that the mutable trie and its iterator match the reference
/// implementation after a freeze/thaw step.
/// Check also that the collector result is unaffected by freeze/thaw and
/// storing.
fn prop_freeze_collector() {
    let prop = |inputs: Vec<(Vec<u8>, Value)>, new: Vec<(Vec<u8>, Value)>| -> anyhow::Result<()> {
        let reference = inputs.iter().cloned().collect::<BTreeMap<_, _>>();
        let (trie, mut loader) = make_mut_trie(inputs.clone());
        let trie = if let Some(trie) = trie.freeze(&mut loader, &mut EmptyCollector) {
            trie
        } else {
            ensure!(reference.is_empty(), "Cannot freeze, but reference is not empty.");
            return Ok(());
        };
        let (trie_1, mut loader_1) = make_mut_trie(inputs);
        let mut trie_1 = if let Some(trie_1) = trie_1.freeze(&mut loader_1, &mut EmptyCollector) {
            trie_1
        } else {
            ensure!(reference.is_empty(), "Cannot freeze, but reference is not empty.");
            return Ok(());
        };
        let mut buf = Vec::new();
        let mut store = Vec::new();
        trie_1.store_update_buf(&mut store, &mut buf).expect("Storing trie_1 should succeed.");
        let stored_location = store.store_raw(&buf).expect("Storing the tree should succeed.");
        let mut loader_1 = Loader {
            inner: store,
        };
        let trie_1 = CachedRef::<Hashed<Node>>::load_from_location(&mut loader_1, stored_location)
            .expect("Loading of the tree failed.");
        let mut m1 = trie.make_mutable(0, &mut loader);
        let mut m2 = trie_1.make_mutable(0, &mut loader_1);

        for (k, v) in &new {
            m1.insert(&mut loader, k, v.clone()).expect("Inserting in m1 should succeed.");
        }

        for (k, v) in new {
            m2.insert(&mut loader_1, &k, v).expect("Inserting in m2 should succeed.");
        }
        let mut collector = SizeCollector::default();
        let mut collector_1 = SizeCollector::default();
        let d1 = format!("{:#?}", m1);
        let d2 = format!("{:#?}", m2);
        m1.freeze(&mut loader, &mut collector).expect("Freezing m1 should succeed.");
        m2.freeze(&mut loader_1, &mut collector_1).expect("Freezing m2 should succeed");
        let s1 = collector.collect();
        let s2 = collector_1.collect();
        ensure!(s1 == s2, "Sizes differ {} != {} {} {}.", s1, s2, d1, d2);
        Ok(())
    };
    QuickCheck::new().tests(NUM_TESTS).quickcheck(prop as fn(Vec<_>, _) -> _);
}

#[test]
/// Check that mutating the new generation does not affect the previous one.
fn prop_matches_reference_after_new_gen_mutate() {
    let prop = |inputs: Vec<(Vec<u8>, Value)>, additions: Vec<(Vec<u8>, Value)>| -> bool {
        let reference = inputs.iter().cloned().collect::<BTreeMap<_, _>>();
        let (mut trie, mut loader) = make_mut_trie(inputs);
        trie.new_generation();
        {
            let reference_iter = reference.iter();
            for (k, _) in reference_iter {
                if let Some(entry) = trie.get_entry(&mut loader, k) {
                    if let Some(v) = trie
                        .get_mut(entry, &mut loader, &mut EmptyCounter)
                        .expect("Empty counter does not error.")
                    {
                        *v = vec![17];
                    } else {
                        return false;
                    }
                    // trie.delete(&mut loader, k); // for good measure delete
                    // the
                } else {
                    return false;
                }
            }

            let mut joined_reference = reference.clone();
            let additions_map = additions.iter().cloned().collect::<BTreeMap<_, _>>();
            for (k, v) in additions {
                trie.insert(&mut loader, &k, v.clone())
                    .expect("No iterators, so insert should succeed.");
                joined_reference.insert(k, v);
            }

            // insert additions into the new generation.
            let reference_iter = joined_reference.keys();
            let mut iterator_gen_1 = if let Some(i) =
                trie.iter(&mut loader, &[]).expect("This is the first iterator, so no overflow.")
            {
                i
            } else {
                return joined_reference.is_empty();
            };
            for k in reference_iter {
                if let Some(entry) = trie
                    .next(&mut loader, &mut iterator_gen_1, &mut EmptyCounter)
                    .expect("Empty counter does not fail.")
                {
                    let lookup_result = trie
                        .with_entry(entry, &mut loader, |ev| {
                            ev == [17] || additions_map.get(k).map(AsRef::as_ref) == Some(ev)
                        })
                        .unwrap_or(false);
                    if !lookup_result {
                        return false;
                    }
                    if iterator_gen_1.get_key() != k {
                        return false;
                    }
                } else {
                    return false;
                }
            }
            if trie
                .next(&mut loader, &mut iterator_gen_1, &mut EmptyCounter)
                .expect("Empty counter does not fail.")
                .is_some()
            {
                return false;
            }
        }

        trie.pop_generation(); // kill the generation we updated.
        let reference_iter = reference.iter();
        let mut iterator = if let Some(i) =
            trie.iter(&mut loader, &[]).expect("This is the first iterator, so no overflow.")
        {
            i
        } else {
            return reference.is_empty();
        };
        for (k, v) in reference_iter {
            if let Some(entry) = trie
                .next(&mut loader, &mut iterator, &mut EmptyCounter)
                .expect("Empty counter does not fail.")
            {
                if !trie.with_entry(entry, &mut loader, |ev| v == ev).unwrap_or(false) {
                    return false;
                }
                if iterator.get_key() != k {
                    return false;
                }
            } else {
                return false;
            }
        }
        trie.next(&mut loader, &mut iterator, &mut EmptyCounter)
            .expect("Empty counter does not fail.")
            .is_none() // there are no values
                       // left to iterate.
    };
    QuickCheck::new().tests(NUM_TESTS).quickcheck(prop as fn(Vec<_>, Vec<_>) -> bool);
}

#[test]
/// Check that mutating the new generation does not affect the previous one.
fn prop_iterator_get_key() {
    let prop = |inputs: Vec<(Vec<u8>, Value)>, prefix: Vec<u8>| -> anyhow::Result<()> {
        let reference = inputs.iter().cloned().collect::<BTreeMap<_, _>>();
        let (mut trie, mut loader) = make_mut_trie(inputs);

        let reference_iter = reference.iter();
        let mut iterator = if let Some(i) =
            trie.iter(&mut loader, &prefix).expect("This is the first iterator, so no overflow.")
        {
            i
        } else {
            for (k, _) in reference_iter {
                if k.starts_with(&prefix) {
                    bail!(
                        "There is a key {:?} that starts with {:?}, but iterator could not be \
                         obtained.",
                        k,
                        prefix
                    )
                }
            }
            return Ok(());
        };
        ensure!(
            iterator.get_key() == prefix,
            "Initial key returned by get_key should be the given prefix {:?}, but it is {:?}.",
            prefix,
            iterator.get_key()
        );
        for (k, v) in reference_iter {
            if k.starts_with(&prefix) {
                if let Some(entry) = trie
                    .next(&mut loader, &mut iterator, &mut EmptyCounter)
                    .expect("Empty counter does not fail.")
                {
                    ensure!(
                        trie.with_entry(entry, &mut loader, |ev| v == ev).unwrap_or(false),
                        "Value at key {:?} does not match.",
                        k
                    );
                    ensure!(
                        iterator.get_key() == k,
                        "Key returned by the iterator {:?} does not match reference {:?}.",
                        iterator.get_key(),
                        k
                    );
                } else {
                    bail!(
                        "Reference iterator has a next key {:?}, but the iterator did not return \
                         a next item.",
                        k
                    );
                }
            }
        }
        Ok(())
    };
    QuickCheck::new().tests(NUM_TESTS).quickcheck(prop as fn(_, _) -> anyhow::Result<()>);
}
