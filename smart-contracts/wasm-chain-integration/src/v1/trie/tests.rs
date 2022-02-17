use super::{low_level::*, Value, *};
use anyhow::{bail, ensure, Context};
use quickcheck::*;
use std::collections::BTreeMap;

const NUM_TESTS: u64 = 1000;

fn make_mut_trie<A: AsRef<[u8]>>(words: Vec<(A, Value)>) -> (MutableTrie<Value>, Loader<Value>) {
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

#[test]
/// Check that storing also caches the data.
fn prop_storing_caches() {
    let prop = |inputs: Vec<(Vec<u8>, Value)>| -> anyhow::Result<()> {
        let reference = inputs.iter().cloned().collect::<BTreeMap<_, _>>();
        let (trie, mut loader) = make_mut_trie(inputs);
        let mut frozen = if let Some(t) = trie.freeze(&mut loader, &mut EmptyCollector) {
            t
        } else {
            ensure!(reference.is_empty(), "Reference map is empty, but trie is not.");
            return Ok(());
        };
        let mut ser = Vec::new();
        let _ = frozen.store_update(&mut ser);
        ensure!(frozen.data.is_stored(), "Not all data is stored.");
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
            // check that the computed size at least accounts for all the data
            // keys are partially shared so we cannot easily bound those.
            let data_size = reference.values().map(|v| v.len() as u64).sum::<u64>();
            ensure!(collector.collect() > data_size);
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
        let trie = Hashed::<Node<Value>>::load_from_location(&mut loader, root);
        ensure!(trie.is_ok(), "Failed to deserialize {:?}", loader.inner);
        Ok(())
    };
    QuickCheck::new().tests(NUM_TESTS).quickcheck(prop as fn(Vec<_>) -> anyhow::Result<()>);
}

#[test]
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
        frozen.serialize(&mut loader, &mut out).context("Serialization failed.")?;
        let mut source = std::io::Cursor::new(&out);
        let deserialized =
            Hashed::<Node<Value>>::deserialize(&mut source).context("Failed to deserialize")?;
        ensure!(source.position() == out.len() as u64, "Some input was not consumed.");
        let mut mutable = deserialized.data.make_mutable(0);
        let mut iterator = if let Some(i) =
            mutable.iter(&mut loader, &[]).expect("This is the first iterator, so no overflow.")
        {
            i
        } else {
            ensure!(reference.is_empty(), "Reference map is empty, but trie is not.");
            return Ok(());
        };
        let reference_iter = reference.iter();
        for (k, v) in reference_iter {
            let entry =
                mutable.next(&mut loader, &mut iterator).context("Trie iterator ends early.")?;
            ensure!(
                mutable.with_entry(entry, &mut loader, |ev| v == ev).unwrap_or(false),
                "Reference value does not match the trie value."
            );
            let it_key = iterator.get_key();
            ensure!(it_key == k, "Iterator returns incorrect key, {:?} != {:?}.", it_key, k);
        }
        Ok(())
    };
    QuickCheck::new().tests(NUM_TESTS).quickcheck(prop as fn(Vec<_>) -> anyhow::Result<()>);
}

#[test]
/// Check that the storing preserves hash.
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
        let hash_1 = frozen.hash;
        let mut backing_store = Vec::new();
        let top = frozen.store_update(&mut backing_store).expect("Storing succeeds.");
        let root = backing_store.store_raw(&top).expect("Storing to a vector succeeds.");
        let mut loader = Loader {
            inner: backing_store,
        };
        let trie = Hashed::<Node<Value>>::load_from_location(&mut loader, root)
            .context("Failed to deserialize.")?;
        let hash_2 = trie.hash;
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
                ensure!(inputs.len() == 0, "Empty tree, but non-empty inputs.");
                return Ok(());
            };
            let hash = frozen.hash;
            // swap pairs and make another tree
            let len = inputs.len(); // we know this is non-zero.
            for (l, r) in swaps {
                inputs.swap(l % len, r % len);
            }
            let (trie_1, mut loader_1) = make_mut_trie(inputs.clone());
            let frozen_1 = if let Some(t) = trie_1.freeze(&mut loader_1, &mut EmptyCollector) {
                t
            } else {
                bail!("The first tree was not empty, but the second one is.");
            };
            let hash_1 = frozen_1.hash;
            ensure!(hash == hash_1, "Hashes differ.");
            Ok(())
        };
    QuickCheck::new().tests(NUM_TESTS).quickcheck(prop as fn(Vec<_>, Vec<_>) -> anyhow::Result<()>);
}

#[test]
/// Check that the mutable trie and its iterator match the reference
/// implementation.
fn prop_matches_reference() {
    let prop = |inputs: Vec<(Vec<u8>, Value)>| -> anyhow::Result<()> {
        let reference = inputs.iter().cloned().collect::<BTreeMap<_, _>>();
        let (mut trie, mut loader) = make_mut_trie(inputs);
        let mut iterator = if let Some(i) =
            trie.iter(&mut loader, &[]).expect("This is the first iterator, so no overflow.")
        {
            i
        } else {
            ensure!(reference.is_empty(), "Reference map is empty, but trie is not.");
            return Ok(());
        };
        let reference_iter = reference.iter();
        for (k, v) in reference_iter {
            let entry =
                trie.next(&mut loader, &mut iterator).context("Trie iterator ends early.")?;
            ensure!(
                trie.with_entry(entry, &mut loader, |ev| v == ev).unwrap_or(false),
                "Reference value does not match the trie value."
            );
            let it_key = iterator.get_key();
            ensure!(it_key == k, "Iterator returns incorrect key, {:?} != {:?}", it_key, k);
        }
        ensure!(
            trie.next(&mut loader, &mut iterator).is_none(),
            "Trie iterator has remaining values."
        );
        Ok(())
    };
    QuickCheck::new().tests(NUM_TESTS).quickcheck(prop as fn(Vec<_>) -> anyhow::Result<()>);
}

#[test]
/// Check that the mutable trie and its iterator match the reference
/// implementation, after deleting a prefix.
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

            let reference_iter = reference.iter();
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

            let mut iterator = if let Some(i) =
                trie.iter(&mut loader, &[]).expect("This is the first iterator, so no overflow.")
            {
                i
            } else if !reference.is_empty() {
                bail!("Iterator is empty, but the reference is not.");
            } else {
                continue;
            };
            for (k, v) in reference_iter {
                if let Some(entry) = trie.next(&mut loader, &mut iterator) {
                    ensure!(
                        trie.with_entry(entry, &mut loader, |ev| v == ev).unwrap_or(false),
                        "Entry value does not match reference value."
                    );
                    let it_key = iterator.get_key();
                    ensure!(it_key == k, "Iterator returns incorrect key, {:?} != {:?}", it_key, k);
                }
            }
            // there are no values left to iterate.
            ensure!(
                trie.next(&mut loader, &mut iterator).is_none(),
                "Iterator has remaining values."
            );
        }
        Ok(())
    };
    QuickCheck::new().tests(NUM_TESTS).quickcheck(prop as fn(Vec<_>) -> anyhow::Result<()>);
}

#[test]
/// Test the following scenarios
/// - creating iterators placed in arbitrary locations in the tree prevents us
///   from deleting in those areas, but still allows us to create and delete in
///   areas that are not locked
fn prop_iterator_locked_for_modification_multiple() {
    let prop = |inputs: Vec<(Vec<u8>, Value)>,
                prefixes_to_lock: Vec<Vec<u8>>,
                to_insert: Vec<Vec<u8>>|
     -> anyhow::Result<()> {
        let (mut trie, mut loader) = make_mut_trie(inputs.clone());
        let mut stop = false;
        for len_to_consider in 0.. {
            if stop {
                break;
            }
            let mut locked_prefixes = Vec::new();
            stop = true;
            for prefix in &prefixes_to_lock {
                if prefix.len() >= len_to_consider {
                    if let Ok(option_iterator) = trie.iter(&mut loader, &prefix) {
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
                    locked_prefixes.iter().any(|iter| candidate.starts_with(iter.get_key()));
                if not_allowed {
                    ensure!(
                        trie.insert(&mut loader, &candidate, data.to_be_bytes().to_vec()).is_err(),
                        "{:?} extends one of the iterator keys.",
                        candidate
                    );
                    ensure!(
                        trie.delete(&mut loader, &candidate).is_err(),
                        "{:?} extends one of the iterator keys, so deletion is not allowed.",
                        candidate
                    );
                    ensure!(
                        trie.delete_prefix(&mut loader, &candidate, &mut EmptyCounter)
                            .expect("Empty counter does not fail.")
                            .is_err(),
                        "{:?} extends one of the iterator keys, but delete_prefix succeded.",
                        candidate
                    )
                } else {
                    ensure!(
                        trie.insert(&mut loader, &candidate, data.to_be_bytes().to_vec()).is_ok(),
                        "{:?} does not extend any of the iterator keys, but insertion failed.",
                        candidate
                    );
                    let not_allowed_delete_subtree =
                        locked_prefixes.iter().any(|iter| iter.get_key().starts_with(candidate));
                    if !not_allowed_delete_subtree {
                        if data % 2 == 0 {
                            // now delete the just inserted entry
                            ensure!(
                                trie.delete(&mut loader, &candidate).is_ok(),
                                "{:?} does not extend any of the iterator keys, but deletion \
                                 failed.",
                                candidate
                            );
                        } else {
                            ensure!(
                                trie.delete_prefix(&mut loader, &candidate, &mut EmptyCounter)
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
                            trie.delete(&mut loader, &candidate).is_ok(),
                            "{:?} does not extend any of the iterator keys, but deletion failed.",
                            candidate
                        );
                    }
                }
            }
            // cleanup the trie
            for iter in &locked_prefixes {
                trie.delete_iter(iter)
            }
        }
        Ok(())
    };
    QuickCheck::new()
        .tests(NUM_TESTS)
        .quickcheck(prop as fn(Vec<_>, Vec<_>, Vec<_>) -> anyhow::Result<()>);
}

#[test]
/// Test the following scenarios
/// - creating iterators placed in arbitrary locations in the tree prevents us
///   from deleting in those areas, but still allows us to create and delete in
///   areas that are not locked
fn prop_iterator_locked_for_modification_generations() {
    // tests is a list of pairs of (prefixes_to_lock, keys to insert/delete)
    let prop = |inputs: Vec<(Vec<u8>, Value)>,
                tests: Vec<(Vec<Vec<u8>>, Vec<Vec<u8>>)>|
     -> anyhow::Result<()> {
        let (mut trie, mut loader) = make_mut_trie(inputs.clone());
        let mut generation_cleanup_stack = Vec::new();
        let mut tester = |prefixes_to_lock: &[Vec<u8>], to_insert: &[Vec<u8>], pop_gen: bool| {
            if pop_gen {
                if let Some(locked_prefixes) = generation_cleanup_stack.pop() {
                    for iter in &locked_prefixes {
                        trie.delete_iter(iter)
                    }
                }
            }
            let mut locked_prefixes = Vec::new();
            for prefix in prefixes_to_lock {
                if let Ok(option_iterator) = trie.iter(&mut loader, &prefix) {
                    if let Some(iterator) = option_iterator {
                        locked_prefixes.push(iterator);
                    }
                }
            }
            for (candidate, data) in to_insert.iter().zip(0u64..) {
                // find out if the candidate can or cannot be inserted
                let not_allowed =
                    locked_prefixes.iter().any(|iter| candidate.starts_with(iter.get_key()));
                if not_allowed {
                    ensure!(
                        trie.insert(&mut loader, &candidate, data.to_be_bytes().to_vec()).is_err(),
                        "{:?} extends one of the iterator keys.",
                        candidate
                    );
                    ensure!(
                        trie.delete(&mut loader, &candidate).is_err(),
                        "{:?} extends one of the iterator keys, so deletion is not allowed.",
                        candidate
                    );
                    ensure!(
                        trie.delete_prefix(&mut loader, &candidate, &mut EmptyCounter)
                            .expect("Empty counter does not fail.")
                            .is_err(),
                        "{:?} extends one of the iterator keys, but delete_prefix succeded.",
                        candidate
                    )
                } else {
                    ensure!(
                        trie.insert(&mut loader, &candidate, data.to_be_bytes().to_vec()).is_ok(),
                        "{:?} does not extend any of the iterator keys, but insertion failed.",
                        candidate
                    );
                    let not_allowed_delete_subtree =
                        locked_prefixes.iter().any(|iter| iter.get_key().starts_with(candidate));
                    if !not_allowed_delete_subtree {
                        if data % 2 == 0 {
                            // now delete the just inserted entry
                            ensure!(
                                trie.delete(&mut loader, &candidate).is_ok(),
                                "{:?} does not extend any of the iterator keys but deletion \
                                 failed, {:#?}, iterator {:#?}",
                                candidate,
                                trie,
                                locked_prefixes,
                            );
                        } else {
                            ensure!(
                                trie.delete_prefix(&mut loader, &candidate, &mut EmptyCounter)
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
                            trie.delete(&mut loader, &candidate).is_ok(),
                            "{:?} does not extend any of the iterator keys, but deletion failed.",
                            candidate
                        );
                    }
                }
            }
            if !pop_gen {
                generation_cleanup_stack.push(locked_prefixes);
            }
            // cleanup the trie
            // for iter in &locked_prefixes {
            // trie.delete_iter(iter)
            // }
            if pop_gen {
                trie.pop_generation().context(
                    "We are iterating over the same list, so we should alwasy succeed in popping.",
                )?;
            } else {
                trie.new_generation();
            }
            Ok(())
        };
        for (prefixes_to_lock, to_insert) in &tests {
            tester(prefixes_to_lock, to_insert, false)?;
        }
        for (prefixes_to_lock, to_insert) in tests.iter().rev() {
            tester(prefixes_to_lock, to_insert, true)?;
        }
        ensure!(trie.pop_generation().is_some(), "We should have one generation left.");
        ensure!(trie.pop_generation().is_none(), "We should have exhausted the generations.");
        Ok(())
    };
    QuickCheck::new().tests(NUM_TESTS).quickcheck(prop as fn(Vec<_>, Vec<_>) -> anyhow::Result<()>);
}

#[test]
/// Check that iterators cannot be modified.
fn prop_iterator_locked_for_modification() {
    let prop = |inputs: Vec<(Vec<u8>, Value)>| -> anyhow::Result<()> {
        let (mut trie, mut loader) = make_mut_trie(inputs.clone());
        for (prefix, _) in inputs.iter() {
            let locked_prefix = prefix.clone();

            if let Some(mut iter) = trie
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

                trie.delete_iter(&mut iter);
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
    let prop = |inputs: Vec<(Vec<u8>, Value)>| -> bool {
        let (mut trie, mut loader) = make_mut_trie(inputs.clone());
        let reference = inputs.iter().cloned().collect::<BTreeMap<_, _>>();
        for (prefix, _) in inputs.iter() {
            trie.new_generation();
            trie.delete_prefix(&mut loader, &prefix[..], &mut EmptyCounter)
                .unwrap()
                .expect("No iterators are present, so we should be able to delete the prefix.");
        }
        trie.normalize(0);
        let mut iterator = if let Some(i) =
            trie.iter(&mut loader, &[]).expect("This is the first iterator, so no overflow.")
        {
            i
        } else {
            return reference.is_empty();
        };
        for (k, v) in reference.iter() {
            if let Some(entry) = trie.next(&mut loader, &mut iterator) {
                if !trie.with_entry(entry, &mut loader, |ev| v == ev).unwrap_or(false) {
                    return false;
                }
                if iterator.get_key() != k {
                    return false;
                }
            }
        }
        // there are no values left to iterate.
        if trie.next(&mut loader, &mut iterator).is_some() {
            return false;
        }
        true
    };
    QuickCheck::new().tests(NUM_TESTS).quickcheck(prop as fn(Vec<_>) -> bool);
}

#[test]
/// Check that the mutable trie and its iterator match the reference
/// implementation, after deleting a single value.
fn prop_matches_reference_delete() {
    let prop = |inputs: Vec<(Vec<u8>, Value)>| -> bool {
        for (to_delete, _) in inputs.iter() {
            let reference = inputs
                .iter()
                .filter(|(key, _)| key != to_delete)
                .cloned()
                .collect::<BTreeMap<_, _>>();
            let (mut trie, mut loader) = make_mut_trie(inputs.clone());
            let reference_iter = reference.iter();
            if trie.delete(&mut loader, &to_delete[..]).is_err() {
                return false;
            }
            let mut iterator = if let Some(i) =
                trie.iter(&mut loader, &[]).expect("This is the first iterator, so no overflow.")
            {
                i
            } else if !reference.is_empty() {
                return false;
            } else {
                continue;
            };
            for (k, v) in reference_iter {
                if let Some(entry) = trie.next(&mut loader, &mut iterator) {
                    if !trie.with_entry(entry, &mut loader, |ev| v == ev).unwrap_or(false) {
                        return false;
                    }
                    if iterator.get_key() != k {
                        return false;
                    }
                }
            }
            // there are no values left to iterate.
            if trie.next(&mut loader, &mut iterator).is_some() {
                return false;
            }
        }
        true
    };
    QuickCheck::new().tests(NUM_TESTS).quickcheck(prop as fn(Vec<_>) -> bool);
}

#[test]
/// Check that the mutable trie and its iterator match the reference
/// implementation after a freeze/thaw step.
fn prop_matches_reference_after_freeze_thaw() {
    let prop = |inputs: Vec<(Vec<u8>, Value)>| -> bool {
        let reference = inputs.iter().cloned().collect::<BTreeMap<_, _>>();
        let (trie, mut loader) = make_mut_trie(inputs);
        let trie = if let Some(Hashed {
            data: trie,
            ..
        }) = trie.freeze(&mut loader, &mut EmptyCollector)
        {
            trie
        } else {
            return reference.is_empty();
        };
        let mut trie = trie.make_mutable(0);
        let mut iterator = if let Some(i) =
            trie.iter(&mut loader, &[]).expect("This is the first iterator, so no overflow.")
        {
            i
        } else {
            return reference.is_empty();
        };
        let reference_iter = reference.iter();
        for (k, v) in reference_iter {
            if let Some(entry) = trie.next(&mut loader, &mut iterator) {
                if !trie.with_entry(entry, &mut loader, |ev| v == ev).unwrap_or(false) {
                    return false;
                }
                if iterator.get_key() != k {
                    return false;
                }
            }
        }
        trie.next(&mut loader, &mut iterator).is_none() // there are no values
                                                        // left to iterate.
    };
    QuickCheck::new().tests(NUM_TESTS).quickcheck(prop as fn(Vec<_>) -> bool);
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
                    if let Some(v) = trie.get_mut(entry, &mut loader) {
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
                if let Some(entry) = trie.next(&mut loader, &mut iterator_gen_1) {
                    if !trie
                        .with_entry(entry, &mut loader, |ev| {
                            ev == &[17] || additions_map.get(k) == Some(ev)
                        })
                        .unwrap_or(false)
                    {
                        return false;
                    }
                    if iterator_gen_1.get_key() != k {
                        return false;
                    }
                } else {
                    return false;
                }
            }
            if trie.next(&mut loader, &mut iterator_gen_1).is_some() {
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
            if let Some(entry) = trie.next(&mut loader, &mut iterator) {
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
        trie.next(&mut loader, &mut iterator).is_none() // there are no values
                                                        // left to iterate.
    };
    QuickCheck::new().tests(NUM_TESTS).quickcheck(prop as fn(Vec<_>, Vec<_>) -> bool);
}
