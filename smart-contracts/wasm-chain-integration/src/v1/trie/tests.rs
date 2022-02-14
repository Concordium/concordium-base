use super::low_level::*;
use anyhow::{bail, ensure, Context};
use quickcheck::*;
use std::collections::BTreeMap;

fn make_mut_trie<A: AsRef<[u8]>>(
    words: Vec<(A, Vec<u8>)>,
) -> (MutableTrie<Vec<u8>>, Loader<Vec<u8>>) {
    let mut node = MutableTrie::empty();
    let mut loader = Loader {
        inner: Vec::<u8>::new(),
    };
    for (key, value) in words {
        node.insert(&mut loader, key.as_ref(), value);
    }
    (node, loader)
}

#[test]
/// Check that storing also caches the data.
fn prop_storing_caches() {
    let prop = |inputs: Vec<(Vec<u8>, Vec<u8>)>| -> anyhow::Result<()> {
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
    QuickCheck::new().tests(10000).quickcheck(prop as fn(Vec<_>) -> anyhow::Result<()>);
}

#[test]
/// Check that storing computes the correct size, and that it can be
/// deserialized.
fn prop_storing() {
    let prop = |inputs: Vec<(Vec<u8>, Vec<u8>)>| -> anyhow::Result<()> {
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
        let trie = Hashed::<Node<Vec<u8>>>::load_from_location(&mut loader, root);
        ensure!(trie.is_ok(), "Failed to deserialize {:?}", loader.inner);
        Ok(())
    };
    QuickCheck::new().tests(10000).quickcheck(prop as fn(Vec<_>) -> anyhow::Result<()>);
}

#[test]
fn prop_serialization() {
    let prop = |inputs: Vec<(Vec<u8>, Vec<u8>)>| -> anyhow::Result<()> {
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
            Hashed::<Node<Vec<u8>>>::deserialize(&mut source).context("Failed to deserialize")?;
        ensure!(source.position() == out.len() as u64, "Some input was not consumed.");
        let mut mutable = deserialized.data.make_mutable(0);
        let mut iterator = if let Some(i) = mutable.iter(&mut loader, &[]) {
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
    QuickCheck::new().tests(10000).quickcheck(prop as fn(Vec<_>) -> anyhow::Result<()>);
}

#[test]
/// Check that the storing preserves hash.
fn prop_storing_preseves_hash() {
    let prop = |inputs: Vec<(Vec<u8>, Vec<u8>)>| -> anyhow::Result<()> {
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
        let trie = Hashed::<Node<Vec<u8>>>::load_from_location(&mut loader, root)
            .context("Failed to deserialize.")?;
        let hash_2 = trie.hash;
        ensure!(hash_1 == hash_2, "Hashes differ.");
        Ok(())
    };
    QuickCheck::new().tests(10000).quickcheck(prop as fn(Vec<_>) -> anyhow::Result<()>);
}

#[test]
/// Check that the hash of the tree is independent of the order of insertions,
/// provided there are no duplicates.
fn prop_hash_independent_of_order() {
    let prop =
        |mut inputs: Vec<(Vec<u8>, Vec<u8>)>, swaps: Vec<(usize, usize)>| -> anyhow::Result<()> {
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
    QuickCheck::new().tests(10000).quickcheck(prop as fn(Vec<_>, Vec<_>) -> anyhow::Result<()>);
}

#[test]
/// Check that the mutable trie and its iterator match the reference
/// implementation.
fn prop_matches_reference() {
    let prop = |inputs: Vec<(Vec<u8>, Vec<u8>)>| -> anyhow::Result<()> {
        let reference = inputs.iter().cloned().collect::<BTreeMap<_, _>>();
        let (mut trie, mut loader) = make_mut_trie(inputs);
        let mut iterator = if let Some(i) = trie.iter(&mut loader, &[]) {
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
    QuickCheck::new().tests(10000).quickcheck(prop as fn(Vec<_>) -> anyhow::Result<()>);
}

#[test]
/// Check that the mutable trie and its iterator match the reference
/// implementation, after deleting a prefix.
fn prop_matches_reference_delete_subtree() {
    let prop = |inputs: Vec<(Vec<u8>, Vec<u8>)>| -> anyhow::Result<()> {
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
                trie.delete_prefix(&mut loader, &prefix[..]).is_some(),
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

            let mut iterator = if let Some(i) = trie.iter(&mut loader, &[]) {
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
    QuickCheck::new().tests(10000).quickcheck(prop as fn(Vec<_>) -> anyhow::Result<()>);
}

#[test]
/// Check that iterators cannot be modified.
/// todo: test locking for deleting prefix
fn prop_iterator_locked_for_modification() {
    let prop = |inputs: Vec<(Vec<u8>, Vec<u8>)>| -> anyhow::Result<()> {
        let (mut trie, mut loader) = make_mut_trie(inputs.clone());
        for (prefix, _) in inputs.iter() {
            let locked_prefix = prefix.clone();
            if let Some(mut iter) = trie.iter(&mut loader, &locked_prefix) {
                let mut modification = locked_prefix.clone();
                modification.push(0);
                ensure!(
                    trie.insert(&mut loader, &modification, vec![]).is_none(),
                    "The subtree should be locked for modification (insertion)."
                );
                ensure!(
                    trie.delete(&mut loader, &modification).is_none(),
                    "The subtree should be locked for modification (removal)."
                );
                ensure!(
                    trie.delete_prefix(&mut loader, &modification).is_none(),
                    "The subtree should be locked for modification (prefix removal)."
                );
                let mut step_up = modification.clone();
                step_up.pop();
                ensure!(
                    trie.delete_prefix(&mut loader, &step_up).is_none(),
                    "The subtree should be locked for modification (prefix removal - step up)."
                );
                trie.delete_iter(&mut loader, &mut iter);
                ensure!(
                    trie.insert(&mut loader, &modification, vec![]).is_some(),
                    "The subtree should not be locked for modification (insertion)."
                );
                ensure!(
                    trie.delete(&mut loader, &modification).is_some(),
                    "The subtree should not be locked for modification (removal)."
                );
                ensure!(
                    trie.insert(&mut loader, &modification, vec![]).is_some(),
                    "The subtree should not be locked for modification (insertion)."
                );
                ensure!(
                    trie.delete_prefix(&mut loader, &modification).is_some(),
                    "The subtree should not be locked for modification (prefix removal)."
                );
                ensure!(
                    trie.delete_prefix(&mut loader, &step_up).is_some(),
                    "The subtree should not be locked for modification (prefix removal - step up)."
                );
            }
        }
        Ok(())
    };
    QuickCheck::new().tests(10000).quickcheck(prop as fn(Vec<_>) -> anyhow::Result<()>);
}

#[test]
/// Check that the mutable trie delete prefix does not affect generations that
/// are frozen.
fn prop_matches_reference_checkpoint_delete_subtree() {
    let prop = |inputs: Vec<(Vec<u8>, Vec<u8>)>| -> bool {
        let (mut trie, mut loader) = make_mut_trie(inputs.clone());
        let reference = inputs.iter().cloned().collect::<BTreeMap<_, _>>();
        for (prefix, _) in inputs.iter() {
            trie.new_generation();
            trie.delete_prefix(&mut loader, &prefix[..]);
        }
        trie.normalize(0);
        let mut iterator = if let Some(i) = trie.iter(&mut loader, &[]) {
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
    QuickCheck::new().tests(10000).quickcheck(prop as fn(Vec<_>) -> bool);
}

#[test]
/// Check that the mutable trie and its iterator match the reference
/// implementation, after deleting a single value.
fn prop_matches_reference_delete() {
    let prop = |inputs: Vec<(Vec<u8>, Vec<u8>)>| -> bool {
        for (to_delete, _) in inputs.iter() {
            let reference = inputs
                .iter()
                .filter(|(key, _)| key != to_delete)
                .cloned()
                .collect::<BTreeMap<_, _>>();
            let (mut trie, mut loader) = make_mut_trie(inputs.clone());
            let reference_iter = reference.iter();
            if trie.delete(&mut loader, &to_delete[..]).is_none() {
                return false;
            }
            let mut iterator = if let Some(i) = trie.iter(&mut loader, &[]) {
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
    QuickCheck::new().tests(10000).quickcheck(prop as fn(Vec<_>) -> bool);
}

#[test]
/// Check that the mutable trie and its iterator match the reference
/// implementation after a freeze/thaw step.
fn prop_matches_reference_after_freeze_thaw() {
    let prop = |inputs: Vec<(Vec<u8>, Vec<u8>)>| -> bool {
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
        let mut iterator = if let Some(i) = trie.iter(&mut loader, &[]) {
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
    QuickCheck::new().tests(10000).quickcheck(prop as fn(Vec<_>) -> bool);
}

#[test]
/// Check that mutating the new generation does not affect the previous one.
fn prop_matches_reference_after_new_gen_mutate() {
    let prop = |inputs: Vec<(Vec<u8>, Vec<u8>)>, additions: Vec<(Vec<u8>, Vec<u8>)>| -> bool {
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
                trie.insert(&mut loader, &k, v.clone());
                joined_reference.insert(k, v);
            }

            // insert additions into the new generation.
            let reference_iter = joined_reference.keys();
            let mut iterator_gen_1 = if let Some(i) = trie.iter(&mut loader, &[]) {
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
        let mut iterator = if let Some(i) = trie.iter(&mut loader, &[]) {
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
    QuickCheck::new().tests(10000).quickcheck(prop as fn(Vec<_>, Vec<_>) -> bool);
}
