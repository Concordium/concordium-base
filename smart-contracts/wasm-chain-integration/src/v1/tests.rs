use super::{
    trie::{self, MutableState},
    types::*,
};
use anyhow::{ensure, Context};
use quickcheck::*;

const NUM_TESTS: u64 = 100000;

#[test]
/// This tests performs the following tasks:
/// 1. Entries can be created.
/// 2. Created entries can be looked up.
/// 3. Writing to created entries and checking that the returned 'write length'
/// is accurate.
/// 4. Reading from an invalidated entry should return u32::MAX.
/// 5. Writing to an invalidated entry should return u32::MAX.
/// 6. Entries can be deleted check that equivalent entries are also
/// invalidated.
/// 7. Deleting already deleted entries returns u32::MAX
fn prop_create_write_read_delete() {
    let prop = |inputs: Vec<(Vec<u8>, trie::Value)>| -> anyhow::Result<()> {
        let mut loader = trie::Loader {
            inner: Vec::<u8>::new(),
        };
        let mut m_state = MutableState::initial_state();
        let inner = m_state.get_inner(&mut loader);
        let mut state = InstanceState::new(loader, inner);
        let mut energy = crate::InterpreterEnergy::from(u64::MAX);
        for (k, v) in &inputs {
            let entry = state
                .create_entry(k)
                .context(format!("The entry should've been created {:?}.", k))?;
            let entry = entry.convert().context("Entry should be valid.")?;

            let lookup_entry =
                state.lookup_entry(k).convert().context("Lookup entry should be valid.")?;

            let write_res = state
                .entry_write(&mut energy, entry, v, 0)
                .context(format!("Failed writing {:?} to key {:?}.", v, k))?;

            ensure!(
                write_res as usize == v.len(),
                "Entry write returned wrong write length {:?} expected {:?}.",
                write_res,
                v.len()
            );

            let mut buff0 = vec![0; v.len()];
            let read0 = state.entry_read(entry, &mut buff0, 0);
            ensure!(
                read0 as usize == v.len(),
                "Unexpected read length {:?} expected {:?}.",
                read0,
                v.len()
            );
            let read1 = state.entry_read(lookup_entry, &mut buff0, 0);
            ensure!(
                read1 as usize == v.len(),
                "Unexpected read length {:?} expected {:?}.",
                read1,
                v.len()
            );
            ensure!(state.delete_entry(k).unwrap() == 2, "Entry should be deleted.");
            ensure!(state.delete_entry(k).unwrap() == 1, "Entry was already deleted.");
            let mut buff0 = vec![0; v.len()];
            ensure!(
                state.entry_read(entry, &mut buff0, 0) == u32::MAX,
                "Reading an invalidated entry should return u32::MAX."
            );

            let write_res = state
                .entry_write(&mut energy, entry, v, 0)
                .context(format!("Failed writing {:?} to key {:?}.", v, k))?;

            ensure!(write_res == u32::MAX, "Entry write on deleted entry should return u32::MAX.");
            ensure!(state.delete_entry(k).unwrap() == 1, "Entry should already have been deleted.");

            ensure!(
                state.entry_read(entry, &mut buff0, 0) == u32::MAX,
                "Entry should have been invalidated."
            );
        }
        Ok(())
    };
    QuickCheck::new().tests(NUM_TESTS).quickcheck(prop as fn(Vec<_>) -> anyhow::Result<()>);
}

#[test]
/// This test performs the following tasks:
/// 1. Writing a buffer of MAX_ENTRY_SIZE succeeds.
/// 2. Reading a buffer of MAX_ENTRY_SIZE succeeds.
/// 3. Writing a buffer of MAX_ENTRY_SIZE + 1 only writes the first
/// MAX_ENTRY_SIZE bytes.
/// 4. Reading a buffer of MAX_ENTRY_SIZE + 1 only returns the corresponding
/// MAX_ENTRY_SIZE bytes.
/// 5. Test resizing to 0 bytes followed by a resize to MAX_ENTRY_SIZE
/// 6. Resizing above MAX_ENTRY_SIZE yields correct result
/// 7. Resizing without enough energy returns an Err.
/// 8. Resizing an invalidated entry returns u32::MAX.
fn test_overflowing_write_resize() -> anyhow::Result<()> {
    let mut loader = trie::Loader {
        inner: Vec::<u8>::new(),
    };
    let mut m_state = MutableState::initial_state();
    let inner = m_state.get_inner(&mut loader);
    let mut state = InstanceState::new(loader, inner);
    let mut energy = crate::InterpreterEnergy::from(u64::MAX);
    let k = &[42];
    let entry = state
        .create_entry(k)
        .context(format!("The entry should've been created {:?}", k))?
        .convert()
        .context("Entry should be valid")?;

    let mut non_overflowing_buffer = vec![0; crate::constants::MAX_ENTRY_SIZE];
    let write_past = state
        .entry_write(&mut energy, entry, &[0], crate::constants::MAX_ENTRY_SIZE as u32)
        .context("Writing past MAX_ENTRY_SIZE should return Ok")?;

    ensure!(write_past == 0, "Writing past MAX_ENTRY_SIZE should return 0.");

    ensure!(
        state.entry_write(&mut energy, entry, &non_overflowing_buffer, 0).is_ok(),
        "The data should be written"
    );
    ensure!(
        state.entry_read(entry, &mut non_overflowing_buffer, 0) as usize
            == non_overflowing_buffer.len(),
        "The whole buffer should be written to."
    );
    let mut overflowing_buffer = vec![0; crate::constants::MAX_ENTRY_SIZE + 1];
    let written = state
        .entry_write(&mut energy, entry, &overflowing_buffer, 0)
        .context("Write should've returned Ok(0)")?;

    ensure!(
        written as usize == crate::constants::MAX_ENTRY_SIZE,
        "The src buffer must at most have a size of 2^31 bytes."
    );

    ensure!(
        state.entry_read(entry, &mut overflowing_buffer, 0) as usize
            == overflowing_buffer.len() - 1,
        "Only 2^31 bytes should be read."
    );
    let mut energy_supplied = crate::InterpreterEnergy {
        energy: u64::MAX,
    };

    let resize_status = state
        .entry_resize(&mut energy_supplied, entry, 0)
        .context("Resizing to empty should not have returned an Err.")?;
    ensure!(resize_status == 1, "Resizing to 0 should have been completed successfully.");

    energy_supplied.energy = 0;
    ensure!(
        state
            .entry_resize(&mut energy_supplied, entry, (crate::constants::MAX_ENTRY_SIZE) as u32)
            .is_err(),
        "Resizing without sufficient energy should return an Err."
    );

    energy_supplied.energy = u64::MAX;
    let resize_status = state
        .entry_resize(&mut energy_supplied, entry, crate::constants::MAX_ENTRY_SIZE as u32)
        .context("Resizing max should not have returned an Err.")?;

    ensure!(
        resize_status == 1,
        "Resizing to MAX_ENTRY_SIZE should have been completed successfully."
    );

    let resize_status = state
        .entry_resize(&mut energy_supplied, entry, (crate::constants::MAX_ENTRY_SIZE + 1) as u32)
        .context("Resizing MAX_ENTRY_SIZE + 1 should not have returned an Err.")?;

    ensure!(
        resize_status == 0,
        "Resizing to MAX_ENTRY_SIZE + 1 should have been completed successfully."
    );

    ensure!(state.delete_entry(k).unwrap() == 2, "Deletion of entry {:?} should return 2", k);
    let resize_status = state
        .entry_resize(&mut energy_supplied, entry, 0)
        .context("Resizing of invalidated entry should not have returned an Err.")?;
    ensure!(resize_status == u32::MAX, "Resizing invalidated entry should return u32::MAX.");
    Ok(())
}

#[test]
/// Test that:
/// 1. Getting the size of an invalid entry returns u32::MAX.
/// 2. Deleting an invalidated entry returns u32::MAX.
/// 3. Looking up an invalid entry returns InstanceStateEntryOption::NEW_NONE.
/// 4. Delete prefix on non existent key in tree returns 1.
fn test_size_of_invalid_entry() -> anyhow::Result<()> {
    let mut loader = trie::Loader {
        inner: Vec::<u8>::new(),
    };
    let mut m_state = MutableState::initial_state();
    let inner = m_state.get_inner(&mut loader);
    let mut state = InstanceState::new(loader, inner);
    let entry = state
        .create_entry(&[0])
        .context("Entry should be created.")?
        .convert()
        .context("Entry should be some.")?;

    ensure!(state.delete_entry(&[0]).unwrap() == 2, "Deleting an entry should return 1.");
    ensure!(
        state.entry_size(entry) == u32::MAX,
        "Entry size of invalidated entry should return u32::MAX."
    );
    ensure!(
        state.lookup_entry(&[42]) == InstanceStateEntryOption::NEW_NONE,
        "Lookup on non existent entry should return None."
    );
    let mut energy_supplied = crate::InterpreterEnergy {
        energy: u64::MAX,
    };
    let res = state
        .delete_prefix(&mut energy_supplied, &[42])
        .context("Delete prefix on non existent part of state should not return None.")?;
    ensure!(res == 1, "Deleting prefix on non existent part of state should return Ok(1).");
    ensure!(
        state.entry_size(42.into()) == u32::MAX,
        "Entry size of non existent entry should return u32::MAX."
    );
    Ok(())
}

/// Entry size/resize focused tests ///

#[test]
/// This test performs the following tasks:
/// 1. Creates entries.
/// 2. Write to the entry.
/// 3. Resize the entry.
/// 4. That the size after resizing is as expected.
fn prop_entry_write_resizing() {
    let prop = |inputs: Vec<(Vec<u8>, trie::Value)>| -> anyhow::Result<()> {
        let mut loader = trie::Loader {
            inner: Vec::<u8>::new(),
        };
        let mut m_state = MutableState::initial_state();
        let inner = m_state.get_inner(&mut loader);
        let mut state = InstanceState::new(loader, inner);
        let mut energy = crate::InterpreterEnergy::from(u64::MAX);
        for (k, v) in &inputs {
            let entry = state
                .create_entry(k)
                .context(format!("The entry should've been created {:?}", k))?
                .convert()
                .context("Entry should be valid")?;

            let written = state
                .entry_write(&mut energy, entry, v, 0)
                .context(format!("Writing to entry failed {:?}", k))?;
            ensure!(written as usize == v.len(), "Write should return the correct length written");

            let entry_size = state.entry_size(entry);
            ensure!(
                entry_size as usize == v.len(),
                "Entry size {:?} for key {:?} not correct expected {:?}.",
                entry_size,
                k,
                v.len()
            );
            let mut energy_supplied = crate::InterpreterEnergy {
                energy: u64::MAX,
            };
            let resize_status = state
                .entry_resize(&mut energy_supplied, entry, (v.len() * k.len()) as u32)
                .context("Rezising failed")?;
            ensure!(resize_status == 1, "Entry should have been resized.");
        }
        Ok(())
    };
    QuickCheck::new().tests(NUM_TESTS).quickcheck(prop as fn(Vec<_>) -> anyhow::Result<()>);
}

#[test]
/// Test that prefix removal fails correctly if out of energy
fn test_prefix_removal_fails_if_out_of_energy() -> anyhow::Result<()> {
    let mut loader = trie::Loader {
        inner: Vec::<u8>::new(),
    };
    let mut m_state = MutableState::initial_state();
    let inner = m_state.get_inner(&mut loader);
    let mut state = InstanceState::new(loader, inner);
    let key = vec![1];
    for k in &key {
        let entry = state
            .create_entry(&[*k])
            .context(format!("The entry should've been created {:?}", k))?;
        ensure!(entry.convert().is_some(), "Entry should be valid");
    }
    let mut energy_supplied = crate::InterpreterEnergy {
        // 2 = 1 step from root + 1 for removing the actual node.
        energy: crate::constants::TREE_TRAVERSAL_STEP_COST * 2 - 1,
    };
    ensure!(
        state.delete_prefix(&mut energy_supplied, &[key[0]]).is_err(),
        "Should run out of energy when deleting prefix."
    );
    Ok(())
}

/// Iterator focused tests ///

#[test]
/// This test performs the following tasks:
/// 1. Entries can be created
/// 2. Created entries can be looked up.
/// 3. Writing to created entries and that the returned 'write length' is
/// accurate.
/// 4. Creating iterators and locking parts of the tree.
/// 5. Making sure that no locked areas can be subject of structural
/// modification.
fn prop_iterators() {
    let prop = |inputs: Vec<(Vec<u8>, trie::Value)>| -> anyhow::Result<()> {
        let mut loader = trie::Loader {
            inner: Vec::<u8>::new(),
        };
        let mut m_state = MutableState::initial_state();
        let inner = m_state.get_inner(&mut loader);
        let mut state = InstanceState::new(loader, inner);
        let mut energy = crate::InterpreterEnergy::from(u64::MAX);
        // create the state with some locked parts.
        for (k, v) in &inputs {
            let entry = state
                .create_entry(k)
                .context(format!("The entry should've been created {:?}", k))?
                .convert()
                .context("Entry should be valid")?;

            ensure!(
                state.lookup_entry(k).convert().is_some(),
                "Lookup failed for entry with key {:?}",
                k
            );

            let write_len = state
                .entry_write(&mut energy, entry, v, 0)
                .context(format!("Entry should have been written to {:?}", k))?;
            ensure!(
                write_len as usize == v.len(),
                "The returned write size does not match expected."
            );

            if k.len() > 5 {
                let _entry = state
                    .create_entry(k)
                    .context("Creating an entry on locked part should not fail.")?
                    .convert()
                    .context("Converting an created entry in a locked part should return Some.")?;

                let iterator = state
                    .iterator(k)
                    .convert()
                    .context(format!("An iterator should have been created {:?}", k))?;
                let iterator_key_size_read = state.iterator_key_size(iterator);
                ensure!(
                    iterator_key_size_read as usize == k.len(),
                    "Current iterator key size {:?} should be length of initialized key {:?}",
                    iterator_key_size_read,
                    k.len()
                );

                let mut key_buff = vec![0; iterator_key_size_read as usize];
                let iterator_key_read_size = state.iterator_key_read(iterator, &mut key_buff, 0);
                ensure!(
                    iterator_key_read_size as usize == k.len(),
                    "Current iterator key read size {:?} should be length of initialized key {:?}",
                    iterator_key_read_size,
                    k.len()
                );

                ensure!(
                    state.delete_entry(k).unwrap() == 0,
                    "Deleting a locked part of the tree should return in 0."
                );
                let mut extended_key = k.clone();
                extended_key.push(0);
                let create_res = state
                    .create_entry(&extended_key)
                    .context("Creating an entry in a locked subtree should not return an Err.")?;
                ensure!(
                    create_res.convert().is_none(),
                    "Creating a new entry in a locked part of the tree should return none."
                );

                let mut energy_supplied = crate::InterpreterEnergy {
                    energy: u64::MAX,
                };
                let res = state
                    .delete_prefix(&mut energy_supplied, k)
                    .context("Deleting prefix of locked subtree should not return Err")?;
                ensure!(res == 0, "Deleting locked subtree should return 0.")
            }
        }

        // make sure that we can only modify the structure of the tree in non locked
        // areas.
        let mut removed_prefixes: Vec<&[u8]> = Vec::new();
        for (k, v) in &inputs {
            // make sure we don't try delete in suffixes of an already deleted prefix key.
            if !removed_prefixes.iter().cloned().any(|x| k.starts_with(x)) {
                let _entry = state
                    .lookup_entry(k)
                    .convert()
                    .context(format!("Could not lookup entry with key {:?}", k))?;

                if k.len() <= 5 {
                    if v.len() % 2 == 0 {
                        ensure!(
                            state.delete_entry(k).unwrap() == 2,
                            "The entry {:?} should have been deleted.",
                            k
                        );
                    } else {
                        let mut energy_supplied = crate::InterpreterEnergy {
                            energy: u64::MAX,
                        };
                        ensure!(
                            state.delete_prefix(&mut energy_supplied, k).is_ok(),
                            "The entry {:?} should have been prefix deleted.",
                            k
                        );
                    }
                    removed_prefixes.push(k);
                } else {
                    ensure!(
                        state.delete_entry(k).unwrap() == 0,
                        "The entry {:?} should not have been deleted.",
                        k
                    );
                }
            }
        }
        Ok(())
    };
    QuickCheck::new().tests(NUM_TESTS).quickcheck(prop as fn(Vec<_>) -> anyhow::Result<()>);
}

#[test]
/// This test performs the following tasks:
/// 1. Create an entry
/// 2. Create an iterator
/// 3. Traverse with the iterator making sure that locking guarantees hold.
/// 4. Traverse with out of energy returns Err.
fn prop_iterator_traversing() {
    let prop = |inputs: Vec<(Vec<u8>, trie::Value)>| -> anyhow::Result<()> {
        let mut loader = trie::Loader {
            inner: Vec::<u8>::new(),
        };
        let mut m_state = MutableState::initial_state();
        let inner = m_state.get_inner(&mut loader);
        let mut state = InstanceState::new(loader, inner);
        let mut energy = crate::InterpreterEnergy::from(u64::MAX);
        let mut prefixes = trie::low_level::PrefixesMap::new();
        for (k, v) in &inputs {
            let entry = state
                .create_entry(k)
                .context("Creating entry should not return Err.")?
                .convert()
                .context("Entry should be Some.")?;

            let write_result =
                state.entry_write(&mut energy, entry, v, 0).context("Write should be ok.")?;
            ensure!(
                write_result as usize == v.len(),
                "Incorrect amount of bytes written {:?} expected {:?}",
                write_result,
                v.len()
            );
            ensure!(prefixes.insert(k).is_ok(), "Prefix should have been added");
        }

        for (k, _) in &inputs {
            if prefixes.is_or_has_prefix(k) {
                let mut energy_supplied = crate::InterpreterEnergy {
                    energy: u64::MAX,
                };
                let iter = state.iterator(k).convert().context("Cannot create iterator.")?;
                ensure!(
                    state.iterator_next(&mut energy_supplied, iter).is_ok(),
                    "Traversing with energy and children should be ok."
                );
                let mut locked_subtree = k.clone();
                locked_subtree.push(0);
                let invalid_create = state
                    .create_entry(&locked_subtree)
                    .context("Creating an entry on locked subtree should not return Err")?;
                ensure!(
                    invalid_create == InstanceStateEntryOption::NEW_NONE,
                    "Creating an entry in a locked part should return \
                     InstanceStateEntryOption::NEW_NONE"
                );
            }
        }
        Ok(())
    };

    QuickCheck::new().tests(NUM_TESTS).quickcheck(prop as fn(Vec<_>) -> anyhow::Result<()>);
}

#[test]
/// Tests that
/// 1. Traversing with 0 energy will yield in an Err.
/// 2. Iterator_key_size with an invalid iterator returns u32::MAX.
/// 3. Iterator_key_read with an invalid iterator returns u32::MAX.
/// 4. Iterator on non existant part of tree returns Ok(None)
/// 5. Creating too many iterators on the same key should return Err.
fn test_iterator_errors() -> anyhow::Result<()> {
    let mut loader = trie::Loader {
        inner: Vec::<u8>::new(),
    };
    let mut m_state = MutableState::initial_state();
    let inner = m_state.get_inner(&mut loader);
    let mut state = InstanceState::new(loader, inner);

    ensure!(state.create_entry(&[0, 1]).is_ok(), "Entry should have been created");
    ensure!(state.create_entry(&[0, 2]).is_ok(), "Entry should have been created");

    let iter = state.iterator(&[0]).convert().context("Iterator should have been created.")?;

    let mut energy_supplied = crate::InterpreterEnergy {
        energy: 0,
    };
    ensure!(
        state.iterator_next(&mut energy_supplied, iter).is_err(),
        "Traversing with zero energy should yield an Err"
    );

    ensure!(
        state.iterator_key_size(42.into()) == u32::MAX,
        "key_size with invalid iterator should return u32::MAX."
    );
    let mut buff = [];
    ensure!(
        state.iterator_key_read(42.into(), &mut buff, 0) == u32::MAX,
        "key_read with invalid iterator should return u32::MAX."
    );

    ensure!(
        state.iterator(&[42]).convert().is_none(),
        "Calling iter on on existent part of tree should return Ok(None)",
    );
    Ok(())
}

#[test]
/// Tests the following:
/// 1. Deleting an existing iterator returns 1.
/// 2. Deleting an already deleted iterator returns 0.
/// 3. Deleting an non-existing iterator returns u32::MAX.
/// 4. Traversing with a deleted iterator should return NEW_OK_NONE
/// 5. Traversing with a non-existing iterator should return
///    InstanceStateEntryResultOption::NEW_ERR.
/// 6. Check that an exhausted iterator returns None on `next`.
/// 7. Check that an exhausted iterator returns the last visited node when
///    querying for key size and key length.
fn test_iterator_deletion_and_consuming() -> anyhow::Result<()> {
    let mut loader = trie::Loader {
        inner: Vec::<u8>::new(),
    };
    let mut m_state = MutableState::initial_state();
    let inner = m_state.get_inner(&mut loader);
    let mut state = InstanceState::new(loader, inner);
    let mut energy = crate::InterpreterEnergy::from(u64::MAX);
    let key = &[0];
    ensure!(state.create_entry(key).is_ok(), "Entry should have been created.");

    let iter = state.iterator(&[0]).convert().context("Iterator should have been created.")?;
    ensure!(
        state.iterator_delete(&mut energy, iter).unwrap() == 1,
        "Iterator should have been deleted."
    );
    ensure!(
        state.iterator_delete(&mut energy, iter).unwrap() == 0,
        "Iterator should already have been deleted."
    );
    ensure!(
        state.iterator_delete(&mut energy, 42.into()).unwrap() == u32::MAX,
        "Iterator should never have existed.."
    );

    let iter = state.iterator(&[0]).convert().context("Iterator should have been created.")?;
    // consume the whole contents of the iterator and it should return NEW_OK_NONE
    ensure!(
        state.iterator_next(&mut energy, iter).is_ok(),
        "Calling next on the iterator at the root of [0] should go fine."
    );
    let last_key_size = state.iterator_key_size(iter);
    let iter_result = state
        .iterator_next(&mut energy, iter)
        .context("Calling next on a non existing iterator should not result in Err.")?;
    ensure!(
        iter_result == InstanceStateEntryResultOption::NEW_OK_NONE,
        "Reaching the end should return in NEW_OK_NONE"
    );

    let key_size = state.iterator_key_size(iter);
    ensure!(
        key_size == last_key_size,
        "After consuming the iterator it should return the last visited nodes key size. Should be \
         {:?} but was {:?}.",
        last_key_size,
        key_size,
    );

    let mut buff = vec![1; key_size as usize];
    ensure!(
        state.iterator_key_read(iter, &mut buff, 0) == key_size,
        "After consuming the iterator then reading the key should should return a written length \
         of {:?}.",
        key_size
    );

    ensure!(
        buff == key,
        "After consuming the iterator then it should write out the last visited key. Expected \
         {:?} but was {:?}",
        buff,
        key
    );

    let iter_result = state
        .iterator_next(&mut energy, 42.into())
        .context("Calling next on a non existing iterator should not result in Err.")?;
    ensure!(
        iter_result == InstanceStateEntryResultOption::NEW_ERR,
        "Traversing with non existing iter (in the instance state) should yield NEW_ERR"
    );
    Ok(())
}

#[test]
/// Tests that operations on entries and iterators with invalid generations
/// fails as expected.
fn test_invalid_generation_operations() -> anyhow::Result<()> {
    let mut loader = trie::Loader {
        inner: Vec::<u8>::new(),
    };
    let mut m_state = MutableState::initial_state();
    let inner = m_state.get_inner(&mut loader);
    let mut state = InstanceState::new(loader, inner);
    let mut energy = crate::InterpreterEnergy::from(u64::MAX);
    let entry = state
        .create_entry(&[0])
        .context("Entry should return Ok")?
        .convert()
        .context("Returned entry id should be Some.")?;

    let (gen, idx) = entry.split();
    let entry_invalid_gen = InstanceStateEntry::new(gen + 1, idx); // invalid generation
    let mut buff = vec![0; 32];
    ensure!(
        state.entry_read(entry_invalid_gen, &mut buff, 0) == u32::MAX,
        "Reading entry with invalid generation should return u32::MAX"
    );

    let write_res = state
        .entry_write(&mut energy, entry_invalid_gen, &buff, 0)
        .context("Writing to entry with invalid generation should return u32::MAX.")?;
    ensure!(
        write_res == u32::MAX,
        "Writing to entry with invalid generation should return u32::MAX"
    );

    ensure!(
        state.entry_size(entry_invalid_gen) == u32::MAX,
        "Getting size of entry with invalid generation should return u32::MAX."
    );

    let resize_res = state
        .entry_resize(&mut energy, entry_invalid_gen, 42)
        .context("Resizing entry with invalid generation should return u32::MAX.")?;
    ensure!(
        resize_res == u32::MAX,
        "Resizing entry with invalid generation should return u32::MAX"
    );

    let iter = state.iterator(&[0]).convert().context("Creating iterator should not fail.")?;
    let (gen, iter_idx) = iter.split();
    let iter_invalid_gen = InstanceStateIteratorResultOption::new_ok_some(gen + 1, iter_idx)
        .convert()
        .context("Creating iter with new generation should not fail.")?;
    ensure!(
        state.iterator_delete(&mut energy, iter_invalid_gen).unwrap() == u32::MAX,
        "Deleting iterator with invalid generation should return u32::MAX."
    );

    ensure!(
        state.iterator_key_size(iter_invalid_gen) == u32::MAX,
        "Iterator key size with invalid generation should return u32::MAX."
    );

    ensure!(
        state.iterator_key_read(iter_invalid_gen, &mut buff, 0) == u32::MAX,
        "Iterator key read with invalid generation should return u32::MAX."
    );

    let next_res = state
        .iterator_next(&mut energy, iter_invalid_gen)
        .context("Calling next on iterator with invalid generation should return Ok.")?;

    ensure!(
        next_res == InstanceStateEntryResultOption::NEW_ERR,
        "Calling next on iterator with invalid generation should return \
         InstanceStateEntryResultOption::NEW_ERR."
    );

    Ok(())
}
