//! This smart contract implements a game of sorts that exercises more advanced
//! features of the smart contracts library. In particular it brings in
//! dependencies from external crates.
//!
//! The logic of the game is quite ad-hoc. Contributions are gathered
//! competing for who can produce the lowest (in lexicographic ordering)
//! SHA256 hash based on a specific hashing scheme.
//!
//! When the contract is initialized the initializer sets the baseline by
//! hashing
//! - a given prefix that is the parameter to the init method
//! - the address of the initializer
//!
//! When the contract is initialized the expiry time is set. After the expiry
//! time has passed the initializer can invoke the `finalize` function to
//! reward everyone who contributed, based on the ranking of their hashes.
//!
//! Each time a new contribution is made a user has to send an appropriate
//! amount of tokens The required amount increases linearly with the number of
//! contributions.
//!
//! Each time a new contribution is made the hash is computed as follows
//! - prefix that the contract was initialized with
//! - address of the sender of the contribution (which must be an account)
//! - the contribution string
//!
//! An account can contribute multiple times, in which case only their smallest
//! contribution is counted when rewards are given out.
//!
//! Note that there is a lot of redundancy and suboptimal choices in the logic
//! of this contract. That is not the point, the point is to exercise as many
//! parts of the library as possible.

#![cfg_attr(not(feature = "std"), no_std)]
use concordium_std::*;

use sha2::Digest;

#[derive(Ord, PartialOrd, PartialEq, Eq, Serialize, SchemaType)]
struct Hash([u8; 32]);

/// Message expected by the `contribute` function.
type Contribution = [u8; 32];

/// The type of prefixes (part of the parameter expected by teh `init` function.
type Prefix = [u8; 32];

/// State of the smart contract instance.
#[contract_state(contract = "simple_game")]
#[derive(Serialize, SchemaType)]
struct State {
    /// Number of contributions. Could be different from the size of the map if
    /// the same person contributes multiple times.
    num_contributions: u32,
    /// Expiry after which point contributors can be rewarded.
    expiry:            Timestamp,
    /// The prefix the initializer chose. It is part of the input to every hash
    /// that is computed.
    prefix:            Prefix,
    /// Stored contributions. The Hash is the lowest per account, and the amount
    /// is the total amount contributed by this account.
    #[concordium(size_length = 4)]
    contributions:     collections::BTreeMap<AccountAddress, (Amount, Hash)>,
}

#[derive(Serialize, SchemaType)]
struct InitParameter(Timestamp, Prefix);

/// Initialize a smart contract.
/// This method expects as parameter a pair of (u64, Prefix), the expiry and the
/// prefix.
#[init(contract = "simple_game", low_level, parameter = "InitParameter", payable, enable_logger)]
#[inline(always)]
fn contract_init(
    ctx: &impl HasInitContext<()>,
    amount: Amount,
    logger: &mut impl HasLogger,
    state: &mut ContractState,
) -> InitResult<()> {
    let initializer = ctx.init_origin();
    let InitParameter(expiry, prefix) = ctx.parameter_cursor().get()?;
    let ct = ctx.metadata().slot_time();
    ensure!(expiry > ct); // Expiry must be strictly in the future.
                          // Compute the initial hash contribution.
    let hash = {
        let mut hasher: sha2::Sha256 = Digest::new();
        hasher.update(&prefix);
        hasher.update(&initializer);
        Hash(hasher.finalize().into())
    };
    // Log who the initializer was.
    logger.log(&initializer)?;
    // And the initial hash
    logger.log_raw(&hex::encode(&hash.0).as_bytes())?;
    let num_contributions: u32 = 1;
    // Manually write the state without any intermediate allocation.
    // We could instead construct the `State` value and then returned it.
    num_contributions.serial(state)?;
    // Write expiry
    expiry.serial(state)?;
    // and the initialization string.
    prefix.serial(state)?;
    // Finally write the map as length as u32 plus a list of triples (address,
    // amount, hash)
    1u32.serial(state)?;
    initializer.serial(state)?;
    amount.serial(state)?;
    hash.serial(state)?;
    Ok(())
}

/// Contribute to the game. The parameter to this method is a single byte-array
/// of length 32.
#[receive(
    contract = "simple_game",
    name = "receive_contribute",
    low_level,
    parameter = "Contribution",
    payable,
    enable_logger
)]
#[inline(always)]
fn contribute<A: HasActions>(
    ctx: &impl HasReceiveContext<()>,
    amount: Amount,
    logger: &mut impl HasLogger,
    state: &mut ContractState,
) -> ReceiveResult<A> {
    // Current number of contributions.
    let num_contributions: u32 = state.get()?;
    // Ensure that you have to contribute more tokens the later you are to the
    // game. The scaling is arbitrarily linear.
    ensure!(amount.micro_ccd > u64::from(num_contributions) * 10); // Amount too small, rejecting contribution.
                                                                   // Try to get the parameter (which should be exactly 32-bytes for this to
                                                                   // succeed).
    let cont: Contribution = ctx.parameter_cursor().get()?;

    // The main logic of the function. If the the sender is an account then we
    // try to accept the contribution, but otherwise we reject.
    // This is an arbitrary choice, but simplifies the state of the contract a bit.
    match ctx.sender() {
        Address::Account(addr) => {
            // First compute the new hash.
            let hash = {
                // Read the prefix first. The prefix is located after the
                // expiry. The previous location of the cursor was just before
                // the expiry (because we read the number of contributions).
                state.seek(SeekFrom::Current(8))?;
                let prefix: Prefix = state.get()?;
                // Now compute the hash as specified, by concatenating
                // the prefix, the address, and the contribution itself.
                let mut hasher: sha2::Sha256 = Digest::new();
                hasher.update(&prefix);
                hasher.update(&addr); // add address to avoid stupidity.
                hasher.update(&cont);
                Hash(hasher.finalize().into())
            };
            // Log the new contribution in base16, just because we can.
            logger.log_raw(&hex::encode(&hash.0).as_bytes())?;
            // Now try to find the contributor in the map. If it does not exist
            // we'll add a new item, otherwise we'll update an existing entry,
            // only updating a small portion of the contract state.

            // The state cursor is now at the position to read the map length.
            let len: u32 = state.get()?;
            // This indicates whether the contributor has been found in the map or not.
            let mut found = false;
            // Go through all the triples (addr, amount, hash) and try to find the
            // contributor.
            for _ in 0..len {
                let key: AccountAddress = state.get()?;
                if key == addr {
                    // we found the contributor in the existing map.
                    // First read the current contributions.
                    let cur_amount: Amount = state.get()?;
                    // Now go back to before the amount so we can update it.
                    state.seek(SeekFrom::Current(-8))?;
                    // update the amount and write it to the state.
                    (cur_amount + amount).serial(state)?;
                    // Now read the existing hash (the cursor is just after the
                    // amount at this point).
                    let cur_hash = state.get()?;
                    // if the new contribution is smaller update the hash.
                    if hash < cur_hash {
                        // Set the cursor back to before the hash
                        state.seek(SeekFrom::Current(-32))?;
                        // and write the new hash in-place of the old one.
                        hash.serial(state)?;
                    }
                    // else we don't need to do anything. The cursor is now at
                    // the position of the next item in the map
                    found = true;
                    break;
                } else {
                    // If we the current entry was not the current contributor we need to skip
                    // the values (amount and hash) so that in the next iteration of the loop
                    // we start at the address.
                    state.seek(SeekFrom::Current(40))?;
                }
            }
            // If we haven't found an existing entry with the contributor's address we need
            // to add one. At this point the cursor is at the end of contract's
            // state.
            if !found {
                addr.serial(state)?;
                amount.serial(state)?;
                hash.serial(state)?;
                // seek back to where the length is written, and bump it by one
                state.seek(SeekFrom::Start(44))?;
                (len + 1).serial(state)?;
            }
            // Finally bump the number of contributions.
            state.seek(SeekFrom::Start(0))?;
            (num_contributions + 1).serial(state)?;
            Ok(A::accept())
        }
        _ => bail!(), // Only accounts can contribute.
    }
}

/// This entry point finalizes the contract instance and sends out rewards to
/// all the contributors.
#[receive(contract = "simple_game", name = "receive_finalize", low_level, enable_logger)]
#[inline(always)]
fn finalize<A: HasActions>(
    ctx: &impl HasReceiveContext<()>,
    logger: &mut impl HasLogger,
    state_cursor: &mut ContractState,
) -> ReceiveResult<A> {
    // We deserialize the whole state here for now.
    // This is not the most efficient way to do it, but is the simplest.
    // If we stored the map better we would be able to reduce the amount of
    // memory we use, as well as the cost of this. We would not have to sort.
    let state: State = state_cursor.get()?;
    let ct = ctx.metadata().slot_time();
    ensure!(ct >= state.expiry); // Cannot finalize before expiry time.
    ensure!(!state.contributions.is_empty()); // Already finalized.
    ensure!(ctx.sender().matches_account(&ctx.owner())); // Only the owner can finalize.

    // Sort the btreemap by the second key.
    // This would be unnecessary if we swapped the values in the BTreeMap so that
    // the hash would come first, the iterator would then give ordered values
    // already.
    let mut v = state.contributions.iter().collect::<Vec<_>>();
    v.sort_by_key(|triple| &(triple.1).1);
    // Split the first element off from the rest. The first element has the lowest
    // hash, so will be rewarded most.
    // This is needed to send out contributions in decreasing amounts.
    match v.split_first() {
        // The first case should not happen since there will always be at least
        // one contribution, but we just terminate cleanly in that case.
        None => Ok(A::accept()),
        Some(((addr, _), rest)) => {
            let mut total: Amount = v.iter().map(|triple| (triple.1).0).sum();
            // Try to send, but if sending to a particular account fails the other
            // actions should still be attempted.
            let try_send =
                |addr, to_transfer| A::simple_transfer(addr, to_transfer).or_else(A::accept());

            // Transfer by decreasing amounts.
            // The first account gets 1/2 of the total balance, the second 1/4, third 1/8
            // ...
            let (to_transfer, _remainder) = total.quotient_remainder(2);
            let send = try_send(addr, to_transfer);
            logger.log::<AccountAddress>(addr)?;
            total -= to_transfer;
            // Send to each account in the list until there is something to send.
            let send = rest.iter().rev().try_fold(send, |acc, (addr, _)| {
                if total.micro_ccd > 0 {
                    let (to_transfer, _remainder) = total.quotient_remainder(2);
                    logger.log::<AccountAddress>(addr).ok()?;
                    total -= to_transfer;
                    Some(acc.and_then(try_send(addr, to_transfer)))
                } else {
                    None
                }
            });
            // Finally truncate the state to 0, so that subsequent calls to
            // finalize and contribute will fail.
            state_cursor.truncate(0);
            // And send the action. The unwrap should always be safe here since there is
            // always at least one action, but we do the safe thing anyhow and just accept
            // in the mythical case with no contributions.
            Ok(send.unwrap_or_else(A::accept))
        }
    }
}

/// After the finalize transaction is done, it is possible that the contract
/// owns some tokens. This can happen if there is only one contributor (in which
/// case 1/2 of all contributions are left on the contract's balance, or if some
/// transfers were unsuccesful).
///
/// This entry-point allows whoever sends the message to recover the remaining
/// tokens. It will simply send all the currently owned tokens to the person who
/// invoked the top-level transaction this invocation is a part of.
#[receive(contract = "simple_game", name = "receive_help_yourself", low_level)]
#[inline(always)]
fn help_yourself<A: HasActions>(
    ctx: &impl HasReceiveContext<()>,
    state: &mut ContractState,
) -> ReceiveResult<A> {
    ensure!(state.size() == 0); // Helping yourself only allowed after normal contributions are sent.
    Ok(A::simple_transfer(&ctx.invoker(), ctx.self_balance()))
}
