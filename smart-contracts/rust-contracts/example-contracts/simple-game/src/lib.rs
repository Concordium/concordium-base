#![cfg_attr(not(feature = "std"), no_std)]
use concordium_sc_base::*;

use sha2::Digest;

impl Serialize for Hash {
    fn serial<W: Write>(&self, out: &mut W) -> Result<(), W::Err> { self.0.serial(out) }

    fn deserial<R: Read>(source: &mut R) -> Result<Self, R::Err> { Ok(Hash(source.get()?)) }
}

impl Serialize for State {
    fn serial<W: Write>(&self, out: &mut W) -> Result<(), W::Err> {
        self.num_contributions.serial(out)?;
        self.expiry.serial(out)?;
        self.prefix.serial(out)?;
        self.contributions.serial(out)
    }

    fn deserial<R: Read>(source: &mut R) -> Result<Self, R::Err> {
        let num_contributions = source.get()?;
        let expiry = source.get()?;
        let prefix = source.get()?;
        let contributions = source.get()?;
        Ok(State {
            num_contributions,
            contributions,
            expiry,
            prefix,
        })
    }
}

#[derive(Ord, PartialOrd, PartialEq, Eq)]
struct Hash([u8; 32]);

type Contribution = [u8; 32];

type Prefix = [u8; 32];

pub struct State {
    /// Number of contributions. Could be different from the size of the map if
    /// the same person contributes multiple times.
    num_contributions: u32,
    expiry: u64,
    prefix: Prefix,
    /// Stored contributions. The Hash is the lowest per account.
    contributions: collections::BTreeMap<AccountAddress, (Amount, Hash)>,
}

#[init(name = "init", low_level)]
#[inline(always)]
fn contract_init(ctx: InitContext, amount: Amount, state: &mut ContractState) -> InitResult<()> {
    let initializer = ctx.init_origin();
    // FIXME: Unify the use of error handling to Result<..,..>  to avoid this kind
    // of stupidity.
    let (expiry, prefix): (u64, Prefix) = ctx.parameter()?;
    let ct = ctx.get_time();
    ensure!(expiry > ct, "Expiry must be strictly in the future.");
    let hash = {
        let mut hasher: sha2::Sha256 = Digest::new();
        hasher.update(&prefix);
        hasher.update(&initializer);
        Hash(hasher.finalize().into())
    };
    events::log(initializer);
    events::log_str(&hex::encode(&hash.0));
    let num_contributions: u32 = 1;
    // Manually write the state without any intermediate allocation.
    num_contributions.serial(state)?;
    // Write expiry
    expiry.serial(state)?;
    // and the initialization string.
    prefix.serial(state)?;
    // Finally write the map.
    1u32.serial(state)?;
    initializer.serial(state)?;
    amount.serial(state)?;
    hash.serial(state)?;
    Ok(())
}

#[receive(name = "receive_contribute", low_level)]
#[inline(always)]
fn contribute(ctx: ReceiveContext, amount: Amount, state: &mut ContractState) -> ReceiveResult {
    let num_contributions: u32 = state.get()?;
    ensure!(
        amount > u64::from(num_contributions) * 10,
        "Amount too small, rejecting contribution."
    );
    let cont: Contribution = match ctx.parameter() {
        Ok(m) => m,
        Err(_) => bail!("Cannot deserialize parameter."),
    };
    match ctx.sender() {
        Address::Account(addr) => {
            let hash = {
                state.seek(SeekFrom::Current(8))?;
                let prefix: Prefix = state.get()?;
                let mut hasher: sha2::Sha256 = Digest::new();
                hasher.update(&prefix);
                hasher.update(&addr); // add address to avoid stupidity.
                hasher.update(&cont);
                Hash(hasher.finalize().into())
            };
            events::log_str(&hex::encode(&hash.0));
            // Now try to find the contribution in the map.
            // map length
            let len: u32 = state.get()?;
            let mut found = false;
            for _ in 0..len {
                let key: AccountAddress = state.get()?;
                if key == *addr {
                    let cur_amount: Amount = state.get()?;
                    // Go back to before the amount;
                    state.seek(SeekFrom::Current(-8)).map_err(|()| Reject::default())?;
                    // update the amount
                    (cur_amount + amount).serial(state)?;
                    let cur_hash = state.get()?;
                    // if the new contribution is smaller update the hash.
                    if hash < cur_hash {
                        state.seek(SeekFrom::Current(-32)).map_err(|()| Reject::default())?;
                        // update the amount
                        hash.serial(state)?;
                    }
                    found = true;
                    break;
                } else {
                    // skip the values otherwise (8 + 32 bytes)
                    state.seek(SeekFrom::Current(40)).map_err(|()| Reject::default())?;
                }
            }
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
            Ok(Action::accept())
        }
        _ => bail!("Only accounts can contribute."),
    }
}

#[receive(name = "receive_finalize", low_level)]
#[inline(always)]
fn finalize(
    ctx: ReceiveContext,
    amount: Amount,
    state_cursor: &mut ContractState,
) -> ReceiveResult {
    let state: State = state_cursor.get()?;
    let ct = ctx.get_time();
    ensure!(amount == 0, "Ending the game should not transfer any tokens.");
    ensure!(ct >= state.expiry, "Cannot finalize before expiry time.");
    ensure!(!state.contributions.is_empty(), "Already finalized.");
    ensure!(ctx.sender().matches_account(ctx.owner()), "Only the owner can finalize.");
    let mut v = state.contributions.iter().collect::<Vec<_>>();
    v.sort_by_key(|triple| &(triple.1).1);
    match v.split_last() {
        None => Ok(Action::accept()),
        Some(((addr, _), init)) => {
            let mut total: Amount = v.iter().map(|triple| (triple.1).0).sum();

            // Try to send, but if sending to a particular account fails the other
            // actions should still be attempted.
            let try_send = |addr, to_transfer| {
                Action::simple_transfer(addr, to_transfer).or_else(Action::accept())
            };

            let to_transfer = total / 2;
            let send = try_send(addr, to_transfer);
            events::log::<AccountAddress>(addr);
            total -= to_transfer;
            let send = init.iter().rev().try_fold(send, |acc, (addr, _)| {
                if total > 0 {
                    let to_transfer = total / 2;
                    events::log::<AccountAddress>(addr);
                    total -= to_transfer;
                    Some(acc.and_then(try_send(addr, to_transfer)))
                } else {
                    None
                }
            });
            state_cursor.truncate(0);
            Ok(send.unwrap_or_else(Action::accept))
        }
    }
}

#[receive(name = "receive_help_yourself", low_level)]
#[inline(always)]
fn help_yourself(ctx: ReceiveContext, amount: Amount, state: &mut ContractState) -> ReceiveResult {
    ensure!(amount == 0, "Helping yourself should not add tokens.");
    ensure!(
        state.size() == 0,
        "Helping yourself only allowed after normal contributions are sent.."
    );
    Ok(Action::simple_transfer(ctx.invoker(), ctx.self_balance()))
}
