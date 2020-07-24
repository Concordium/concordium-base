#![cfg_attr(not(feature = "std"), no_std)]
use concordium_sc_base::*;

use sha2::Digest;

impl Serialize for Hash {
    fn serial<W: Write>(&self, out: &mut W) -> Option<()> { self.0.serial(out) }

    fn deserial<R: Read>(source: &mut R) -> Option<Self> { Some(Hash(source.get()?)) }
}

impl Serialize for State {
    fn serial<W: Write>(&self, out: &mut W) -> Option<()> {
        self.num_contributions.serial(out)?;
        self.contributions.serial(out)?;
        self.expiry.serial(out)?;
        self.prefix.serial(out)
    }

    fn deserial<R: Read>(source: &mut R) -> Option<Self> {
        let num_contributions = source.get()?;
        let contributions = source.get()?;
        let expiry = source.get()?;
        let prefix = source.get()?;
        Some(State {
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

pub struct State {
    /// Number of contributions. Could be different from the size of the map if
    /// the same person contributes multiple times.
    num_contributions: u32,
    /// Stored contributions. The Hash is the lowest per account.
    contributions: collections::BTreeMap<AccountAddress, (Amount, Hash)>,
    expiry: u64,
    prefix: [u8; 32],
}

#[init(name = "init")]
#[inline(always)]
fn contract_init(ctx: InitContext, amount: Amount) -> InitResult<State> {
    let initializer = ctx.init_origin();
    let mut contributions = collections::BTreeMap::new();
    let (expiry, init): (_, Contribution) = ctx.parameter().ok_or_else(Reject::default)?;
    let ct = ctx.get_time();
    ensure!(expiry > ct, "Expiry must be strictly in the future.");
    let hash = {
        let mut hasher: sha2::Sha256 = Digest::new();
        hasher.update(&init);
        hasher.update(&initializer);
        Hash(hasher.finalize().into())
    };
    events::log(initializer);
    events::log_str(&hex::encode(&hash.0));
    contributions.insert(*initializer, (amount, hash));
    let state = State {
        num_contributions: 1,
        contributions,
        expiry,
        prefix: init,
    };
    Ok(state)
}

#[receive(name = "receive_contribute")]
#[inline(always)]
fn contribute(ctx: ReceiveContext, amount: Amount, state: &mut State) -> ReceiveResult {
    ensure!(
        amount > u64::from(state.num_contributions) * 10,
        "Amount too small, rejecting contribution."
    );
    let cont: Contribution = match ctx.parameter() {
        Some(m) => m,
        None => bail!("Cannot deserialize parameter."),
    };
    match ctx.sender() {
        Address::Account(addr) => {
            let hash = {
                let mut hasher: sha2::Sha256 = Digest::new();
                hasher.update(&state.prefix);
                hasher.update(&addr); // add address to avoid stupidity.
                hasher.update(&cont);
                Hash(hasher.finalize().into())
            };
            events::log_str(&hex::encode(&hash.0));
            match state.contributions.get_mut(&addr) {
                Some(pair) => {
                    pair.0 += amount;
                    if hash < pair.1 {
                        pair.1 = hash
                    }
                }
                None => {
                    state.contributions.insert(*addr, (amount, hash));
                }
            }
            Ok(Action::accept())
        }
        _ => bail!("Only accounts can contribute."),
    }
}

#[receive(name = "receive_finalize")]
#[inline(always)]
fn finalize(ctx: ReceiveContext, amount: Amount, state: &mut State) -> ReceiveResult {
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

            // Invalidate state so others can help themselves.
            state.expiry = 0;
            state.contributions.clear();
            state.num_contributions = 0;

            Ok(send.unwrap_or_else(Action::accept))
        }
    }
}

#[receive(name = "receive_help_yourself")]
#[inline(always)]
fn help_yourself(ctx: ReceiveContext, amount: Amount, state: &mut State) -> ReceiveResult {
    ensure!(amount == 0, "Helping yourself should not add tokens.");
    ensure!(state.contributions.is_empty(), "Cannot help yourself while there are participants.");
    Ok(Action::simple_transfer(ctx.invoker(), ctx.self_balance()))
}
