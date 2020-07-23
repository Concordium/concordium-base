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

impl Serialize for Message {
    fn serial<W: Write>(&self, out: &mut W) -> Option<()> {
        use Message::*;
        match self {
            Contribute(ref cont) => {
                out.write_u8(0).ok()?;
                out.write_all(cont).ok()
            }
            Finalize => out.write_u8(1).ok(),
        }
    }

    fn deserial<R: Read>(source: &mut R) -> Option<Self> {
        use Message::*;
        let tag = u8::deserial(source)?;
        match tag {
            0 => {
                let mut bytes = [0u8; 32];
                source.read_exact(&mut bytes).ok()?;
                Some(Contribute(bytes))
            }
            1 => Some(Finalize),
            _ => None,
        }
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

pub enum Message {
    Contribute(Contribution),
    Finalize,
}

#[init(name = "init")]
#[inline(always)]
fn contract_init(ctx: InitContext, amount: Amount) -> InitResult<State> {
    let initializer = ctx.init_origin();
    let mut contributions = collections::BTreeMap::new();
    let (expiry, init): (_, Contribution) = ctx.parameter().ok_or_else(Reject::default)?;
    let hash = {
        let mut hasher: sha2::Sha256 = Digest::new();
        hasher.update(&init);
        hasher.update(&initializer);
        Hash(hasher.finalize().into())
    };
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

#[receive(name = "receive")]
#[inline(always)]
fn contract_receive(ctx: ReceiveContext, amount: Amount, state: &mut State) -> ReceiveResult {
    ensure!(
        amount > u64::from(state.num_contributions) * 10,
        "Amount too small, rejecting contribution."
    );
    let msg: Message = ctx.parameter().ok_or_else(Reject::default)?;
    match msg {
        Message::Contribute(cont) => {
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
                    Ok(ReceiveActions::Accept)
                }
                _ => bail!("Only accounts can contribute."),
            }
        }
        Message::Finalize => {
            let ct = ctx.get_time();
            ensure!(ct >= state.expiry, "Cannot finalize before expiry time.");
            ensure!(ctx.sender().matches_account(ctx.owner()), "Only the owner can finalize.");
            let mut v = state.contributions.iter().collect::<Vec<_>>();
            v.sort_by_key(|triple| &(triple.1).1);
            let mut total: Amount = v.iter().map(|triple| (triple.1).0).sum();
            for (addr, _) in v.iter().rev() {
                let to_transfer = total / 2;
                // FIXME: Not sure what the best way to not ignore the action is.
                let _ = Action::simple_transfer(addr, to_transfer);
                events::log::<AccountAddress>(addr);
                total -= to_transfer;
                if total == 0 {
                    break;
                }
            }
            Ok(ReceiveActions::Accept)
        }
    }
}
