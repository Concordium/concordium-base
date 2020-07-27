#![cfg_attr(not(feature = "std"), no_std)]
use concordium_sc_base::*;

pub struct State {
    step:          u8,
    current_count: u32,
}

impl Serialize for State {
    fn serial<W: Write>(&self, out: &mut W) -> Result<(), W::Err> {
        out.write_u8(self.step)?;
        out.write_u32(self.current_count)
    }

    fn deserial<R: Read>(source: &mut R) -> Result<Self, R::Err> {
        let step = source.read_u8()?;
        let current_count = source.read_u32()?;
        Ok(State {
            step,
            current_count,
        })
    }
}

#[init(name = "init")]
#[inline(always)]
fn contract_init(_ctx: InitContext, amount: Amount) -> InitResult<State> {
    let step: u8 = (amount % 256) as u8;
    events::log(&(0u8, step));
    let state = State {
        step,
        current_count: 0,
    };
    Ok(state)
}

#[receive(name = "receive")]
#[inline(always)]
fn contract_receive(ctx: ReceiveContext, amount: Amount, state: &mut State) -> ReceiveResult {
    ensure!(amount > 10, "Amount too small, not increasing.");
    ensure!(ctx.sender().matches_account(&ctx.owner()), "Only the owner can increment.");
    events::log(&(1u8, state.step));
    state.current_count += u32::from(state.step);
    Ok(Action::accept())
}

/// This function does the same as the previous one, but uses a more low-level
/// interface to contract state. In particular it only writes the current_count
/// to the new state writing only bytes 1-5 of the new state.
///
/// While in this particular case this is likely irrelevant, it serves to
/// demonstrates the pattern.
#[receive(name = "receive_optimized", low_level)]
#[inline(always)]
fn contract_receive_optimized(
    ctx: ReceiveContext,
    amount: Amount,
    state_cursor: &mut ContractState,
) -> ReceiveResult {
    ensure!(amount > 10, "Amount too small, not increasing.");
    ensure!(ctx.sender().matches_account(&ctx.owner()), "Only the owner can increment.");
    let state: State = state_cursor.get()?;
    events::log(&(1u8, state.step));
    // get to the current count position.
    state_cursor.seek(SeekFrom::Start(1))?;
    // and overwrite it with the new count.
    (state.current_count + u32::from(state.step)).serial(state_cursor)?;
    Ok(Action::accept())
}
