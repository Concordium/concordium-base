#![cfg_attr(not(feature = "std"), no_std)]
use concordium_sc_base::*;

pub struct State {
    step:          u8,
    current_count: u32,
    initializer:   AccountAddress,
}

impl Serialize for State {
    fn serial<W: Write>(&self, out: &mut W) -> Option<()> {
        out.write_u8(self.step).ok()?;
        out.write_u32(self.current_count).ok()?;
        self.initializer.serial(out)
    }

    fn deserial<R: Read>(source: &mut R) -> Option<Self> {
        let step = source.read_u8().ok()?;
        let current_count = source.read_u32().ok()?;
        let initializer = AccountAddress::deserial(source)?;
        Some(State {
            step,
            current_count,
            initializer,
        })
    }
}

#[init(name = "init")]
#[inline(always)]
fn contract_init(ctx: InitContext, amount: Amount) -> InitResult<State> {
    let initializer = *ctx.init_origin();
    let step: u8 = (amount % 256) as u8;
    events::log(&(0u8, step));
    let state = State {
        step,
        current_count: 0,
        initializer,
    };
    Ok(state)
}

#[receive(name = "receive")]
#[inline(always)]
fn contract_receive(ctx: ReceiveContext, amount: Amount, state: &mut State) -> ReceiveResult {
    ensure!(amount > 10, "Amount too small, not increasing.");
    ensure!(
        ctx.sender().matches_account(&state.initializer),
        "Only the initializer can increment."
    );
    events::log(&(1u8, state.step));
    state.current_count += u32::from(state.step);
    Ok(ReceiveActions::Accept)
}
