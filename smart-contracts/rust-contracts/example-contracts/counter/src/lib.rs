#![cfg_attr(not(feature = "std"), no_std)]
use concordium_sc_base::*;

// #[no_mangle]
// pub extern "C" fn init(amount: Amount) {
//     let ctx = InitContext {};
//     let mut state_bytes = ContractState::new();
//     match contract_init(ctx, amount) {
//         Ok(state) => {
//             if state.serial(&mut state_bytes).is_none() {
//                 panic!("Could not initialize contract.");
//             }
//         }
//         Err(_) => internal::fail(),
//     }
// }

// #[no_mangle]
// pub extern "C" fn receive(amount: Amount) {
//     let ctx = ReceiveContext {};
//     let mut state_bytes = ContractState::new();
//     if let Some(mut state) = State::deserial(&mut state_bytes) {
//         match contract_receive(ctx, amount, &mut state) {
//             Ok(_) => {
//                 let res = state_bytes
//                     .seek(SeekFrom::Start(0))
//                     .ok()
//                     .and_then(|_| state.serial(&mut state_bytes));
//                 if res.is_none() {
//                     panic!("Could not write state.")
//                 } else {
//                     internal::accept()
//                 }
//             }
//             Err(_) => internal::fail(),
//         }
//     } else {
//         panic!("Could not read state fully.")
//     }
// }

// The following is an example.
// Example state
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
fn contract_init(ctx: InitContext, amount: Amount) -> InitResult<State> {
    let initializer = ctx.sender();
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
fn contract_receive(ctx: ReceiveContext, amount: Amount, state: &mut State) -> ReceiveResult {
    if amount <= 10 {
        bail!("Amount too small, not increasing.");
    }
    if ctx.sender() != state.initializer {
        bail!("Only the initializer can increment.");
    } else {
        let current_count = state.current_count + u32::from(state.step);
        events::log(&(1u8, state.step));
        state.current_count = current_count;
        Ok(ReceiveActions::Accept)
    }
}
