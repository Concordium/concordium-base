#![cfg_attr(not(feature = "std"), no_std)]
use concordium_sc_base::*;

pub struct State {
    result: u64,
}

impl Serialize for State {
    fn serial<W: Write>(&self, out: &mut W) -> Result<(), W::Err> { out.write_u64(self.result) }

    fn deserial<R: Read>(source: &mut R) -> Result<Self, R::Err> {
        let result = source.read_u64()?;
        Ok(State {
            result,
        })
    }
}

#[init(name = "init")]
#[inline(always)]
fn contract_init(_ctx: InitContext, _amount: Amount) -> InitResult<State> {
    let state = State {
        result: 0,
    };
    Ok(state)
}

// Add the the nth Fibonacci number F(n) to this contract's state.
// This is achieved by recursively sending messages to this receive method,
// corresponding to the recursive evaluation F(n) = F(n-1) + F(n-2) (for n>1).
#[receive(name = "receive")]
#[inline(always)]
fn contract_receive(ctx: ReceiveContext, _amount: Amount, state: &mut State) -> ReceiveResult {
    // Try to get the parameter (64bit unsigned integer).
    let n: u64 = ctx.parameter()?;
    if n <= 1 {
        state.result += 1;
        Ok(Action::accept())
    } else {
        Ok(Action::send(ctx.self_address(), "receive", 0, &(n - 1).to_le_bytes())
            .and_then(Action::send(ctx.self_address(), "receive", 0, &(n - 2).to_le_bytes())))
    }
}

// Calculates the nth Fibonacci number where n is the given amount and sets the
// state to that number.
#[receive(name = "receive_calc_fib")]
#[inline(always)]
fn contract_receive_calc_fib(
    _ctx: ReceiveContext,
    amount: Amount,
    state: &mut State,
) -> ReceiveResult {
    state.result = fib(amount);
    Ok(Action::accept())
}

// Recursively and naively calculate the nth Fibonacci number.
fn fib(n: u64) -> u64 {
    if n <= 1 {
        1
    } else {
        fib(n - 1) + fib(n - 2)
    }
}
