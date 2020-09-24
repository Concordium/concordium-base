#![cfg_attr(not(feature = "std"), no_std)]
use concordium_sc_base::*;

#[derive(Serialize)]
pub struct State {
    result: u64,
}

#[init(name = "init")]
#[inline(always)]
fn contract_init<I: HasInitContext<()>, L: HasLogger>(
    _ctx: I,
    _amount: Amount,
    _logger: &mut L,
) -> InitResult<State> {
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
fn contract_receive<R: HasReceiveContext<()>, A: HasActions, L: HasLogger>(
    ctx: R,
    _amount: Amount,
    _logger: &mut L,
    state: &mut State,
) -> ReceiveResult<A> {
    // Try to get the parameter (64bit unsigned integer).
    let n: u64 = ctx.parameter_cursor().get()?;
    if n <= 1 {
        state.result += 1;
        Ok(A::accept())
    } else {
        let self_address = ctx.self_address();
        Ok(A::send(&self_address, "receive", 0, &(n - 1).to_le_bytes()).and_then(A::send(
            &self_address,
            "receive",
            0,
            &(n - 2).to_le_bytes(),
        )))
    }
}

// Calculates the nth Fibonacci number where n is the given amount and sets the
// state to that number.
#[receive(name = "receive_calc_fib")]
#[inline(always)]
fn contract_receive_calc_fib<R: HasReceiveContext<()>, A: HasActions, L: HasLogger>(
    _ctx: R,
    amount: Amount,
    _logger: &mut L,
    state: &mut State,
) -> ReceiveResult<A> {
    state.result = fib(amount);
    Ok(A::accept())
}

// Recursively and naively calculate the nth Fibonacci number.
fn fib(n: u64) -> u64 {
    if n <= 1 {
        1
    } else {
        fib(n - 1) + fib(n - 2)
    }
}
