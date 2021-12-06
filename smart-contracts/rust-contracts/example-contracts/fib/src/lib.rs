#![cfg_attr(not(feature = "std"), no_std)]
use concordium_std::*;

#[contract_state(contract = "fib")]
#[derive(Serialize, SchemaType)]
pub struct State {
    result: u64,
}

#[init(contract = "fib")]
#[inline(always)]
fn contract_init(_ctx: &impl HasInitContext<()>) -> InitResult<State> {
    let state = State {
        result: 0,
    };
    Ok(state)
}

// Add the the nth Fibonacci number F(n) to this contract's state.
// This is achieved by recursively sending messages to this receive method,
// corresponding to the recursive evaluation F(n) = F(n-1) + F(n-2) (for n>1).
#[inline(always)]
#[receive(contract = "fib", name = "receive")]
fn contract_receive<A: HasActions>(
    ctx: &impl HasReceiveContext<()>,
    state: &mut State,
) -> ReceiveResult<A> {
    // Try to get the parameter (64bit unsigned integer).
    let n: u64 = ctx.parameter_cursor().get()?;
    if n <= 1 {
        state.result += 1;
        Ok(A::accept())
    } else {
        let self_address = ctx.self_address();
        Ok(A::send_raw(
            &self_address,
            ReceiveName::new_unchecked("fib.receive"),
            Amount::zero(),
            &(n - 1).to_le_bytes(),
        )
        .and_then(A::send_raw(
            &self_address,
            ReceiveName::new_unchecked("fib.receive"),
            Amount::zero(),
            &(n - 2).to_le_bytes(),
        )))
    }
}

// Calculates the nth Fibonacci number where n is the given amount and sets the
// state to that number.
#[inline(always)]
#[receive(contract = "fib", name = "receive_calc_fib", payable)]
fn contract_receive_calc_fib<A: HasActions>(
    _ctx: &impl HasReceiveContext<()>,
    amount: Amount,
    state: &mut State,
) -> ReceiveResult<A> {
    state.result = fib(amount.micro_ccd);
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
