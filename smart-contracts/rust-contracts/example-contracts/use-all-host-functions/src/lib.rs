#![cfg_attr(not(feature = "std"), no_std)]
use concordium_sc_base::*;

type State = u8;

#[init(name = "init")]
#[inline(always)]
fn contract_init<L: HasLogger>(
    ctx: InitContext,
    _amount: Amount,
    _logger: &mut L,
) -> InitResult<State> {
    Ok(ctx.get_time().to_be_bytes()[0])
}

#[receive(name = "receive", low_level)]
#[inline(always)]
fn contract_receive<A: HasActions, L: HasLogger>(
    ctx: ReceiveContext,
    _amount: Amount,
    logger: &mut L,
    state: &mut ContractState,
) -> ReceiveResult<A> {
    logger.log_bytes(&[1, 2, 3]); // Exercises log_event()
    let _x: u8 = ctx.parameter_cursor().get()?; // Exercises get_parameter_size() & get_parameter_section()
    let state_contents: [u8; 32] = state.get()?; // Exercises state_size() & load_state()
    state.write(&state_contents)?; // Exercises write_state()
    state.reserve(0); // Exercises state_size() & resize_state()
                      // get_receive_ctx_size() currently unreachable
    Ok(A::send(ctx.self_address(), "receive", 100, &[1, 2, 3])
        .and_then(A::simple_transfer(ctx.owner(), 100).or_else(A::accept())))
    // Exercises combine_and, combine_or, send, simple_transfer and accept
}
