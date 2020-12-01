#![cfg_attr(not(feature = "std"), no_std)]
use concordium_std::*;

type State = u8;

#[init(contract = "use_all")]
#[inline(always)]
fn contract_init<I: HasInitContext<()>, L: HasLogger>(
    ctx: &I,
    _amount: Amount,
    _logger: &mut L,
) -> InitResult<State> {
    Ok(ctx.metadata().slot_time().to_be_bytes()[0])
}

#[receive(contract = "use_all", name = "receive", low_level)]
#[inline(always)]
fn contract_receive<R: HasReceiveContext<()>, A: HasActions, L: HasLogger>(
    ctx: &R,
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
    Ok(A::send(&ctx.self_address(), "receive", Amount::from_micro_gtu(100), &[1, 2, 3]).and_then(
        A::simple_transfer(&ctx.owner(), Amount::from_micro_gtu(100)).or_else(A::accept()),
    ))
    // Exercises combine_and, combine_or, send, simple_transfer and accept
}
