#![cfg_attr(not(feature = "std"), no_std)]
use concordium_std::*;

type State = u8;

#[init(contract = "use_all")]
#[inline(always)]
fn contract_init(ctx: &impl HasInitContext<()>) -> InitResult<State> {
    Ok(ctx.metadata().slot_time().timestamp_millis().to_be_bytes()[0])
}

#[receive(contract = "use_all", name = "receive", low_level, enable_logger)]
#[inline(always)]
fn contract_receive<A: HasActions>(
    ctx: &impl HasReceiveContext<()>,
    logger: &mut impl HasLogger,
    state: &mut ContractState,
) -> ReceiveResult<A> {
    logger.log_raw(&[1, 2, 3])?; // Exercises log_event()
    let _x: u8 = ctx.parameter_cursor().get()?; // Exercises get_parameter_size() & get_parameter_section()
    let state_contents: [u8; 32] = state.get()?; // Exercises state_size() & load_state()
    state.write(&state_contents)?; // Exercises write_state()
    state.reserve(0); // Exercises state_size() & resize_state()
                      // get_receive_ctx_size() currently unreachable
    Ok(A::send_raw(
        &ctx.self_address(),
        ReceiveName::new_unchecked("use_all.receive"),
        Amount::from_micro_ccd(100),
        &[1, 2, 3],
    )
    .and_then(A::simple_transfer(&ctx.owner(), Amount::from_micro_ccd(100)).or_else(A::accept())))
    // Exercises combine_and, combine_or, send, simple_transfer and accept
}
