#![cfg_attr(all(not(feature = "std"), not(test)), no_std)]
use concordium_sc_base::*;

#[contract_state]
#[derive(Serialize, SchemaType)]
pub struct State {
    step:          u8,
    current_count: u32,
}

#[init(name = "init")]
fn contract_init<I: HasInitContext<()>, L: HasLogger>(
    _ctx: &I,
    amount: Amount,
    logger: &mut L,
) -> InitResult<State> {
    let step: u8 = (amount % 256) as u8;
    logger.log(&(0u8, step));
    let state = State {
        step,
        current_count: 0,
    };
    Ok(state)
}

#[receive(name = "receive")]
fn contract_receive<R: HasReceiveContext<()>, L: HasLogger, A: HasActions>(
    ctx: &R,
    amount: Amount,
    logger: &mut L,
    state: &mut State,
) -> ReceiveResult<A> {
    ensure!(amount > 10, "Amount too small, not increasing.");
    ensure!(ctx.sender().matches_account(&ctx.owner()), "Only the owner can increment.");
    logger.log(&(1u8, state.step));
    state.current_count += u32::from(state.step);
    Ok(A::accept())
}

/// This function does the same as the previous one, but uses a more low-level
/// interface to contract state. In particular it only writes the current_count
/// to the new state writing only bytes 1-5 of the new state.
///
/// While in this particular case this is likely irrelevant, it serves to
/// demonstrates the pattern.
#[receive(name = "receive_optimized", low_level)]
fn contract_receive_optimized<
    R: HasReceiveContext<()>,
    L: HasLogger,
    S: HasContractState<()>,
    A: HasActions,
>(
    ctx: &R,
    amount: Amount,
    logger: &mut L,
    state_cursor: &mut S,
) -> ReceiveResult<A> {
    ensure!(amount > 10, r#"Amount too small, not increasing."#);
    ensure!(ctx.sender().matches_account(&ctx.owner()), "Only the owner can increment.");
    let state: State = state_cursor.get()?;
    logger.log(&(1u8, state.step));
    // get to the current count position.
    state_cursor.seek(SeekFrom::Start(1))?;
    // and overwrite it with the new count.
    (state.current_count + u32::from(state.step)).serial(state_cursor)?;
    Ok(A::accept())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    /// Test that init succeeds or fails based on what parameter and amount are.
    fn test_init() {
        println!("Schema {:?}", State::get_type());
        // Setup our example state the contract is to be run in.
        // First the context.
        let metadata = ChainMetadata {
            slot_number:      0,
            block_height:     0,
            finalized_height: 0,
            slot_time:        0,
        };
        let init_origin = AccountAddress([0u8; 32]);
        let init_ctx = InitContext {
            metadata,
            init_origin,
        };
        // The init function does not expect a parameter, so empty will do.
        let parameter = Vec::new();
        let ctx = test_infrastructure::InitContextWrapper {
            init_ctx,
            parameter: &parameter,
        };
        // set up the logger so we can intercept and analyze them at the end.
        let mut logger = test_infrastructure::LogRecorder::init();

        // call the init function
        let out = contract_init(&ctx, 13, &mut logger);

        // and inspect the result.
        if let Ok(state) = out {
            claim_eq!(state.step, 13, "The counting step differs from initial amount (mod 256).");
            claim_eq!(state.current_count, 0);
        } else {
            claim!(false, "Contract initialization failed.");
        }
        // and make sure the correct logs were produced.
        claim_eq!(logger.logs.len(), 1, "Incorrect number of logs produced.");
        claim_eq!(&logger.logs[0], &[0, 13], "Incorrect log produced.");
    }

    #[test]
    /// Basic functional correctness of receive.
    ///
    /// - step is maintained
    /// - count is bumped by the step
    fn test_receive() {
        // Setup our example state the contract is to be run in.
        // First the context.
        let metadata = ChainMetadata {
            slot_number:      0,
            block_height:     0,
            finalized_height: 0,
            slot_time:        0,
        };
        let invoker = AccountAddress([0u8; 32]);
        let receive_ctx = ReceiveContext {
            metadata,
            invoker,
            self_address: ContractAddress {
                index:    0,
                subindex: 0,
            },
            self_balance: 0,
            sender: Address::Account(invoker),
            owner: invoker,
        };
        // Still no parameter expected.
        let parameter = Vec::new();
        let ctx = test_infrastructure::ReceiveContextWrapper {
            receive_ctx,
            parameter: &parameter,
        };
        // set up the logger so we can intercept and analyze them at the end.
        let mut logger = test_infrastructure::LogRecorder::init();
        let mut state = State {
            step:          1,
            current_count: 13,
        };
        let res: ReceiveResult<test_infrastructure::ActionsTree> =
            contract_receive(&ctx, 11, &mut logger, &mut state);
        match res {
            Err(_) => claim!(false, "Contract receive failed, but it should not have."),
            Ok(actions) => {
                claim_eq!(
                    actions,
                    test_infrastructure::ActionsTree::Accept,
                    "Contract receive produced incorrect actions."
                );
                claim_eq!(state.step, 1, "Contract receive updated the step.");
                claim_eq!(state.current_count, 14, "Contract receive did not bump the step.");
            }
        }
    }
}
