#![cfg_attr(all(not(feature = "std"), not(test)), no_std)]
use concordium_std::*;

#[contract_state(contract = "counter")]
#[derive(Serialize)]
#[cfg_attr(feature = "std", derive(SchemaType))]
struct State {
    step:          u8,
    current_count: u32,
}

#[init(contract = "counter", enable_logger, payable)]
fn contract_init(
    _ctx: &impl HasInitContext<()>,
    amount: Amount,
    logger: &mut impl HasLogger,
) -> InitResult<State> {
    let step: u8 = (amount.micro_ccd % 256) as u8;
    logger.log(&(0u8, step))?;
    let state = State {
        step,
        current_count: 0,
    };
    Ok(state)
}

/// Custom Error type only for testing purposes.
/// Not usable when contract is deployed to the chain.
#[derive(Debug, PartialEq, Eq, Reject)]
enum ReceiveError {
    /// Amount too small to allow increasing.
    SmallAmount,
    /// Only the owner can increment.
    OnlyOwner,
}

#[receive(contract = "counter", name = "receive", payable, enable_logger)]
fn contract_receive<A: HasActions>(
    ctx: &impl HasReceiveContext<()>,
    amount: Amount,
    logger: &mut impl HasLogger,
    state: &mut State,
) -> Result<A, ReceiveError> {
    ensure!(amount.micro_ccd > 10, ReceiveError::SmallAmount);
    ensure!(ctx.sender().matches_account(&ctx.owner()), ReceiveError::OnlyOwner);
    logger.log(&(1u8, state.step)).expect("Cannot happen.");
    state.current_count += u32::from(state.step);
    Ok(A::accept())
}

/// This function does the same as the previous one, but uses a more low-level
/// interface to contract state. In particular it only writes the current_count
/// to the new state writing only bytes 1-5 of the new state.
///
/// While in this particular case this is likely irrelevant, it serves to
/// demonstrates the pattern.
#[receive(contract = "counter", name = "receive_optimized", low_level, payable, enable_logger)]
fn contract_receive_optimized<A: HasActions>(
    ctx: &impl HasReceiveContext<()>,
    amount: Amount,
    logger: &mut impl HasLogger,
    state_cursor: &mut impl HasContractState<()>,
) -> ReceiveResult<A> {
    ensure!(amount.micro_ccd > 10); // Amount too small, not increasing.
    ensure!(ctx.sender().matches_account(&ctx.owner())); // Only the owner can increment.
    let state: State = state_cursor.get()?;
    logger.log(&(1u8, state.step)).expect("Cannot happen.");
    // get to the current count position.
    state_cursor.seek(SeekFrom::Start(1))?;
    // and overwrite it with the new count.
    (state.current_count + u32::from(state.step)).serial(state_cursor)?;
    Ok(A::accept())
}

#[concordium_cfg_test]
mod tests {
    use super::*;
    use concordium_std::test_infrastructure::*;

    #[concordium_test]
    /// Test that init succeeds or fails based on what parameter and amount are.
    fn test_init() {
        // Setup our example state the contract is to be run in.
        // First the context.
        let ctx = InitContextTest::empty();

        // set up the logger so we can intercept and analyze them at the end.
        let mut logger = LogRecorder::init();

        // call the init function
        let out = contract_init(&ctx, Amount::from_micro_ccd(13), &mut logger);

        // and inspect the result.
        let state = match out {
            Ok(state) => state,
            Err(_) => fail!("Contract initialization failed."),
        };
        claim_eq!(state.current_count, 0);
        claim_eq!(state.step, 13, "The counting step differs from initial amount (mod 256).");
        // and make sure the correct logs were produced.
        claim_eq!(logger.logs.len(), 1, "Incorrect number of logs produced.");
        claim_eq!(&logger.logs[0], &[0, 13], "Incorrect log produced.");
    }

    #[concordium_test]
    /// Basic functional correctness of receive.
    ///
    /// - step is maintained
    /// - count is bumped by the step
    fn test_receive() {
        // Setup our example state the contract is to be run in.
        // First the context.
        let mut ctx = ReceiveContextTest::empty();
        // Set the owner as sender in the context
        let owner = AccountAddress([0u8; 32]);
        ctx.set_owner(owner);
        ctx.set_sender(Address::Account(owner));

        // set up the logger so we can intercept and analyze them at the end.
        let mut logger = LogRecorder::init();
        let mut state = State {
            step:          1,
            current_count: 13,
        };
        let res: Result<ActionsTree, _> =
            contract_receive(&ctx, Amount::from_micro_ccd(11), &mut logger, &mut state);
        let actions = match res {
            Err(_) => fail!("Contract receive failed, but it should not have."),
            Ok(actions) => actions,
        };
        claim_eq!(actions, ActionsTree::Accept, "Contract receive produced incorrect actions.");
        claim_eq!(state.step, 1, "Contract receive updated the step.");
        claim_eq!(state.current_count, 14, "Contract receive did not bump the step.");
    }

    #[concordium_test]
    /// Test receive fails a user which is not the owner increments
    fn test_receive_fails() {
        // Setup our example state the contract is to be run in.
        // First the context.
        let mut ctx = ReceiveContextTest::default();
        // Set the owner as sender in the context
        let owner = AccountAddress([0u8; 32]);
        let sender = AccountAddress([1u8; 32]);
        ctx.set_owner(owner);
        ctx.set_sender(Address::Account(sender));

        // set up the logger so we can intercept and analyze them at the end.
        let mut logger = test_infrastructure::LogRecorder::init();
        let mut state = State {
            step:          1,
            current_count: 13,
        };
        let res: Result<ActionsTree, _> =
            contract_receive(&ctx, Amount::from_micro_ccd(11), &mut logger, &mut state);
        match res {
            Err(reason) => claim_eq!(
                reason,
                ReceiveError::OnlyOwner,
                "Expected error for only owner can increment"
            ),
            Ok(_) => fail!("Contract receive succeeded, but it should not have."),
        };
    }
}
