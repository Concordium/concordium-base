#![cfg_attr(not(feature = "std"), no_std)]
use concordium_sc_base::*;

/* This Escrow contract is more a code sample than a real-world contract that
 * someone might want to use in production.
 *
 * The semantics of this contract have been chosen somewhat arbitrarily.
 * The contract utilises an arbitrator account to resolve disputes between
 * a buyer and seller, and that arbitrator gets paid when the contract is
 * completed (either in favour of the buyer or the seller).
 *
 * More advanced, real-world contracts may want to consider the parties
 * requesting to withdraw funds rather than having them pushed to their
 * accounts and so on, in light of best practises from other chains.
 */

// Types
#[derive(Copy, Clone, Serialize, SchemaType)]
enum Mode {
    AwaitingDeposit,
    AwaitingDelivery,
    AwaitingArbitration,
    Done,
}

#[derive(Serialize, SchemaType)]
enum Arbitration {
    ReturnDepositToBuyer,
    ReleaseFundsToSeller,
    ReawaitDelivery,
}

#[derive(Serialize, SchemaType)]
enum Message {
    SubmitDeposit,
    AcceptDelivery,
    Contest,
    Arbitrate(Arbitration),
}

#[derive(Serialize, SchemaType)]
pub struct InitParams {
    required_deposit: Amount,
    arbiter_fee:      Amount,
    buyer:            AccountAddress,
    seller:           AccountAddress,
    arbiter:          AccountAddress,
}

#[contract_state]
#[derive(Serialize, SchemaType)]
pub struct State {
    mode:        Mode,
    init_params: InitParams,
}

// Contract implementation

#[init(name = "init")]
#[inline(always)]
fn contract_init<I: HasInitContext<()>, L: HasLogger>(
    ctx: &I,
    amount: Amount,
    _logger: &mut L,
) -> InitResult<State> {
    ensure!(amount == 0, "This escrow contract must be initialised with a 0 amount.");
    let init_params: InitParams = ctx.parameter_cursor().get()?;
    ensure!(
        init_params.buyer != init_params.seller,
        "Buyer and seller must have different accounts."
    );
    let state = State {
        mode: Mode::AwaitingDeposit,
        init_params,
    };
    Ok(state)
}

#[receive(name = "receive")]
#[inline(always)]
fn contract_receive<R: HasReceiveContext<()>, L: HasLogger, A: HasActions>(
    ctx: &R,
    amount: Amount,
    _logger: &mut L,
    state: &mut State,
) -> ReceiveResult<A> {
    let msg: Message = ctx.parameter_cursor().get()?;
    match (state.mode, msg) {
        (Mode::AwaitingDeposit, Message::SubmitDeposit) => {
            ensure!(
                ctx.sender().matches_account(&state.init_params.buyer),
                "Only the designated buyer can submit the deposit."
            );
            ensure!(
                amount == state.init_params.required_deposit + state.init_params.arbiter_fee,
                "Amount given does not match the required deposit and arbiter fee."
            );
            state.mode = Mode::AwaitingDelivery;
            Ok(A::accept())
        }

        (Mode::AwaitingDelivery, Message::AcceptDelivery) => {
            ensure!(
                ctx.sender().matches_account(&state.init_params.buyer),
                "Only the designated buyer can accept delivery."
            );
            state.mode = Mode::Done;
            let release_payment_to_seller =
                A::simple_transfer(&state.init_params.seller, state.init_params.required_deposit);
            let pay_arbiter =
                A::simple_transfer(&state.init_params.arbiter, state.init_params.arbiter_fee);
            Ok(try_send_both(release_payment_to_seller, pay_arbiter))
        }

        (Mode::AwaitingDelivery, Message::Contest) => {
            ensure!(
                ctx.sender().matches_account(&state.init_params.buyer)
                    || ctx.sender().matches_account(&state.init_params.seller),
                "Only the designated buyer or seller can contest delivery."
            );
            state.mode = Mode::AwaitingArbitration;
            Ok(A::accept())
        }

        (Mode::AwaitingArbitration, Message::Arbitrate(Arbitration::ReturnDepositToBuyer)) => {
            state.mode = Mode::Done;
            let return_deposit =
                A::simple_transfer(&state.init_params.buyer, state.init_params.required_deposit);
            let pay_arbiter =
                A::simple_transfer(&state.init_params.arbiter, state.init_params.arbiter_fee);
            Ok(try_send_both(return_deposit, pay_arbiter))
        }

        (Mode::AwaitingArbitration, Message::Arbitrate(Arbitration::ReleaseFundsToSeller)) => {
            state.mode = Mode::Done;
            let release_payment_to_seller =
                A::simple_transfer(&state.init_params.seller, state.init_params.required_deposit);
            let pay_arbiter =
                A::simple_transfer(&state.init_params.arbiter, state.init_params.arbiter_fee);
            Ok(try_send_both(release_payment_to_seller, pay_arbiter))
        }

        (Mode::AwaitingArbitration, Message::Arbitrate(Arbitration::ReawaitDelivery)) => {
            state.mode = Mode::AwaitingDelivery;
            Ok(A::accept())
        }

        (Mode::Done, _) => {
            bail!("This escrow contract has been completed - there is nothing more for it to do.")
        }

        _ => bail!("Invalid operation for current mode."),
    }
}

// Try to send a, and whether it succeeds or fails, try to send b
fn try_send_both<A: HasActions>(a: A, b: A) -> A {
    let best_effort_a = a.or_else(A::accept());
    let best_effort_b = b.or_else(A::accept());
    best_effort_a.and_then(best_effort_b)
}

// Tests

// We don't use claim_eq! etc. here since they end up requiring formatters
// which we don't necessarily want to import, etc., etc.
#[cfg(test)]
pub mod tests {
    use super::*;

    #[test]
    #[no_mangle]
    fn test_init_rejects_non_zero_amounts() {
        let metadata = ChainMetadata {
            slot_number:      1172,
            block_height:     1150,
            finalized_height: 1148,
            slot_time:        43578934,
        };
        let init_origin = AccountAddress([4; ACCOUNT_ADDRESS_SIZE]);
        let init_ctx = InitContext {
            metadata,
            init_origin,
        };
        let parameter = InitParams {
            required_deposit: 20,
            arbiter_fee:      30,
            buyer:            init_origin,
            seller:           AccountAddress([3; ACCOUNT_ADDRESS_SIZE]),
            arbiter:          AccountAddress([3; ACCOUNT_ADDRESS_SIZE]),
        };
        let ctx = test_infrastructure::InitContextWrapper {
            init_ctx,
            parameter: &to_bytes(&parameter),
        };
        let amount = 200;
        let mut logger = test_infrastructure::LogRecorder::init();
        let result = contract_init(&ctx, amount, &mut logger);
        claim!(result.is_err(), "init failed to reject a non-zero amount");
    }

    #[test]
    #[no_mangle]
    fn test_init_rejects_same_buyer_and_seller() {
        todo!("implement me");
    }

    #[test]
    #[no_mangle]
    fn test_init_builds_corresponding_state_from_init_params() {
        todo!("implement me");
    }

    #[test]
    #[no_mangle]
    fn test_receive_happy_path() {
        todo!("implement me");
    }

    // TODO Lots more to test!
}
